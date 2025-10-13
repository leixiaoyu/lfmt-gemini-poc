import { handler, s3Client, ddbClient } from './processUpload';
import { HeadObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { UpdateCommand } from '@aws-sdk/lib-dynamodb';

// Use jest.spyOn to mock the send method on the imported client instances
const s3SendSpy = jest.spyOn(s3Client, 'send');
const ddbSendSpy = jest.spyOn(ddbClient, 'send');

describe('Process Upload Handler', () => {
  beforeEach(() => {
    // Clear mock history before each test
    s3SendSpy.mockClear();
    ddbSendSpy.mockClear();
    process.env.JOBS_TABLE_NAME = 'test-jobs-table';
  });

  afterAll(() => {
    // Restore original implementations after all tests
    s3SendSpy.mockRestore();
    ddbSendSpy.mockRestore();
  });

  const createS3Event = (key: string) => ({
    Records: [{ s3: { bucket: { name: 'test-bucket' }, object: { key: encodeURIComponent(key) } } }],
  } as any);

  it('should validate a correct file and update status to VALIDATED', async () => {
    // Arrange
    s3SendSpy.mockImplementation((command) => {
      if (command instanceof HeadObjectCommand) {
        return Promise.resolve({ ContentType: 'text/plain', ContentLength: 2000000 });
      }
      if (command instanceof GetObjectCommand) {
        const mockFileContent = 'word '.repeat(66000);
        return Promise.resolve({ Body: { transformToString: () => Promise.resolve(mockFileContent) } as any });
      }
      return Promise.reject(new Error('Unexpected S3 command'));
    });
    ddbSendSpy.mockImplementation(() => Promise.resolve({}));

    // Act
    await handler(createS3Event('uploads/user-123/job-abc'), {} as any, () => {});

    // Assert
    expect(ddbSendSpy).toHaveBeenCalledWith(expect.any(UpdateCommand));
    const updateCommand = ddbSendSpy.mock.calls[0][0] as UpdateCommand;
    expect(updateCommand.input.ExpressionAttributeValues?.[':status']).toEqual('VALIDATED');
    expect(updateCommand.input.Key).toEqual({ jobId: 'job-abc', userId: 'user-123' });
  });

  it('should fail validation for wrong file type', async () => {
    // Arrange
    s3SendSpy.mockImplementation(() => Promise.resolve({ ContentType: 'application/zip', ContentLength: 2000000 }));
    ddbSendSpy.mockImplementation(() => Promise.resolve({}));

    // Act
    await handler(createS3Event('uploads/user-123/job-abc'), {} as any, () => {});

    // Assert
    expect(ddbSendSpy).toHaveBeenCalledWith(expect.any(UpdateCommand));
    const updateCommand = ddbSendSpy.mock.calls[0][0] as UpdateCommand;
    expect(updateCommand.input.ExpressionAttributeValues?.[':status']).toEqual('VALIDATION_FAILED');
    expect(updateCommand.input.ExpressionAttributeValues?.[':details'].error).toContain('Invalid file type');
  });

  it('should fail validation for file size too large', async () => {
    // Arrange
    s3SendSpy.mockImplementation(() => Promise.resolve({ ContentType: 'text/plain', ContentLength: 11 * 1024 * 1024 }));
    ddbSendSpy.mockImplementation(() => Promise.resolve({}));

    // Act
    await handler(createS3Event('uploads/user-123/job-abc'), {} as any, () => {});

    // Assert
    expect(ddbSendSpy).toHaveBeenCalledWith(expect.any(UpdateCommand));
    const updateCommand = ddbSendSpy.mock.calls[0][0] as UpdateCommand;
    expect(updateCommand.input.ExpressionAttributeValues?.[':status']).toEqual('VALIDATION_FAILED');
    expect(updateCommand.input.ExpressionAttributeValues?.[':details'].error).toContain('exceeds limit');
  });

  it('should fail validation for word count too low', async () => {
    // Arrange
    s3SendSpy.mockImplementation((command) => {
      if (command instanceof HeadObjectCommand) {
        return Promise.resolve({ ContentType: 'text/plain', ContentLength: 1000 });
      }
      if (command instanceof GetObjectCommand) {
        return Promise.resolve({ Body: { transformToString: () => Promise.resolve('word '.repeat(1000)) } as any });
      }
      return Promise.reject(new Error('Unexpected S3 command'));
    });
    ddbSendSpy.mockImplementation(() => Promise.resolve({}));

    // Act
    await handler(createS3Event('uploads/user-123/job-abc'), {} as any, () => {});

    // Assert
    expect(ddbSendSpy).toHaveBeenCalledWith(expect.any(UpdateCommand));
    const updateCommand = ddbSendSpy.mock.calls[0][0] as UpdateCommand;
    expect(updateCommand.input.ExpressionAttributeValues?.[':status']).toEqual('VALIDATION_FAILED');
    expect(updateCommand.input.ExpressionAttributeValues?.[':details'].error).toContain('outside the allowed range');
  });

  it('should handle invalid S3 key format gracefully', async () => {
    // Arrange
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    
    // Act
    await handler(createS3Event('invalid-key'), {} as any, () => {});

    // Assert
    expect(ddbSendSpy).not.toHaveBeenCalled();
    expect(consoleErrorSpy).toHaveBeenCalledWith('Invalid S3 key format:', 'invalid-key');

    consoleErrorSpy.mockRestore();
  });
});

