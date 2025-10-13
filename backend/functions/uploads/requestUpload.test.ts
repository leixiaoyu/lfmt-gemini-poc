import { handler } from './requestUpload';
import { S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { mockClient } from 'aws-sdk-client-mock';

const s3Mock = mockClient(S3Client as any);

jest.mock('@aws-sdk/s3-request-presigner', () => ({
  getSignedUrl: jest.fn(),
}));

describe('Request Upload URL', () => {
  beforeEach(() => {
    s3Mock.reset();
    (getSignedUrl as jest.Mock).mockClear();
    process.env.DOCUMENT_BUCKET_NAME = 'test-bucket';
  });

  it('should return a pre-signed URL on successful request', async () => {
    const mockUrl = 'https://s3.amazonaws.com/test-bucket/test-file.txt?...';
    (getSignedUrl as jest.Mock).mockResolvedValue(mockUrl);

    const event = {
      requestContext: {
        authorizer: {
          claims: {
            sub: 'user-123',
          },
        },
      },
      body: JSON.stringify({
        fileName: 'test-file.txt',
        contentType: 'text/plain',
      }),
    } as any;

    const result = await handler(event);

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.uploadUrl).toBe(mockUrl);
    expect(body.key).toBe('user-123/test-file.txt');
  });
});
