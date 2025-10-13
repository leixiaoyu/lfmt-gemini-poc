import { S3Event, S3Handler } from 'aws-lambda';
import { S3Client, GetObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, UpdateCommand } from '@aws-sdk/lib-dynamodb';

export const s3Client = new S3Client({});
export const ddbClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const JOBS_TABLE_NAME = process.env.JOBS_TABLE_NAME!;
const MIN_WORD_COUNT = 65000;
const MAX_WORD_COUNT = 400000;
const MAX_FILE_SIZE_MB = 10;

export const handler: S3Handler = async (event: S3Event): Promise<void> => {
  for (const record of event.Records) {
    const bucket = record.s3.bucket.name;
    const key = decodeURIComponent(record.s3.object.key.replace(/\+/g, ' '));
    const keyParts = key.split('/');
    // Expected key format: uploads/userId/jobId
    if (keyParts.length < 3) {
      console.error('Invalid S3 key format:', key);
      return;
    }
    const userId = keyParts[1];
    const jobId = keyParts[2];

    try {
      // 1. Get File Metadata
      const headCmd = new HeadObjectCommand({ Bucket: bucket, Key: key });
      const metadata = await s3Client.send(headCmd);

      // 2. Validate File Type
      const allowedTypes = ['text/plain', 'text/markdown'];
      if (!metadata.ContentType || !allowedTypes.includes(metadata.ContentType)) {
        throw new Error(`Invalid file type: ${metadata.ContentType}. Only ${allowedTypes.join(', ')} are accepted.`);
      }

      // 3. Validate File Size
      const fileSizeMb = (metadata.ContentLength || 0) / 1024 / 1024;
      if (fileSizeMb > MAX_FILE_SIZE_MB) {
        throw new Error(`File size ${fileSizeMb.toFixed(2)}MB exceeds limit of ${MAX_FILE_SIZE_MB}MB`);
      }

      // 3. Get File Content
      const getCmd = new GetObjectCommand({ Bucket: bucket, Key: key });
      const response = await s3Client.send(getCmd);
      const content = await response.Body?.transformToString('utf-8') || '';

      // 4. Validate Word Count
      const wordCount = content.trim().split(/\s+/).length;
      if (wordCount < MIN_WORD_COUNT || wordCount > MAX_WORD_COUNT) {
        throw new Error(`Word count ${wordCount} is outside the allowed range (${MIN_WORD_COUNT}-${MAX_WORD_COUNT})`);
      }

      // 5. Update DynamoDB on Success
      await updateJobStatus(jobId, userId, 'VALIDATED', { wordCount });

    } catch (error: any) {
      console.error(`Validation failed for ${key}:`, error);
      // 6. Update DynamoDB on Failure
      await updateJobStatus(jobId, userId, 'VALIDATION_FAILED', { error: error.message });
    }
  }
};

async function updateJobStatus(jobId: string, userId: string, status: string, additionalData: object = {}) {
  console.log('--- JOBS_TABLE_NAME ---', JOBS_TABLE_NAME);
  const updateCmd = new UpdateCommand({
    TableName: JOBS_TABLE_NAME,
    Key: { jobId, userId },
    UpdateExpression: 'SET #status = :status, #updatedAt = :updatedAt, #details = :details',
    ExpressionAttributeNames: {
      '#status': 'status',
      '#updatedAt': 'updatedAt',
      '#details': 'details',
    },
    ExpressionAttributeValues: {
      ':status': status,
      ':updatedAt': new Date().toISOString(),
      ':details': additionalData,
    },
  });
  await ddbClient.send(updateCmd);
}
