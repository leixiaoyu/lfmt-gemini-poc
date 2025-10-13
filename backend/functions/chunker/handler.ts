import { SQSHandler } from 'aws-lambda';

// TODO: Fetch these from a shared configuration
const CHUNK_SIZE_TOKENS = 3500;
const OVERLAP_TOKENS = 250;

/**
 * This Lambda is triggered by an SQS message when a document has been validated.
 * It retrieves the document from S3, splits it into chunks, and stores the chunks
 * back in S3. It then starts the Step Functions workflow for translation.
 */
export const handler: SQSHandler = async (event) => {
  console.log('Chunker function triggered');

  for (const record of event.Records) {
    try {
      const body = JSON.parse(record.body);
      const { jobId, userId, s3Key } = body;

      console.log(`Processing job ${jobId} for user ${userId}`);

      // 1. Download the document from S3 (logic to be implemented)
      const documentContent = await downloadDocument(s3Key);

      // 2. Split the document into chunks (logic to be implemented)
      const chunks = splitIntoChunks(documentContent);

      // 3. Upload chunks to S3 (logic to be implemented)
      await uploadChunks(jobId, chunks);

      // 4. Start the Step Functions translation workflow (logic to be implemented)
      await startTranslationWorkflow(jobId);

      console.log(`Successfully chunked document for job ${jobId} and started workflow.`);

    } catch (error) {
      console.error('Error processing SQS record:', error);
      // TODO: Implement dead-letter queue or other error handling
    }
  }
};

async function downloadDocument(s3Key: string): Promise<string> {
  // TODO: Implement S3 GetObject
  console.log(`Downloading document from ${s3Key}...`);
  return "This is a placeholder for the full document content. ".repeat(5000);
}

function splitIntoChunks(content: string): string[] {
  // TODO: Implement a proper token-based chunking algorithm
  console.log('Splitting document into chunks...');
  return [content.substring(0, 10000), content.substring(9000, 19000)];
}

async function uploadChunks(jobId: string, chunks: string[]) {
  // TODO: Implement S3 PutObject for each chunk
  console.log(`Uploading ${chunks.length} chunks for job ${jobId}...`);
}

async function startTranslationWorkflow(jobId: string) {
  // TODO: Implement Step Functions StartExecution
  console.log(`Starting translation workflow for job ${jobId}...`);
}
