# Low-Level Design Document 7: Job State Management

## 1. Component Overview & Responsibilities

The Job State Management system provides centralized tracking and coordination of translation jobs throughout their lifecycle. It manages job states, progress tracking, error recovery, and provides real-time status updates for the polling-based frontend architecture while ensuring data consistency and audit trails.

**Key Responsibilities:**
- Centralized job lifecycle management and state transitions
- Real-time progress tracking with polling optimization
- Chunk-level status aggregation and job completion detection
- Error state management and recovery coordination
- Job history and audit trail maintenance
- Integration with Step Functions workflow orchestration

**Why This Design:** Centralized state management ensures consistency across distributed components, provides reliable progress tracking for the polling architecture, and enables robust error recovery and job resumption capabilities.

## 2. API Design & Interfaces

### Job Management Endpoints
```typescript
// POST /jobs
interface CreateJobRequest {
  userId: string;
  documentId: string;
  filename: string;
  targetLanguage: string;
  documentMetadata: {
    wordCount: number;
    fileSize: number;
    contentHash: string;
  };
  translationOptions?: {
    preserveFormatting: boolean;
    customGlossary?: string;
    qualityLevel: 'STANDARD' | 'PREMIUM';
  };
  priority: 'LOW' | 'NORMAL' | 'HIGH';
}

interface CreateJobResponse {
  jobId: string;
  status: JobStatus;
  estimatedCompletion: string;
  estimatedCost: number;
  chunkCount: number;
  progressTrackingUrl: string;
}

// GET /jobs/{jobId}
interface JobDetailsResponse {
  jobId: string;
  userId: string;
  documentId: string;
  filename: string;
  targetLanguage: string;
  status: JobStatus;
  progress: JobProgress;
  timestamps: JobTimestamps;
  costs: JobCosts;
  chunks: ChunkSummary[];
  errors?: JobError[];
  metadata: JobMetadata;
}

// GET /jobs/{jobId}/progress
interface JobProgressResponse {
  jobId: string;
  status: JobStatus;
  overallProgress: number; // 0-100
  chunksCompleted: number;
  totalChunks: number;
  estimatedTimeRemaining?: number; // seconds
  currentStage: string;
  lastUpdated: string;
  processingSpeed?: number; // words per minute
  detailedProgress: {
    chunking: StageProgress;
    translation: StageProgress;
    assembly: StageProgress;
    delivery: StageProgress;
  };
}

// PATCH /jobs/{jobId}/status
interface UpdateJobStatusRequest {
  status: JobStatus;
  reason?: string;
  metadata?: Record<string, any>;
}

// GET /jobs/user/{userId}
interface UserJobsRequest {
  userId: string;
  status?: JobStatus[];
  startDate?: string;
  endDate?: string;
  limit?: number;
  cursor?: string;
}

interface UserJobsResponse {
  jobs: JobSummary[];
  totalCount: number;
  nextCursor?: string;
  hasMore: boolean;
}
```

### Job State Definitions
```typescript
type JobStatus = 
  | 'CREATED'           // Initial state after job creation
  | 'VALIDATING'        // Legal attestation and document validation
  | 'VALIDATED'         // Ready for processing
  | 'QUEUED'           // Waiting in processing queue
  | 'CHUNKING'         // Document being split into chunks
  | 'CHUNKED'          // Chunking completed, ready for translation
  | 'TRANSLATING'      // Translation in progress
  | 'ASSEMBLING'       // Combining translated chunks
  | 'FINALIZING'       // Quality checks and final processing
  | 'COMPLETED'        // Successfully completed
  | 'FAILED'           // Permanently failed
  | 'CANCELLED'        // User cancelled
  | 'PAUSED'           // Temporarily paused
  | 'RESUMING'         // Resuming from pause
  | 'RETRYING'         // Retrying after recoverable error
  | 'RATE_LIMITED'     // Waiting due to API rate limits
  | 'RECOVERING';      // Error recovery in progress

interface JobProgress {
  overallPercentage: number;
  currentStage: JobStatus;
  stageProgress: number; // 0-100 for current stage
  chunksCompleted: number;
  totalChunks: number;
  startTime: string;
  estimatedCompletion?: string;
  lastActivity: string;
}

interface StageProgress {
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  progress: number; // 0-100
  startTime?: string;
  endTime?: string;
  duration?: number; // milliseconds
  itemsProcessed?: number;
  totalItems?: number;
}

interface ChunkSummary {
  chunkId: string;
  index: number;
  status: ChunkStatus;
  progress: number;
  tokenCount: number;
  translatedAt?: string;
  retryCount: number;
  lastError?: string;
}

type ChunkStatus = 
  | 'PENDING'
  | 'TRANSLATING'
  | 'COMPLETED'
  | 'FAILED'
  | 'RETRYING'
  | 'RATE_LIMITED';
```

## 3. Data Models & Storage

### DynamoDB Schema for Job Management
```typescript
// Primary Table: TranslationJobs
interface TranslationJobRecord {
  PK: string; // JOB#{jobId}
  SK: string; // METADATA
  jobId: string;
  userId: string;
  documentId: string;
  filename: string;
  targetLanguage: string;
  
  // Status and progress
  status: JobStatus;
  overallProgress: number;
  currentStage: JobStatus;
  stageProgress: number;
  
  // Chunk tracking
  totalChunks: number;
  chunksCompleted: number;
  chunksTranslating: number;
  chunksFailed: number;
  
  // Timestamps
  createdAt: string;
  updatedAt: string;
  startedAt?: string;
  completedAt?: string;
  lastActivityAt: string;
  
  // Estimates and actuals
  estimatedCompletion?: string;
  estimatedCost: number;
  actualCost?: number;
  estimatedDuration: number; // seconds
  actualDuration?: number;
  
  // Processing metadata
  workflowExecutionArn?: string; // Step Functions execution
  priority: 'LOW' | 'NORMAL' | 'HIGH';
  retryCount: number;
  maxRetries: number;
  
  // Document metadata
  wordCount: number;
  fileSize: number;
  contentHash: string;
  
  // Translation options
  preserveFormatting: boolean;
  customGlossary?: string;
  qualityLevel: 'STANDARD' | 'PREMIUM';
  
  // Error tracking
  lastError?: {
    code: string;
    message: string;
    timestamp: string;
    retryable: boolean;
  };
  
  // Performance metrics
  processingSpeed?: number; // words per minute
  averageChunkTime?: number; // milliseconds per chunk
  
  ttl?: number; // Optional TTL for completed jobs
}

// GSI: JobsByUser
interface JobsByUser {
  GSI1PK: string; // USER#{userId}
  GSI1SK: string; // STATUS#{status}#CREATED#{createdAt}
  jobId: string;
  status: JobStatus;
  createdAt: string;
  filename: string;
  targetLanguage: string;
  overallProgress: number;
}

// GSI: JobsByStatus
interface JobsByStatus {
  GSI2PK: string; // STATUS#{status}
  GSI2SK: string; // PRIORITY#{priority}#CREATED#{createdAt}
  jobId: string;
  userId: string;
  priority: string;
  createdAt: string;
  workflowExecutionArn?: string;
}

// GSI: JobsByDocument
interface JobsByDocument {
  GSI3PK: string; // DOCUMENT#{documentId}
  GSI3SK: string; // CREATED#{createdAt}
  jobId: string;
  userId: string;
  status: JobStatus;
  targetLanguage: string;
}

// Chunk Status Table
interface ChunkStatusRecord {
  PK: string; // JOB#{jobId}
  SK: string; // CHUNK#{chunkIndex:03d}
  jobId: string;
  chunkId: string;
  chunkIndex: number;
  status: ChunkStatus;
  progress: number;
  
  // Processing details
  tokenCount: number;
  translationStarted?: string;
  translationCompleted?: string;
  processingTime?: number; // milliseconds
  
  // Retry tracking
  retryCount: number;
  lastAttempt?: string;
  nextRetry?: string;
  
  // Error information
  lastError?: {
    code: string;
    message: string;
    timestamp: string;
    isRetryable: boolean;
  };
  
  // Gemini API details
  geminiRequestId?: string;
  inputTokens?: number;
  outputTokens?: number;
  cost?: number;
  
  // Quality metrics
  translationConfidence?: number;
  qualityFlags?: string[];
  
  ttl?: number; // Cleanup after job completion + retention period
}
```

### Job State Transition Table
```typescript
// State Machine Definition
interface JobStateTransition {
  fromState: JobStatus;
  toState: JobStatus;
  condition?: StateTransitionCondition;
  actions?: StateTransitionAction[];
  validationRules?: ValidationRule[];
}

interface StateTransitionCondition {
  type: 'AUTOMATIC' | 'MANUAL' | 'CONDITIONAL';
  expression?: string; // For conditional transitions
  requiredData?: string[]; // Required fields for transition
}

interface StateTransitionAction {
  type: 'UPDATE_PROGRESS' | 'SEND_NOTIFICATION' | 'TRIGGER_WORKFLOW' | 'LOG_AUDIT';
  parameters: Record<string, any>;
}

const JOB_STATE_MACHINE: JobStateTransition[] = [
  {
    fromState: 'CREATED',
    toState: 'VALIDATING',
    condition: { type: 'AUTOMATIC' },
    actions: [{ type: 'TRIGGER_WORKFLOW', parameters: { workflow: 'legal-validation' } }]
  },
  {
    fromState: 'VALIDATING',
    toState: 'VALIDATED',
    condition: { type: 'CONDITIONAL', expression: 'legal_attestation_valid == true' }
  },
  {
    fromState: 'VALIDATED',
    toState: 'QUEUED',
    condition: { type: 'AUTOMATIC' },
    actions: [{ type: 'UPDATE_PROGRESS', parameters: { stage: 'QUEUED', progress: 5 } }]
  },
  {
    fromState: 'QUEUED',
    toState: 'CHUNKING',
    condition: { type: 'CONDITIONAL', expression: 'queue_position == 1' },
    actions: [{ type: 'TRIGGER_WORKFLOW', parameters: { workflow: 'document-chunking' } }]
  },
  {
    fromState: 'CHUNKING',
    toState: 'CHUNKED',
    condition: { type: 'CONDITIONAL', expression: 'chunks_created > 0' },
    actions: [{ type: 'UPDATE_PROGRESS', parameters: { stage: 'CHUNKED', progress: 15 } }]
  },
  {
    fromState: 'CHUNKED',
    toState: 'TRANSLATING',
    condition: { type: 'AUTOMATIC' },
    actions: [{ type: 'TRIGGER_WORKFLOW', parameters: { workflow: 'parallel-translation' } }]
  },
  {
    fromState: 'TRANSLATING',
    toState: 'ASSEMBLING',
    condition: { type: 'CONDITIONAL', expression: 'chunks_completed == total_chunks' },
    actions: [{ type: 'UPDATE_PROGRESS', parameters: { stage: 'ASSEMBLING', progress: 85 } }]
  },
  {
    fromState: 'ASSEMBLING',
    toState: 'FINALIZING',
    condition: { type: 'CONDITIONAL', expression: 'document_assembled == true' }
  },
  {
    fromState: 'FINALIZING',
    toState: 'COMPLETED',
    condition: { type: 'CONDITIONAL', expression: 'quality_check_passed == true' },
    actions: [
      { type: 'UPDATE_PROGRESS', parameters: { stage: 'COMPLETED', progress: 100 } },
      { type: 'SEND_NOTIFICATION', parameters: { type: 'JOB_COMPLETED' } }
    ]
  }
];
```

## 4. Core Job Management Logic

### Job State Manager Implementation
```typescript
class JobStateManager {
  private dynamoClient: AWS.DynamoDB.DocumentClient;
  private stateMachine: Map<JobStatus, JobStateTransition[]>;
  private eventBridge: AWS.EventBridge;

  constructor() {
    this.dynamoClient = new AWS.DynamoDB.DocumentClient();
    this.stateMachine = this.buildStateMachine();
    this.eventBridge = new AWS.EventBridge();
  }

  async createJob(request: CreateJobRequest): Promise<CreateJobResponse> {
    const jobId = this.generateJobId();
    const timestamp = new Date().toISOString();
    
    // Calculate estimates
    const estimates = await this.calculateJobEstimates(request);
    
    // Create initial job record
    const jobRecord: TranslationJobRecord = {
      PK: `JOB#${jobId}`,
      SK: 'METADATA',
      jobId,
      userId: request.userId,
      documentId: request.documentId,
      filename: request.filename,
      targetLanguage: request.targetLanguage,
      
      // Initial status
      status: 'CREATED',
      overallProgress: 0,
      currentStage: 'CREATED',
      stageProgress: 0,
      
      // Chunk tracking (to be updated during chunking)
      totalChunks: estimates.estimatedChunks,
      chunksCompleted: 0,
      chunksTranslating: 0,
      chunksFailed: 0,
      
      // Timestamps
      createdAt: timestamp,
      updatedAt: timestamp,
      lastActivityAt: timestamp,
      
      // Estimates
      estimatedCompletion: estimates.estimatedCompletion,
      estimatedCost: estimates.estimatedCost,
      estimatedDuration: estimates.estimatedDuration,
      
      // Processing metadata
      priority: request.priority,
      retryCount: 0,
      maxRetries: 3,
      
      // Document metadata
      wordCount: request.documentMetadata.wordCount,
      fileSize: request.documentMetadata.fileSize,
      contentHash: request.documentMetadata.contentHash,
      
      // Translation options
      preserveFormatting: request.translationOptions?.preserveFormatting ?? true,
      customGlossary: request.translationOptions?.customGlossary,
      qualityLevel: request.translationOptions?.qualityLevel ?? 'STANDARD'
    };

    // Store job record
    await this.dynamoClient.put({
      TableName: process.env.JOBS_TABLE!,
      Item: jobRecord,
      ConditionExpression: 'attribute_not_exists(PK)'
    }).promise();

    // Create GSI records
    await this.createGSIRecords(jobRecord);

    // Trigger initial state transition
    await this.transitionJobState(jobId, 'CREATED', 'VALIDATING', {
      reason: 'Initial job creation',
      triggeredBy: 'SYSTEM'
    });

    // Publish job creation event
    await this.publishJobEvent(jobId, 'JOB_CREATED', jobRecord);

    return {
      jobId,
      status: 'CREATED',
      estimatedCompletion: estimates.estimatedCompletion,
      estimatedCost: estimates.estimatedCost,
      chunkCount: estimates.estimatedChunks,
      progressTrackingUrl: `/jobs/${jobId}/progress`
    };
  }

  async transitionJobState(
    jobId: string,
    fromState: JobStatus,
    toState: JobStatus,
    context: StateTransitionContext
  ): Promise<void> {
    // Validate transition
    const validTransition = this.validateStateTransition(fromState, toState);
    if (!validTransition.isValid) {
      throw new Error(`Invalid state transition from ${fromState} to ${toState}: ${validTransition.reason}`);
    }

    const timestamp = new Date().toISOString();

    // Update job record atomically
    const updateParams = {
      TableName: process.env.JOBS_TABLE!,
      Key: { PK: `JOB#${jobId}`, SK: 'METADATA' },
      UpdateExpression: 'SET #status = :toState, #currentStage = :toState, #updatedAt = :timestamp, #lastActivityAt = :timestamp',
      ConditionExpression: '#status = :fromState',
      ExpressionAttributeNames: {
        '#status': 'status',
        '#currentStage': 'currentStage',
        '#updatedAt': 'updatedAt',
        '#lastActivityAt': 'lastActivityAt'
      },
      ExpressionAttributeValues: {
        ':fromState': fromState,
        ':toState': toState,
        ':timestamp': timestamp
      },
      ReturnValues: 'ALL_NEW'
    };

    // Add additional updates based on state
    if (toState === 'TRANSLATING') {
      updateParams.UpdateExpression += ', #startedAt = :timestamp';
      updateParams.ExpressionAttributeNames['#startedAt'] = 'startedAt';
    }

    if (toState === 'COMPLETED' || toState === 'FAILED') {
      updateParams.UpdateExpression += ', #completedAt = :timestamp';
      updateParams.ExpressionAttributeNames['#completedAt'] = 'completedAt';
      
      if (context.actualCost) {
        updateParams.UpdateExpression += ', #actualCost = :actualCost';
        updateParams.ExpressionAttributeNames['#actualCost'] = 'actualCost';
        updateParams.ExpressionAttributeValues[':actualCost'] = context.actualCost;
      }
    }

    try {
      const result = await this.dynamoClient.update(updateParams).promise();
      
      // Execute state transition actions
      const transition = this.getStateTransition(fromState, toState);
      if (transition?.actions) {
        await this.executeTransitionActions(jobId, transition.actions, context);
      }

      // Update GSI records
      await this.updateGSIRecords(jobId, toState, result.Attributes as TranslationJobRecord);

      // Publish state change event
      await this.publishJobEvent(jobId, 'JOB_STATE_CHANGED', {
        fromState,
        toState,
        timestamp,
        context
      });

      // Log audit trail
      await this.logStateTransition(jobId, fromState, toState, context);

    } catch (error) {
      if (error.code === 'ConditionalCheckFailedException') {
        throw new Error(`Job ${jobId} is not in expected state ${fromState}`);
      }
      throw error;
    }
  }

  async updateJobProgress(
    jobId: string,
    progressUpdate: JobProgressUpdate
  ): Promise<void> {
    const timestamp = new Date().toISOString();
    
    // Calculate overall progress
    const overallProgress = this.calculateOverallProgress(progressUpdate);
    
    const updateParams = {
      TableName: process.env.JOBS_TABLE!,
      Key: { PK: `JOB#${jobId}`, SK: 'METADATA' },
      UpdateExpression: 'SET #overallProgress = :overallProgress, #stageProgress = :stageProgress, #updatedAt = :timestamp, #lastActivityAt = :timestamp',
      ExpressionAttributeNames: {
        '#overallProgress': 'overallProgress',
        '#stageProgress': 'stageProgress',
        '#updatedAt': 'updatedAt',
        '#lastActivityAt': 'lastActivityAt'
      },
      ExpressionAttributeValues: {
        ':overallProgress': overallProgress,
        ':stageProgress': progressUpdate.stageProgress,
        ':timestamp': timestamp
      }
    };

    // Add chunk progress updates if provided
    if (progressUpdate.chunksCompleted !== undefined) {
      updateParams.UpdateExpression += ', #chunksCompleted = :chunksCompleted';
      updateParams.ExpressionAttributeNames['#chunksCompleted'] = 'chunksCompleted';
      updateParams.ExpressionAttributeValues[':chunksCompleted'] = progressUpdate.chunksCompleted;
    }

    if (progressUpdate.chunksTranslating !== undefined) {
      updateParams.UpdateExpression += ', #chunksTranslating = :chunksTranslating';
      updateParams.ExpressionAttributeNames['#chunksTranslating'] = 'chunksTranslating';
      updateParams.ExpressionAttributeValues[':chunksTranslating'] = progressUpdate.chunksTranslating;
    }

    // Update processing speed if provided
    if (progressUpdate.processingSpeed !== undefined) {
      updateParams.UpdateExpression += ', #processingSpeed = :processingSpeed';
      updateParams.ExpressionAttributeNames['#processingSpeed'] = 'processingSpeed';
      updateParams.ExpressionAttributeValues[':processingSpeed'] = progressUpdate.processingSpeed;
    }

    // Update estimated completion time
    const estimatedCompletion = this.calculateEstimatedCompletion(progressUpdate);
    if (estimatedCompletion) {
      updateParams.UpdateExpression += ', #estimatedCompletion = :estimatedCompletion';
      updateParams.ExpressionAttributeNames['#estimatedCompletion'] = 'estimatedCompletion';
      updateParams.ExpressionAttributeValues[':estimatedCompletion'] = estimatedCompletion;
    }

    await this.dynamoClient.update(updateParams).promise();

    // Publish progress update event
    await this.publishJobEvent(jobId, 'JOB_PROGRESS_UPDATED', {
      overallProgress,
      stageProgress: progressUpdate.stageProgress,
      chunksCompleted: progressUpdate.chunksCompleted,
      timestamp
    });
  }

  async updateChunkStatus(
    jobId: string,
    chunkId: string,
    chunkIndex: number,
    statusUpdate: ChunkStatusUpdate
  ): Promise<void> {
    const timestamp = new Date().toISOString();

    // Update chunk status record
    const chunkUpdateParams = {
      TableName: process.env.CHUNKS_TABLE!,
      Key: { PK: `JOB#${jobId}`, SK: `CHUNK#${chunkIndex.toString().padStart(3, '0')}` },
      UpdateExpression: 'SET #status = :status, #progress = :progress, #updatedAt = :timestamp',
      ExpressionAttributeNames: {
        '#status': 'status',
        '#progress': 'progress',
        '#updatedAt': 'updatedAt'
      },
      ExpressionAttributeValues: {
        ':status': statusUpdate.status,
        ':progress': statusUpdate.progress,
        ':timestamp': timestamp
      }
    };

    // Add completion timestamp if chunk is completed
    if (statusUpdate.status === 'COMPLETED') {
      chunkUpdateParams.UpdateExpression += ', #translationCompleted = :timestamp';
      chunkUpdateParams.ExpressionAttributeNames['#translationCompleted'] = 'translationCompleted';
      
      if (statusUpdate.processingTime) {
        chunkUpdateParams.UpdateExpression += ', #processingTime = :processingTime';
        chunkUpdateParams.ExpressionAttributeNames['#processingTime'] = 'processingTime';
        chunkUpdateParams.ExpressionAttributeValues[':processingTime'] = statusUpdate.processingTime;
      }
    }

    // Add error information if chunk failed
    if (statusUpdate.status === 'FAILED' && statusUpdate.error) {
      chunkUpdateParams.UpdateExpression += ', #lastError = :error';
      chunkUpdateParams.ExpressionAttributeNames['#lastError'] = 'lastError';
      chunkUpdateParams.ExpressionAttributeValues[':error'] = statusUpdate.error;
    }

    await this.dynamoClient.update(chunkUpdateParams).promise();

    // Update job-level chunk counters
    await this.updateJobChunkCounters(jobId, statusUpdate.status);

    // Check if job should transition states
    await this.checkJobStateTransitions(jobId);
  }

  private async updateJobChunkCounters(jobId: string, chunkStatus: ChunkStatus): Promise<void> {
    // Get current chunk counts
    const chunkCounts = await this.getChunkCounts(jobId);
    
    // Update job record with new counts
    await this.dynamoClient.update({
      TableName: process.env.JOBS_TABLE!,
      Key: { PK: `JOB#${jobId}`, SK: 'METADATA' },
      UpdateExpression: 'SET #chunksCompleted = :completed, #chunksTranslating = :translating, #chunksFailed = :failed, #lastActivityAt = :timestamp',
      ExpressionAttributeNames: {
        '#chunksCompleted': 'chunksCompleted',
        '#chunksTranslating': 'chunksTranslating',
        '#chunksFailed': 'chunksFailed',
        '#lastActivityAt': 'lastActivityAt'
      },
      ExpressionAttributeValues: {
        ':completed': chunkCounts.completed,
        ':translating': chunkCounts.translating,
        ':failed': chunkCounts.failed,
        ':timestamp': new Date().toISOString()
      }
    }).promise();
  }

  private async checkJobStateTransitions(jobId: string): Promise<void> {
    const job = await this.getJob(jobId);
    if (!job) return;

    // Check if all chunks are completed
    if (job.status === 'TRANSLATING' && job.chunksCompleted === job.totalChunks) {
      await this.transitionJobState(jobId, 'TRANSLATING', 'ASSEMBLING', {
        reason: 'All chunks completed',
        triggeredBy: 'SYSTEM'
      });
    }

    // Check if too many chunks failed
    if (job.chunksFailed > job.totalChunks * 0.1) { // More than 10% failed
      await this.transitionJobState(jobId, job.status, 'FAILED', {
        reason: 'Too many chunk failures',
        triggeredBy: 'SYSTEM',
        metadata: { failureRate: job.chunksFailed / job.totalChunks }
      });
    }
  }

  private calculateOverallProgress(update: JobProgressUpdate): number {
    // Weight different stages
    const stageWeights = {
      CREATED: 0,
      VALIDATING: 5,
      VALIDATED: 5,
      QUEUED: 5,
      CHUNKING: 10,
      CHUNKED: 15,
      TRANSLATING: 70, // Most of the work
      ASSEMBLING: 85,
      FINALIZING: 95,
      COMPLETED: 100
    };

    const baseProgress = stageWeights[update.currentStage] || 0;
    const stageContribution = (update.stageProgress / 100) * (
      stageWeights[this.getNextStage(update.currentStage)] - baseProgress
    );

    return Math.min(100, baseProgress + stageContribution);
  }
}
```

### Chunk Progress Aggregator
```typescript
class ChunkProgressAggregator {
  private dynamoClient: AWS.DynamoDB.DocumentClient;

  async aggregateJobProgress(jobId: string): Promise<AggregatedProgress> {
    // Get all chunks for the job
    const chunks = await this.getJobChunks(jobId);
    
    if (chunks.length === 0) {
      return {
        overallProgress: 0,
        chunksCompleted: 0,
        totalChunks: 0,
        averageProcessingTime: 0,
        estimatedTimeRemaining: 0
      };
    }

    const completedChunks = chunks.filter(c => c.status === 'COMPLETED');
    const translatingChunks = chunks.filter(c => c.status === 'TRANSLATING');
    const failedChunks = chunks.filter(c => c.status === 'FAILED');

    // Calculate processing speed
    const processingTimes = completedChunks
      .filter(c => c.processingTime)
      .map(c => c.processingTime!);
    
    const averageProcessingTime = processingTimes.length > 0
      ? processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length
      : 0;

    // Calculate weighted progress (completed chunks + partial progress of translating chunks)
    const completedProgress = completedChunks.length * 100;
    const translatingProgress = translatingChunks.reduce((sum, chunk) => sum + chunk.progress, 0);
    const totalProgress = completedProgress + translatingProgress;
    const overallProgress = totalProgress / chunks.length;

    // Estimate time remaining
    const remainingChunks = chunks.length - completedChunks.length;
    const estimatedTimeRemaining = remainingChunks * averageProcessingTime;

    return {
      overallProgress: Math.round(overallProgress),
      chunksCompleted: completedChunks.length,
      chunksTranslating: translatingChunks.length,
      chunksFailed: failedChunks.length,
      totalChunks: chunks.length,
      averageProcessingTime,
      estimatedTimeRemaining,
      processingSpeed: this.calculateProcessingSpeed(completedChunks)
    };
  }

  private calculateProcessingSpeed(completedChunks: ChunkStatusRecord[]): number {
    if (completedChunks.length === 0) return 0;

    const totalTokens = completedChunks.reduce((sum, chunk) => sum + chunk.tokenCount, 0);
    const totalTime = completedChunks.reduce((sum, chunk) => sum + (chunk.processingTime || 0), 0);

    if (totalTime === 0) return 0;

    // Convert to words per minute (assuming 1.3 tokens per word)
    const wordsPerMinute = (totalTokens / 1.3) / (totalTime / 60000);
    return Math.round(wordsPerMinute);
  }

  async getJobChunks(jobId: string): Promise<ChunkStatusRecord[]> {
    const params = {
      TableName: process.env.CHUNKS_TABLE!,
      KeyConditionExpression: 'PK = :jobPK',
      ExpressionAttributeValues: {
        ':jobPK': `JOB#${jobId}`
      }
    };

    const result = await this.dynamoClient.query(params).promise();
    return result.Items as ChunkStatusRecord[];
  }
}
```

## 5. Error Handling & Recovery

### Job Error Recovery System
```typescript
class JobErrorRecovery {
  async handleJobError(
    jobId: string,
    error: JobError,
    context: ErrorContext
  ): Promise<RecoveryAction> {
    // Classify error
    const errorClassification = this.classifyError(error);
    
    // Get job current state
    const job = await this.getJob(jobId);
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    // Determine recovery strategy
    const recoveryStrategy = this.determineRecoveryStrategy(
      error,
      errorClassification,
      job.retryCount,
      job.maxRetries
    );

    switch (recoveryStrategy.action) {
      case 'RETRY_IMMEDIATE':
        return await this.retryJobImmediate(jobId, error);
      
      case 'RETRY_DELAYED':
        return await this.retryJobDelayed(jobId, error, recoveryStrategy.delay!);
      
      case 'RETRY_PARTIAL':
        return await this.retryFailedChunks(jobId);
      
      case 'PAUSE_AND_REVIEW':
        return await this.pauseJobForReview(jobId, error);
      
      case 'FAIL_PERMANENT':
        return await this.failJobPermanently(jobId, error);
      
      case 'ESCALATE':
        return await this.escalateToManualReview(jobId, error);
      
      default:
        throw new Error(`Unknown recovery action: ${recoveryStrategy.action}`);
    }
  }

  private classifyError(error: JobError): ErrorClassification {
    // Rate limiting errors
    if (error.code === 'RATE_LIMITED' || error.code === 'TOO_MANY_REQUESTS') {
      return {
        category: 'RATE_LIMIT',
        severity: 'TEMPORARY',
        retryable: true,
        suggestedDelay: 60000 // 1 minute
      };
    }

    // API errors
    if (error.code === 'SERVICE_UNAVAILABLE' || error.code === 'TIMEOUT') {
      return {
        category: 'SERVICE_ERROR',
        severity: 'TEMPORARY',
        retryable: true,
        suggestedDelay: 30000 // 30 seconds
      };
    }

    // Authentication errors
    if (error.code === 'UNAUTHORIZED' || error.code === 'FORBIDDEN') {
      return {
        category: 'AUTHENTICATION',
        severity: 'PERMANENT',
        retryable: false
      };
    }

    // Content errors
    if (error.code === 'CONTENT_TOO_LARGE' || error.code === 'INVALID_CONTENT') {
      return {
        category: 'CONTENT_ERROR',
        severity: 'PERMANENT',
        retryable: false
      };
    }

    // System errors
    if (error.code === 'INTERNAL_ERROR' || error.code === 'STORAGE_ERROR') {
      return {
        category: 'SYSTEM_ERROR',
        severity: 'TEMPORARY',
        retryable: true,
        suggestedDelay: 120000 // 2 minutes
      };
    }

    // Default classification
    return {
      category: 'UNKNOWN',
      severity: 'TEMPORARY',
      retryable: true,
      suggestedDelay: 60000
    };
  }

  private determineRecoveryStrategy(
    error: JobError,
    classification: ErrorClassification,
    currentRetries: number,
    maxRetries: number
  ): RecoveryStrategy {
    // Check if retries exhausted
    if (currentRetries >= maxRetries) {
      if (classification.category === 'RATE_LIMIT' || classification.category === 'SERVICE_ERROR') {
        return { action: 'PAUSE_AND_REVIEW' };
      }
      return { action: 'FAIL_PERMANENT' };
    }

    // Non-retryable errors
    if (!classification.retryable) {
      return { action: 'FAIL_PERMANENT' };
    }

    // Rate limit handling
    if (classification.category === 'RATE_LIMIT') {
      return {
        action: 'RETRY_DELAYED',
        delay: Math.min(classification.suggestedDelay! * Math.pow(2, currentRetries), 300000) // Max 5 minutes
      };
    }

    // Service errors with exponential backoff
    if (classification.category === 'SERVICE_ERROR') {
      return {
        action: 'RETRY_DELAYED',
        delay: classification.suggestedDelay! * Math.pow(2, currentRetries)
      };
    }

    // Chunk-level failures
    if (error.scope === 'CHUNK') {
      return { action: 'RETRY_PARTIAL' };
    }

    // System errors
    if (classification.category === 'SYSTEM_ERROR') {
      if (currentRetries < 2) {
        return { action: 'RETRY_IMMEDIATE' };
      } else {
        return { action: 'ESCALATE' };
      }
    }

    // Default to immediate retry for unknown errors
    return { action: 'RETRY_IMMEDIATE' };
  }

  private async retryJobDelayed(
    jobId: string,
    error: JobError,
    delay: number
  ): Promise<RecoveryAction> {
    // Update job to RETRYING state
    await this.stateManager.transitionJobState(jobId, 'FAILED', 'RETRYING', {
      reason: `Retrying after ${delay}ms delay due to ${error.code}`,
      triggeredBy: 'SYSTEM',
      metadata: { retryDelay: delay, originalError: error }
    });

    // Schedule retry using Step Functions
    const retryTime = new Date(Date.now() + delay).toISOString();
    const retryInput = {
      jobId,
      retryReason: error.code,
      scheduledTime: retryTime
    };

    await this.stepFunctions.startExecution({
      stateMachineArn: process.env.RETRY_STATE_MACHINE_ARN!,
      input: JSON.stringify(retryInput),
      name: `retry-${jobId}-${Date.now()}`
    }).promise();

    return {
      action: 'RETRY_DELAYED',
      delay,
      message: `Job will retry in ${Math.round(delay / 1000)} seconds`,
      nextAttemptTime: retryTime
    };
  }

  private async retryFailedChunks(jobId: string): Promise<RecoveryAction> {
    // Get failed chunks
    const failedChunks = await this.getFailedChunks(jobId);
    
    if (failedChunks.length === 0) {
      return {
        action: 'NO_ACTION',
        message: 'No failed chunks to retry'
      };
    }

    // Reset failed chunks to pending
    for (const chunk of failedChunks) {
      await this.chunkProgressAggregator.updateChunkStatus(
        jobId,
        chunk.chunkId,
        chunk.chunkIndex,
        {
          status: 'PENDING',
          progress: 0,
          retryCount: chunk.retryCount + 1
        }
      );
    }

    // Transition job back to TRANSLATING if it was failed
    const job = await this.getJob(jobId);
    if (job && job.status === 'FAILED') {
      await this.stateManager.transitionJobState(jobId, 'FAILED', 'TRANSLATING', {
        reason: `Retrying ${failedChunks.length} failed chunks`,
        triggeredBy: 'SYSTEM'
      });
    }

    return {
      action: 'RETRY_PARTIAL',
      message: `Retrying ${failedChunks.length} failed chunks`,
      retriedChunks: failedChunks.length
    };
  }

  private async pauseJobForReview(jobId: string, error: JobError): Promise<RecoveryAction> {
    await this.stateManager.transitionJobState(jobId, 'FAILED', 'PAUSED', {
      reason: `Paused for manual review due to ${error.code}`,
      triggeredBy: 'SYSTEM',
      metadata: { pauseReason: error.code, requiresReview: true }
    });

    // Create review ticket
    const reviewTicket = await this.createReviewTicket(jobId, error);

    // Notify administrators
    await this.notifyAdministrators(jobId, error, reviewTicket);

    return {
      action: 'PAUSE_AND_REVIEW',
      message: 'Job paused for manual review',
      reviewTicket: reviewTicket.id
    };
  }
}
```

## 6. Performance & Monitoring

### Job Performance Metrics
```typescript
class JobPerformanceMonitor {
  private cloudWatch: AWS.CloudWatch;

  async publishJobMetrics(jobId: string, metrics: JobMetrics): Promise<void> {
    const metricData: AWS.CloudWatch.MetricDatum[] = [
      {
        MetricName: 'JobDuration',
        Value: metrics.duration,
        Unit: 'Seconds',
        Dimensions: [
          { Name: 'JobStatus', Value: metrics.finalStatus },
          { Name: 'Priority', Value: metrics.priority }
        ]
      },
      {
        MetricName: 'ChunkProcessingSpeed',
        Value: metrics.averageChunkTime,
        Unit: 'Milliseconds',
        Dimensions: [
          { Name: 'TargetLanguage', Value: metrics.targetLanguage }
        ]
      },
      {
        MetricName: 'JobThroughput',
        Value: metrics.wordsPerMinute,
        Unit: 'Count/Second',
        Dimensions: [
          { Name: 'DocumentSize', Value: this.categorizeDocumentSize(metrics.wordCount) }
        ]
      },
      {
        MetricName: 'ErrorRate',
        Value: metrics.chunkFailureRate,
        Unit: 'Percent',
        Dimensions: [
          { Name: 'JobStatus', Value: metrics.finalStatus }
        ]
      },
      {
        MetricName: 'RetryCount',
        Value: metrics.totalRetries,
        Unit: 'Count',
        Dimensions: [
          { Name: 'JobId', Value: jobId }
        ]
      }
    ];

    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/Jobs',
      MetricData: metricData
    }).promise();
  }

  async generateJobReport(
    startDate: string,
    endDate: string
  ): Promise<JobPerformanceReport> {
    const jobs = await this.getJobsInDateRange(startDate, endDate);
    
    const report: JobPerformanceReport = {
      reportPeriod: { startDate, endDate },
      totalJobs: jobs.length,
      completedJobs: jobs.filter(j => j.status === 'COMPLETED').length,
      failedJobs: jobs.filter(j => j.status === 'FAILED').length,
      averageProcessingTime: this.calculateAverageProcessingTime(jobs),
      throughputMetrics: {
        wordsPerHour: this.calculateWordsPerHour(jobs),
        jobsPerHour: jobs.length / this.getHoursBetween(startDate, endDate),
        peakHours: this.identifyPeakHours(jobs)
      },
      errorAnalysis: {
        topErrorCodes: this.getTopErrorCodes(jobs),
        errorsByStage: this.getErrorsByStage(jobs),
        retrySuccessRate: this.calculateRetrySuccessRate(jobs)
      },
      costAnalysis: {
        totalCost: jobs.reduce((sum, job) => sum + (job.actualCost || 0), 0),
        averageCostPerJob: this.calculateAverageCostPerJob(jobs),
        costByLanguage: this.getCostByLanguage(jobs)
      },
      recommendations: this.generateRecommendations(jobs)
    };

    return report;
  }

  private generateRecommendations(jobs: TranslationJobRecord[]): string[] {
    const recommendations: string[] = [];
    
    const failureRate = jobs.filter(j => j.status === 'FAILED').length / jobs.length;
    if (failureRate > 0.05) { // 5% failure rate threshold
      recommendations.push('High failure rate detected. Review error handling and retry logic.');
    }
    
    const avgProcessingTime = this.calculateAverageProcessingTime(jobs);
    const slowJobs = jobs.filter(j => j.actualDuration && j.actualDuration > avgProcessingTime * 2);
    if (slowJobs.length > jobs.length * 0.1) {
      recommendations.push('Significant number of slow-processing jobs. Consider optimizing chunking strategy.');
    }
    
    const retryRate = jobs.filter(j => j.retryCount > 0).length / jobs.length;
    if (retryRate > 0.20) { // 20% retry rate threshold
      recommendations.push('High retry rate. Review API integration and rate limiting strategies.');
    }
    
    return recommendations;
  }
}
```

## 7. Implementation Examples

### Complete Job Service Implementation
```typescript
export class TranslationJobService {
  private stateManager: JobStateManager;
  private progressAggregator: ChunkProgressAggregator;
  private errorRecovery: JobErrorRecovery;
  private performanceMonitor: JobPerformanceMonitor;

  constructor() {
    this.stateManager = new JobStateManager();
    this.progressAggregator = new ChunkProgressAggregator();
    this.errorRecovery = new JobErrorRecovery();
    this.performanceMonitor = new JobPerformanceMonitor();
  }

  async createJob(request: CreateJobRequest): Promise<CreateJobResponse> {
    // Validate request
    await this.validateJobRequest(request);
    
    // Check user quotas
    await this.checkUserQuotas(request.userId);
    
    // Create job
    return await this.stateManager.createJob(request);
  }

  async getJobDetails(jobId: string): Promise<JobDetailsResponse> {
    const job = await this.stateManager.getJob(jobId);
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    // Get real-time progress
    const progress = await this.progressAggregator.aggregateJobProgress(jobId);
    
    // Get chunk details
    const chunks = await this.progressAggregator.getJobChunks(jobId);
    
    return {
      jobId: job.jobId,
      userId: job.userId,
      documentId: job.documentId,
      filename: job.filename,
      targetLanguage: job.targetLanguage,
      status: job.status,
      progress: {
        overallPercentage: progress.overallProgress,
        currentStage: job.currentStage,
        stageProgress: job.stageProgress,
        chunksCompleted: progress.chunksCompleted,
        totalChunks: job.totalChunks,
        startTime: job.startedAt || job.createdAt,
        estimatedCompletion: job.estimatedCompletion,
        lastActivity: job.lastActivityAt
      },
      timestamps: {
        created: job.createdAt,
        started: job.startedAt,
        completed: job.completedAt,
        lastUpdated: job.updatedAt
      },
      costs: {
        estimated: job.estimatedCost,
        actual: job.actualCost
      },
      chunks: chunks.map(chunk => ({
        chunkId: chunk.chunkId,
        index: chunk.chunkIndex,
        status: chunk.status,
        progress: chunk.progress,
        tokenCount: chunk.tokenCount,
        translatedAt: chunk.translationCompleted,
        retryCount: chunk.retryCount,
        lastError: chunk.lastError?.message
      })),
      errors: job.lastError ? [job.lastError] : [],
      metadata: {
        wordCount: job.wordCount,
        fileSize: job.fileSize,
        priority: job.priority,
        retryCount: job.retryCount,
        processingSpeed: job.processingSpeed
      }
    };
  }

  async getJobProgress(jobId: string): Promise<JobProgressResponse> {
    const job = await this.stateManager.getJob(jobId);
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    const progress = await this.progressAggregator.aggregateJobProgress(jobId);
    
    return {
      jobId: job.jobId,
      status: job.status,
      overallProgress: progress.overallProgress,
      chunksCompleted: progress.chunksCompleted,
      totalChunks: job.totalChunks,
      estimatedTimeRemaining: progress.estimatedTimeRemaining,
      currentStage: this.getHumanReadableStage(job.currentStage),
      lastUpdated: job.lastActivityAt,
      processingSpeed: progress.processingSpeed,
      detailedProgress: {
        chunking: this.getStageProgress(job, 'CHUNKING'),
        translation: this.getStageProgress(job, 'TRANSLATING'),
        assembly: this.getStageProgress(job, 'ASSEMBLING'),
        delivery: this.getStageProgress(job, 'FINALIZING')
      }
    };
  }

  async pauseJob(jobId: string, userId: string): Promise<void> {
    const job = await this.stateManager.getJob(jobId);
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    if (job.userId !== userId) {
      throw new Error('Unauthorized to pause this job');
    }

    if (!['QUEUED', 'TRANSLATING'].includes(job.status)) {
      throw new Error(`Cannot pause job in status ${job.status}`);
    }

    await this.stateManager.transitionJobState(jobId, job.status, 'PAUSED', {
      reason: 'User requested pause',
      triggeredBy: userId
    });
  }

  async resumeJob(jobId: string, userId: string): Promise<void> {
    const job = await this.stateManager.getJob(jobId);
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    if (job.userId !== userId) {
      throw new Error('Unauthorized to resume this job');
    }

    if (job.status !== 'PAUSED') {
      throw new Error(`Cannot resume job in status ${job.status}`);
    }

    await this.stateManager.transitionJobState(jobId, 'PAUSED', 'RESUMING', {
      reason: 'User requested resume',
      triggeredBy: userId
    });

    // Restart processing workflow
    await this.restartProcessingWorkflow(jobId);
  }

  private getHumanReadableStage(stage: JobStatus): string {
    const stageMap = {
      'CREATED': 'Initializing job',
      'VALIDATING': 'Validating legal requirements',
      'VALIDATED': 'Validation complete',
      'QUEUED': 'Waiting in queue',
      'CHUNKING': 'Preparing document sections',
      'CHUNKED': 'Document prepared for translation',
      'TRANSLATING': 'Translating content',
      'ASSEMBLING': 'Combining translated sections',
      'FINALIZING': 'Final quality checks',
      'COMPLETED': 'Translation complete',
      'FAILED': 'Translation failed',
      'PAUSED': 'Translation paused',
      'RETRYING': 'Retrying translation'
    };

    return stageMap[stage] || stage;
  }

  private getStageProgress(job: TranslationJobRecord, stage: JobStatus): StageProgress {
    const isCompleted = this.isStageCompleted(job.status, stage);
    const isInProgress = job.currentStage === stage;
    const isPending = this.isStageAfter(stage, job.currentStage);

    return {
      status: isCompleted ? 'COMPLETED' : isInProgress ? 'IN_PROGRESS' : 'PENDING',
      progress: isCompleted ? 100 : isInProgress ? job.stageProgress : 0,
      startTime: this.getStageStartTime(job, stage),
      endTime: this.getStageEndTime(job, stage)
    };
  }
}
```

### Lambda Handler for Job Management
```typescript
export const getJobProgressHandler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  try {
    const jobId = event.pathParameters?.jobId;
    if (!jobId) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Job ID is required' })
      };
    }

    // Extract user from JWT token
    const userInfo = extractUserFromToken(event.headers.Authorization);
    
    const jobService = new TranslationJobService();
    const progress = await jobService.getJobProgress(jobId);
    
    // Verify user access to job
    const job = await jobService.getJobDetails(jobId);
    if (job.userId !== userInfo.userId) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: 'Access denied' })
      };
    }

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'max-age=30' // 30-second cache for polling optimization
      },
      body: JSON.stringify(progress)
    };

  } catch (error) {
    console.error('Error getting job progress:', error);
    
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Internal server error',
        message: 'Failed to retrieve job progress'
      })
    };
  }
};
```

## 8. Testing Strategy

### Job State Management Testing
```typescript
describe('JobStateManager', () => {
  let stateManager: JobStateManager;
  let mockDynamoDB: jest.Mocked<AWS.DynamoDB.DocumentClient>;

  beforeEach(() => {
    mockDynamoDB = {
      put: jest.fn().mockReturnValue({ promise: jest.fn().mockResolvedValue({}) }),
      update: jest.fn().mockReturnValue({ promise: jest.fn().mockResolvedValue({ Attributes: {} }) }),
      query: jest.fn().mockReturnValue({ promise: jest.fn().mockResolvedValue({ Items: [] }) }),
      get: jest.fn().mockReturnValue({ promise: jest.fn().mockResolvedValue({ Item: {} }) })
    } as any;

    stateManager = new JobStateManager();
    (stateManager as any).dynamoClient = mockDynamoDB;
  });

  it('creates job successfully', async () => {
    const request: CreateJobRequest = {
      userId: 'user-123',
      documentId: 'doc-456',
      filename: 'test-document.txt',
      targetLanguage: 'spanish',
      documentMetadata: {
        wordCount: 10000,
        fileSize: 50000,
        contentHash: 'hash123'
      },
      priority: 'NORMAL'
    };

    const result = await stateManager.createJob(request);

    expect(result.jobId).toMatch(/^JOB_/);
    expect(result.status).toBe('CREATED');
    expect(mockDynamoDB.put).toHaveBeenCalledWith(
      expect.objectContaining({
        TableName: expect.any(String),
        Item: expect.objectContaining({
          jobId: result.jobId,
          status: 'CREATED',
          userId: 'user-123'
        })
      })
    );
  });

  it('transitions job state correctly', async () => {
    const jobId = 'test-job-123';
    
    mockDynamoDB.update.mockReturnValueOnce({
      promise: jest.fn().mockResolvedValue({
        Attributes: { status: 'VALIDATING' }
      })
    } as any);

    await stateManager.transitionJobState(jobId, 'CREATED', 'VALIDATING', {
      reason: 'Test transition',
      triggeredBy: 'SYSTEM'
    });

    expect(mockDynamoDB.update).toHaveBeenCalledWith(
      expect.objectContaining({
        Key: { PK: `JOB#${jobId}`, SK: 'METADATA' },
        ConditionExpression: '#status = :fromState',
        ExpressionAttributeValues: expect.objectContaining({
          ':fromState': 'CREATED',
          ':toState': 'VALIDATING'
        })
      })
    );
  });

  it('rejects invalid state transitions', async () => {
    const jobId = 'test-job-123';
    
    await expect(
      stateManager.transitionJobState(jobId, 'COMPLETED', 'TRANSLATING', {
        reason: 'Invalid transition',
        triggeredBy: 'SYSTEM'
      })
    ).rejects.toThrow('Invalid state transition');
  });

  it('handles conditional check failures', async () => {
    const jobId = 'test-job-123';
    
    mockDynamoDB.update.mockReturnValueOnce({
      promise: jest.fn().mockRejectedValue({
        code: 'ConditionalCheckFailedException'
      })
    } as any);

    await expect(
      stateManager.transitionJobState(jobId, 'CREATED', 'VALIDATING', {
        reason: 'Test transition',
        triggeredBy: 'SYSTEM'
      })
    ).rejects.toThrow('not in expected state');
  });
});

describe('ChunkProgressAggregator', () => {
  let aggregator: ChunkProgressAggregator;
  let mockDynamoDB: jest.Mocked<AWS.DynamoDB.DocumentClient>;

  beforeEach(() => {
    mockDynamoDB = {
      query: jest.fn()
    } as any;

    aggregator = new ChunkProgressAggregator();
    (aggregator as any).dynamoClient = mockDynamoDB;
  });

  it('calculates progress correctly', async () => {
    const mockChunks: ChunkStatusRecord[] = [
      createMockChunk({ status: 'COMPLETED', progress: 100, processingTime: 30000 }),
      createMockChunk({ status: 'COMPLETED', progress: 100, processingTime: 25000 }),
      createMockChunk({ status: 'TRANSLATING', progress: 50 }),
      createMockChunk({ status: 'PENDING', progress: 0 }),
      createMockChunk({ status: 'PENDING', progress: 0 })
    ];

    mockDynamoDB.query.mockReturnValue({
      promise: jest.fn().mockResolvedValue({ Items: mockChunks })
    } as any);

    const result = await aggregator.aggregateJobProgress('test-job');

    expect(result.overallProgress).toBe(50); // (200 + 50 + 0 + 0) / 5 = 50
    expect(result.chunksCompleted).toBe(2);
    expect(result.chunksTranslating).toBe(1);
    expect(result.totalChunks).toBe(5);
    expect(result.averageProcessingTime).toBe(27500); // (30000 + 25000) / 2
  });

  it('handles empty chunk list', async () => {
    mockDynamoDB.query.mockReturnValue({
      promise: jest.fn().mockResolvedValue({ Items: [] })
    } as any);

    const result = await aggregator.aggregateJobProgress('test-job');

    expect(result.overallProgress).toBe(0);
    expect(result.chunksCompleted).toBe(0);
    expect(result.totalChunks).toBe(0);
  });
});

function createMockChunk(overrides: Partial<ChunkStatusRecord>): ChunkStatusRecord {
  return {
    PK: 'JOB#test-job',
    SK: 'CHUNK#001',
    jobId: 'test-job',
    chunkId: 'chunk-1',
    chunkIndex: 1,
    status: 'PENDING',
    progress: 0,
    tokenCount: 1000,
    retryCount: 0,
    ...overrides
  };
}
```

## 9. Configuration & Deployment

### CloudFormation Template for Job Management
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Job State Management Infrastructure'

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, staging, prod]

Resources:
  # DynamoDB Table for Jobs
  JobsTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub 'translation-jobs-${Environment}'
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: PK
          AttributeType: S
        - AttributeName: SK
          AttributeType: S
        - AttributeName: GSI1PK
          AttributeType: S
        - AttributeName: GSI1SK
          AttributeType: S
        - AttributeName: GSI2PK
          AttributeType: S
        - AttributeName: GSI2SK
          AttributeType: S
        - AttributeName: GSI3PK
          AttributeType: S
        - AttributeName: GSI3SK
          AttributeType: S
      KeySchema:
        - AttributeName: PK
          KeyType: HASH
        - AttributeName: SK
          KeyType: RANGE
      GlobalSecondaryIndexes:
        - IndexName: JobsByUser
          KeySchema:
            - AttributeName: GSI1PK
              KeyType: HASH
            - AttributeName: GSI1SK
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
        - IndexName: JobsByStatus
          KeySchema:
            - AttributeName: GSI2PK
              KeyType: HASH
            - AttributeName: GSI2SK
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
        - IndexName: JobsByDocument
          KeySchema:
            - AttributeName: GSI3PK
              KeyType: HASH
            - AttributeName: GSI3SK
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES
      PointInTimeRecoverySpecification:
        PointInTimeRecoveryEnabled: true

  # DynamoDB Table for Chunk Status
  ChunksTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub 'translation-chunks-${Environment}'
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: PK
          AttributeType: S
        - AttributeName: SK
          AttributeType: S
      KeySchema:
        - AttributeName: PK
          KeyType: HASH
        - AttributeName: SK
          KeyType: RANGE
      TimeToLiveSpecification:
        AttributeName: ttl
        Enabled: true

  # Lambda Functions
  JobManagementFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'job-management-${Environment}'
      Runtime: nodejs18.x
      Handler: dist/jobs.handler
      Code:
        S3Bucket: !Ref DeploymentBucket
        S3Key: !Sub 'job-management-${Environment}.zip'
      MemorySize: 1024
      Timeout: 300
      Environment:
        Variables:
          JOBS_TABLE: !Ref JobsTable
          CHUNKS_TABLE: !Ref ChunksTable
          ENVIRONMENT: !Ref Environment
      ReservedConcurrencyLimit: 50

  # CloudWatch Alarms
  JobFailureAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub 'job-high-failure-rate-${Environment}'
      AlarmDescription: 'High job failure rate detected'
      MetricName: JobsCreated
      Namespace: TranslationService/Jobs
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 2
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold

Outputs:
  JobsTableName:
    Description: 'Name of the jobs DynamoDB table'
    Value: !Ref JobsTable
    Export:
      Name: !Sub '${AWS::StackName}-JobsTable'
```

---

This comprehensive Job State Management design provides robust tracking, coordination, and monitoring of translation jobs while ensuring data consistency, error recovery, and optimal performance for the Long-Form Translation Service's polling-based architecture.