# Low-Level Design Document 8: Step Functions Workflow

## 1. Component Overview & Responsibilities

The Step Functions Workflow orchestrates the entire translation process from document validation through final delivery. It provides centralized workflow management, parallel chunk processing, error handling, and retry logic while maintaining state consistency and enabling observability across the distributed translation pipeline.

**Key Responsibilities:**
- End-to-end translation workflow orchestration
- Parallel chunk processing coordination with rate limiting
- State transitions and job lifecycle management
- Error handling and recovery orchestration
- Integration with all system components (Legal, Chunking, Gemini API, Job State)
- Workflow monitoring and audit trail maintenance

**Why This Design:** Step Functions provides visual workflow management, built-in error handling, automatic retries, and parallel execution capabilities essential for coordinating complex, long-running translation processes while maintaining reliability and observability.

## 2. API Design & Interfaces

### Workflow Execution Endpoints
```typescript
// POST /workflows/translation
interface StartTranslationWorkflowRequest {
  jobId: string;
  documentId: string;
  userId: string;
  targetLanguage: string;
  documentMetadata: {
    filename: string;
    wordCount: number;
    fileSize: number;
    contentHash: string;
  };
  translationOptions: {
    preserveFormatting: boolean;
    qualityLevel: 'STANDARD' | 'PREMIUM';
    customGlossary?: string;
  };
  priority: 'LOW' | 'NORMAL' | 'HIGH';
}

interface StartWorkflowResponse {
  executionArn: string;
  executionName: string;
  startDate: string;
  status: 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'TIMED_OUT';
  jobId: string;
}

// GET /workflows/execution/{executionArn}
interface WorkflowExecutionResponse {
  executionArn: string;
  stateMachineArn: string;
  name: string;
  status: ExecutionStatus;
  startDate: string;
  stopDate?: string;
  input: string;
  output?: string;
  error?: WorkflowError;
  currentState?: string;
  stateHistory: StateHistoryEntry[];
}

// POST /workflows/execution/{executionArn}/stop
interface StopWorkflowRequest {
  cause?: string;
  error?: string;
}
```

### Workflow State Definitions
```typescript
interface WorkflowInput {
  jobId: string;
  documentId: string;
  userId: string;
  targetLanguage: string;
  documentMetadata: DocumentMetadata;
  translationOptions: TranslationOptions;
  priority: 'LOW' | 'NORMAL' | 'HIGH';
  retryCount?: number;
  resumeFromState?: string;
}

interface WorkflowOutput {
  jobId: string;
  status: 'COMPLETED' | 'FAILED';
  finalDocumentUrl?: string;
  totalCost: number;
  processingTime: number;
  chunkSummary: {
    totalChunks: number;
    successfulChunks: number;
    failedChunks: number;
  };
  qualityMetrics: {
    averageConfidence: number;
    qualityFlags: string[];
  };
  error?: WorkflowError;
}

interface ChunkProcessingTask {
  chunkId: string;
  chunkIndex: number;
  content: string;
  contextWindow: {
    preceding: string;
    following: string;
  };
  targetLanguage: string;
  translationHints: string[];
  retryCount: number;
}

interface ChunkProcessingResult {
  chunkId: string;
  status: 'SUCCESS' | 'FAILED' | 'RETRY';
  translatedContent?: string;
  confidence?: number;
  tokenUsage?: {
    inputTokens: number;
    outputTokens: number;
    cost: number;
  };
  processingTime: number;
  error?: {
    code: string;
    message: string;
    retryable: boolean;
  };
}
```

## 3. Step Functions State Machine Definition

### Main Translation Workflow
```json
{
  "Comment": "Long-Form Translation Service Workflow",
  "StartAt": "ValidateInput",
  "States": {
    "ValidateInput": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:validate-workflow-input",
      "Parameters": {
        "input.$": "$"
      },
      "ResultPath": "$.validation",
      "Next": "UpdateJobStatus_Validating",
      "Catch": [
        {
          "ErrorEquals": ["ValidationError"],
          "Next": "HandleValidationError",
          "ResultPath": "$.error"
        }
      ]
    },
    
    "UpdateJobStatus_Validating": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "VALIDATING",
        "metadata": {
          "stage": "validation",
          "timestamp.$": "$$.State.EnteredTime"
        }
      },
      "ResultPath": "$.statusUpdate",
      "Next": "CheckLegalAttestation"
    },
    
    "CheckLegalAttestation": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:check-legal-attestation",
      "Parameters": {
        "userId.$": "$.userId",
        "documentId.$": "$.documentId"
      },
      "ResultPath": "$.attestation",
      "Next": "IsAttestationValid",
      "Retry": [
        {
          "ErrorEquals": ["States.TaskFailed"],
          "IntervalSeconds": 2,
          "MaxAttempts": 3,
          "BackoffRate": 2.0
        }
      ]
    },
    
    "IsAttestationValid": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.attestation.isValid",
          "BooleanEquals": true,
          "Next": "UpdateJobStatus_Validated"
        }
      ],
      "Default": "WaitForAttestation"
    },
    
    "WaitForAttestation": {
      "Type": "Wait",
      "Seconds": 300,
      "Next": "CheckLegalAttestation"
    },
    
    "UpdateJobStatus_Validated": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "VALIDATED"
      },
      "ResultPath": "$.statusUpdate",
      "Next": "ChunkDocument"
    },
    
    "ChunkDocument": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:chunk-document",
      "Parameters": {
        "documentId.$": "$.documentId",
        "targetLanguage.$": "$.targetLanguage",
        "chunkSize": 3500,
        "overlapSize": 250
      },
      "ResultPath": "$.chunking",
      "Next": "UpdateJobStatus_Chunked",
      "Retry": [
        {
          "ErrorEquals": ["States.TaskFailed"],
          "IntervalSeconds": 5,
          "MaxAttempts": 3,
          "BackoffRate": 2.0
        }
      ],
      "Catch": [
        {
          "ErrorEquals": ["ChunkingError"],
          "Next": "HandleChunkingError",
          "ResultPath": "$.error"
        }
      ]
    },
    
    "UpdateJobStatus_Chunked": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "CHUNKED",
        "metadata": {
          "totalChunks.$": "$.chunking.totalChunks",
          "estimatedTokens.$": "$.chunking.estimatedTokens"
        }
      },
      "ResultPath": "$.statusUpdate",
      "Next": "InitializeChunkProcessing"
    },
    
    "InitializeChunkProcessing": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:initialize-chunk-processing",
      "Parameters": {
        "jobId.$": "$.jobId",
        "chunks.$": "$.chunking.chunks",
        "concurrencyLimit": 5
      },
      "ResultPath": "$.chunkProcessing",
      "Next": "UpdateJobStatus_Translating"
    },
    
    "UpdateJobStatus_Translating": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "TRANSLATING"
      },
      "ResultPath": "$.statusUpdate",
      "Next": "ProcessChunksParallel"
    },
    
    "ProcessChunksParallel": {
      "Type": "Map",
      "ItemsPath": "$.chunkProcessing.chunkBatches",
      "MaxConcurrency": 5,
      "Iterator": {
        "StartAt": "ProcessChunkBatch",
        "States": {
          "ProcessChunkBatch": {
            "Type": "Map",
            "ItemsPath": "$.chunks",
            "MaxConcurrency": 3,
            "Iterator": {
              "StartAt": "TranslateChunk",
              "States": {
                "TranslateChunk": {
                  "Type": "Task",
                  "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:translate-chunk",
                  "Parameters": {
                    "chunkId.$": "$.chunkId",
                    "content.$": "$.content",
                    "targetLanguage.$": "$.targetLanguage",
                    "contextWindow.$": "$.contextWindow"
                  },
                  "End": true,
                  "Retry": [
                    {
                      "ErrorEquals": ["RateLimitError"],
                      "IntervalSeconds": 60,
                      "MaxAttempts": 5,
                      "BackoffRate": 2.0
                    },
                    {
                      "ErrorEquals": ["ServiceUnavailableError"],
                      "IntervalSeconds": 30,
                      "MaxAttempts": 3,
                      "BackoffRate": 2.0
                    }
                  ],
                  "Catch": [
                    {
                      "ErrorEquals": ["States.ALL"],
                      "Next": "HandleChunkError",
                      "ResultPath": "$.error"
                    }
                  ]
                },
                
                "HandleChunkError": {
                  "Type": "Pass",
                  "Parameters": {
                    "chunkId.$": "$.chunkId",
                    "status": "FAILED",
                    "error.$": "$.error"
                  },
                  "End": true
                }
              }
            },
            "End": true
          }
        }
      },
      "ResultPath": "$.translationResults",
      "Next": "AggregateResults"
    },
    
    "AggregateResults": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:aggregate-translation-results",
      "Parameters": {
        "jobId.$": "$.jobId",
        "translationResults.$": "$.translationResults"
      },
      "ResultPath": "$.aggregation",
      "Next": "CheckTranslationSuccess"
    },
    
    "CheckTranslationSuccess": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.aggregation.successRate",
          "NumericGreaterThanEquals": 0.9,
          "Next": "UpdateJobStatus_Assembling"
        }
      ],
      "Default": "HandleTranslationFailure"
    },
    
    "UpdateJobStatus_Assembling": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "ASSEMBLING"
      },
      "ResultPath": "$.statusUpdate",
      "Next": "AssembleDocument"
    },
    
    "AssembleDocument": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:assemble-translated-document",
      "Parameters": {
        "jobId.$": "$.jobId",
        "translatedChunks.$": "$.aggregation.successfulChunks",
        "originalFormat.$": "$.documentMetadata.format",
        "preserveFormatting.$": "$.translationOptions.preserveFormatting"
      },
      "ResultPath": "$.assembly",
      "Next": "UpdateJobStatus_Finalizing",
      "Retry": [
        {
          "ErrorEquals": ["States.TaskFailed"],
          "IntervalSeconds": 10,
          "MaxAttempts": 3,
          "BackoffRate": 2.0
        }
      ]
    },
    
    "UpdateJobStatus_Finalizing": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "FINALIZING"
      },
      "ResultPath": "$.statusUpdate",
      "Next": "PerformQualityCheck"
    },
    
    "PerformQualityCheck": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:quality-check",
      "Parameters": {
        "documentUrl.$": "$.assembly.documentUrl",
        "qualityLevel.$": "$.translationOptions.qualityLevel"
      },
      "ResultPath": "$.qualityCheck",
      "Next": "IsQualityAcceptable",
      "Retry": [
        {
          "ErrorEquals": ["States.TaskFailed"],
          "IntervalSeconds": 5,
          "MaxAttempts": 2
        }
      ]
    },
    
    "IsQualityAcceptable": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.qualityCheck.passed",
          "BooleanEquals": true,
          "Next": "UpdateJobStatus_Completed"
        }
      ],
      "Default": "HandleQualityFailure"
    },
    
    "UpdateJobStatus_Completed": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "COMPLETED",
        "metadata": {
          "finalDocumentUrl.$": "$.assembly.documentUrl",
          "totalCost.$": "$.aggregation.totalCost",
          "processingTime.$": "$.aggregation.totalProcessingTime"
        }
      },
      "ResultPath": "$.statusUpdate",
      "Next": "SendCompletionNotification"
    },
    
    "SendCompletionNotification": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:send-notification",
      "Parameters": {
        "userId.$": "$.userId",
        "jobId.$": "$.jobId",
        "type": "JOB_COMPLETED",
        "documentUrl.$": "$.assembly.documentUrl"
      },
      "ResultPath": "$.notification",
      "Next": "WorkflowSuccess"
    },
    
    "WorkflowSuccess": {
      "Type": "Pass",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "COMPLETED",
        "finalDocumentUrl.$": "$.assembly.documentUrl",
        "totalCost.$": "$.aggregation.totalCost",
        "processingTime.$": "$.aggregation.totalProcessingTime",
        "chunkSummary": {
          "totalChunks.$": "$.aggregation.totalChunks",
          "successfulChunks.$": "$.aggregation.successfulChunks",
          "failedChunks.$": "$.aggregation.failedChunks"
        },
        "qualityMetrics": {
          "averageConfidence.$": "$.aggregation.averageConfidence",
          "qualityFlags.$": "$.qualityCheck.flags"
        }
      },
      "End": true
    },
    
    "HandleValidationError": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "FAILED",
        "error.$": "$.error"
      },
      "Next": "WorkflowFailed"
    },
    
    "HandleChunkingError": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "FAILED",
        "error.$": "$.error"
      },
      "Next": "WorkflowFailed"
    },
    
    "HandleTranslationFailure": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:handle-translation-failure",
      "Parameters": {
        "jobId.$": "$.jobId",
        "failureRate.$": "$.aggregation.failureRate",
        "failedChunks.$": "$.aggregation.failedChunks"
      },
      "ResultPath": "$.failureHandling",
      "Next": "ShouldRetryTranslation"
    },
    
    "ShouldRetryTranslation": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.failureHandling.shouldRetry",
          "BooleanEquals": true,
          "Next": "RetryFailedChunks"
        }
      ],
      "Default": "UpdateJobStatus_Failed"
    },
    
    "RetryFailedChunks": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:retry-failed-chunks",
      "Parameters": {
        "jobId.$": "$.jobId",
        "failedChunks.$": "$.aggregation.failedChunks"
      },
      "ResultPath": "$.retryResult",
      "Next": "ProcessChunksParallel"
    },
    
    "HandleQualityFailure": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:handle-quality-failure",
      "Parameters": {
        "jobId.$": "$.jobId",
        "qualityIssues.$": "$.qualityCheck.issues"
      },
      "Next": "UpdateJobStatus_Failed"
    },
    
    "UpdateJobStatus_Failed": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:update-job-status",
      "Parameters": {
        "jobId.$": "$.jobId",
        "status": "FAILED",
        "error": {
          "code": "WORKFLOW_FAILED",
          "message": "Translation workflow failed"
        }
      },
      "Next": "WorkflowFailed"
    },
    
    "WorkflowFailed": {
      "Type": "Fail",
      "Cause": "Translation workflow failed",
      "Error": "WorkflowExecutionFailed"
    }
  }
}
```

### Rate Limiting Sub-Workflow
```json
{
  "Comment": "Rate-limited chunk processing workflow",
  "StartAt": "CheckRateLimit",
  "States": {
    "CheckRateLimit": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:check-rate-limit",
      "Parameters": {
        "service": "gemini-api",
        "estimatedTokens.$": "$.estimatedTokens"
      },
      "ResultPath": "$.rateLimitCheck",
      "Next": "IsRateLimitOk"
    },
    
    "IsRateLimitOk": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.rateLimitCheck.canProceed",
          "BooleanEquals": true,
          "Next": "ProcessChunk"
        }
      ],
      "Default": "WaitForRateLimit"
    },
    
    "WaitForRateLimit": {
      "Type": "Wait",
      "SecondsPath": "$.rateLimitCheck.waitSeconds",
      "Next": "CheckRateLimit"
    },
    
    "ProcessChunk": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:translate-chunk",
      "End": true,
      "Retry": [
        {
          "ErrorEquals": ["RateLimitError"],
          "IntervalSeconds": 60,
          "MaxAttempts": 5,
          "BackoffRate": 2.0
        }
      ]
    }
  }
}
```

## 4. Core Workflow Logic

### Workflow Orchestrator Implementation
```typescript
class TranslationWorkflowOrchestrator {
  private stepFunctions: AWS.StepFunctions;
  private stateMachineArn: string;

  constructor() {
    this.stepFunctions = new AWS.StepFunctions();
    this.stateMachineArn = process.env.TRANSLATION_STATE_MACHINE_ARN!;
  }

  async startTranslationWorkflow(request: StartTranslationWorkflowRequest): Promise<StartWorkflowResponse> {
    const executionName = this.generateExecutionName(request.jobId);
    
    const input: WorkflowInput = {
      jobId: request.jobId,
      documentId: request.documentId,
      userId: request.userId,
      targetLanguage: request.targetLanguage,
      documentMetadata: request.documentMetadata,
      translationOptions: request.translationOptions,
      priority: request.priority
    };

    try {
      const execution = await this.stepFunctions.startExecution({
        stateMachineArn: this.stateMachineArn,
        name: executionName,
        input: JSON.stringify(input)
      }).promise();

      return {
        executionArn: execution.executionArn,
        executionName: executionName,
        startDate: execution.startDate.toISOString(),
        status: 'RUNNING',
        jobId: request.jobId
      };

    } catch (error) {
      console.error('Failed to start workflow:', error);
      throw new WorkflowError('WORKFLOW_START_FAILED', `Failed to start translation workflow: ${error.message}`);
    }
  }

  async getWorkflowExecution(executionArn: string): Promise<WorkflowExecutionResponse> {
    try {
      const execution = await this.stepFunctions.describeExecution({
        executionArn
      }).promise();

      const history = await this.stepFunctions.getExecutionHistory({
        executionArn,
        reverseOrder: true,
        maxResults: 100
      }).promise();

      return {
        executionArn: execution.executionArn,
        stateMachineArn: execution.stateMachineArn,
        name: execution.name,
        status: execution.status as ExecutionStatus,
        startDate: execution.startDate.toISOString(),
        stopDate: execution.stopDate?.toISOString(),
        input: execution.input,
        output: execution.output,
        error: execution.error ? JSON.parse(execution.error) : undefined,
        currentState: this.getCurrentState(history.events),
        stateHistory: this.parseStateHistory(history.events)
      };

    } catch (error) {
      throw new WorkflowError('WORKFLOW_DESCRIBE_FAILED', `Failed to describe workflow execution: ${error.message}`);
    }
  }

  async stopWorkflowExecution(executionArn: string, request: StopWorkflowRequest): Promise<void> {
    try {
      await this.stepFunctions.stopExecution({
        executionArn,
        cause: request.cause || 'User requested stop',
        error: request.error
      }).promise();

      // Extract job ID from execution and update job status
      const execution = await this.stepFunctions.describeExecution({ executionArn }).promise();
      const input = JSON.parse(execution.input) as WorkflowInput;
      
      await this.updateJobStatus(input.jobId, 'CANCELLED', {
        reason: request.cause || 'User cancelled',
        executionArn
      });

    } catch (error) {
      throw new WorkflowError('WORKFLOW_STOP_FAILED', `Failed to stop workflow execution: ${error.message}`);
    }
  }

  async resumeWorkflowFromFailure(
    jobId: string,
    resumeFromState: string,
    updatedInput?: Partial<WorkflowInput>
  ): Promise<StartWorkflowResponse> {
    // Get original workflow input
    const originalExecution = await this.getLatestExecutionForJob(jobId);
    const originalInput = JSON.parse(originalExecution.input) as WorkflowInput;

    // Merge with updated input
    const resumeInput: WorkflowInput = {
      ...originalInput,
      ...updatedInput,
      resumeFromState,
      retryCount: (originalInput.retryCount || 0) + 1
    };

    // Start new execution with resume parameters
    return await this.startTranslationWorkflow({
      jobId,
      documentId: resumeInput.documentId,
      userId: resumeInput.userId,
      targetLanguage: resumeInput.targetLanguage,
      documentMetadata: resumeInput.documentMetadata,
      translationOptions: resumeInput.translationOptions,
      priority: resumeInput.priority
    });
  }

  private generateExecutionName(jobId: string): string {
    const timestamp = Date.now();
    return `translation-${jobId}-${timestamp}`;
  }

  private getCurrentState(events: AWS.StepFunctions.HistoryEvent[]): string | undefined {
    for (const event of events) {
      if (event.type === 'TaskStateEntered' || event.type === 'ChoiceStateEntered') {
        return event.stateEnteredEventDetails?.name || event.choiceStateEnteredEventDetails?.name;
      }
    }
    return undefined;
  }

  private parseStateHistory(events: AWS.StepFunctions.HistoryEvent[]): StateHistoryEntry[] {
    return events
      .filter(event => ['StateEntered', 'StateExited', 'TaskFailed', 'TaskSucceeded'].some(type => event.type.includes(type)))
      .map(event => ({
        timestamp: event.timestamp.toISOString(),
        type: event.type,
        stateName: this.extractStateName(event),
        duration: this.calculateStateDuration(event, events),
        error: this.extractErrorFromEvent(event)
      }))
      .reverse(); // Show chronological order
  }

  private async getLatestExecutionForJob(jobId: string): Promise<AWS.StepFunctions.DescribeExecutionOutput> {
    // This would typically query DynamoDB or use a custom indexing strategy
    // to find the latest execution for a specific job
    const executions = await this.stepFunctions.listExecutions({
      stateMachineArn: this.stateMachineArn,
      statusFilter: 'FAILED',
      maxResults: 50
    }).promise();

    for (const execution of executions.executions) {
      const details = await this.stepFunctions.describeExecution({
        executionArn: execution.executionArn
      }).promise();
      
      const input = JSON.parse(details.input) as WorkflowInput;
      if (input.jobId === jobId) {
        return details;
      }
    }

    throw new Error(`No failed execution found for job ${jobId}`);
  }
}
```

### Chunk Batch Processing Coordinator
```typescript
class ChunkBatchCoordinator {
  private maxConcurrentChunks: number = 5;
  private rateLimitBuffer: number = 0.8; // Use 80% of rate limit

  async createChunkBatches(
    chunks: ChunkProcessingTask[],
    priority: string
  ): Promise<ChunkBatch[]> {
    // Calculate optimal batch size based on rate limits and priority
    const batchSize = this.calculateOptimalBatchSize(chunks, priority);
    
    const batches: ChunkBatch[] = [];
    for (let i = 0; i < chunks.length; i += batchSize) {
      const batchChunks = chunks.slice(i, i + batchSize);
      
      batches.push({
        batchId: `batch-${Math.floor(i / batchSize) + 1}`,
        chunks: batchChunks,
        estimatedProcessingTime: this.estimateBatchProcessingTime(batchChunks),
        priority: this.calculateBatchPriority(batchChunks, priority),
        rateLimitBudget: this.calculateRateLimitBudget(batchChunks)
      });
    }

    return this.optimizeBatchOrder(batches, priority);
  }

  private calculateOptimalBatchSize(chunks: ChunkProcessingTask[], priority: string): number {
    // Base batch size on priority and system load
    const baseBatchSize = priority === 'HIGH' ? 3 : priority === 'NORMAL' ? 5 : 8;
    
    // Adjust based on average chunk size
    const avgTokens = chunks.reduce((sum, chunk) => sum + this.estimateTokens(chunk.content), 0) / chunks.length;
    
    if (avgTokens > 3000) {
      return Math.max(2, Math.floor(baseBatchSize * 0.7)); // Smaller batches for large chunks
    } else if (avgTokens < 1500) {
      return Math.min(10, Math.floor(baseBatchSize * 1.3)); // Larger batches for small chunks
    }
    
    return baseBatchSize;
  }

  private estimateBatchProcessingTime(chunks: ChunkProcessingTask[]): number {
    const totalTokens = chunks.reduce((sum, chunk) => sum + this.estimateTokens(chunk.content), 0);
    
    // Base estimation: 1000 tokens per 10 seconds + API overhead
    const baseTime = (totalTokens / 1000) * 10000; // milliseconds
    const apiOverhead = chunks.length * 2000; // 2 seconds per API call
    const rateLimitDelay = this.estimateRateLimitDelay(totalTokens);
    
    return baseTime + apiOverhead + rateLimitDelay;
  }

  private estimateRateLimitDelay(totalTokens: number): number {
    const tokensPerMinute = 405000; // Gemini API limit
    const usageRatio = totalTokens / tokensPerMinute;
    
    if (usageRatio > this.rateLimitBuffer) {
      // Estimate delay needed to stay under rate limit
      const excessTokens = totalTokens - (tokensPerMinute * this.rateLimitBuffer);
      return (excessTokens / tokensPerMinute) * 60000; // Convert to milliseconds
    }
    
    return 0;
  }

  private optimizeBatchOrder(batches: ChunkBatch[], priority: string): ChunkBatch[] {
    // Sort batches for optimal processing order
    return batches.sort((a, b) => {
      // Higher priority batches first
      if (a.priority !== b.priority) {
        return b.priority - a.priority;
      }
      
      // Shorter batches first for faster initial results
      return a.estimatedProcessingTime - b.estimatedProcessingTime;
    });
  }

  async monitorBatchProgress(batchId: string): Promise<BatchProgressInfo> {
    // Get current status of all chunks in the batch
    const chunkStatuses = await this.getChunkStatuses(batchId);
    
    const completed = chunkStatuses.filter(s => s.status === 'COMPLETED').length;
    const failed = chunkStatuses.filter(s => s.status === 'FAILED').length;
    const inProgress = chunkStatuses.filter(s => s.status === 'TRANSLATING').length;
    
    return {
      batchId,
      totalChunks: chunkStatuses.length,
      completedChunks: completed,
      failedChunks: failed,
      inProgressChunks: inProgress,
      overallProgress: (completed / chunkStatuses.length) * 100,
      estimatedTimeRemaining: this.calculateRemainingTime(chunkStatuses),
      currentThroughput: this.calculateCurrentThroughput(chunkStatuses)
    };
  }
}
```

### Workflow Error Recovery System
```typescript
class WorkflowErrorRecovery {
  async handleWorkflowError(
    executionArn: string,
    error: WorkflowError,
    context: WorkflowErrorContext
  ): Promise<RecoveryAction> {
    const errorType = this.classifyWorkflowError(error);
    const execution = await this.stepFunctions.describeExecution({ executionArn }).promise();
    const workflowInput = JSON.parse(execution.input) as WorkflowInput;
    
    switch (errorType.category) {
      case 'TRANSIENT_ERROR':
        return await this.handleTransientError(workflowInput, error, context);
      
      case 'RATE_LIMIT_ERROR':
        return await this.handleRateLimitError(workflowInput, error, context);
      
      case 'RESOURCE_ERROR':
        return await this.handleResourceError(workflowInput, error, context);
      
      case 'DATA_ERROR':
        return await this.handleDataError(workflowInput, error, context);
      
      case 'SYSTEM_ERROR':
        return await this.handleSystemError(workflowInput, error, context);
      
      default:
        return await this.handleUnknownError(workflowInput, error, context);
    }
  }

  private async handleTransientError(
    input: WorkflowInput,
    error: WorkflowError,
    context: WorkflowErrorContext
  ): Promise<RecoveryAction> {
    const retryCount = input.retryCount || 0;
    const maxRetries = 3;

    if (retryCount < maxRetries) {
      // Calculate exponential backoff delay
      const baseDelay = 30000; // 30 seconds
      const delay = baseDelay * Math.pow(2, retryCount);
      
      // Schedule retry
      await this.scheduleWorkflowRetry(input, delay, context.failedState);
      
      return {
        action: 'RETRY_DELAYED',
        delay,
        message: `Retrying workflow after ${delay / 1000} seconds (attempt ${retryCount + 1}/${maxRetries})`,
        retryCount: retryCount + 1
      };
    } else {
      // Mark job as failed after exhausting retries
      await this.updateJobStatus(input.jobId, 'FAILED', {
        reason: 'Maximum retry attempts exceeded',
        originalError: error
      });
      
      return {
        action: 'FAIL_PERMANENT',
        message: 'Workflow failed permanently after maximum retry attempts',
        finalStatus: 'FAILED'
      };
    }
  }

  private async handleRateLimitError(
    input: WorkflowInput,
    error: WorkflowError,
    context: WorkflowErrorContext
  ): Promise<RecoveryAction> {
    // Parse rate limit information from error
    const rateLimitInfo = this.parseRateLimitError(error);
    const waitTime = rateLimitInfo.resetTime || 60000; // Default 1 minute
    
    // Update job status to rate limited
    await this.updateJobStatus(input.jobId, 'RATE_LIMITED', {
      reason: 'API rate limit exceeded',
      estimatedResumption: new Date(Date.now() + waitTime).toISOString()
    });
    
    // Schedule resume after rate limit resets
    await this.scheduleWorkflowRetry(input, waitTime, context.failedState);
    
    return {
      action: 'PAUSE_FOR_RATE_LIMIT',
      delay: waitTime,
      message: `Workflow paused due to rate limit. Will resume in ${Math.round(waitTime / 1000)} seconds`,
      resumeTime: new Date(Date.now() + waitTime).toISOString()
    };
  }

  private async handleResourceError(
    input: WorkflowInput,
    error: WorkflowError,
    context: WorkflowErrorContext
  ): Promise<RecoveryAction> {
    // Check if resources are available for retry
    const resourceAvailability = await this.checkResourceAvailability();
    
    if (resourceAvailability.available) {
      // Resources are available, retry immediately
      await this.scheduleWorkflowRetry(input, 0, context.failedState);
      
      return {
        action: 'RETRY_IMMEDIATE',
        message: 'Resources available, retrying immediately'
      };
    } else {
      // Wait for resources to become available
      const estimatedWait = resourceAvailability.estimatedWaitTime || 300000; // 5 minutes default
      
      await this.updateJobStatus(input.jobId, 'QUEUED', {
        reason: 'Waiting for available resources',
        estimatedResumption: new Date(Date.now() + estimatedWait).toISOString()
      });
      
      await this.scheduleWorkflowRetry(input, estimatedWait, context.failedState);
      
      return {
        action: 'WAIT_FOR_RESOURCES',
        delay: estimatedWait,
        message: `Waiting for resources. Estimated wait time: ${Math.round(estimatedWait / 60000)} minutes`
      };
    }
  }

  private async scheduleWorkflowRetry(
    input: WorkflowInput,
    delay: number,
    resumeFromState?: string
  ): Promise<void> {
    if (delay === 0) {
      // Immediate retry
      await this.startRetryWorkflow(input, resumeFromState);
    } else {
      // Scheduled retry using CloudWatch Events
      const retryTime = new Date(Date.now() + delay);
      
      await this.cloudWatchEvents.putRule({
        Name: `retry-workflow-${input.jobId}-${Date.now()}`,
        ScheduleExpression: `at(${retryTime.toISOString()})`,
        State: 'ENABLED'
      }).promise();
      
      // Add target to trigger workflow restart
      await this.cloudWatchEvents.putTargets({
        Rule: `retry-workflow-${input.jobId}-${Date.now()}`,
        Targets: [{
          Id: '1',
          Arn: process.env.WORKFLOW_RETRY_LAMBDA_ARN!,
          Input: JSON.stringify({
            workflowInput: input,
            resumeFromState
          })
        }]
      }).promise();
    }
  }

  private classifyWorkflowError(error: WorkflowError): WorkflowErrorClassification {
    if (error.code.includes('RateLimit') || error.code.includes('TooManyRequests')) {
      return {
        category: 'RATE_LIMIT_ERROR',
        severity: 'RECOVERABLE',
        retryable: true
      };
    }
    
    if (error.code.includes('ServiceUnavailable') || error.code.includes('Timeout')) {
      return {
        category: 'TRANSIENT_ERROR',
        severity: 'RECOVERABLE',
        retryable: true
      };
    }
    
    if (error.code.includes('InsufficientCapacity') || error.code.includes('ResourceLimit')) {
      return {
        category: 'RESOURCE_ERROR',
        severity: 'RECOVERABLE',
        retryable: true
      };
    }
    
    if (error.code.includes('ValidationError') || error.code.includes('InvalidInput')) {
      return {
        category: 'DATA_ERROR',
        severity: 'PERMANENT',
        retryable: false
      };
    }
    
    return {
      category: 'SYSTEM_ERROR',
      severity: 'UNKNOWN',
      retryable: true
    };
  }
}
```

## 5. Performance & Monitoring

### Workflow Performance Monitoring
```typescript
class WorkflowPerformanceMonitor {
  private cloudWatch: AWS.CloudWatch;

  async publishWorkflowMetrics(
    executionArn: string,
    workflowResult: WorkflowOutput
  ): Promise<void> {
    const metrics: AWS.CloudWatch.MetricDatum[] = [
      {
        MetricName: 'WorkflowDuration',
        Value: workflowResult.processingTime / 1000, // Convert to seconds
        Unit: 'Seconds',
        Dimensions: [
          { Name: 'WorkflowStatus', Value: workflowResult.status },
          { Name: 'TargetLanguage', Value: this.extractLanguageFromArn(executionArn) }
        ]
      },
      {
        MetricName: 'ChunkSuccessRate',
        Value: (workflowResult.chunkSummary.successfulChunks / workflowResult.chunkSummary.totalChunks) * 100,
        Unit: 'Percent'
      },
      {
        MetricName: 'WorkflowCost',
        Value: workflowResult.totalCost,
        Unit: 'None'
      },
      {
        MetricName: 'AverageConfidence',
        Value: workflowResult.qualityMetrics.averageConfidence,
        Unit: 'Percent'
      }
    ];

    if (workflowResult.chunkSummary.totalChunks > 0) {
      metrics.push({
        MetricName: 'ChunksPerSecond',
        Value: workflowResult.chunkSummary.totalChunks / (workflowResult.processingTime / 1000),
        Unit: 'Count/Second'
      });
    }

    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/Workflow',
      MetricData: metrics
    }).promise();
  }

  async trackStateTransitions(
    executionArn: string,
    stateHistory: StateHistoryEntry[]
  ): Promise<void> {
    for (const entry of stateHistory) {
      if (entry.duration) {
        await this.cloudWatch.putMetricData({
          Namespace: 'TranslationService/Workflow/States',
          MetricData: [{
            MetricName: 'StateDuration',
            Value: entry.duration / 1000, // Convert to seconds
            Unit: 'Seconds',
            Dimensions: [
              { Name: 'StateName', Value: entry.stateName },
              { Name: 'StateType', Value: entry.type }
            ]
          }]
        }).promise();
      }
    }
  }

  async generateWorkflowReport(
    startDate: string,
    endDate: string
  ): Promise<WorkflowPerformanceReport> {
    const executions = await this.getExecutionsInDateRange(startDate, endDate);
    
    const report: WorkflowPerformanceReport = {
      reportPeriod: { startDate, endDate },
      totalExecutions: executions.length,
      successfulExecutions: executions.filter(e => e.status === 'SUCCEEDED').length,
      failedExecutions: executions.filter(e => e.status === 'FAILED').length,
      averageExecutionTime: this.calculateAverageExecutionTime(executions),
      throughputMetrics: {
        documentsPerHour: this.calculateDocumentsPerHour(executions),
        averageChunksPerDocument: this.calculateAverageChunksPerDocument(executions),
        peakProcessingHours: this.identifyPeakHours(executions)
      },
      costAnalysis: {
        totalCost: this.calculateTotalCost(executions),
        averageCostPerDocument: this.calculateAverageCostPerDocument(executions),
        costTrends: this.analyzeCostTrends(executions)
      },
      errorAnalysis: {
        errorsByState: this.analyzeErrorsByState(executions),
        retrySuccessRate: this.calculateRetrySuccessRate(executions),
        topErrorCodes: this.getTopErrorCodes(executions)
      },
      recommendations: this.generateOptimizationRecommendations(executions)
    };

    return report;
  }

  private generateOptimizationRecommendations(executions: WorkflowExecution[]): string[] {
    const recommendations: string[] = [];
    
    // Analyze failure patterns
    const failureRate = executions.filter(e => e.status === 'FAILED').length / executions.length;
    if (failureRate > 0.05) { // 5% failure rate threshold
      recommendations.push('High failure rate detected. Review error handling and retry strategies.');
    }
    
    // Analyze processing times
    const avgTime = this.calculateAverageExecutionTime(executions);
    const slowExecutions = executions.filter(e => e.duration && e.duration > avgTime * 2);
    if (slowExecutions.length > executions.length * 0.1) {
      recommendations.push('Significant number of slow executions. Consider optimizing parallel processing.');
    }
    
    // Analyze cost efficiency
    const avgCostPerChunk = this.calculateAverageCostPerChunk(executions);
    if (avgCostPerChunk > 0.05) { // $0.05 per chunk threshold
      recommendations.push('High cost per chunk detected. Review chunk sizing and API usage optimization.');
    }
    
    // Analyze retry patterns
    const highRetryRate = executions.filter(e => e.retryCount > 2).length / executions.length;
    if (highRetryRate > 0.15) { // 15% high retry rate threshold
      recommendations.push('High retry rate indicates systemic issues. Review rate limiting and error classification.');
    }
    
    return recommendations;
  }
}
```

## 6. Implementation Examples

### Lambda Functions for Workflow Steps
```typescript
// Chunk Document Lambda Handler
export const chunkDocumentHandler = async (event: any): Promise<any> => {
  try {
    const { documentId, targetLanguage, chunkSize = 3500, overlapSize = 250 } = event;
    
    const chunkingService = new DocumentChunkingService();
    const result = await chunkingService.chunkDocument({
      documentId,
      content: await getDocumentContent(documentId),
      targetLanguage,
      chunkSize,
      overlapSize
    });
    
    return {
      totalChunks: result.totalChunks,
      estimatedTokens: result.estimatedTokens,
      chunks: result.chunks,
      metadata: result.metadata
    };
    
  } catch (error) {
    console.error('Chunking failed:', error);
    throw new WorkflowError('CHUNKING_FAILED', error.message);
  }
};

// Translate Chunk Lambda Handler
export const translateChunkHandler = async (event: any): Promise<any> => {
  try {
    const { chunkId, content, targetLanguage, contextWindow } = event;
    
    const geminiService = new GeminiAPIClient(getGeminiConfig());
    const result = await geminiService.translateChunk({
      chunkId,
      content,
      targetLanguage,
      contextWindow
    });
    
    // Update chunk status
    await updateChunkStatus(chunkId, 'COMPLETED', result);
    
    return {
      chunkId: result.chunkId,
      status: 'SUCCESS',
      translatedContent: result.translatedContent,
      confidence: result.confidence,
      tokenUsage: result.tokenUsage,
      processingTime: result.processingTime
    };
    
  } catch (error) {
    console.error('Translation failed:', error);
    
    // Update chunk status to failed
    await updateChunkStatus(event.chunkId, 'FAILED', { error: error.message });
    
    // Determine if error is retryable
    const isRetryable = error instanceof RateLimitError || error instanceof ServiceUnavailableError;
    
    if (isRetryable) {
      throw new RetryableError(error.message, error.code);
    } else {
      throw new PermanentError(error.message, error.code);
    }
  }
};

// Aggregate Results Lambda Handler
export const aggregateResultsHandler = async (event: any): Promise<any> => {
  try {
    const { jobId, translationResults } = event;
    
    const aggregator = new ResultsAggregator();
    const aggregation = await aggregator.aggregateTranslationResults(jobId, translationResults);
    
    return {
      totalChunks: aggregation.totalChunks,
      successfulChunks: aggregation.successfulChunks,
      failedChunks: aggregation.failedChunks,
      successRate: aggregation.successRate,
      totalCost: aggregation.totalCost,
      totalProcessingTime: aggregation.totalProcessingTime,
      averageConfidence: aggregation.averageConfidence,
      qualityMetrics: aggregation.qualityMetrics
    };
    
  } catch (error) {
    console.error('Result aggregation failed:', error);
    throw new WorkflowError('AGGREGATION_FAILED', error.message);
  }
};

// Assemble Document Lambda Handler  
export const assembleDocumentHandler = async (event: any): Promise<any> => {
  try {
    const { jobId, translatedChunks, originalFormat, preserveFormatting } = event;
    
    const assembler = new DocumentAssembler();
    const result = await assembler.assembleTranslatedDocument({
      jobId,
      translatedChunks,
      originalFormat,
      preserveFormatting
    });
    
    return {
      documentUrl: result.documentUrl,
      wordCount: result.wordCount,
      format: result.format,
      assemblyTime: result.processingTime
    };
    
  } catch (error) {
    console.error('Document assembly failed:', error);
    throw new WorkflowError('ASSEMBLY_FAILED', error.message);
  }
};
```

### Workflow Starter Integration
```typescript
export class WorkflowStarter {
  private orchestrator: TranslationWorkflowOrchestrator;
  private jobService: TranslationJobService;

  constructor() {
    this.orchestrator = new TranslationWorkflowOrchestrator();
    this.jobService = new TranslationJobService();
  }

  async startTranslationJob(request: CreateJobRequest): Promise<CreateJobResponse> {
    // Create job record first
    const jobResponse = await this.jobService.createJob(request);
    
    try {
      // Start Step Functions workflow
      const workflowResponse = await this.orchestrator.startTranslationWorkflow({
        jobId: jobResponse.jobId,
        documentId: request.documentId,
        userId: request.userId,
        targetLanguage: request.targetLanguage,
        documentMetadata: request.documentMetadata,
        translationOptions: request.translationOptions || {
          preserveFormatting: true,
          qualityLevel: 'STANDARD'
        },
        priority: request.priority
      });
      
      // Update job with workflow execution ARN
      await this.jobService.updateJobMetadata(jobResponse.jobId, {
        workflowExecutionArn: workflowResponse.executionArn,
        workflowStarted: true
      });
      
      return {
        ...jobResponse,
        workflowExecutionArn: workflowResponse.executionArn
      };
      
    } catch (error) {
      // Mark job as failed if workflow failed to start
      await this.jobService.updateJobStatus(jobResponse.jobId, 'FAILED', {
        reason: 'Failed to start workflow',
        error: error.message
      });
      
      throw error;
    }
  }

  async pauseTranslationJob(jobId: string, userId: string): Promise<void> {
    // Get job details
    const job = await this.jobService.getJobDetails(jobId);
    
    if (job.userId !== userId) {
      throw new Error('Unauthorized to pause this job');
    }
    
    if (!job.metadata.workflowExecutionArn) {
      throw new Error('No active workflow found for this job');
    }
    
    // Stop the workflow
    await this.orchestrator.stopWorkflowExecution(job.metadata.workflowExecutionArn, {
      cause: 'User requested pause'
    });
    
    // Update job status
    await this.jobService.updateJobStatus(jobId, 'PAUSED', {
      reason: 'User requested pause',
      pausedAt: new Date().toISOString()
    });
  }

  async resumeTranslationJob(jobId: string, userId: string): Promise<void> {
    // Get job details
    const job = await this.jobService.getJobDetails(jobId);
    
    if (job.userId !== userId) {
      throw new Error('Unauthorized to resume this job');
    }
    
    if (job.status !== 'PAUSED') {
      throw new Error('Job is not in paused state');
    }
    
    // Determine resume point based on job progress
    const resumeState = this.determineResumeState(job);
    
    // Start new workflow execution from resume point
    const workflowResponse = await this.orchestrator.resumeWorkflowFromFailure(
      jobId,
      resumeState,
      {
        resumeFromPause: true,
        originalExecutionArn: job.metadata.workflowExecutionArn
      }
    );
    
    // Update job status and workflow ARN
    await this.jobService.updateJobStatus(jobId, 'RESUMING', {
      reason: 'User requested resume',
      newWorkflowExecutionArn: workflowResponse.executionArn,
      resumedAt: new Date().toISOString()
    });
  }

  private determineResumeState(job: JobDetailsResponse): string {
    // Determine where to resume based on current job state and progress
    if (job.status === 'PAUSED') {
      if (job.progress.chunksCompleted === 0) {
        return 'ChunkDocument';
      } else if (job.progress.chunksCompleted < job.progress.totalChunks) {
        return 'ProcessChunksParallel';
      } else {
        return 'AssembleDocument';
      }
    }
    
    return 'ValidateInput'; // Default to start
  }
}
```

## 7. Testing Strategy

### Workflow Integration Testing
```typescript
describe('Translation Workflow Integration', () => {
  let orchestrator: TranslationWorkflowOrchestrator;
  let mockStepFunctions: jest.Mocked<AWS.StepFunctions>;

  beforeEach(() => {
    mockStepFunctions = {
      startExecution: jest.fn(),
      describeExecution: jest.fn(),
      stopExecution: jest.fn(),
      getExecutionHistory: jest.fn()
    } as any;

    orchestrator = new TranslationWorkflowOrchestrator();
    (orchestrator as any).stepFunctions = mockStepFunctions;
  });

  it('starts workflow successfully', async () => {
    const mockExecutionArn = 'arn:aws:states:us-east-1:123456789012:execution:test:12345';
    
    mockStepFunctions.startExecution.mockReturnValue({
      promise: jest.fn().mockResolvedValue({
        executionArn: mockExecutionArn,
        startDate: new Date()
      })
    } as any);

    const request: StartTranslationWorkflowRequest = {
      jobId: 'test-job-123',
      documentId: 'doc-456',
      userId: 'user-789',
      targetLanguage: 'spanish',
      documentMetadata: {
        filename: 'test.txt',
        wordCount: 10000,
        fileSize: 50000,
        contentHash: 'hash123'
      },
      translationOptions: {
        preserveFormatting: true,
        qualityLevel: 'STANDARD'
      },
      priority: 'NORMAL'
    };

    const result = await orchestrator.startTranslationWorkflow(request);

    expect(result.executionArn).toBe(mockExecutionArn);
    expect(result.status).toBe('RUNNING');
    expect(mockStepFunctions.startExecution).toHaveBeenCalledWith(
      expect.objectContaining({
        stateMachineArn: expect.any(String),
        input: expect.stringContaining('test-job-123')
      })
    );
  });

  it('handles workflow start failure', async () => {
    mockStepFunctions.startExecution.mockReturnValue({
      promise: jest.fn().mockRejectedValue(new Error('Failed to start execution'))
    } as any);

    const request: StartTranslationWorkflowRequest = createTestWorkflowRequest();

    await expect(orchestrator.startTranslationWorkflow(request))
      .rejects.toThrow(WorkflowError);
  });

  it('retrieves workflow execution details', async () => {
    const mockExecution = {
      executionArn: 'test-arn',
      stateMachineArn: 'test-sm-arn',
      name: 'test-execution',
      status: 'RUNNING',
      startDate: new Date(),
      input: JSON.stringify({ jobId: 'test-job' })
    };

    const mockHistory = {
      events: [
        {
          timestamp: new Date(),
          type: 'ExecutionStarted',
          id: 1
        }
      ]
    };

    mockStepFunctions.describeExecution.mockReturnValue({
      promise: jest.fn().mockResolvedValue(mockExecution)
    } as any);

    mockStepFunctions.getExecutionHistory.mockReturnValue({
      promise: jest.fn().mockResolvedValue(mockHistory)
    } as any);

    const result = await orchestrator.getWorkflowExecution('test-arn');

    expect(result.executionArn).toBe('test-arn');
    expect(result.status).toBe('RUNNING');
    expect(result.stateHistory).toHaveLength(1);
  });
});

describe('Workflow Error Recovery', () => {
  let errorRecovery: WorkflowErrorRecovery;

  beforeEach(() => {
    errorRecovery = new WorkflowErrorRecovery();
  });

  it('handles transient errors with retry', async () => {
    const error: WorkflowError = {
      code: 'ServiceUnavailable',
      message: 'Service temporarily unavailable'
    };

    const context: WorkflowErrorContext = {
      executionArn: 'test-arn',
      failedState: 'TranslateChunk',
      retryCount: 0
    };

    const result = await errorRecovery.handleWorkflowError('test-arn', error, context);

    expect(result.action).toBe('RETRY_DELAYED');
    expect(result.delay).toBeGreaterThan(0);
    expect(result.retryCount).toBe(1);
  });

  it('handles rate limit errors with appropriate delay', async () => {
    const error: WorkflowError = {
      code: 'RateLimitExceeded',
      message: 'Rate limit exceeded'
    };

    const context: WorkflowErrorContext = {
      executionArn: 'test-arn',
      failedState: 'TranslateChunk',
      retryCount: 0
    };

    const result = await errorRecovery.handleWorkflowError('test-arn', error, context);

    expect(result.action).toBe('PAUSE_FOR_RATE_LIMIT');
    expect(result.delay).toBeGreaterThanOrEqual(60000); // At least 1 minute
  });

  it('fails permanently after max retries', async () => {
    const error: WorkflowError = {
      code: 'ServiceUnavailable',
      message: 'Service unavailable'
    };

    const context: WorkflowErrorContext = {
      executionArn: 'test-arn',
      failedState: 'TranslateChunk',
      retryCount: 3 // Already at max retries
    };

    const result = await errorRecovery.handleWorkflowError('test-arn', error, context);

    expect(result.action).toBe('FAIL_PERMANENT');
    expect(result.finalStatus).toBe('FAILED');
  });
});

function createTestWorkflowRequest(): StartTranslationWorkflowRequest {
  return {
    jobId: 'test-job-123',
    documentId: 'doc-456',
    userId: 'user-789',
    targetLanguage: 'spanish',
    documentMetadata: {
      filename: 'test.txt',
      wordCount: 10000,
      fileSize: 50000,
      contentHash: 'hash123'
    },
    translationOptions: {
      preserveFormatting: true,
      qualityLevel: 'STANDARD'
    },
    priority: 'NORMAL'
  };
}
```

## 8. Configuration & Deployment

### CloudFormation Template for Step Functions
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Step Functions Workflow Infrastructure'

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, staging, prod]

Resources:
  # IAM Role for Step Functions
  StepFunctionsRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: states.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: StepFunctionsExecutionPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - lambda:InvokeFunction
                Resource: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:*'
              - Effect: Allow
                Action:
                  - dynamodb:GetItem
                  - dynamodb:PutItem
                  - dynamodb:UpdateItem
                  - dynamodb:Query
                Resource: 
                  - !Sub 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/*'
              - Effect: Allow
                Action:
                  - events:PutEvents
                Resource: !Sub 'arn:aws:events:${AWS::Region}:${AWS::AccountId}:event-bus/default'

  # Main Translation State Machine
  TranslationStateMachine:
    Type: AWS::StepFunctions::StateMachine
    Properties:
      StateMachineName: !Sub 'translation-workflow-${Environment}'
      RoleArn: !GetAtt StepFunctionsRole.Arn
      DefinitionString: !Sub |
        {
          "Comment": "Long-Form Translation Service Workflow",
          "StartAt": "ValidateInput",
          "States": {
            "ValidateInput": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:validate-workflow-input-${Environment}",
              "Next": "CheckLegalAttestation",
              "Catch": [
                {
                  "ErrorEquals": ["ValidationError"],
                  "Next": "HandleValidationError"
                }
              ]
            },
            "CheckLegalAttestation": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:check-legal-attestation-${Environment}",
              "Next": "ChunkDocument",
              "Retry": [
                {
                  "ErrorEquals": ["States.TaskFailed"],
                  "IntervalSeconds": 2,
                  "MaxAttempts": 3,
                  "BackoffRate": 2.0
                }
              ]
            },
            "ChunkDocument": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:chunk-document-${Environment}",
              "Next": "ProcessChunksParallel",
              "Retry": [
                {
                  "ErrorEquals": ["States.TaskFailed"],
                  "IntervalSeconds": 5,
                  "MaxAttempts": 3,
                  "BackoffRate": 2.0
                }
              ]
            },
            "ProcessChunksParallel": {
              "Type": "Map",
              "ItemsPath": "$.chunks",
              "MaxConcurrency": 5,
              "Iterator": {
                "StartAt": "TranslateChunk",
                "States": {
                  "TranslateChunk": {
                    "Type": "Task",
                    "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:translate-chunk-${Environment}",
                    "End": true,
                    "Retry": [
                      {
                        "ErrorEquals": ["RateLimitError"],
                        "IntervalSeconds": 60,
                        "MaxAttempts": 5,
                        "BackoffRate": 2.0
                      }
                    ]
                  }
                }
              },
              "Next": "AssembleDocument"
            },
            "AssembleDocument": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:assemble-document-${Environment}",
              "End": true
            },
            "HandleValidationError": {
              "Type": "Fail",
              "Cause": "Validation failed"
            }
          }
        }
      LoggingConfiguration:
        Level: ALL
        IncludeExecutionData: true
        Destinations:
          - CloudWatchLogsLogGroup:
              LogGroupArn: !GetAtt WorkflowLogGroup.Arn

  # CloudWatch Log Group for Step Functions
  WorkflowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/stepfunctions/translation-workflow-${Environment}'
      RetentionInDays: 30

  # CloudWatch Alarms
  WorkflowFailureAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub 'workflow-high-failure-rate-${Environment}'
      AlarmDescription: 'High failure rate in translation workflows'
      MetricName: ExecutionsFailed
      Namespace: AWS/States
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 2
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: StateMachineArn
          Value: !Ref TranslationStateMachine

  WorkflowDurationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub 'workflow-long-duration-${Environment}'
      AlarmDescription: 'Workflows taking too long to complete'
      MetricName: ExecutionTime
      Namespace: AWS/States
      Statistic: Average
      Period: 300
      EvaluationPeriods: 3
      Threshold: 1800000 # 30 minutes in milliseconds
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: StateMachineArn
          Value: !Ref TranslationStateMachine

Outputs:
  StateMachineArn:
    Description: 'ARN of the translation workflow state machine'
    Value: !Ref TranslationStateMachine
    Export:
      Name: !Sub '${AWS::StackName}-StateMachineArn'
      
  StateMachineName:
    Description: 'Name of the translation workflow state machine'
    Value: !GetAtt TranslationStateMachine.Name
    Export:
      Name: !Sub '${AWS::StackName}-StateMachineName'
```

---

This comprehensive Step Functions Workflow design provides robust orchestration of the entire translation process with built-in error handling, parallel processing capabilities, and comprehensive monitoring for the Long-Form Translation Service.