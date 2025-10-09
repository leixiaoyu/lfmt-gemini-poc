# Low-Level Design Document 9: Error Handling & Recovery

## 1. Component Overview & Responsibilities

The Error Handling & Recovery system provides comprehensive error management across all components of the Long-Form Translation Service. It implements centralized error classification, intelligent recovery strategies, circuit breaker patterns, and detailed error tracking while ensuring system resilience and maintaining service availability during failures.

**Key Responsibilities:**
- Centralized error classification and categorization
- Intelligent retry logic with exponential backoff
- Circuit breaker implementation for service protection
- Dead letter queue management and poison message handling
- Error correlation and root cause analysis
- Recovery workflow orchestration and failure escalation
- Error monitoring, alerting, and observability

**Why This Design:** Comprehensive error handling ensures system reliability, provides clear failure recovery paths, and maintains service availability. The centralized approach enables consistent error handling patterns across all components while providing detailed observability for troubleshooting and system optimization.

## 2. API Design & Interfaces

### Error Management Endpoints
```typescript
// POST /errors/report
interface ErrorReportRequest {
  errorId: string;
  component: string;
  errorCode: string;
  message: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  context: {
    jobId?: string;
    userId?: string;
    chunkId?: string;
    requestId?: string;
    timestamp: string;
    stackTrace?: string;
    additionalData?: Record<string, any>;
  };
  retryable: boolean;
  autoRecover: boolean;
}

interface ErrorReportResponse {
  errorId: string;
  acknowledged: boolean;
  recoveryAction: RecoveryAction;
  estimatedResolutionTime?: number;
  escalationLevel: number;
}

// GET /errors/{errorId}
interface ErrorDetailsResponse {
  errorId: string;
  component: string;
  errorCode: string;
  message: string;
  severity: string;
  status: ErrorStatus;
  context: ErrorContext;
  timeline: ErrorTimelineEntry[];
  recoveryAttempts: RecoveryAttempt[];
  relatedErrors: string[];
  resolution?: ErrorResolution;
}

// POST /errors/{errorId}/recover
interface RecoveryRequest {
  recoveryStrategy: 'RETRY' | 'SKIP' | 'MANUAL' | 'ROLLBACK';
  parameters?: Record<string, any>;
  triggeredBy: string;
}

interface RecoveryResponse {
  recoveryId: string;
  status: 'INITIATED' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  estimatedDuration: number;
  actions: RecoveryAction[];
}

// GET /errors/analytics
interface ErrorAnalyticsRequest {
  startDate: string;
  endDate: string;
  component?: string;
  severity?: string[];
  includeResolved?: boolean;
}

interface ErrorAnalyticsResponse {
  totalErrors: number;
  errorsByComponent: ComponentErrorStats[];
  errorsByCode: ErrorCodeStats[];
  errorTrends: ErrorTrendData[];
  meanTimeToResolution: number;
  recoverySuccessRate: number;
  topFailureReasons: FailureReason[];
  recommendations: string[];
}
```

### Error Classification System
```typescript
type ErrorCategory = 
  | 'NETWORK_ERROR'           // Connectivity, timeouts, DNS
  | 'API_ERROR'              // External API failures, rate limits
  | 'AUTHENTICATION_ERROR'   // Auth failures, token expiration
  | 'AUTHORIZATION_ERROR'    // Permission denied, access control
  | 'VALIDATION_ERROR'       // Input validation, schema violations
  | 'BUSINESS_LOGIC_ERROR'   // Domain rule violations
  | 'DATA_ERROR'            // Database errors, data corruption
  | 'RESOURCE_ERROR'        // Memory, disk, CPU limitations
  | 'CONFIGURATION_ERROR'   // Misconfiguration, missing settings
  | 'SYSTEM_ERROR'          // Infrastructure, platform failures
  | 'UNKNOWN_ERROR';        // Unclassified errors

type ErrorSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

type ErrorStatus = 
  | 'NEW'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'RECOVERING'
  | 'RECOVERED'
  | 'ESCALATED'
  | 'RESOLVED'
  | 'CLOSED';

interface ErrorClassification {
  category: ErrorCategory;
  severity: ErrorSeverity;
  retryable: boolean;
  autoRecoverable: boolean;
  escalationRequired: boolean;
  maxRetries: number;
  backoffStrategy: 'FIXED' | 'LINEAR' | 'EXPONENTIAL' | 'CUSTOM';
  circuitBreakerEligible: boolean;
}

interface RecoveryStrategy {
  type: 'IMMEDIATE_RETRY' | 'DELAYED_RETRY' | 'CIRCUIT_BREAKER' | 'FALLBACK' | 'ESCALATION' | 'MANUAL_INTERVENTION';
  parameters: {
    maxAttempts?: number;
    baseDelay?: number;
    maxDelay?: number;
    backoffMultiplier?: number;
    circuitBreakerThreshold?: number;
    fallbackAction?: string;
    escalationDelay?: number;
  };
}
```

## 3. Data Models & Storage

### DynamoDB Schema for Error Tracking
```typescript
// Primary Table: ErrorRecords
interface ErrorRecord {
  PK: string; // ERROR#{errorId}
  SK: string; // TIMESTAMP#{timestamp}
  errorId: string;
  component: string;
  errorCode: string;
  message: string;
  severity: ErrorSeverity;
  category: ErrorCategory;
  status: ErrorStatus;
  
  // Context information
  jobId?: string;
  userId?: string;
  chunkId?: string;
  requestId?: string;
  sessionId?: string;
  
  // Error details
  stackTrace?: string;
  errorData?: string; // JSON string with additional error data
  userAgent?: string;
  ipAddress?: string;
  
  // Classification
  retryable: boolean;
  autoRecoverable: boolean;
  maxRetries: number;
  currentRetries: number;
  
  // Timing
  firstOccurrence: string;
  lastOccurrence: string;
  occurrenceCount: number;
  
  // Recovery
  recoveryStrategy?: string;
  recoveryAttempts: number;
  lastRecoveryAttempt?: string;
  recoveredAt?: string;
  
  // Escalation
  escalationLevel: number;
  escalatedAt?: string;
  assignedTo?: string;
  
  // Resolution
  resolvedAt?: string;
  resolutionMethod?: string;
  resolutionNotes?: string;
  
  ttl?: number; // Retention period
}

// GSI: ErrorsByComponent
interface ErrorsByComponent {
  GSI1PK: string; // COMPONENT#{component}
  GSI1SK: string; // SEVERITY#{severity}#TIMESTAMP#{timestamp}
  errorId: string;
  errorCode: string;
  status: ErrorStatus;
  severity: ErrorSeverity;
  firstOccurrence: string;
}

// GSI: ErrorsByJob
interface ErrorsByJob {
  GSI2PK: string; // JOB#{jobId}
  GSI2SK: string; // TIMESTAMP#{timestamp}
  errorId: string;
  component: string;
  errorCode: string;
  severity: ErrorSeverity;
  status: ErrorStatus;
}

// GSI: ErrorsByStatus
interface ErrorsByStatus {
  GSI3PK: string; // STATUS#{status}
  GSI3SK: string; // SEVERITY#{severity}#TIMESTAMP#{timestamp}
  errorId: string;
  component: string;
  errorCode: string;
  assignedTo?: string;
}

// Recovery Attempts Table
interface RecoveryAttemptRecord {
  PK: string; // ERROR#{errorId}
  SK: string; // RECOVERY#{attemptNumber}#{timestamp}
  errorId: string;
  attemptNumber: number;
  recoveryStrategy: string;
  startedAt: string;
  completedAt?: string;
  status: 'INITIATED' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  result?: {
    success: boolean;
    message?: string;
    nextAction?: string;
  };
  triggeredBy: string; // SYSTEM or user ID
  parameters?: string; // JSON string
  duration?: number; // milliseconds
}
```

### Circuit Breaker State Storage
```typescript
interface CircuitBreakerState {
  serviceName: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failureCount: number;
  successCount: number;
  lastFailureTime: number;
  lastSuccessTime: number;
  
  // Configuration
  failureThreshold: number;
  successThreshold: number;
  timeout: number; // milliseconds
  
  // Metrics
  totalRequests: number;
  totalFailures: number;
  totalSuccesses: number;
  avgResponseTime: number;
  
  // Window data for rolling calculations
  requestWindow: RequestWindowEntry[];
  windowSizeMs: number;
}

interface RequestWindowEntry {
  timestamp: number;
  success: boolean;
  responseTime: number;
  errorCode?: string;
}
```

## 4. Core Error Handling Logic

### Centralized Error Handler
```typescript
class CentralizedErrorHandler {
  private errorClassifier: ErrorClassifier;
  private recoveryOrchestrator: RecoveryOrchestrator;
  private circuitBreakerManager: CircuitBreakerManager;
  private deadLetterHandler: DeadLetterHandler;
  private errorMetrics: ErrorMetricsCollector;

  constructor() {
    this.errorClassifier = new ErrorClassifier();
    this.recoveryOrchestrator = new RecoveryOrchestrator();
    this.circuitBreakerManager = new CircuitBreakerManager();
    this.deadLetterHandler = new DeadLetterHandler();
    this.errorMetrics = new ErrorMetricsCollector();
  }

  async handleError(
    error: Error,
    context: ErrorContext,
    component: string
  ): Promise<ErrorHandlingResult> {
    const errorId = this.generateErrorId();
    const timestamp = new Date().toISOString();

    try {
      // Classify the error
      const classification = await this.errorClassifier.classifyError(error, context);
      
      // Check if this is a duplicate/recurring error
      const existingError = await this.checkForDuplicateError(error, context, component);
      
      let errorRecord: ErrorRecord;
      
      if (existingError) {
        // Update existing error record
        errorRecord = await this.updateExistingError(existingError, timestamp);
      } else {
        // Create new error record
        errorRecord = await this.createNewErrorRecord(
          errorId,
          error,
          context,
          component,
          classification,
          timestamp
        );
      }

      // Determine recovery strategy
      const recoveryStrategy = this.determineRecoveryStrategy(classification, errorRecord);
      
      // Update circuit breaker state
      await this.circuitBreakerManager.recordFailure(component, error);
      
      // Publish error metrics
      await this.errorMetrics.recordError(errorRecord, classification);
      
      // Execute recovery if applicable
      let recoveryResult: RecoveryResult | undefined;
      if (recoveryStrategy.type !== 'MANUAL_INTERVENTION') {
        recoveryResult = await this.recoveryOrchestrator.executeRecovery(
          errorRecord,
          recoveryStrategy,
          context
        );
      }
      
      // Check for escalation
      await this.checkEscalationCriteria(errorRecord, classification);
      
      return {
        errorId: errorRecord.errorId,
        classification,
        recoveryStrategy,
        recoveryResult,
        shouldRetry: this.shouldRetry(errorRecord, classification),
        nextAction: this.determineNextAction(errorRecord, recoveryResult)
      };

    } catch (handlingError) {
      // Error in error handling - this is critical
      console.error('Error in error handling:', handlingError);
      
      // Fall back to basic error logging
      await this.fallbackErrorLogging(error, context, component, handlingError);
      
      return {
        errorId,
        classification: {
          category: 'SYSTEM_ERROR',
          severity: 'CRITICAL',
          retryable: false,
          autoRecoverable: false,
          escalationRequired: true,
          maxRetries: 0,
          backoffStrategy: 'FIXED',
          circuitBreakerEligible: false
        },
        recoveryStrategy: { type: 'MANUAL_INTERVENTION', parameters: {} },
        shouldRetry: false,
        nextAction: 'ESCALATE_IMMEDIATELY'
      };
    }
  }

  private async createNewErrorRecord(
    errorId: string,
    error: Error,
    context: ErrorContext,
    component: string,
    classification: ErrorClassification,
    timestamp: string
  ): Promise<ErrorRecord> {
    const errorRecord: ErrorRecord = {
      PK: `ERROR#${errorId}`,
      SK: `TIMESTAMP#${timestamp}`,
      errorId,
      component,
      errorCode: this.extractErrorCode(error),
      message: error.message,
      severity: classification.severity,
      category: classification.category,
      status: 'NEW',
      
      // Context
      jobId: context.jobId,
      userId: context.userId,
      chunkId: context.chunkId,
      requestId: context.requestId,
      sessionId: context.sessionId,
      
      // Error details
      stackTrace: error.stack,
      errorData: JSON.stringify(context.additionalData || {}),
      
      // Classification
      retryable: classification.retryable,
      autoRecoverable: classification.autoRecoverable,
      maxRetries: classification.maxRetries,
      currentRetries: 0,
      
      // Timing
      firstOccurrence: timestamp,
      lastOccurrence: timestamp,
      occurrenceCount: 1,
      
      // Recovery
      recoveryAttempts: 0,
      
      // Escalation
      escalationLevel: 0,
      
      ttl: this.calculateTTL(classification.severity)
    };

    await this.dynamoClient.put({
      TableName: process.env.ERRORS_TABLE!,
      Item: errorRecord
    }).promise();

    // Create GSI records
    await this.createGSIRecords(errorRecord);

    return errorRecord;
  }

  private async updateExistingError(
    existingError: ErrorRecord,
    timestamp: string
  ): Promise<ErrorRecord> {
    const updateParams = {
      TableName: process.env.ERRORS_TABLE!,
      Key: { PK: existingError.PK, SK: existingError.SK },
      UpdateExpression: 'SET #lastOccurrence = :timestamp, #occurrenceCount = #occurrenceCount + :inc, #status = :status',
      ExpressionAttributeNames: {
        '#lastOccurrence': 'lastOccurrence',
        '#occurrenceCount': 'occurrenceCount',
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':timestamp': timestamp,
        ':inc': 1,
        ':status': 'ACKNOWLEDGED'
      },
      ReturnValues: 'ALL_NEW'
    };

    const result = await this.dynamoClient.update(updateParams).promise();
    return result.Attributes as ErrorRecord;
  }

  private determineRecoveryStrategy(
    classification: ErrorClassification,
    errorRecord: ErrorRecord
  ): RecoveryStrategy {
    // Check if retries exhausted
    if (errorRecord.currentRetries >= classification.maxRetries) {
      if (classification.escalationRequired) {
        return { type: 'ESCALATION', parameters: {} };
      }
      return { type: 'MANUAL_INTERVENTION', parameters: {} };
    }

    // Check circuit breaker status
    if (classification.circuitBreakerEligible) {
      const cbState = this.circuitBreakerManager.getState(errorRecord.component);
      if (cbState === 'OPEN') {
        return { type: 'CIRCUIT_BREAKER', parameters: { waitTime: 60000 } };
      }
    }

    // Determine retry strategy based on classification
    if (classification.retryable) {
      const delay = this.calculateRetryDelay(
        errorRecord.currentRetries,
        classification.backoffStrategy
      );
      
      if (delay === 0) {
        return { type: 'IMMEDIATE_RETRY', parameters: {} };
      } else {
        return {
          type: 'DELAYED_RETRY',
          parameters: {
            delay,
            maxAttempts: classification.maxRetries
          }
        };
      }
    }

    // Non-retryable errors
    if (classification.autoRecoverable) {
      return { type: 'FALLBACK', parameters: {} };
    }

    return { type: 'MANUAL_INTERVENTION', parameters: {} };
  }

  private calculateRetryDelay(
    attemptNumber: number,
    strategy: string,
    baseDelay: number = 1000
  ): number {
    switch (strategy) {
      case 'FIXED':
        return baseDelay;
      
      case 'LINEAR':
        return baseDelay * (attemptNumber + 1);
      
      case 'EXPONENTIAL':
        return baseDelay * Math.pow(2, attemptNumber);
      
      case 'CUSTOM':
        // Custom jittered exponential backoff
        const exponentialDelay = baseDelay * Math.pow(2, attemptNumber);
        const jitter = Math.random() * 0.1 * exponentialDelay;
        return Math.min(exponentialDelay + jitter, 300000); // Max 5 minutes
      
      default:
        return baseDelay;
    }
  }

  private shouldRetry(
    errorRecord: ErrorRecord,
    classification: ErrorClassification
  ): boolean {
    return (
      classification.retryable &&
      errorRecord.currentRetries < classification.maxRetries &&
      errorRecord.status !== 'ESCALATED'
    );
  }

  private async checkEscalationCriteria(
    errorRecord: ErrorRecord,
    classification: ErrorClassification
  ): Promise<void> {
    let shouldEscalate = false;
    let escalationReason = '';

    // Critical severity always escalates
    if (classification.severity === 'CRITICAL') {
      shouldEscalate = true;
      escalationReason = 'Critical severity error';
    }

    // High frequency of same error
    if (errorRecord.occurrenceCount >= 5) {
      shouldEscalate = true;
      escalationReason = 'High frequency error pattern';
    }

    // Retries exhausted on important components
    if (errorRecord.currentRetries >= classification.maxRetries && 
        ['gemini-api', 'job-management', 'legal-attestation'].includes(errorRecord.component)) {
      shouldEscalate = true;
      escalationReason = 'Retries exhausted on critical component';
    }

    // Error affecting multiple jobs
    const relatedErrors = await this.findRelatedErrors(errorRecord, '1 hour');
    if (relatedErrors.length >= 3) {
      shouldEscalate = true;
      escalationReason = 'Error affecting multiple operations';
    }

    if (shouldEscalate) {
      await this.escalateError(errorRecord, escalationReason);
    }
  }

  private async escalateError(errorRecord: ErrorRecord, reason: string): Promise<void> {
    // Update error record
    await this.dynamoClient.update({
      TableName: process.env.ERRORS_TABLE!,
      Key: { PK: errorRecord.PK, SK: errorRecord.SK },
      UpdateExpression: 'SET #status = :status, #escalationLevel = #escalationLevel + :inc, #escalatedAt = :timestamp',
      ExpressionAttributeNames: {
        '#status': 'status',
        '#escalationLevel': 'escalationLevel',
        '#escalatedAt': 'escalatedAt'
      },
      ExpressionAttributeValues: {
        ':status': 'ESCALATED',
        ':inc': 1,
        ':timestamp': new Date().toISOString()
      }
    }).promise();

    // Create escalation ticket
    await this.createEscalationTicket(errorRecord, reason);

    // Send alerts
    await this.sendEscalationAlert(errorRecord, reason);
  }
}
```

### Circuit Breaker Implementation
```typescript
class CircuitBreakerManager {
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private defaultConfig: CircuitBreakerConfig = {
    failureThreshold: 5,
    successThreshold: 3,
    timeout: 60000, // 1 minute
    windowSizeMs: 60000
  };

  getCircuitBreaker(serviceName: string, config?: Partial<CircuitBreakerConfig>): CircuitBreaker {
    if (!this.circuitBreakers.has(serviceName)) {
      const cbConfig = { ...this.defaultConfig, ...config };
      this.circuitBreakers.set(serviceName, new CircuitBreaker(serviceName, cbConfig));
    }
    return this.circuitBreakers.get(serviceName)!;
  }

  async recordFailure(serviceName: string, error: Error): Promise<void> {
    const circuitBreaker = this.getCircuitBreaker(serviceName);
    await circuitBreaker.recordFailure(error);
  }

  async recordSuccess(serviceName: string, responseTime: number): Promise<void> {
    const circuitBreaker = this.getCircuitBreaker(serviceName);
    await circuitBreaker.recordSuccess(responseTime);
  }

  isOpen(serviceName: string): boolean {
    const circuitBreaker = this.circuitBreakers.get(serviceName);
    return circuitBreaker ? circuitBreaker.isOpen() : false;
  }

  getState(serviceName: string): 'CLOSED' | 'OPEN' | 'HALF_OPEN' {
    const circuitBreaker = this.circuitBreakers.get(serviceName);
    return circuitBreaker ? circuitBreaker.getState() : 'CLOSED';
  }
}

class CircuitBreaker {
  private state: CircuitBreakerState;
  private config: CircuitBreakerConfig;

  constructor(serviceName: string, config: CircuitBreakerConfig) {
    this.config = config;
    this.state = {
      serviceName,
      state: 'CLOSED',
      failureCount: 0,
      successCount: 0,
      lastFailureTime: 0,
      lastSuccessTime: 0,
      
      failureThreshold: config.failureThreshold,
      successThreshold: config.successThreshold,
      timeout: config.timeout,
      
      totalRequests: 0,
      totalFailures: 0,
      totalSuccesses: 0,
      avgResponseTime: 0,
      
      requestWindow: [],
      windowSizeMs: config.windowSizeMs
    };
  }

  async recordFailure(error: Error): Promise<void> {
    const now = Date.now();
    
    this.cleanupWindow(now);
    this.state.requestWindow.push({
      timestamp: now,
      success: false,
      responseTime: 0,
      errorCode: error.name
    });

    this.state.failureCount++;
    this.state.totalFailures++;
    this.state.totalRequests++;
    this.state.lastFailureTime = now;

    // Check if we need to open the circuit
    if (this.state.state === 'CLOSED' && this.shouldOpen()) {
      await this.openCircuit();
    } else if (this.state.state === 'HALF_OPEN') {
      // Any failure in half-open state reopens the circuit
      await this.openCircuit();
    }

    await this.persistState();
  }

  async recordSuccess(responseTime: number): Promise<void> {
    const now = Date.now();
    
    this.cleanupWindow(now);
    this.state.requestWindow.push({
      timestamp: now,
      success: true,
      responseTime
    });

    this.state.successCount++;
    this.state.totalSuccesses++;
    this.state.totalRequests++;
    this.state.lastSuccessTime = now;
    
    // Update average response time
    this.updateAverageResponseTime(responseTime);

    // Check if we can close the circuit
    if (this.state.state === 'HALF_OPEN' && this.shouldClose()) {
      await this.closeCircuit();
    }

    await this.persistState();
  }

  isOpen(): boolean {
    // Check if circuit should transition from OPEN to HALF_OPEN
    if (this.state.state === 'OPEN' && this.shouldTryHalfOpen()) {
      this.state.state = 'HALF_OPEN';
      this.state.successCount = 0;
      this.state.failureCount = 0;
    }

    return this.state.state === 'OPEN';
  }

  getState(): 'CLOSED' | 'OPEN' | 'HALF_OPEN' {
    return this.state.state;
  }

  private shouldOpen(): boolean {
    // Calculate failure rate in current window
    const recentRequests = this.state.requestWindow;
    if (recentRequests.length < this.state.failureThreshold) {
      return false;
    }

    const failures = recentRequests.filter(r => !r.success).length;
    const failureRate = failures / recentRequests.length;
    
    return failureRate >= 0.5 && failures >= this.state.failureThreshold;
  }

  private shouldClose(): boolean {
    return this.state.successCount >= this.state.successThreshold;
  }

  private shouldTryHalfOpen(): boolean {
    return Date.now() - this.state.lastFailureTime >= this.state.timeout;
  }

  private async openCircuit(): Promise<void> {
    this.state.state = 'OPEN';
    this.state.successCount = 0;
    
    // Publish circuit breaker opened event
    await this.publishEvent('CIRCUIT_OPENED', {
      serviceName: this.state.serviceName,
      failureCount: this.state.failureCount,
      failureRate: this.calculateCurrentFailureRate()
    });
  }

  private async closeCircuit(): Promise<void> {
    this.state.state = 'CLOSED';
    this.state.failureCount = 0;
    this.state.successCount = 0;
    
    // Publish circuit breaker closed event
    await this.publishEvent('CIRCUIT_CLOSED', {
      serviceName: this.state.serviceName,
      recoveryTime: Date.now() - this.state.lastFailureTime
    });
  }

  private cleanupWindow(now: number): void {
    const cutoff = now - this.state.windowSizeMs;
    this.state.requestWindow = this.state.requestWindow.filter(r => r.timestamp > cutoff);
  }

  private updateAverageResponseTime(responseTime: number): void {
    const totalTime = this.state.avgResponseTime * (this.state.totalSuccesses - 1);
    this.state.avgResponseTime = (totalTime + responseTime) / this.state.totalSuccesses;
  }

  private calculateCurrentFailureRate(): number {
    const recentRequests = this.state.requestWindow;
    if (recentRequests.length === 0) return 0;
    
    const failures = recentRequests.filter(r => !r.success).length;
    return failures / recentRequests.length;
  }

  private async persistState(): Promise<void> {
    // Persist circuit breaker state to DynamoDB for durability
    await dynamoClient.put({
      TableName: process.env.CIRCUIT_BREAKER_TABLE!,
      Item: {
        PK: `CB#${this.state.serviceName}`,
        SK: 'STATE',
        ...this.state,
        requestWindow: JSON.stringify(this.state.requestWindow),
        updatedAt: new Date().toISOString()
      }
    }).promise();
  }

  private async publishEvent(eventType: string, data: any): Promise<void> {
    await eventBridge.putEvents({
      Entries: [{
        Source: 'translation-service.circuit-breaker',
        DetailType: eventType,
        Detail: JSON.stringify(data)
      }]
    }).promise();
  }
}
```

### Recovery Orchestrator
```typescript
class RecoveryOrchestrator {
  private recoveryStrategies: Map<string, RecoveryHandler> = new Map();

  constructor() {
    this.initializeRecoveryStrategies();
  }

  async executeRecovery(
    errorRecord: ErrorRecord,
    strategy: RecoveryStrategy,
    context: ErrorContext
  ): Promise<RecoveryResult> {
    const recoveryId = this.generateRecoveryId();
    const startTime = Date.now();

    // Record recovery attempt
    await this.recordRecoveryAttempt(errorRecord.errorId, strategy, recoveryId);

    try {
      const handler = this.recoveryStrategies.get(strategy.type);
      if (!handler) {
        throw new Error(`No recovery handler found for strategy: ${strategy.type}`);
      }

      const result = await handler.execute(errorRecord, strategy.parameters, context);
      
      // Record successful recovery
      await this.recordRecoveryResult(recoveryId, {
        success: true,
        duration: Date.now() - startTime,
        result: result.message,
        nextAction: result.nextAction
      });

      return result;

    } catch (recoveryError) {
      // Record failed recovery
      await this.recordRecoveryResult(recoveryId, {
        success: false,
        duration: Date.now() - startTime,
        error: recoveryError.message,
        nextAction: 'ESCALATE'
      });

      throw new RecoveryError(
        `Recovery failed for error ${errorRecord.errorId}: ${recoveryError.message}`,
        recoveryError
      );
    }
  }

  private initializeRecoveryStrategies(): void {
    this.recoveryStrategies.set('IMMEDIATE_RETRY', new ImmediateRetryHandler());
    this.recoveryStrategies.set('DELAYED_RETRY', new DelayedRetryHandler());
    this.recoveryStrategies.set('CIRCUIT_BREAKER', new CircuitBreakerHandler());
    this.recoveryStrategies.set('FALLBACK', new FallbackHandler());
    this.recoveryStrategies.set('ESCALATION', new EscalationHandler());
  }

  private async recordRecoveryAttempt(
    errorId: string,
    strategy: RecoveryStrategy,
    recoveryId: string
  ): Promise<void> {
    const attempt: RecoveryAttemptRecord = {
      PK: `ERROR#${errorId}`,
      SK: `RECOVERY#${Date.now()}#${recoveryId}`,
      errorId,
      attemptNumber: await this.getNextAttemptNumber(errorId),
      recoveryStrategy: strategy.type,
      startedAt: new Date().toISOString(),
      status: 'INITIATED',
      triggeredBy: 'SYSTEM',
      parameters: JSON.stringify(strategy.parameters)
    };

    await dynamoClient.put({
      TableName: process.env.RECOVERY_ATTEMPTS_TABLE!,
      Item: attempt
    }).promise();
  }

  private async recordRecoveryResult(
    recoveryId: string,
    result: RecoveryAttemptResult
  ): Promise<void> {
    // Update recovery attempt with result
    // Implementation would update the recovery attempt record
  }
}

// Recovery Handler Implementations
class ImmediateRetryHandler implements RecoveryHandler {
  async execute(
    errorRecord: ErrorRecord,
    parameters: any,
    context: ErrorContext
  ): Promise<RecoveryResult> {
    // Trigger immediate retry of the failed operation
    const retryResult = await this.triggerRetry(errorRecord, context);
    
    return {
      success: retryResult.success,
      message: retryResult.success ? 'Immediate retry successful' : 'Immediate retry failed',
      nextAction: retryResult.success ? 'CONTINUE' : 'TRY_DELAYED_RETRY',
      metadata: {
        retryDuration: retryResult.duration,
        retryMethod: 'IMMEDIATE'
      }
    };
  }

  private async triggerRetry(errorRecord: ErrorRecord, context: ErrorContext): Promise<RetryResult> {
    // Implementation depends on the component and operation type
    switch (errorRecord.component) {
      case 'gemini-api':
        return await this.retryGeminiAPICall(context);
      case 'chunking':
        return await this.retryChunkingOperation(context);
      case 'job-management':
        return await this.retryJobOperation(context);
      default:
        throw new Error(`Unsupported component for retry: ${errorRecord.component}`);
    }
  }

  private async retryGeminiAPICall(context: ErrorContext): Promise<RetryResult> {
    try {
      // Get original request parameters
      const originalRequest = await this.getOriginalRequest(context.requestId!);
      
      // Retry the Gemini API call
      const geminiClient = new GeminiAPIClient(getGeminiConfig());
      const result = await geminiClient.translateChunk(originalRequest);
      
      return {
        success: true,
        duration: result.processingTime
      };
    } catch (error) {
      return {
        success: false,
        duration: 0,
        error: error.message
      };
    }
  }
}

class DelayedRetryHandler implements RecoveryHandler {
  async execute(
    errorRecord: ErrorRecord,
    parameters: any,
    context: ErrorContext
  ): Promise<RecoveryResult> {
    const delay = parameters.delay || 30000; // Default 30 seconds
    
    // Schedule delayed retry using Step Functions or SQS
    await this.scheduleDelayedRetry(errorRecord, context, delay);
    
    return {
      success: true,
      message: `Scheduled retry in ${delay / 1000} seconds`,
      nextAction: 'WAIT_FOR_RETRY',
      metadata: {
        retryDelay: delay,
        scheduledAt: new Date(Date.now() + delay).toISOString()
      }
    };
  }

  private async scheduleDelayedRetry(
    errorRecord: ErrorRecord,
    context: ErrorContext,
    delay: number
  ): Promise<void> {
    // Send message to SQS with delay
    await sqs.sendMessage({
      QueueUrl: process.env.RETRY_QUEUE_URL!,
      MessageBody: JSON.stringify({
        errorId: errorRecord.errorId,
        component: errorRecord.component,
        context,
        retryAttempt: errorRecord.currentRetries + 1
      }),
      DelaySeconds: Math.floor(delay / 1000)
    }).promise();
  }
}

class FallbackHandler implements RecoveryHandler {
  async execute(
    errorRecord: ErrorRecord,
    parameters: any,
    context: ErrorContext
  ): Promise<RecoveryResult> {
    // Implement fallback logic based on component
    const fallbackResult = await this.executeFallback(errorRecord.component, context);
    
    return {
      success: fallbackResult.success,
      message: fallbackResult.message,
      nextAction: fallbackResult.success ? 'CONTINUE_WITH_FALLBACK' : 'ESCALATE',
      metadata: fallbackResult.metadata
    };
  }

  private async executeFallback(component: string, context: ErrorContext): Promise<FallbackResult> {
    switch (component) {
      case 'gemini-api':
        return await this.geminiAPIFallback(context);
      case 'legal-attestation':
        return await this.legalAttestationFallback(context);
      default:
        return {
          success: false,
          message: `No fallback available for component: ${component}`
        };
    }
  }

  private async geminiAPIFallback(context: ErrorContext): Promise<FallbackResult> {
    // Fallback: Use cached translation or simplified processing
    try {
      const cachedTranslation = await this.getCachedTranslation(context.chunkId!);
      if (cachedTranslation) {
        return {
          success: true,
          message: 'Used cached translation as fallback',
          metadata: { fallbackType: 'CACHED_TRANSLATION' }
        };
      }

      // Alternative: Mark chunk for manual translation
      await this.markForManualTranslation(context.chunkId!);
      return {
        success: true,
        message: 'Marked chunk for manual translation',
        metadata: { fallbackType: 'MANUAL_TRANSLATION' }
      };
    } catch (error) {
      return {
        success: false,
        message: `Fallback failed: ${error.message}`
      };
    }
  }
}
```

## 5. Dead Letter Queue Management

### Dead Letter Handler
```typescript
class DeadLetterHandler {
  private dlqProcessor: DLQProcessor;
  private poisonMessageDetector: PoisonMessageDetector;

  async processDLQMessage(message: DLQMessage): Promise<DLQProcessingResult> {
    try {
      // Analyze the message to determine why it failed
      const analysis = await this.analyzeDLQMessage(message);
      
      // Check if this is a poison message
      const isPoisonMessage = await this.poisonMessageDetector.isPoisonMessage(message);
      
      if (isPoisonMessage) {
        return await this.handlePoisonMessage(message, analysis);
      }
      
      // Determine if message can be recovered
      if (analysis.isRecoverable) {
        return await this.recoverDLQMessage(message, analysis);
      } else {
        return await this.archiveDLQMessage(message, analysis);
      }
      
    } catch (error) {
      console.error('Error processing DLQ message:', error);
      return {
        messageId: message.messageId,
        action: 'RETRY_LATER',
        success: false,
        error: error.message
      };
    }
  }

  private async analyzeDLQMessage(message: DLQMessage): Promise<DLQAnalysis> {
    const errorPatterns = [
      {
        pattern: /rate.*limit/i,
        category: 'RATE_LIMIT',
        recoverable: true,
        suggestedDelay: 300000 // 5 minutes
      },
      {
        pattern: /timeout/i,
        category: 'TIMEOUT',
        recoverable: true,
        suggestedDelay: 60000 // 1 minute
      },
      {
        pattern: /unauthorized|forbidden/i,
        category: 'AUTHENTICATION',
        recoverable: false
      },
      {
        pattern: /invalid.*format|malformed/i,
        category: 'DATA_FORMAT',
        recoverable: false
      },
      {
        pattern: /service.*unavailable/i,
        category: 'SERVICE_UNAVAILABLE',
        recoverable: true,
        suggestedDelay: 120000 // 2 minutes
      }
    ];

    const errorInfo = message.attributes.errorMessage || '';
    
    for (const pattern of errorPatterns) {
      if (pattern.pattern.test(errorInfo)) {
        return {
          category: pattern.category,
          isRecoverable: pattern.recoverable,
          suggestedDelay: pattern.suggestedDelay,
          confidence: 0.8,
          analysis: `Matched pattern: ${pattern.pattern.source}`
        };
      }
    }

    // Default analysis for unrecognized errors
    return {
      category: 'UNKNOWN',
      isRecoverable: message.receiveCount < 3, // Retry up to 3 times
      suggestedDelay: 60000,
      confidence: 0.3,
      analysis: 'Unknown error pattern'
    };
  }

  private async recoverDLQMessage(
    message: DLQMessage,
    analysis: DLQAnalysis
  ): Promise<DLQProcessingResult> {
    try {
      // Wait for suggested delay if specified
      if (analysis.suggestedDelay) {
        await this.scheduleDelayedRetry(message, analysis.suggestedDelay);
        
        return {
          messageId: message.messageId,
          action: 'SCHEDULED_RETRY',
          success: true,
          metadata: {
            retryDelay: analysis.suggestedDelay,
            category: analysis.category
          }
        };
      }

      // Immediate retry
      await this.reprocessMessage(message);
      
      return {
        messageId: message.messageId,
        action: 'IMMEDIATE_RETRY',
        success: true,
        metadata: {
          category: analysis.category,
          retryAttempt: message.receiveCount + 1
        }
      };

    } catch (error) {
      return {
        messageId: message.messageId,
        action: 'RECOVERY_FAILED',
        success: false,
        error: error.message
      };
    }
  }

  private async handlePoisonMessage(
    message: DLQMessage,
    analysis: DLQAnalysis
  ): Promise<DLQProcessingResult> {
    // Archive poison message
    await this.archivePoisonMessage(message, analysis);
    
    // Create alert for poison message
    await this.createPoisonMessageAlert(message);
    
    // Extract any salvageable data
    const salvageResult = await this.attemptDataSalvage(message);
    
    return {
      messageId: message.messageId,
      action: 'ARCHIVED_AS_POISON',
      success: true,
      metadata: {
        archiveLocation: `poison-messages/${message.messageId}`,
        salvageAttempted: salvageResult.attempted,
        dataSalvaged: salvageResult.success
      }
    };
  }

  private async archivePoisonMessage(message: DLQMessage, analysis: DLQAnalysis): Promise<void> {
    const archiveData = {
      messageId: message.messageId,
      originalMessage: message.body,
      attributes: message.attributes,
      receiveCount: message.receiveCount,
      analysis,
      timestamp: new Date().toISOString(),
      reason: 'POISON_MESSAGE'
    };

    // Store in S3 for long-term retention
    await s3Client.putObject({
      Bucket: process.env.DLQ_ARCHIVE_BUCKET!,
      Key: `poison-messages/${new Date().getFullYear()}/${message.messageId}.json`,
      Body: JSON.stringify(archiveData, null, 2),
      Metadata: {
        'message-id': message.messageId,
        'category': analysis.category,
        'archived-at': new Date().toISOString()
      }
    }).promise();
  }

  private async scheduleDelayedRetry(message: DLQMessage, delay: number): Promise<void> {
    // Send back to main queue with delay
    await sqs.sendMessage({
      QueueUrl: process.env.MAIN_QUEUE_URL!,
      MessageBody: message.body,
      DelaySeconds: Math.floor(delay / 1000),
      MessageAttributes: {
        'RetryAttempt': {
          DataType: 'Number',
          StringValue: (message.receiveCount + 1).toString()
        },
        'RecoveryReason': {
          DataType: 'String',
          StringValue: 'DLQ_RECOVERY'
        }
      }
    }).promise();
  }
}

class PoisonMessageDetector {
  async isPoisonMessage(message: DLQMessage): Promise<boolean> {
    // Multiple criteria for poison message detection
    
    // 1. Excessive retry count
    if (message.receiveCount > 5) return true;
    
    // 2. Malformed message structure
    try {
      JSON.parse(message.body);
    } catch {
      return true;
    }
    
    // 3. Historical pattern analysis
    const historicalFailures = await this.getHistoricalFailures(message);
    if (historicalFailures.length > 10) return true;
    
    // 4. Message age
    const messageAge = Date.now() - new Date(message.attributes.sentTimestamp).getTime();
    if (messageAge > 24 * 60 * 60 * 1000) return true; // 24 hours
    
    // 5. Known poison patterns
    const poisonPatterns = [
      /\x00/, // Null bytes
      /[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/, // Control characters
      /.{100000,}/ // Extremely long content
    ];
    
    for (const pattern of poisonPatterns) {
      if (pattern.test(message.body)) return true;
    }
    
    return false;
  }

  private async getHistoricalFailures(message: DLQMessage): Promise<FailureRecord[]> {
    // Query DynamoDB for historical failures of similar messages
    const params = {
      TableName: process.env.ERRORS_TABLE!,
      IndexName: 'ErrorsByComponent',
      KeyConditionExpression: 'GSI1PK = :component',
      FilterExpression: 'contains(#msg, :msgPattern)',
      ExpressionAttributeNames: {
        '#msg': 'message'
      },
      ExpressionAttributeValues: {
        ':component': `COMPONENT#${this.extractComponent(message)}`,
        ':msgPattern': this.extractMessagePattern(message)
      },
      Limit: 20
    };

    const result = await dynamoClient.query(params).promise();
    return result.Items as FailureRecord[];
  }
}
```

## 6. Performance & Monitoring

### Error Analytics and Monitoring
```typescript
class ErrorAnalyticsEngine {
  private cloudWatch: AWS.CloudWatch;
  private timestream: AWS.TimestreamWrite;

  async generateErrorReport(request: ErrorAnalyticsRequest): Promise<ErrorAnalyticsResponse> {
    const startDate = new Date(request.startDate);
    const endDate = new Date(request.endDate);
    
    // Get all errors in date range
    const errors = await this.getErrorsInDateRange(startDate, endDate, request);
    
    // Analyze error patterns
    const analytics = await this.analyzeErrorPatterns(errors);
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(analytics);
    
    return {
      totalErrors: errors.length,
      errorsByComponent: analytics.componentStats,
      errorsByCode: analytics.codeStats,
      errorTrends: analytics.trends,
      meanTimeToResolution: analytics.mttr,
      recoverySuccessRate: analytics.recoveryRate,
      topFailureReasons: analytics.topReasons,
      recommendations
    };
  }

  private async analyzeErrorPatterns(errors: ErrorRecord[]): Promise<ErrorAnalytics> {
    // Component analysis
    const componentStats = this.analyzeByComponent(errors);
    
    // Error code analysis
    const codeStats = this.analyzeByErrorCode(errors);
    
    // Trend analysis
    const trends = this.analyzeTrends(errors);
    
    // Recovery analysis
    const recoveryStats = await this.analyzeRecoveryPatterns(errors);
    
    // MTTR calculation
    const mttr = this.calculateMTTR(errors);
    
    return {
      componentStats,
      codeStats,
      trends,
      mttr,
      recoveryRate: recoveryStats.successRate,
      topReasons: this.identifyTopFailureReasons(errors)
    };
  }

  private generateRecommendations(analytics: ErrorAnalytics): string[] {
    const recommendations: string[] = [];
    
    // High error rate recommendations
    const highErrorComponents = analytics.componentStats
      .filter(stat => stat.errorRate > 0.05)
      .sort((a, b) => b.errorRate - a.errorRate);
    
    if (highErrorComponents.length > 0) {
      recommendations.push(
        `High error rate detected in ${highErrorComponents[0].component} (${(highErrorComponents[0].errorRate * 100).toFixed(1)}%). Review error handling and resilience patterns.`
      );
    }
    
    // Recovery rate recommendations
    if (analytics.recoveryRate < 0.8) {
      recommendations.push(
        `Low recovery success rate (${(analytics.recoveryRate * 100).toFixed(1)}%). Consider improving retry logic and fallback mechanisms.`
      );
    }
    
    // MTTR recommendations
    if (analytics.mttr > 3600000) { // > 1 hour
      recommendations.push(
        `High mean time to resolution (${Math.round(analytics.mttr / 60000)} minutes). Consider automation improvements and faster escalation.`
      );
    }
    
    // Pattern-based recommendations
    const rateLimitErrors = analytics.codeStats.find(stat => stat.errorCode.includes('RateLimit'));
    if (rateLimitErrors && rateLimitErrors.count > analytics.codeStats[0].count * 0.2) {
      recommendations.push(
        'High rate limit error frequency. Consider implementing request queuing and better rate limit management.'
      );
    }
    
    return recommendations;
  }

  async publishErrorMetrics(errorRecord: ErrorRecord): Promise<void> {
    const metrics = [
      {
        MetricName: 'ErrorCount',
        Value: 1,
        Unit: 'Count',
        Dimensions: [
          { Name: 'Component', Value: errorRecord.component },
          { Name: 'ErrorCode', Value: errorRecord.errorCode },
          { Name: 'Severity', Value: errorRecord.severity }
        ]
      },
      {
        MetricName: 'ErrorOccurrenceCount',
        Value: errorRecord.occurrenceCount,
        Unit: 'Count',
        Dimensions: [
          { Name: 'Component', Value: errorRecord.component },
          { Name: 'ErrorCode', Value: errorRecord.errorCode }
        ]
      }
    ];

    if (errorRecord.recoveryAttempts > 0) {
      metrics.push({
        MetricName: 'RecoveryAttempts',
        Value: errorRecord.recoveryAttempts,
        Unit: 'Count',
        Dimensions: [
          { Name: 'Component', Value: errorRecord.component },
          { Name: 'RecoveryType', Value: errorRecord.recoveryStrategy || 'UNKNOWN' }
        ]
      });
    }

    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/Errors',
      MetricData: metrics
    }).promise();
  }

  async trackErrorResolution(errorId: string, resolutionMethod: string, duration: number): Promise<void> {
    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/Errors/Resolution',
      MetricData: [
        {
          MetricName: 'ResolutionTime',
          Value: duration / 1000, // Convert to seconds
          Unit: 'Seconds',
          Dimensions: [
            { Name: 'ResolutionMethod', Value: resolutionMethod }
          ]
        }
      ]
    }).promise();

    // Store detailed resolution data in Timestream
    await this.timestream.writeRecords({
      DatabaseName: process.env.TIMESTREAM_DATABASE!,
      TableName: 'error_resolutions',
      Records: [{
        Time: Date.now().toString(),
        TimeUnit: 'MILLISECONDS',
        Dimensions: [
          { Name: 'error_id', Value: errorId },
          { Name: 'resolution_method', Value: resolutionMethod }
        ],
        MeasureName: 'resolution_time',
        MeasureValue: duration.toString(),
        MeasureValueType: 'BIGINT'
      }]
    }).promise();
  }
}
```

## 7. Implementation Examples

### Lambda Handler for Error Processing
```typescript
export const processErrorHandler = async (event: any): Promise<any> => {
  const errorHandler = new CentralizedErrorHandler();
  
  try {
    // Extract error information from event
    const { error, context, component } = event;
    
    // Create Error object if not already one
    const errorObj = error instanceof Error ? error : new Error(error.message || 'Unknown error');
    
    // Handle the error
    const result = await errorHandler.handleError(errorObj, context, component);
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        errorId: result.errorId,
        classification: result.classification,
        recoveryStrategy: result.recoveryStrategy.type,
        shouldRetry: result.shouldRetry,
        nextAction: result.nextAction
      })
    };
    
  } catch (handlingError) {
    console.error('Critical error in error handler:', handlingError);
    
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Error handler failure',
        message: handlingError.message
      })
    };
  }
};

export const processDLQHandler = async (event: any): Promise<any> => {
  const dlqHandler = new DeadLetterHandler();
  const results: DLQProcessingResult[] = [];
  
  for (const record of event.Records) {
    const message: DLQMessage = {
      messageId: record.messageId,
      body: record.body,
      receiveCount: parseInt(record.attributes.ApproximateReceiveCount),
      attributes: record.attributes
    };
    
    try {
      const result = await dlqHandler.processDLQMessage(message);
      results.push(result);
      
      // Delete message from DLQ if processed successfully
      if (result.success) {
        await sqs.deleteMessage({
          QueueUrl: process.env.DLQ_URL!,
          ReceiptHandle: record.receiptHandle
        }).promise();
      }
      
    } catch (error) {
      console.error(`Failed to process DLQ message ${message.messageId}:`, error);
      results.push({
        messageId: message.messageId,
        action: 'PROCESSING_FAILED',
        success: false,
        error: error.message
      });
    }
  }
  
  return {
    batchItemFailures: results
      .filter(r => !r.success)
      .map(r => ({ itemIdentifier: r.messageId }))
  };
};
```

### Error Handling Middleware
```typescript
class ErrorHandlingMiddleware {
  static create(component: string) {
    return (req: any, res: any, next: any) => {
      const originalSend = res.send;
      const originalJson = res.json;
      
      // Wrap response methods to catch errors
      res.send = function(body: any) {
        if (res.statusCode >= 400) {
          ErrorHandlingMiddleware.handleHTTPError(req, res, body, component);
        }
        return originalSend.call(this, body);
      };
      
      res.json = function(obj: any) {
        if (res.statusCode >= 400) {
          ErrorHandlingMiddleware.handleHTTPError(req, res, obj, component);
        }
        return originalJson.call(this, obj);
      };
      
      next();
    };
  }
  
  private static async handleHTTPError(req: any, res: any, body: any, component: string) {
    const errorHandler = new CentralizedErrorHandler();
    
    const error = new Error(body.message || `HTTP ${res.statusCode} error`);
    const context: ErrorContext = {
      requestId: req.id,
      userId: req.user?.id,
      sessionId: req.session?.id,
      timestamp: new Date().toISOString(),
      additionalData: {
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        body,
        headers: req.headers
      }
    };
    
    try {
      await errorHandler.handleError(error, context, component);
    } catch (handlingError) {
      console.error('Error handling middleware failed:', handlingError);
    }
  }
}

// Usage in Express app
app.use(ErrorHandlingMiddleware.create('api-gateway'));
```

## 8. Testing Strategy

### Error Handling Testing
```typescript
describe('CentralizedErrorHandler', () => {
  let errorHandler: CentralizedErrorHandler;
  let mockClassifier: jest.Mocked<ErrorClassifier>;
  let mockOrchestrator: jest.Mocked<RecoveryOrchestrator>;

  beforeEach(() => {
    mockClassifier = {
      classifyError: jest.fn()
    } as any;
    
    mockOrchestrator = {
      executeRecovery: jest.fn()
    } as any;
    
    errorHandler = new CentralizedErrorHandler();
    (errorHandler as any).errorClassifier = mockClassifier;
    (errorHandler as any).recoveryOrchestrator = mockOrchestrator;
  });

  it('handles new errors correctly', async () => {
    const error = new Error('Test error');
    const context: ErrorContext = {
      jobId: 'test-job',
      userId: 'test-user',
      timestamp: new Date().toISOString()
    };

    const classification: ErrorClassification = {
      category: 'API_ERROR',
      severity: 'MEDIUM',
      retryable: true,
      autoRecoverable: true,
      escalationRequired: false,
      maxRetries: 3,
      backoffStrategy: 'EXPONENTIAL',
      circuitBreakerEligible: true
    };

    mockClassifier.classifyError.mockResolvedValue(classification);
    mockOrchestrator.executeRecovery.mockResolvedValue({
      success: true,
      message: 'Recovery successful',
      nextAction: 'CONTINUE'
    });

    const result = await errorHandler.handleError(error, context, 'test-component');

    expect(result.errorId).toBeDefined();
    expect(result.classification).toEqual(classification);
    expect(result.shouldRetry).toBe(true);
    expect(mockClassifier.classifyError).toHaveBeenCalledWith(error, context);
    expect(mockOrchestrator.executeRecovery).toHaveBeenCalled();
  });

  it('handles critical errors with escalation', async () => {
    const error = new Error('Critical system failure');
    const context: ErrorContext = {
      timestamp: new Date().toISOString()
    };

    const classification: ErrorClassification = {
      category: 'SYSTEM_ERROR',
      severity: 'CRITICAL',
      retryable: false,
      autoRecoverable: false,
      escalationRequired: true,
      maxRetries: 0,
      backoffStrategy: 'FIXED',
      circuitBreakerEligible: false
    };

    mockClassifier.classifyError.mockResolvedValue(classification);

    const result = await errorHandler.handleError(error, context, 'critical-component');

    expect(result.classification.severity).toBe('CRITICAL');
    expect(result.shouldRetry).toBe(false);
    expect(result.nextAction).toBe('ESCALATE_IMMEDIATELY');
  });

  it('handles duplicate errors correctly', async () => {
    const error = new Error('Duplicate error');
    const context: ErrorContext = {
      jobId: 'test-job',
      timestamp: new Date().toISOString()
    };

    // Mock existing error
    jest.spyOn(errorHandler as any, 'checkForDuplicateError')
      .mockResolvedValue({
        errorId: 'existing-error',
        occurrenceCount: 3,
        currentRetries: 1
      });

    const result = await errorHandler.handleError(error, context, 'test-component');

    expect(result.errorId).toBe('existing-error');
  });
});

describe('CircuitBreaker', () => {
  let circuitBreaker: CircuitBreaker;
  const config: CircuitBreakerConfig = {
    failureThreshold: 3,
    successThreshold: 2,
    timeout: 60000,
    windowSizeMs: 60000
  };

  beforeEach(() => {
    circuitBreaker = new CircuitBreaker('test-service', config);
  });

  it('opens circuit after threshold failures', async () => {
    expect(circuitBreaker.getState()).toBe('CLOSED');

    // Record multiple failures
    for (let i = 0; i < 3; i++) {
      await circuitBreaker.recordFailure(new Error('Test failure'));
    }

    expect(circuitBreaker.getState()).toBe('OPEN');
    expect(circuitBreaker.isOpen()).toBe(true);
  });

  it('transitions to half-open after timeout', async () => {
    // Force circuit to open
    for (let i = 0; i < 3; i++) {
      await circuitBreaker.recordFailure(new Error('Test failure'));
    }
    expect(circuitBreaker.getState()).toBe('OPEN');

    // Mock time passage
    jest.spyOn(Date, 'now')
      .mockReturnValue(Date.now() + config.timeout + 1000);

    expect(circuitBreaker.isOpen()).toBe(false);
    expect(circuitBreaker.getState()).toBe('HALF_OPEN');
  });

  it('closes circuit after successful recoveries', async () => {
    // Open circuit
    for (let i = 0; i < 3; i++) {
      await circuitBreaker.recordFailure(new Error('Test failure'));
    }

    // Transition to half-open
    jest.spyOn(Date, 'now')
      .mockReturnValue(Date.now() + config.timeout + 1000);
    circuitBreaker.isOpen(); // Trigger state check

    // Record successes
    for (let i = 0; i < 2; i++) {
      await circuitBreaker.recordSuccess(100);
    }

    expect(circuitBreaker.getState()).toBe('CLOSED');
  });
});

describe('DeadLetterHandler', () => {
  let dlqHandler: DeadLetterHandler;

  beforeEach(() => {
    dlqHandler = new DeadLetterHandler();
  });

  it('recovers rate-limited messages', async () => {
    const message: DLQMessage = {
      messageId: 'test-msg-1',
      body: JSON.stringify({ test: 'data' }),
      receiveCount: 2,
      attributes: {
        errorMessage: 'Rate limit exceeded',
        sentTimestamp: new Date().toISOString()
      }
    };

    const result = await dlqHandler.processDLQMessage(message);

    expect(result.success).toBe(true);
    expect(result.action).toBe('SCHEDULED_RETRY');
    expect(result.metadata?.category).toBe('RATE_LIMIT');
  });

  it('archives poison messages', async () => {
    const message: DLQMessage = {
      messageId: 'poison-msg',
      body: 'invalid json {',
      receiveCount: 10, // Excessive retries
      attributes: {
        errorMessage: 'Malformed message',
        sentTimestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString() // 48 hours old
      }
    };

    const result = await dlqHandler.processDLQMessage(message);

    expect(result.success).toBe(true);
    expect(result.action).toBe('ARCHIVED_AS_POISON');
    expect(result.metadata?.archiveLocation).toContain('poison-messages');
  });
});
```

## 9. Configuration & Deployment

### CloudFormation Template for Error Handling
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Error Handling & Recovery Infrastructure'

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, staging, prod]

Resources:
  # DynamoDB Table for Error Records
  ErrorsTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub 'error-records-${Environment}'
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
        - IndexName: ErrorsByComponent
          KeySchema:
            - AttributeName: GSI1PK
              KeyType: HASH
            - AttributeName: GSI1SK
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
        - IndexName: ErrorsByJob
          KeySchema:
            - AttributeName: GSI2PK
              KeyType: HASH
            - AttributeName: GSI2SK
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
        - IndexName: ErrorsByStatus
          KeySchema:
            - AttributeName: GSI3PK
              KeyType: HASH
            - AttributeName: GSI3SK
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
      TimeToLiveSpecification:
        AttributeName: ttl
        Enabled: true
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES

  # DynamoDB Table for Circuit Breaker State
  CircuitBreakerTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub 'circuit-breaker-state-${Environment}'
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

  # Dead Letter Queue