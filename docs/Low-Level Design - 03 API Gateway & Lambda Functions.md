# Low-Level Design Document 3: API Gateway & Lambda Functions

## 1. Component Overview & Responsibilities

The API Gateway & Lambda Functions component serves as the primary backend interface for the Long-Form Translation Service. It provides a REST API with optimized polling endpoints, comprehensive caching, and serverless compute for all business logic operations.

**Key Responsibilities:**
- RESTful API endpoints with <500ms response time targets
- Progress tracking endpoints optimized for polling (30s cache TTL)
- Legal attestation validation and storage
- File upload coordination with presigned URLs
- User authentication and authorization
- Request/response transformation and validation
- Rate limiting and error handling

**Why This Design:** API Gateway provides managed scaling, caching, and monitoring while Lambda functions offer cost-effective, event-driven compute. The polling-focused design eliminates WebSocket complexity while maintaining responsive user experience.

## 2. API Design & Interfaces

### API Gateway Structure
```yaml
# API Gateway Configuration
APIGateway:
  Name: translation-service-api
  EndpointType: REGIONAL
  Description: "Long-Form Translation Service REST API"
  
  # Caching Configuration
  CacheClusterEnabled: true
  CacheClusterSize: 0.5  # 0.5GB cache cluster
  
  # Request/Response Models
  Models:
    - ErrorResponse
    - ProgressResponse
    - JobRequest
    - AttestationRequest
    
  # CORS Configuration
  Cors:
    AllowOrigin: "*"
    AllowHeaders: "Content-Type,X-Amz-Date,Authorization,X-Api-Key"
    AllowMethods: "GET,POST,PUT,DELETE,OPTIONS"
```

### Core API Endpoints

#### Authentication Endpoints
```typescript
// POST /auth/login
interface LoginRequest {
  email: string;
  password: string;
}

interface LoginResponse {
  token: string;
  refreshToken: string;
  user: {
    userId: string;
    email: string;
    createdAt: string;
    hasValidAttestation: boolean;
  };
  expiresIn: number; // seconds
}

// POST /auth/register  
interface RegisterRequest {
  email: string;
  password: string;
  confirmPassword: string;
}

// POST /auth/refresh
interface RefreshRequest {
  refreshToken: string;
}

// POST /auth/reset-password
interface ResetPasswordRequest {
  email: string;
}
```

#### Progress Tracking Endpoints (Polling-Optimized)
```typescript
// GET /translation/jobs/{jobId}/progress
// Cache: 30 seconds, ETag support
interface ProgressRequest {
  jobId: string; // Path parameter
}

interface ProgressResponse {
  jobId: string;
  status: JobStatus;
  progress: number; // 0-100
  chunksProcessed: number;
  totalChunks: number;
  estimatedTimeRemaining?: number; // seconds
  lastUpdated: string; // ISO 8601
  processingSpeed?: number; // words per minute
  currentStage?: string;
  // Metadata for polling optimization
  cacheAge?: number; // seconds since last update
  nextPollRecommendation?: number; // recommended next poll interval
}

// GET /translation/jobs/{jobId}/status
// Lightweight status-only endpoint for health checks
interface StatusResponse {
  jobId: string;
  status: JobStatus;
  lastUpdated: string;
  errorMessage?: string;
}

type JobStatus = 
  | 'QUEUED'
  | 'PROCESSING' 
  | 'RETRYING'
  | 'RATE_LIMITED'
  | 'RECOVERING'
  | 'COMPLETED'
  | 'FAILED'
  | 'RESUMED';
```

#### File Upload Endpoints
```typescript
// POST /upload/presigned-url
interface PresignedUrlRequest {
  fileName: string;
  fileSize: number;
  contentType: string;
}

interface PresignedUrlResponse {
  uploadUrl: string;
  fileId: string;
  expiresIn: number; // seconds
  requiredHeaders: Record<string, string>;
}

// POST /upload/validate
interface FileValidationRequest {
  fileId: string;
  expectedHash?: string;
}

interface FileValidationResponse {
  isValid: boolean;
  metadata: {
    fileName: string;
    fileSize: number;
    wordCount: number;
    estimatedCost: number;
    processingTimeEstimate: {
      min: number; // minutes
      max: number;
      expected: number;
    };
  };
  errors: string[];
  fileHash: string;
}
```

#### Legal Attestation Endpoints
```typescript
// POST /legal/attestation
interface AttestationRequest {
  legalStatements: {
    copyrightOwnership: boolean;
    translationRights: boolean;
    liabilityAcceptance: boolean;
    publicDomainAcknowledgment: boolean;
  };
  auditTrail: {
    pageViewDuration: number;
    scrollCompletionPercentage: number;
    attestationMethod: 'checkbox' | 'digital_signature';
    browserFingerprint: string;
  };
  documentHash: string;
  ipAddress?: string; // Auto-detected if not provided
}

interface AttestationResponse {
  attestationId: string;
  timestamp: string;
  isValid: boolean;
  expiresAt?: string; // If attestations have expiration
}

// GET /legal/terms/{version}
interface TermsResponse {
  version: string;
  content: string;
  updatedAt: string;
  requiresNewAttestation: boolean;
}
```

#### Translation Job Endpoints
```typescript
// POST /translation/jobs
interface CreateJobRequest {
  fileId: string;
  targetLanguage: 'spanish' | 'french' | 'german' | 'italian' | 'chinese';
  attestationId: string;
}

interface CreateJobResponse {
  jobId: string;
  status: 'QUEUED';
  estimatedCost: number;
  estimatedProcessingTime: number; // minutes
  createdAt: string;
}

// GET /translation/jobs/{jobId}/result
interface ResultResponse {
  jobId: string;
  downloadUrl: string; // Presigned URL for result download
  expiresIn: number;
  metadata: {
    originalFileName: string;
    targetLanguage: string;
    wordCount: number;
    actualCost: number;
    processingTime: number; // minutes
    qualityMetrics: {
      completionRate: number; // percentage
      consistencyScore: number;
    };
  };
}

// DELETE /translation/jobs/{jobId}
interface DeleteJobResponse {
  jobId: string;
  deleted: boolean;
  message: string;
}
```

## 3. Data Models & Storage

### Request/Response Models
```typescript
// API Gateway Request Models
interface APIGatewayRequestModel {
  body: string;
  headers: Record<string, string>;
  pathParameters: Record<string, string>;
  queryStringParameters: Record<string, string>;
  requestContext: {
    requestId: string;
    apiId: string;
    httpMethod: string;
    path: string;
    authorizer?: {
      userId: string;
      email: string;
    };
  };
}

// Standard API Response Format
interface APIResponse<T = any> {
  statusCode: number;
  headers: {
    'Content-Type': 'application/json';
    'Cache-Control'?: string;
    'ETag'?: string;
    'X-RateLimit-Remaining'?: string;
    'X-RateLimit-Reset'?: string;
    'Access-Control-Allow-Origin': string;
  };
  body: string; // JSON stringified
}

interface SuccessResponse<T> {
  data: T;
  meta?: {
    requestId: string;
    timestamp: string;
    cacheStatus?: 'hit' | 'miss' | 'stale';
  };
}

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
  };
  meta: {
    requestId: string;
    timestamp: string;
  };
}
```

### Caching Strategy
```typescript
interface CacheConfiguration {
  // Progress endpoints - frequently polled
  'GET /translation/jobs/{id}/progress': {
    ttl: 30; // seconds
    varyBy: ['Authorization', 'jobId'];
    staleWhileRevalidate: true;
  };
  
  // Status endpoints - health checks
  'GET /translation/jobs/{id}/status': {
    ttl: 30;
    varyBy: ['jobId'];
    staleWhileRevalidate: true;
  };
  
  // Legal terms - rarely change
  'GET /legal/terms/{version}': {
    ttl: 3600; // 1 hour
    varyBy: ['version'];
    staleWhileRevalidate: false;
  };
  
  // User history - user-specific
  'GET /user/history': {
    ttl: 300; // 5 minutes
    varyBy: ['Authorization'];
    staleWhileRevalidate: true;
  };
}
```

## 4. Core Algorithms & Logic

### Response Time Optimization
```typescript
class ResponseTimeOptimizer {
  private readonly TARGET_RESPONSE_TIME = 500; // milliseconds

  async optimizeResponse<T>(
    operation: () => Promise<T>,
    cacheKey?: string,
    fallbackData?: T
  ): Promise<T> {
    const startTime = Date.now();

    try {
      // Try cache first for cacheable operations
      if (cacheKey) {
        const cached = await this.getFromCache(cacheKey);
        if (cached) {
          const responseTime = Date.now() - startTime;
          console.log(`Cache hit for ${cacheKey}: ${responseTime}ms`);
          return cached;
        }
      }

      // Execute operation with timeout
      const result = await this.withTimeout(operation(), this.TARGET_RESPONSE_TIME);
      
      // Cache successful results
      if (cacheKey) {
        await this.setCache(cacheKey, result);
      }

      const responseTime = Date.now() - startTime;
      if (responseTime > this.TARGET_RESPONSE_TIME) {
        console.warn(`Slow response: ${responseTime}ms for ${cacheKey || 'operation'}`);
      }

      return result;

    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      if (error.name === 'TimeoutError' && fallbackData) {
        console.warn(`Timeout after ${responseTime}ms, using fallback data`);
        return fallbackData;
      }

      throw error;
    }
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('TimeoutError')), timeoutMs);
    });

    return Promise.race([promise, timeout]);
  }

  private async getFromCache<T>(key: string): Promise<T | null> {
    // Implementation would use Redis or DAX
    return null; // Placeholder
  }

  private async setCache<T>(key: string, value: T, ttl: number = 30): Promise<void> {
    // Implementation would use Redis or DAX
  }
}
```

### Request Validation
```typescript
class RequestValidator {
  static validateCreateJob(request: CreateJobRequest): ValidationResult {
    const errors: string[] = [];

    // File ID validation
    if (!request.fileId || !/^[a-zA-Z0-9-_]{8,64}$/.test(request.fileId)) {
      errors.push('Invalid file ID format');
    }

    // Target language validation
    const supportedLanguages = ['spanish', 'french', 'german', 'italian', 'chinese'];
    if (!supportedLanguages.includes(request.targetLanguage)) {
      errors.push(`Unsupported target language: ${request.targetLanguage}`);
    }

    // Attestation ID validation
    if (!request.attestationId || !/^[a-f0-9-]{36}$/.test(request.attestationId)) {
      errors.push('Invalid attestation ID format');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  static validateAttestationRequest(request: AttestationRequest): ValidationResult {
    const errors: string[] = [];

    // All legal statements must be true
    const { legalStatements } = request;
    if (!legalStatements.copyrightOwnership) {
      errors.push('Copyright ownership must be acknowledged');
    }
    if (!legalStatements.translationRights) {
      errors.push('Translation rights must be acknowledged');
    }
    if (!legalStatements.liabilityAcceptance) {
      errors.push('Liability acceptance must be acknowledged');
    }
    if (!legalStatements.publicDomainAcknowledgment) {
      errors.push('Public domain acknowledgment must be accepted');
    }

    // Audit trail validation
    const { auditTrail } = request;
    if (auditTrail.pageViewDuration < 30000) { // 30 seconds minimum
      errors.push('Insufficient time spent reviewing terms');
    }
    if (auditTrail.scrollCompletionPercentage < 80) {
      errors.push('Terms must be fully read (scroll to end)');
    }

    // Document hash validation
    if (!request.documentHash || !/^[a-f0-9]{64}$/.test(request.documentHash)) {
      errors.push('Invalid document hash format');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}
```

## 5. Implementation Examples

### Lambda Function Structure
```typescript
// Base Lambda Handler
abstract class BaseLambdaHandler {
  protected responseTimeOptimizer = new ResponseTimeOptimizer();

  async handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
    const startTime = Date.now();
    const requestId = event.requestContext.requestId;

    try {
      // CORS preflight handling
      if (event.httpMethod === 'OPTIONS') {
        return this.corsResponse();
      }

      // Authentication check
      const user = await this.authenticate(event);
      
      // Route to specific handler
      const result = await this.handleRequest(event, user);
      
      const responseTime = Date.now() - startTime;
      console.log(`Request ${requestId} completed in ${responseTime}ms`);

      return this.successResponse(result, {
        requestId,
        responseTime,
      });

    } catch (error) {
      const responseTime = Date.now() - startTime;
      console.error(`Request ${requestId} failed after ${responseTime}ms:`, error);

      return this.errorResponse(error, requestId);
    }
  }

  protected abstract handleRequest(
    event: APIGatewayProxyEvent, 
    user?: AuthenticatedUser
  ): Promise<any>;

  protected async authenticate(event: APIGatewayProxyEvent): Promise<AuthenticatedUser | null> {
    const authHeader = event.headers['Authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    const token = authHeader.substring(7);
    try {
      return await AuthService.verifyToken(token);
    } catch (error) {
      throw new UnauthorizedError('Invalid token');
    }
  }

  protected successResponse<T>(data: T, meta?: any): APIGatewayProxyResult {
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache',
      },
      body: JSON.stringify({
        data,
        meta: {
          timestamp: new Date().toISOString(),
          ...meta,
        },
      }),
    };
  }

  protected cachedResponse<T>(
    data: T, 
    cacheSeconds: number = 30,
    etag?: string
  ): APIGatewayProxyResult {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': `public, max-age=${cacheSeconds}`,
    };

    if (etag) {
      headers['ETag'] = etag;
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        data,
        meta: {
          timestamp: new Date().toISOString(),
          cacheStatus: 'miss',
          cacheTtl: cacheSeconds,
        },
      }),
    };
  }

  protected errorResponse(error: Error, requestId: string): APIGatewayProxyResult {
    const statusCode = this.getStatusCode(error);
    
    return {
      statusCode,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        error: {
          code: error.constructor.name,
          message: error.message,
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
        },
      }),
    };
  }

  private getStatusCode(error: Error): number {
    if (error instanceof UnauthorizedError) return 401;
    if (error instanceof ForbiddenError) return 403;
    if (error instanceof NotFoundError) return 404;
    if (error instanceof ValidationError) return 400;
    if (error instanceof ConflictError) return 409;
    if (error instanceof RateLimitError) return 429;
    return 500;
  }

  private corsResponse(): APIGatewayProxyResult {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      },
      body: '',
    };
  }
}
```

### Progress Tracking Handler (Critical for Polling)
```typescript
class ProgressHandler extends BaseLambdaHandler {
  private jobStateService = new JobStateService();

  protected async handleRequest(
    event: APIGatewayProxyEvent,
    user: AuthenticatedUser
  ): Promise<ProgressResponse> {
    const jobId = event.pathParameters?.jobId;
    if (!jobId) {
      throw new ValidationError('Job ID is required');
    }

    // Check if request includes If-None-Match for ETag support
    const ifNoneMatch = event.headers['If-None-Match'];
    
    return await this.responseTimeOptimizer.optimizeResponse(
      async () => {
        const job = await this.jobStateService.getJobProgress(jobId, user.userId);
        
        if (!job) {
          throw new NotFoundError(`Job ${jobId} not found`);
        }

        // Generate ETag based on last updated time
        const etag = `"${Buffer.from(job.lastUpdated).toString('base64')}"`;
        
        // Return 304 if client has current version
        if (ifNoneMatch === etag) {
          throw new NotModifiedError();
        }

        // Calculate next poll recommendation based on status
        const nextPollRecommendation = this.calculateNextPollInterval(job);

        return {
          jobId: job.jobId,
          status: job.status,
          progress: job.progress,
          chunksProcessed: job.chunksProcessed,
          totalChunks: job.totalChunks,
          estimatedTimeRemaining: job.estimatedTimeRemaining,
          lastUpdated: job.lastUpdated,
          processingSpeed: job.processingSpeed,
          currentStage: job.currentStage,
          nextPollRecommendation,
          etag,
        };
      },
      `progress:${jobId}:${user.userId}`,
      // Fallback data for timeout scenarios
      {
        jobId,
        status: 'PROCESSING' as JobStatus,
        progress: 0,
        chunksProcessed: 0,
        totalChunks: 1,
        lastUpdated: new Date().toISOString(),
        nextPollRecommendation: 30000,
      }
    );
  }

  private calculateNextPollInterval(job: TranslationJob): number {
    const jobAge = Date.now() - new Date(job.createdAt).getTime();
    
    // Fast polling for new jobs
    if (jobAge < 5 * 60 * 1000) return 15000; // 15s for first 5 minutes
    
    // Medium polling for active jobs
    if (jobAge < 30 * 60 * 1000) return 30000; // 30s for 5-30 minutes
    
    // Slow polling for long-running jobs
    return 60000; // 60s for 30+ minutes
  }

  // Override to add caching headers
  protected successResponse<T>(data: T, meta?: any): APIGatewayProxyResult {
    const etag = (data as any).etag;
    const cacheSeconds = 30;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': `public, max-age=${cacheSeconds}`,
    };

    if (etag) {
      headers['ETag'] = etag;
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        data,
        meta: {
          timestamp: new Date().toISOString(),
          cacheStatus: 'miss',
          ...meta,
        },
      }),
    };
  }
}
```

### Legal Attestation Handler
```typescript
class LegalAttestationHandler extends BaseLambdaHandler {
  private legalService = new LegalAttestationService();

  protected async handleRequest(
    event: APIGatewayProxyEvent,
    user: AuthenticatedUser
  ): Promise<AttestationResponse> {
    const request: AttestationRequest = JSON.parse(event.body || '{}');
    
    // Add IP address from request context
    request.ipAddress = this.getClientIP(event);

    // Validate request
    const validation = RequestValidator.validateAttestationRequest(request);
    if (!validation.isValid) {
      throw new ValidationError(validation.errors.join(', '));
    }

    // Check for existing valid attestation
    const existingAttestation = await this.legalService.getLatestAttestation(user.userId);
    if (existingAttestation && this.isAttestationValid(existingAttestation)) {
      return {
        attestationId: existingAttestation.attestationId,
        timestamp: existingAttestation.createdAt,
        isValid: true,
        expiresAt: existingAttestation.expiresAt,
      };
    }

    // Create new attestation
    const attestation = await this.legalService.createAttestation({
      ...request,
      userId: user.userId,
      userAgent: event.headers['User-Agent'] || '',
    });

    return {
      attestationId: attestation.attestationId,
      timestamp: attestation.createdAt,
      isValid: true,
      expiresAt: attestation.expiresAt,
    };
  }

  private getClientIP(event: APIGatewayProxyEvent): string {
    return event.headers['X-Forwarded-For']?.split(',')[0] ||
           event.headers['X-Real-IP'] ||
           event.requestContext.identity?.sourceIp ||
           'unknown';
  }

  private isAttestationValid(attestation: LegalAttestation): boolean {
    if (attestation.expiresAt) {
      return new Date(attestation.expiresAt) > new Date();
    }
    return true; // No expiration set
  }
}
```

## 6. Error Handling & Edge Cases

### Comprehensive Error Handler
```typescript
class APIErrorHandler {
  static handleError(error: Error, context: string): APIGatewayProxyResult {
    console.error(`Error in ${context}:`, error);

    // Send to monitoring service
    if (process.env.SENTRY_DSN) {
      Sentry.captureException(error, {
        tags: { component: 'api-gateway', context },
      });
    }

    const statusCode = this.getStatusCode(error);
    const response = this.formatErrorResponse(error, statusCode);

    return response;
  }

  private static getStatusCode(error: Error): number {
    const errorMappings = {
      ValidationError: 400,
      UnauthorizedError: 401,
      ForbiddenError: 403,
      NotFoundError: 404,
      ConflictError: 409,
      RateLimitError: 429,
      ServiceUnavailableError: 503,
      TimeoutError: 504,
    };

    return errorMappings[error.constructor.name] || 500;
  }

  private static formatErrorResponse(error: Error, statusCode: number): APIGatewayProxyResult {
    const isDevelopment = process.env.NODE_ENV === 'development';

    return {
      statusCode,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        error: {
          code: error.constructor.name,
          message: error.message,
          // Only include stack trace in development
          ...(isDevelopment && { stack: error.stack }),
        },
        meta: {
          timestamp: new Date().toISOString(),
          requestId: context.awsRequestId,
        },
      }),
    };
  }
}

// Custom Error Classes
class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

class UnauthorizedError extends Error {
  constructor(message: string = 'Unauthorized') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

class RateLimitError extends Error {
  constructor(message: string = 'Rate limit exceeded') {
    super(message);
    this.name = 'RateLimitError';
  }
}

class ServiceUnavailableError extends Error {
  constructor(message: string = 'Service temporarily unavailable') {
    super(message);
    this.name = 'ServiceUnavailableError';
  }
}
```

### Rate Limiting Implementation
```typescript
class RateLimiter {
  private redis: Redis; // Assume Redis client for rate limiting
  
  constructor() {
    this.redis = new Redis(process.env.REDIS_URL);
  }

  async checkRateLimit(
    identifier: string, 
    windowMs: number = 60000, // 1 minute
    maxRequests: number = 100
  ): Promise<RateLimitResult> {
    const window = Math.floor(Date.now() / windowMs);
    const key = `rate_limit:${identifier}:${window}`;

    const current = await this.redis.incr(key);
    
    if (current === 1) {
      // Set expiration for first request in window
      await this.redis.expire(key, Math.ceil(windowMs / 1000));
    }

    const remaining = Math.max(0, maxRequests - current);
    const resetTime = (window + 1) * windowMs;

    if (current > maxRequests) {
      throw new RateLimitError('Rate limit exceeded');
    }

    return {
      allowed: true,
      remaining,
      resetTime,
      current,
    };
  }
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  current: number;
}
```

## 7. Performance & Monitoring

### CloudWatch Metrics Integration
```typescript
class MetricsCollector {
  private cloudWatch: CloudWatch;

  constructor() {
    this.cloudWatch = new CloudWatch({ region: process.env.AWS_REGION });
  }

  async recordAPIMetrics(
    endpoint: string,
    statusCode: number,
    responseTime: number,
    cacheHit: boolean = false
  ): Promise<void> {
    const metrics: MetricDatum[] = [
      {
        MetricName: 'ResponseTime',
        Value: responseTime,
        Unit: 'Milliseconds',
        Dimensions: [
          { Name: 'Endpoint', Value: endpoint },
          { Name: 'StatusCode', Value: statusCode.toString() },
        ],
      },
      {
        MetricName: 'RequestCount',
        Value: 1,
        Unit: 'Count',
        Dimensions: [
          { Name: 'Endpoint', Value: endpoint },
          { Name: 'StatusCode', Value: statusCode.toString() },
        ],
      },
    ];

    if (cacheHit) {
      metrics.push({
        MetricName: 'CacheHitRate',
        Value: 1,
        Unit: 'Count',
        Dimensions: [{ Name: 'Endpoint', Value: endpoint }],
      });
    }

    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/API',
      MetricData: metrics,
    }).promise();
  }

  async recordPollingMetrics(
    pollingInterval: number,
    responseTime: number,
    errorRate: number
  ): Promise<void> {
    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/Polling',
      MetricData: [
        {
          MetricName: 'PollingInterval',
          Value: pollingInterval,
          Unit: 'Milliseconds',
        },
        {
          MetricName: 'PollingResponseTime',
          Value: responseTime,
          Unit: 'Milliseconds',
        },
        {
          MetricName: 'PollingErrorRate',
          Value: errorRate,
          Unit: 'Percent',
        },
      ],
    }).promise();
  }
}
```

### API Gateway Caching Configuration
```yaml
# CloudFormation template for caching
CachePolicy:
  Type: AWS::CloudFront::CachePolicy
  Properties:
    CachePolicyConfig:
      Name: translation-api-cache
      DefaultTTL: 30  # 30 seconds for progress endpoints
      MaxTTL: 3600    # 1 hour max
      MinTTL: 0
      ParametersInCacheKeyAndForwardedToOrigin:
        EnableAcceptEncodingGzip: true
        QueryStringsConfig:
          QueryStringBehavior: whitelist
          QueryStrings:
            - jobId
            - version
        HeadersConfig:
          HeaderBehavior: whitelist
          Headers:
            - Authorization
            - If-None-Match
            - X-Api-Key

# API Gateway Method with Caching
ProgressMethod:
  Type: AWS::ApiGateway::Method
  Properties:
    RestApiId: !Ref TranslationAPI
    ResourceId: !Ref ProgressResource
    HttpMethod: GET
    AuthorizationType: AWS_IAM
    Integration:
      Type: AWS_PROXY
      IntegrationHttpMethod: POST
      Uri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${ProgressFunction.Arn}/invocations"
      CacheKeyParameters:
        - method.request.path.jobId
        - method.request.header.Authorization
    MethodResponses:
      - StatusCode: 200
        ResponseParameters:
          method.response.header.Cache-Control: true
          method.response.header.ETag: true
    RequestParameters:
      method.request.path.jobId: true
      method.request.header.Authorization: false
```

## 8. Testing Strategy

### Unit Testing Examples
```typescript
// __tests__/handlers/progress-handler.test.ts
describe('ProgressHandler', () => {
  let handler: ProgressHandler;
  let mockJobStateService: jest.Mocked<JobStateService>;

  beforeEach(() => {
    mockJobStateService = {
      getJobProgress: jest.fn(),
    } as any;
    
    handler = new ProgressHandler();
    (handler as any).jobStateService = mockJobStateService;
  });

  it('returns progress data with proper caching headers', async () => {
    const mockJob = {
      jobId: 'test-job-1',
      status: 'PROCESSING',
      progress: 50,
      chunksProcessed: 5,
      totalChunks: 10,
      lastUpdated: '2024-01-01T12:00:00Z',
    };

    mockJobStateService.getJobProgress.mockResolvedValue(mockJob);

    const event = createMockEvent('GET', '/translation/jobs/test-job-1/progress', {
      pathParameters: { jobId: 'test-job-1' },
      headers: { Authorization: 'Bearer valid-token' },
    });

    const result = await handler.handler(event);

    expect(result.statusCode).toBe(200);
    expect(result.headers['Cache-Control']).toBe('public, max-age=30');
    expect(result.headers['ETag']).toBeDefined();
    
    const body = JSON.parse(result.body);
    expect(body.data.jobId).toBe('test-job-1');
    expect(body.data.nextPollRecommendation).toBeDefined();
  });

  it('handles ETag conditional requests', async () => {
    const etag = '"MTIzNDU2Nzg5MA=="';
    
    const event = createMockEvent('GET', '/translation/jobs/test-job-1/progress', {
      pathParameters: { jobId: 'test-job-1' },
      headers: { 
        Authorization: 'Bearer valid-token',
        'If-None-Match': etag,
      },
    });

    const result = await handler.handler(event);
    
    // Should return 304 if content hasn't changed
    expect(result.statusCode).toBe(304);
  });

  it('returns fallback data on timeout', async () => {
    mockJobStateService.getJobProgress.mockImplementation(
      () => new Promise(resolve => setTimeout(resolve, 1000))
    );

    const event = createMockEvent('GET', '/translation/jobs/test-job-1/progress', {
      pathParameters: { jobId: 'test-job-1' },
      headers: { Authorization: 'Bearer valid-token' },
    });

    const result = await handler.handler(event);

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.data.status).toBe('PROCESSING');
    expect(body.data.progress).toBe(0);
  });
});

// Helper function for creating mock events
function createMockEvent(
  method: string, 
  path: string, 
  overrides: Partial<APIGatewayProxyEvent> = {}
): APIGatewayProxyEvent {
  return {
    httpMethod: method,
    path,
    pathParameters: {},
    queryStringParameters: {},
    headers: {},
    body: null,
    requestContext: {
      requestId: 'test-request-id',
      apiId: 'test-api',
      httpMethod: method,
      path,
      authorizer: undefined,
    } as any,
    ...overrides,
  } as APIGatewayProxyEvent;
}
```

### Integration Testing
```typescript
// __tests__/integration/api-integration.test.ts
describe('API Integration Tests', () => {
  const baseUrl = process.env.TEST_API_URL || 'http://localhost:3000';
  let authToken: string;

  beforeAll(async () => {
    // Get auth token for tests
    const loginResponse = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'test123',
      }),
    });
    
    const loginData = await loginResponse.json();
    authToken = loginData.data.token;
  });

  it('handles polling workflow correctly', async () => {
    // Create a test job
    const createJobResponse = await fetch(`${baseUrl}/translation/jobs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        fileId: 'test-file-123',
        targetLanguage: 'spanish',
        attestationId: 'test-attestation-456',
      }),
    });

    expect(createJobResponse.status).toBe(201);
    const createJobData = await createJobResponse.json();
    const jobId = createJobData.data.jobId;

    // Poll for progress
    let attempts = 0;
    let completed = false;
    
    while (attempts < 10 && !completed) {
      const progressResponse = await fetch(
        `${baseUrl}/translation/jobs/${jobId}/progress`,
        {
          headers: { 'Authorization': `Bearer ${authToken}` },
        }
      );

      expect(progressResponse.status).toBe(200);
      expect(progressResponse.headers.get('Cache-Control')).toContain('max-age=30');

      const progressData = await progressResponse.json();
      console.log(`Progress: ${progressData.data.progress}%`);

      if (progressData.data.status === 'COMPLETED') {
        completed = true;
      }

      // Wait for recommended polling interval
      const nextPoll = progressData.data.nextPollRecommendation || 15000;
      await new Promise(resolve => setTimeout(resolve, nextPoll));
      attempts++;
    }

    expect(completed).toBe(true);
  });

  it('respects rate limits', async () => {
    const requests = Array.from({ length: 110 }, (_, i) =>
      fetch(`${baseUrl}/translation/jobs/test-job/status`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      })
    );

    const responses = await Promise.all(requests);
    const rateLimitedResponses = responses.filter(r => r.status === 429);
    
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
  });
});
```

## 9. Deployment & Configuration

### CloudFormation Template
```yaml
# api-gateway-lambda.yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Parameters:
  Environment:
    Type: String
    AllowedValues: [development, staging, production]
    Default: development
  
Resources:
  # API Gateway
  TranslationAPI:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Sub "translation-service-api-${Environment}"
      Description: "Long-Form Translation Service REST API"
      EndpointConfiguration:
        Types: [REGIONAL]
      
  # API Gateway Caching
  APICacheCluster:
    Type: AWS::ApiGateway::RequestValidator
    Properties:
      RestApiId: !Ref TranslationAPI
      ValidateRequestBody: true
      ValidateRequestParameters: true

  # Lambda Functions
  ProgressFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub "translation-progress-${Environment}"
      CodeUri: dist/handlers/progress-handler.js
      Handler: index.handler
      Runtime: nodejs18.x
      Architecture: arm64  # Cost optimization
      MemorySize: 512
      Timeout: 30
      Environment:
        Variables:
          NODE_ENV: !Ref Environment
          DYNAMODB_TABLE: !Ref JobsTable
          REDIS_URL: !Ref RedisCluster
      Events:
        GetProgress:
          Type: Api
          Properties:
            RestApiId: !Ref TranslationAPI
            Path: /translation/jobs/{jobId}/progress
            Method: GET
            Caching:
              Enabled: true
              TTLInSeconds: 30
              KeyParameters:
                - method.request.path.jobId
                - method.request.header.Authorization

  AttestationFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub "translation-attestation-${Environment}"
      CodeUri: dist/handlers/attestation-handler.js
      Handler: index.handler
      Runtime: nodejs18.x
      Architecture: arm64
      MemorySize: 256
      Timeout: 15
      Environment:
        Variables:
          NODE_ENV: !Ref Environment
          DYNAMODB_TABLE: !Ref AttestationsTable
          LEGAL_BUCKET: !Ref LegalDocumentsBucket
      Events:
        CreateAttestation:
          Type: Api
          Properties:
            RestApiId: !Ref TranslationAPI
            Path: /legal/attestation
            Method: POST

  # DynamoDB Tables
  JobsTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub "translation-jobs-${Environment}"
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: jobId
          AttributeType: S
        - AttributeName: userId
          AttributeType: S
      KeySchema:
        - AttributeName: jobId
          KeyType: HASH
      GlobalSecondaryIndexes:
        - IndexName: user-jobs-index
          KeySchema:
            - AttributeName: userId
              KeyType: HASH
          Projection:
            ProjectionType: ALL

  # ElastiCache Redis for Rate Limiting
  RedisCluster:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      CacheNodeType: cache.t3.micro
      Engine: redis
      NumCacheNodes: 1
      VpcSecurityGroupIds:
        - !Ref RedisSecurityGroup

Outputs:
  APIGatewayURL:
    Description: "API Gateway endpoint URL"
    Value: !Sub "https://${TranslationAPI}.execute-api.${AWS::Region}.amazonaws.com/${Environment}"
    Export:
      Name: !Sub "${AWS::StackName}-api-url"
```

### Environment Configuration
```typescript
// config/api-config.ts
interface APIConfig {
  corsOrigins: string[];
  rateLimits: {
    default: { windowMs: number; maxRequests: number };
    polling: { windowMs: number; maxRequests: number };
    upload: { windowMs: number; maxRequests: number };
  };
  caching: {
    defaultTTL: number;
    progressTTL: number;
    legalTermsTTL: number;
  };
  timeouts: {
    defaultTimeout: number;
    uploadTimeout: number;
    longRunningTimeout: number;
  };
}

const environments: Record<string, APIConfig> = {
  development: {
    corsOrigins: ['http://localhost:3000', 'http://localhost:3001'],
    rateLimits: {
      default: { windowMs: 60000, maxRequests: 1000 },
      polling: { windowMs: 60000, maxRequests: 200 },
      upload: { windowMs: 300000, maxRequests: 10 },
    },
    caching: {
      defaultTTL: 10,
      progressTTL: 10,
      legalTermsTTL: 300,
    },
    timeouts: {
      defaultTimeout: 10000,
      uploadTimeout: 30000,
      longRunningTimeout: 60000,
    },
  },
  production: {
    corsOrigins: ['https://translation-service.com'],
    rateLimits: {
      default: { windowMs: 60000, maxRequests: 100 },
      polling: { windowMs: 60000, maxRequests: 60 },
      upload: { windowMs: 300000, maxRequests: 5 },
    },
    caching: {
      defaultTTL: 30,
      progressTTL: 30,
      legalTermsTTL: 3600,
    },
    timeouts: {
      defaultTimeout: 5000,
      uploadTimeout: 30000,
      longRunningTimeout: 30000,
    },
  },
};

export const getAPIConfig = (): APIConfig => {
  const env = process.env.NODE_ENV as keyof typeof environments;
  return environments[env] || environments.development;
};
```

---

This comprehensive API Gateway & Lambda Functions design provides a robust, scalable backend with optimized polling endpoints, comprehensive error handling, and production-ready monitoring. The architecture prioritizes response time targets while maintaining cost efficiency through ARM64 functions and intelligent caching strategies.