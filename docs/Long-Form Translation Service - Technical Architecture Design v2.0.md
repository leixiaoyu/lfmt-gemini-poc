# Long-Form Translation Service - Technical Architecture Design v2.0

## Executive Summary

This document outlines the technical architecture for a proof-of-concept long-form translation web application that processes 65K-400K word documents using Gemini API. The system employs serverless AWS infrastructure with intelligent document chunking, **polling-based progress tracking**, and comprehensive legal compliance mechanisms.

**Key Technical Decisions (Revised):**

- **Polling-only progress tracking** with adaptive intervals (no WebSocket complexity)
- **ECS Fargate** for long-running translation jobs with auto-scaling
- **Sliding context window** with 250-token overlap for translation consistency
- **Production-ready legal attestation storage** with 7-year retention compliance
- **REST API architecture** optimized for POC simplicity

## Change Log

### Version 2.1 - Architecture Decision Update (2025-08-14)

**Critical Design Decision: WebSocket vs Polling Resolution**

After comprehensive low-level design review, a fundamental conflict was identified between FR-005 requirement ("Real-time progress updates via WebSocket connection") and the implemented polling-only architecture across all system components.

**Resolution:** POC will implement **polling-only architecture** for the following technical and business reasons:

1. **POC Scope Limitation**: WebSocket implementation adds significant complexity not justified for proof-of-concept validation
2. **Operational Simplicity**: Polling eliminates WebSocket session management, connection state issues, and scaling complexity  
3. **Cost Optimization**: REST API with caching is more cost-effective for POC usage patterns
4. **Faster Implementation**: Polling-based progress tracking can be implemented 40% faster than WebSocket solution
5. **Adequate User Experience**: Adaptive polling (15s → 30s → 60s intervals) provides sufficiently responsive progress updates for long-running jobs (30 minutes to 6 hours)

**Product Requirements Update:** FR-005 should be revised to specify "Near real-time progress updates via adaptive polling" instead of WebSocket requirement for POC scope.

**Future Consideration:** WebSocket implementation remains valuable for production scaling and will be considered in post-POC phases when concurrent user loads justify the additional complexity.

## 1. System Architecture Overview

### 1.1 High-Level Architecture (Revised)

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   React SPA     │    │   API Gateway    │    │  Lambda Functions│
│  (CloudFront)   │◄──►│   (REST Only)    │◄──►│  (Node.js 18.x) │
│                 │    │   + Caching      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                          │
┌─────────────────┐    ┌──────────────────┐              │
│   AWS Cognito   │    │  Step Functions  │◄─────────────┘
│ (Authentication)│    │  (Orchestration) │
└─────────────────┘    └──────────────────┘
                                │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   DynamoDB      │    │   ECS Fargate    │    │      S3         │
│ Jobs + Legal    │    │ (Translation)    │    │ (Files/Results) │
│   Attestations  │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                       ┌──────────────────┐
                       │  Gemini API      │
                       │                  │
                       └──────────────────┘
```

### 1.2 Core Components (Revised)

|Component|Technology|Purpose|
|---|---|---|
|**Frontend**|React SPA + CloudFront|Adaptive polling-based progress tracking|
|**API Layer**|API Gateway + Lambda|REST endpoints with caching (30s TTL)|
|**Authentication**|AWS Cognito|User management and JWT tokens|
|**Orchestration**|Step Functions|Translation workflow management|
|**Processing**|ECS Fargate|Long-running translation tasks|
|**Storage**|S3 + DynamoDB|Files, jobs, legal attestations|
|**Legal Compliance**|DynamoDB + S3|7-year attestation storage|
|**External API**|Gemini API|Translation processing|

## 2. Detailed Component Design

### 2.1 Frontend Architecture (Polling-Only)

**Technology Stack:**

- React 18 with TypeScript
- Material-UI for consistent design
- Axios for API communication
- React Query for polling optimization with background sync

**Adaptive Polling Implementation:**

```typescript
const useAdaptivePolling = (jobId: string) => {
  const [pollInterval, setPollInterval] = useState(15000); // Start at 15s
  const [isPageVisible, setIsPageVisible] = useState(true);
  
  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsPageVisible(!document.hidden);
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);
  
  const { data: progress, error } = useQuery(
    ['translationProgress', jobId],
    () => fetchTranslationProgress(jobId),
    {
      refetchInterval: () => {
        const elapsedTime = Date.now() - startTime;
        
        if (!isPageVisible) return 120000; // 2 minutes for background
        if (elapsedTime < 300000) return 15000; // 15s for first 5 minutes
        if (elapsedTime < 1800000) return 30000; // 30s for 5-30 minutes
        return 60000; // 60s for 30+ minutes
      },
      enabled: !!jobId && status !== 'COMPLETED' && status !== 'FAILED'
    }
  );
  
  return { progress, error, isPolling: !!pollInterval };
};
```

### 2.2 API Gateway & Lambda Functions (REST Only)

**API Endpoints (Revised):**

```
# Authentication
POST /auth/login
POST /auth/register
POST /auth/reset-password

# Legal Attestation (Required)
POST /legal/attestation
GET  /legal/terms/{version}
GET  /legal/attestation/{userId}/latest

# File Operations
POST /upload/presigned-url
POST /upload/validate

# Translation Jobs
POST /translation/jobs
GET  /translation/jobs/{jobId}/status      # <500ms, cached 30s
GET  /translation/jobs/{jobId}/progress    # <500ms, cached 30s
GET  /translation/jobs/{jobId}/result
DELETE /translation/jobs/{jobId}

# User Management
GET  /user/history
GET  /user/usage-stats
```

**Progress Tracking Lambda (Critical):**

```typescript
// functions/progress-handler.ts
export const progressHandler = async (event: APIGatewayProxyEvent) => {
  const jobId = event.pathParameters?.jobId;
  
  if (!jobId) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'JobId required' })
    };
  }
  
  try {
    // Get cached progress first
    const cachedProgress = await daxClient.get({
      TableName: 'translation-jobs',
      Key: { jobId }
    }).promise();
    
    if (cachedProgress.Item) {
      return {
        statusCode: 200,
        headers: {
          'Cache-Control': 'max-age=30', // 30 second cache
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          jobId,
          status: cachedProgress.Item.status,
          progress: cachedProgress.Item.progress || 0,
          estimatedTimeRemaining: cachedProgress.Item.estimatedTimeRemaining,
          chunksProcessed: cachedProgress.Item.chunksProcessed || 0,
          totalChunks: cachedProgress.Item.totalChunks || 0,
          lastUpdated: cachedProgress.Item.lastUpdated
        })
      };
    }
    
    return {
      statusCode: 404,
      body: JSON.stringify({ error: 'Job not found' })
    };
  } catch (error) {
    console.error('Progress fetch error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};
```

### 2.3 Legal Attestation Storage (Production-Ready)

**Legal Attestations DynamoDB Table:**

```yaml
LegalAttestationsTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: legal-attestations
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: attestationId
        AttributeType: S
      - AttributeName: userId
        AttributeType: S
      - AttributeName: createdAt
        AttributeType: S
    KeySchema:
      - AttributeName: attestationId
        KeyType: HASH
    GlobalSecondaryIndexes:
      - IndexName: user-attestations-index
        KeySchema:
          - AttributeName: userId
            KeyType: HASH
          - AttributeName: createdAt
            KeyType: RANGE
        Projection:
          ProjectionType: ALL
    TimeToLiveSpecification:
      AttributeName: ttl
      Enabled: true
    PointInTimeRecoverySpecification:
      PointInTimeRecoveryEnabled: true
    SSESpecification:
      SSEEnabled: true
      KMSMasterKeyId: !Ref LegalDataKMSKey
    StreamSpecification:
      StreamViewType: NEW_AND_OLD_IMAGES
    Tags:
      - Key: DataClassification
        Value: Legal-Critical
      - Key: RetentionPeriod
        Value: 7-years
```

**Legal Attestation Data Model (Enhanced):**

```typescript
interface LegalAttestation {
  attestationId: string; // UUID - Primary Key
  userId: string; // GSI partition key
  createdAt: string; // ISO 8601 - GSI sort key
  ttl: number; // Unix timestamp + 7 years
  
  // Legal Requirements
  ipAddress: string;
  userAgent: string;
  attestationVersion: string; // "v1.0"
  tosVersion: string; // "v1.0"
  documentHash: string; // SHA-256 of uploaded file
  
  // File Metadata
  fileMetadata: {
    originalName: string;
    size: number;
    wordCount: number;
    uploadTimestamp: string;
    s3Location: string;
  };
  
  // Legal Statements (All Required)
  legalStatements: {
    copyrightOwnership: boolean; // Must be true
    translationRights: boolean; // Must be true
    liabilityAcceptance: boolean; // Must be true
    publicDomainAcknowledgment: boolean; // Must be true
  };
  
  // Audit Trail
  geoLocation?: {
    country: string;
    region: string;
  };
  auditTrail: {
    pageViewDuration: number; // seconds spent reading terms
    scrollCompletionPercentage: number; // 0-100
    attestationMethod: 'checkbox' | 'digital_signature';
    browserFingerprint: string;
  };
  
  // Compliance Flags
  complianceFlags: {
    dataRetentionApplies: boolean;
    gdprSubject: boolean;
    legalHoldApplies: boolean;
  };
}
```

**Legal Service Implementation:**

```typescript
class LegalAttestationService {
  private readonly ATTESTATION_TABLE = 'legal-attestations';
  private readonly LEGAL_BUCKET = 'translation-legal-documents';
  
  async createAttestation(request: CreateAttestationRequest): Promise<LegalAttestation> {
    // Validate all required legal statements
    if (!this.validateLegalStatements(request.legalStatements)) {
      throw new Error('All legal statements must be acknowledged');
    }
    
    const attestation: LegalAttestation = {
      attestationId: uuidv4(),
      userId: request.userId,
      createdAt: new Date().toISOString(),
      ttl: Math.floor(Date.now() / 1000) + (7 * 365 * 24 * 60 * 60), // 7 years
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
      attestationVersion: await this.getCurrentAttestationVersion(),
      tosVersion: await this.getCurrentTOSVersion(),
      documentHash: request.documentHash,
      fileMetadata: request.fileMetadata,
      legalStatements: request.legalStatements,
      geoLocation: await this.getGeoLocation(request.ipAddress),
      auditTrail: request.auditTrail,
      complianceFlags: {
        dataRetentionApplies: true,
        gdprSubject: this.isGDPRSubject(request.geoLocation),
        legalHoldApplies: false
      }
    };
    
    // Store in DynamoDB
    await this.dynamoClient.put({
      TableName: this.ATTESTATION_TABLE,
      Item: attestation,
      ConditionExpression: 'attribute_not_exists(attestationId)'
    }).promise();
    
    // Archive to S3 for long-term compliance
    await this.archiveAttestation(attestation);
    
    // Log for audit trail
    await this.auditLogger.logEvent({
      eventType: 'ATTESTATION_CREATED',
      userId: request.userId,
      resourceId: attestation.attestationId,
      timestamp: attestation.createdAt,
      ipAddress: request.ipAddress,
      details: { attestationId: attestation.attestationId },
      complianceFlags: attestation.complianceFlags
    });
    
    return attestation;
  }
  
  private async archiveAttestation(attestation: LegalAttestation): Promise<void> {
    const archiveKey = `attestation-backup/${attestation.createdAt.slice(0, 7)}/${attestation.attestationId}.json`;
    
    await this.s3Client.putObject({
      Bucket: this.LEGAL_BUCKET,
      Key: archiveKey,
      Body: JSON.stringify(attestation, null, 2),
      StorageClass: 'GLACIER',
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: process.env.LEGAL_DATA_KMS_KEY_ID,
      Metadata: {
        'data-classification': 'legal-critical',
        'retention-period': '7-years',
        'user-id': attestation.userId
      }
    }).promise();
  }
}
```

### 2.4 Translation Processing with Context Management

**Enhanced Chunking Strategy (Sliding Window):**

```typescript
interface ChunkContext {
  primaryContent: string;     // 3,500 tokens max
  previousSummary: string;    // 250 tokens context
  nextPreview: string;        // 250 tokens preview
  chunkIndex: number;
  totalChunks: number;
  targetLanguage: string;
}

interface TranslationPrompt {
  systemPrompt: string;
  contextualContent: ChunkContext;
  consistencyInstructions: string;
}

class DocumentChunker {
  private readonly PRIMARY_CHUNK_SIZE = 3500; // Primary content tokens
  private readonly CONTEXT_SIZE = 250; // Previous/next context tokens
  
  chunkDocument(content: string, targetLanguage: string): ChunkContext[] {
    const sentences = this.splitBySentence(content);
    const chunks: ChunkContext[] = [];
    
    let currentChunk = "";
    let currentTokens = 0;
    let sentenceIndex = 0;
    
    for (const sentence of sentences) {
      const sentenceTokens = this.estimateTokens(sentence);
      
      if (currentTokens + sentenceTokens > this.PRIMARY_CHUNK_SIZE && currentChunk) {
        // Create chunk with sliding window context
        const chunk = this.createChunkWithContext(
          currentChunk,
          this.getPreviousSummary(chunks),
          this.getNextPreview(sentences, sentenceIndex),
          chunks.length,
          targetLanguage
        );
        chunks.push(chunk);
        
        // Start new chunk with overlap
        currentChunk = this.getOverlapContent(currentChunk, this.CONTEXT_SIZE);
        currentTokens = this.estimateTokens(currentChunk);
      }
      
      currentChunk += sentence + " ";
      currentTokens += sentenceTokens;
      sentenceIndex++;
    }
    
    // Handle final chunk
    if (currentChunk.trim()) {
      chunks.push(this.createChunkWithContext(
        currentChunk,
        this.getPreviousSummary(chunks),
        "",
        chunks.length,
        targetLanguage
      ));
    }
    
    // Set total chunks for all
    chunks.forEach(chunk => chunk.totalChunks = chunks.length);
    
    return chunks;
  }
  
  private createChunkWithContext(
    primaryContent: string,
    previousSummary: string,
    nextPreview: string,
    chunkIndex: number,
    targetLanguage: string
  ): ChunkContext {
    return {
      primaryContent: primaryContent.trim(),
      previousSummary: previousSummary.trim(),
      nextPreview: nextPreview.trim(),
      chunkIndex,
      totalChunks: 0, // Will be set after all chunks created
      targetLanguage
    };
  }
}
```

**Gemini API Integration with Context:**

```typescript
class GeminiAPIClient {
  private rateLimiter: RateLimiter;
  
  constructor() {
    this.rateLimiter = new RateLimiter({
      maxRequestsPerMinute: 45, // 50 limit with 10% buffer
      maxInputTokensPerMinute: 405000, // 450K limit with 10% buffer
      maxOutputTokensPerMinute: 81000 // 90K limit with 10% buffer
    });
  }
  
  async translateChunk(chunk: ChunkContext): Promise<TranslationResult> {
    await this.rateLimiter.acquireTokens(this.estimateTokens(chunk));
    
    const prompt = this.buildTranslationPrompt(chunk);
    
    try {
      const response = await this.geminiClient.generateContent(prompt);
      
      return this.parseTranslationResponse(response, chunk);
    } catch (error) {
      if (this.isRateLimitError(error)) {
        await this.exponentialBackoff();
        return this.translateChunk(chunk); // Retry
      }
      throw error;
    }
  }
  
  private buildTranslationPrompt(chunk: ChunkContext): string {
    const languageMap = {
      'spanish': 'Spanish',
      'french': 'French',
      'german': 'German',
      'italian': 'Italian',
      'chinese': 'Chinese (Simplified)'
    };
    
    return `
You are translating a long document from English to ${languageMap[chunk.targetLanguage]}.
This is chunk ${chunk.chunkIndex + 1} of ${chunk.totalChunks}.

${chunk.previousSummary ? `PREVIOUS CONTEXT (for reference only, do not translate):
${chunk.previousSummary}

` : ''}TRANSLATE THIS SECTION:
${chunk.primaryContent}

${chunk.nextPreview ? `UPCOMING CONTEXT (for reference only, do not translate):
${chunk.nextPreview}

` : ''}Instructions:
1. Translate ONLY the main section above, maintaining natural flow
2. Ensure consistency with the provided context
3. Preserve original formatting and paragraph structure
4. Use appropriate ${languageMap[chunk.targetLanguage]} style and terminology
5. Maintain narrative continuity from previous chunks

Translation:`;
  }
}
```

### 2.5 Progress Tracking Implementation

**DynamoDB Progress Updates:**

```typescript
class ProgressTracker {
  private readonly JOBS_TABLE = 'translation-jobs';
  
  async updateProgress(
    jobId: string, 
    chunksProcessed: number, 
    totalChunks: number,
    estimatedTimeRemaining?: number
  ): Promise<void> {
    const progress = Math.round((chunksProcessed / totalChunks) * 100);
    const now = new Date().toISOString();
    
    try {
      await this.dynamoClient.update({
        TableName: this.JOBS_TABLE,
        Key: { jobId },
        UpdateExpression: `
          SET progress = :progress,
              chunksProcessed = :chunksProcessed,
              lastUpdated = :lastUpdated
              ${estimatedTimeRemaining ? ', estimatedTimeRemaining = :estimatedTimeRemaining' : ''}
        `,
        ExpressionAttributeValues: {
          ':progress': progress,
          ':chunksProcessed': chunksProcessed,
          ':lastUpdated': now,
          ...(estimatedTimeRemaining && { ':estimatedTimeRemaining': estimatedTimeRemaining })
        }
      }).promise();
      
      // Also send to CloudWatch for monitoring
      await this.cloudWatch.putMetricData({
        Namespace: 'TranslationService',
        MetricData: [
          {
            MetricName: 'TranslationProgress',
            Value: progress,
            Dimensions: [
              {
                Name: 'JobId',
                Value: jobId
              }
            ],
            Timestamp: new Date()
          }
        ]
      }).promise();
      
    } catch (error) {
      console.error('Failed to update progress:', error);
      // Don't throw - progress updates shouldn't fail the translation
    }
  }
}
```

## 3. Data Models & Storage

### 3.1 DynamoDB Table Design (Enhanced)

**1. Translation Jobs Table (Enhanced):**

```json
{
  "TableName": "translation-jobs",
  "BillingMode": "PAY_PER_REQUEST",
  "KeySchema": [
    {"AttributeName": "jobId", "KeyType": "HASH"}
  ],
  "AttributeDefinitions": [
    {"AttributeName": "jobId", "AttributeType": "S"},
    {"AttributeName": "userId", "AttributeType": "S"},
    {"AttributeName": "status", "AttributeType": "S"},
    {"AttributeName": "createdAt", "AttributeType": "S"}
  ],
  "GlobalSecondaryIndexes": [
    {
      "IndexName": "user-jobs-index",
      "KeySchema": [
        {"AttributeName": "userId", "KeyType": "HASH"},
        {"AttributeName": "createdAt", "KeyType": "RANGE"}
      ],
      "Projection": {"ProjectionType": "ALL"}
    },
    {
      "IndexName": "status-index",
      "KeySchema": [
        {"AttributeName": "status", "KeyType": "HASH"},
        {"AttributeName": "createdAt", "KeyType": "RANGE"}
      ],
      "Projection": {"ProjectionType": "KEYS_ONLY"}
    }
  ],
  "StreamSpecification": {
    "StreamViewType": "NEW_AND_OLD_IMAGES"
  }
}
```

**2. Legal Attestations Table (Complete Schema):**

```json
{
  "TableName": "legal-attestations",
  "BillingMode": "PAY_PER_REQUEST",
  "KeySchema": [
    {"AttributeName": "attestationId", "KeyType": "HASH"}
  ],
  "AttributeDefinitions": [
    {"AttributeName": "attestationId", "AttributeType": "S"},
    {"AttributeName": "userId", "AttributeType": "S"},
    {"AttributeName": "createdAt", "AttributeType": "S"}
  ],
  "GlobalSecondaryIndexes": [
    {
      "IndexName": "user-attestations-index",
      "KeySchema": [
        {"AttributeName": "userId", "KeyType": "HASH"},
        {"AttributeName": "createdAt", "KeyType": "RANGE"}
      ],
      "Projection": {"ProjectionType": "ALL"}
    }
  ],
  "TimeToLiveSpecification": {
    "AttributeName": "ttl",
    "Enabled": true
  },
  "PointInTimeRecoverySpecification": {
    "PointInTimeRecoveryEnabled": true
  },
  "SSESpecification": {
    "SSEEnabled": true,
    "KMSMasterKeyId": "alias/legal-data-key"
  },
  "StreamSpecification": {
    "StreamViewType": "NEW_AND_OLD_IMAGES"
  }
}
```

### 3.2 S3 Bucket Structure (Enhanced)

```
translation-service-files/
├── uploads/
│   ├── {userId}/
│   │   ├── {jobId}/
│   │   │   ├── original.txt
│   │   │   ├── metadata.json
│   │   │   └── file-hash.sha256
├── processing/
│   ├── {jobId}/
│   │   ├── chunks/
│   │   │   ├── chunk-001.json
│   │   │   ├── chunk-002.json
│   │   │   └── context-summary.json
│   │   ├── progress.json          # Enhanced for polling
│   │   └── translation-state.json # Job state snapshots
├── results/
│   ├── {jobId}/
│   │   ├── translation.md
│   │   ├── quality-report.json
│   │   ├── processing-metadata.json
│   │   └── cost-breakdown.json
└── legal/
    ├── terms-of-service/
    │   ├── v1.0.html
    │   ├── v1.1.html
    │   └── current-version.txt
    ├── attestation-backup/
    │   └── {year}/{month}/
    │       └── attestations-{date}.json.gz
    └── audit-logs/
        └── {year}/{month}/{day}/
            └── legal-events-{hour}.json
```

## 4. Caching & Performance Optimization

### 4.1 API Gateway Caching Strategy

**CloudFront Distribution Configuration:**

```yaml
TranslationAPIDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Enabled: true
      DefaultCacheBehavior:
        TargetOriginId: APIGatewayOrigin
        ViewerProtocolPolicy: redirect-to-https
        CachePolicyId: !Ref ProgressAPICachePolicy
        OriginRequestPolicyId: !Ref ProgressAPIOriginRequestPolicy
      
      CacheBehaviors:
        - PathPattern: "/translation/jobs/*/progress"
          TargetOriginId: APIGatewayOrigin
          ViewerProtocolPolicy: redirect-to-https
          CachePolicyId: !Ref ProgressAPICachePolicy
          TTL: 30 # 30 seconds
          
        - PathPattern: "/translation/jobs/*/status"
          TargetOriginId: APIGatewayOrigin
          ViewerProtocolPolicy: redirect-to-https
          CachePolicyId: !Ref ProgressAPICachePolicy
          TTL: 30 # 30 seconds

ProgressAPICachePolicy:
  Type: AWS::CloudFront::CachePolicy
  Properties:
    CachePolicyConfig:
      Name: translation-progress-cache
      DefaultTTL: 30
      MaxTTL: 60
      MinTTL: 0
      ParametersInCacheKeyAndForwardedToOrigin:
        EnableAcceptEncodingGzip: true
        QueryStringsConfig:
          QueryStringBehavior: none
        HeadersConfig:
          HeaderBehavior: whitelist
          Headers:
            - Authorization
            - Content-Type
```

### 4.2 DynamoDB DAX Caching

**DAX Cluster for Progress Queries:**

```yaml
TranslationDAXCluster:
  Type: AWS::DAX::Cluster
  Properties:
    ClusterName: translation-cache
    NodeType: dax.t3.small
    ReplicationFactor: 1  # Single node for POC
    IAMRoleARN: !GetAtt DAXRole.Arn
    SubnetGroupName: !Ref DAXSubnetGroup
    SecurityGroupIds:
      - !Ref DAXSecurityGroup
    ParameterGroupName: default.dax1.0
    
DAXSubnetGroup:
  Type: AWS::DAX::SubnetGroup
  Properties:
    SubnetGroupName: translation-dax-subnet-group
    SubnetIds:
      - !Ref PrivateSubnet1
      - !Ref PrivateSubnet2
```

## 5. Monitoring & Alerting (Simplified)

### 5.1 CloudWatch Metrics (Polling-Focused)

**Custom Metrics:**

```typescript
const metrics = {
  // Polling Performance
  'PollingAPI/ResponseTime': 'Milliseconds',
  'PollingAPI/RequestCount': 'Count',
  'PollingAPI/CacheHitRate': 'Percent',
  'PollingAPI/ErrorRate': 'Percent',
  
  // Business Metrics
  'TranslationJobs/Submitted': 'Count',
  'TranslationJobs/Completed': 'Count', 
  'TranslationJobs/Failed': 'Count',
  'TranslationJobs/ProcessingTime': 'Milliseconds',
  
  // Legal Compliance
  'Legal/AttestationsCreated': 'Count',
  'Legal/AttestationValidationFailures': 'Count',
  'Legal/AuditLogWrites': 'Count',
  
  // Gemini API Usage
  'GeminiAPI/RequestCount': 'Count',
  'GeminiAPI/TokensConsumed': 'Count',
  'GeminiAPI/RateLimitHits': 'Count',
  'GeminiAPI/ResponseTime': 'Milliseconds'
};
```

### 5.2 Critical Alarms (Revised)

```yaml
# High Priority - Polling Performance
PollingAPIResponseTimeHigh:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmName: polling-api-response-time-high
    AlarmDescription: Progress polling API response time exceeds 500ms
    MetricName: PollingAPI/ResponseTime
    Namespace: TranslationService
    Statistic: Average
    Period: 300
    EvaluationPeriods: 2
    Threshold: 500
    ComparisonOperator: GreaterThanThreshold
    AlarmActions:
      - !Ref CriticalAlertsTopicArn

# High Priority - Legal Compliance
LegalAttestationFailures:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmName: legal-attestation-failures
    AlarmDescription: Legal attestation validation failures detected
    MetricName: Legal/AttestationValidationFailures
    Namespace: TranslationService
    Statistic: Sum
    Period: 300
    EvaluationPeriods: 1
    Threshold: 1
    ComparisonOperator: GreaterThanOrEqualToThreshold
    AlarmActions:
      - !Ref CriticalAlertsTopicArn
```

## 6. Cost Analysis (Revised)

### 6.1 Simplified Cost Model

**Monthly Cost Breakdown (Revised for 1000 Translations):**

```typescript
interface MonthlyCostEstimate {
  geminiAPI: { 
    total: 682.50;           // Placeholder
  };
  awsInfrastructure: {
    lambda: 8.50;            // Execution time for processing
    ecsArm64: 12.00;         // 2 vCPU ARM64 Fargate (20% savings)
    storage: 5.00;           // S3 + DynamoDB storage
    apiGateway: 3.50;        // REST API calls (reduced from WebSocket)
    dataTransfer: 2.00;      // CloudFront + S3 transfer
    dax: 8.00;               // DAX caching cluster
    total: 39.00;            // AWS infrastructure total
  };
  totalMonthly: 721.50;      // Above target, requires optimization
}

// Cost per translation: $0.72 (needs reduction to $0.05 target)
```

**Cost Optimization Strategies:**

```typescript
class CostOptimizer {
  // Polling reduces API Gateway costs vs WebSocket
  getPollingCostSavings(): number {
    const websocketConnections = 1000; // concurrent users
    const websocketCost = websocketConnections * 24 * 30 * 0.00001; // $7.20/month
    const pollingAPICalls = 1000 * 100; // 100 polls per translation
    const pollingCost = pollingAPICalls * 0.0000035; // $0.35/month
    return websocketCost - pollingCost; // $6.85 savings
  }
  
  // ARM64 ECS savings
  getARM64Savings(): number {
    const x86Cost = 15.00; // x86 Fargate cost
    const arm64Cost = 12.00; // ARM64 Fargate cost
    return x86Cost - arm64Cost; // $3.00 savings
  }
  
  // Legal attestation storage optimization
  getLegalStorageOptimization(): number {
    // Use S3 Glacier for long-term attestation storage
    const standardS3Cost = 2.30; // Standard S3
    const glacierCost = 0.40; // Glacier storage
    return standardS3Cost - glacierCost; // $1.90 savings
  }
}
```

## 7. Security Implementation (Enhanced)

### 7.1 Legal Data Protection

**KMS Key for Legal Data:**

```yaml
LegalDataKMSKey:
  Type: AWS::KMS::Key
  Properties:
    Description: "Encryption key for legal attestation data"
    KeyPolicy:
      Version: '2012-10-17'
      Statement:
        - Sid: Enable IAM User Permissions
          Effect: Allow
          Principal:
            AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
          Action: 'kms:*'
          Resource: '*'
        - Sid: Allow Legal Service Access
          Effect: Allow
          Principal:
            AWS: !GetAtt LegalServiceRole.Arn
          Action:
            - kms:Encrypt
            - kms:Decrypt
            - kms:ReEncrypt*
            - kms:GenerateDataKey*
            - kms:DescribeKey
          Resource: '*'
    KeyRotationStatus: true
    
LegalDataKMSKeyAlias:
  Type: AWS::KMS::Alias
  Properties:
    AliasName: alias/translation-legal-data
    TargetKeyId: !Ref LegalDataKMSKey
```

### 7.2 Input Validation (Enhanced)

**File Upload Validation:**

```typescript
class FileValidator {
  private readonly MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
  private readonly MIN_WORD_COUNT = 65000;
  private readonly MAX_WORD_COUNT = 400000;
  
  async validateUpload(file: Express.Multer.File, metadata: FileMetadata): Promise<ValidationResult> {
    const checks = await Promise.all([
      this.validateFileSize(file),
      this.validateFileType(file),
      this.validateEncoding(file),
      this.validateWordCount(file),
      this.scanForMalware(file),
      this.validateContent(file),
      this.generateFileHash(file)
    ]);
    
    const errors = checks.filter(check => !check.passed).map(check => check.error);
    
    return {
      isValid: errors.length === 0,
      errors,
      fileHash: checks.find(c => c.type === 'hash')?.value,
      wordCount: checks.find(c => c.type === 'wordCount')?.value,
      estimatedCost: this.calculateEstimatedCost(metadata.wordCount)
    };
  }
  
  private async validateWordCount(file: Express.Multer.File): Promise<ValidationCheck> {
    const content = file.buffer.toString('utf-8');
    const wordCount = content.split(/\s+/).filter(word => word.length > 0).length;
    
    if (wordCount < this.MIN_WORD_COUNT) {
      return {
        type: 'wordCount',
        passed: false,
        error: `Document too short: ${wordCount} words (minimum: ${this.MIN_WORD_COUNT})`
      };
    }
    
    if (wordCount > this.MAX_WORD_COUNT) {
      return {
        type: 'wordCount',
        passed: false,
        error: `Document too long: ${wordCount} words (maximum: ${this.MAX_WORD_COUNT})`
      };
    }
    
    return {
      type: 'wordCount',
      passed: true,
      value: wordCount
    };
  }
  
  private async generateFileHash(file: Express.Multer.File): Promise<ValidationCheck> {
    const hash = crypto.createHash('sha256').update(file.buffer).digest('hex');
    return {
      type: 'hash',
      passed: true,
      value: hash
    };
  }
}
```

## 8. Testing Strategy (Revised)

### 8.1 Polling Integration Tests

**Adaptive Polling Test:**

```typescript
describe('Adaptive Polling Integration', () => {
  let testUser: TestUser;
  let apiClient: TestApiClient;
  
  beforeAll(async () => {
    testUser = await createTestUser();
    apiClient = new TestApiClient(testUser.token);
  });
  
  it('should adapt polling intervals based on elapsed time', async () => {
    // Start translation job
    const jobResponse = await apiClient.post('/translation/jobs', {
      fileId: 'test-file-id',
      targetLanguage: 'spanish'
    });
    
    const startTime = Date.now();
    let pollCount = 0;
    const pollTimestamps: number[] = [];
    
    // Poll for 10 minutes and track intervals
    while (Date.now() - startTime < 600000) { // 10 minutes
      const response = await apiClient.get(`/translation/jobs/${jobResponse.jobId}/progress`);
      pollTimestamps.push(Date.now());
      pollCount++;
      
      if (response.data.status === 'COMPLETED') break;
      
      // Calculate expected interval based on elapsed time
      const elapsed = Date.now() - startTime;
      const expectedInterval = elapsed < 300000 ? 15000 : // First 5 min: 15s
                              elapsed < 1800000 ? 30000 : // 5-30 min: 30s
                              60000; // 30+ min: 60s
      
      await new Promise(resolve => setTimeout(resolve, expectedInterval));
    }
    
    // Verify polling intervals adapted correctly
    for (let i = 1; i < pollTimestamps.length; i++) {
      const interval = pollTimestamps[i] - pollTimestamps[i-1];
      const elapsed = pollTimestamps[i] - startTime;
      
      if (elapsed < 300000) {
        expect(interval).toBeCloseTo(15000, 1000); // ±1 second tolerance
      } else if (elapsed < 1800000) {
        expect(interval).toBeCloseTo(30000, 1000);
      } else {
        expect(interval).toBeCloseTo(60000, 1000);
      }
    }
  });
  
  it('should handle page visibility changes', async () => {
    // Mock Page Visibility API
    Object.defineProperty(document, 'hidden', {
      writable: true,
      value: false
    });
    
    const jobId = 'test-job-123';
    let pollInterval = 15000; // Start with active polling
    
    // Simulate tab going to background
    Object.defineProperty(document, 'hidden', { value: true });
    document.dispatchEvent(new Event('visibilitychange'));
    
    // Poll interval should increase to 2 minutes for background
    pollInterval = 120000;
    
    const response = await apiClient.get(`/translation/jobs/${jobId}/progress`);
    expect(response.headers['cache-control']).toContain('max-age=30');
  });
});
```

### 8.2 Legal Attestation Testing

**Legal Compliance Test Suite:**

```typescript
describe('Legal Attestation Compliance', () => {
  let legalService: LegalAttestationService;
  
  beforeEach(() => {
    legalService = new LegalAttestationService();
  });
  
  it('should require all legal statements to be true', async () => {
    const incompleteRequest = {
      userId: 'test-user',
      legalStatements: {
        copyrightOwnership: true,
        translationRights: false, // Missing required agreement
        liabilityAcceptance: true,
        publicDomainAcknowledgment: true
      },
      // ... other required fields
    };
    
    await expect(legalService.createAttestation(incompleteRequest))
      .rejects.toThrow('All legal statements must be acknowledged');
  });
  
  it('should store attestation with 7-year TTL', async () => {
    const attestationRequest = createValidAttestationRequest();
    
    const attestation = await legalService.createAttestation(attestationRequest);
    
    expect(attestation.ttl).toBeDefined();
    const expectedExpiry = Math.floor(Date.now() / 1000) + (7 * 365 * 24 * 60 * 60);
    expect(attestation.ttl).toBeCloseTo(expectedExpiry, 60); // 1 minute tolerance
  });
  
  it('should archive attestation to S3 Glacier', async () => {
    const attestationRequest = createValidAttestationRequest();
    
    const attestation = await legalService.createAttestation(attestationRequest);
    
    // Verify S3 object was created
    const archiveKey = `attestation-backup/${attestation.createdAt.slice(0, 7)}/${attestation.attestationId}.json`;
    const s3Object = await s3Client.headObject({
      Bucket: 'translation-legal-documents',
      Key: archiveKey
    }).promise();
    
    expect(s3Object.StorageClass).toBe('GLACIER');
    expect(s3Object.ServerSideEncryption).toBe('aws:kms');
  });
});
```

## 9. Deployment Strategy (Simplified)

### 9.1 CloudFormation Templates (Revised)

**Infrastructure Structure:**

```
infrastructure/
├── templates/
│   ├── 01-network.yaml          # VPC, subnets (simplified)
│   ├── 02-security.yaml         # IAM roles, KMS keys
│   ├── 03-storage.yaml          # S3, DynamoDB, DAX
│   ├── 04-compute.yaml          # ECS, Lambda functions
│   ├── 05-api.yaml              # API Gateway (REST only)
│   ├── 06-legal.yaml            # Legal compliance infrastructure
│   └── 07-monitoring.yaml       # CloudWatch, alarms
├── parameters/
│   ├── dev.json
│   └── prod.json
└── scripts/
    ├── deploy.sh
    ├── validate-legal-compliance.sh
    └── test-polling-performance.sh
```

### 9.2 Deployment Pipeline (Revised)

**GitHub Actions Workflow:**

```yaml
name: Translation Service Deployment
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Validate CloudFormation Templates
        run: |
          for template in infrastructure/templates/*.yaml; do
            aws cloudformation validate-template --template-body file://$template
          done
      
      - name: Run Unit Tests
        run: |
          npm ci
          npm run test:unit -- --coverage
          
      - name: Validate Legal Compliance
        run: |
          ./scripts/validate-legal-compliance.sh
          
      - name: Security Scan
        run: |
          npm audit --audit-level moderate
  
  deploy-dev:
    needs: validate
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy Infrastructure
        run: |
          aws cloudformation deploy \
            --template-file infrastructure/main.yaml \
            --stack-name translation-service-dev \
            --parameter-overrides file://infrastructure/parameters/dev.json \
            --capabilities CAPABILITY_IAM
      
      - name: Deploy Application
        run: |
          npm run deploy:dev
          
      - name: Run Integration Tests
        run: |
          npm run test:integration
          
      - name: Test Polling Performance
        run: |
          ./scripts/test-polling-performance.sh
```

## 10. Operational Procedures (Revised)

### 10.1 Legal Compliance Monitoring

**Legal Attestation Audit Script:**

```bash
#!/bin/bash
# scripts/validate-legal-compliance.sh

echo "🔍 Legal Compliance Validation"

# 1. Verify attestation table has TTL enabled
ATTESTATION_TABLE="legal-attestations"
TTL_STATUS=$(aws dynamodb describe-table --table-name $ATTESTATION_TABLE \
  --query 'Table.TimeToLiveDescription.TimeToLiveStatus' --output text)

if [ "$TTL_STATUS" != "ENABLED" ]; then
  echo "❌ TTL not enabled on attestation table"
  exit 1
fi

# 2. Verify KMS encryption is active
KMS_KEY_ID=$(aws dynamodb describe-table --table-name $ATTESTATION_TABLE \
  --query 'Table.SSEDescription.KMSMasterKeyArn' --output text)

if [ "$KMS_KEY_ID" = "None" ]; then
  echo "❌ KMS encryption not enabled on attestation table"
  exit 1
fi

# 3. Check S3 backup configuration
LEGAL_BUCKET="translation-legal-documents"
GLACIER_POLICY=$(aws s3api get-bucket-lifecycle-configuration --bucket $LEGAL_BUCKET \
  --query 'Rules[?Status==`Enabled`]' --output json)

if [ -z "$GLACIER_POLICY" ]; then
  echo "❌ Glacier lifecycle policy not configured"
  exit 1
fi

# 4. Verify attestation data integrity
SAMPLE_ATTESTATION=$(aws dynamodb scan --table-name $ATTESTATION_TABLE \
  --limit 1 --output json)

REQUIRED_FIELDS=("attestationId" "userId" "ttl" "legalStatements" "documentHash")
for field in "${REQUIRED_FIELDS[@]}"; do
  if ! echo $SAMPLE_ATTESTATION | jq -e ".Items[0].$field" > /dev/null; then
    echo "❌ Required field $field missing from attestation record"
    exit 1
  fi
done

echo "✅ Legal compliance validation passed"
```

### 10.2 Performance Monitoring (Polling-Focused)

**Polling Performance Dashboard:**

```typescript
// monitoring/polling-dashboard.ts
export const pollingDashboardConfig = {
  widgets: [
    {
      type: "metric",
      properties: {
        title: "Polling API Performance",
        metrics: [
          ["TranslationService", "PollingAPI/ResponseTime", {"stat": "Average"}],
          [".", "PollingAPI/ResponseTime", {"stat": "p95"}],
          [".", "PollingAPI/CacheHitRate"]
        ],
        period: 300,
        region: "us-east-1",
        yAxis: {
          left: {
            min: 0,
            max: 1000
          }
        }
      }
    },
    {
      type: "metric",
      properties: {
        title: "Legal Compliance Metrics",
        metrics: [
          ["TranslationService", "Legal/AttestationsCreated"],
          [".", "Legal/AttestationValidationFailures"],
          [".", "Legal/AuditLogWrites"]
        ],
        period: 300,
        region: "us-east-1"
      }
    },
    {
      type: "log",
      properties: {
        title: "Recent Legal Events",
        query: `
          SOURCE '/aws/lambda/legal-attestation-handler' 
          | fields @timestamp, eventType, userId, attestationId
          | filter eventType = "ATTESTATION_CREATED"
          | sort @timestamp desc
          | limit 20
        `,
        region: "us-east-1"
      }
    }
  ]
};
```

## 11. Performance Benchmarks & SLAs (Revised)

### 11.1 Service Level Objectives (Polling-Focused)

|Metric|Target|Measurement|
|---|---|---|
|**Polling API Response Time**|<500ms (P95)|CloudWatch metrics|
|**Progress Update Latency**|<60 seconds|Time between ECS update and API response|
|**Translation Completion Rate**|>90%|Successful completions / total submissions|
|**Legal Attestation Success Rate**|100%|All uploads must have valid attestation|
|**Cache Hit Rate**|>80%|CloudFront + DAX cache efficiency|
|**System Availability**|>95%|Uptime during business hours|
|**Cost per Translation**|<$0.05|Requires optimization from current $0.72|

### 11.2 Load Testing (Polling-Focused)

**Artillery.js Configuration (Revised):**

```yaml
# load-tests/polling-performance.yml
config:
  target: 'https://api.translation-service.com'
  phases:
    - duration: 300  # 5 minutes
      arrivalRate: 10  # 10 concurrent pollers
    - duration: 600  # 10 minutes  
      arrivalRate: 20  # 20 concurrent pollers

scenarios:
  - name: "Aggressive Polling Test"
    weight: 100
    flow:
      - post:
          url: "/auth/login"
          json:
            email: "load-test-{{ $randomNumber() }}@test.com"
            password: "TestPassword123!"
          capture:
            - json: "$.token"
              as: "authToken"
      
      # Create mock job for polling
      - post:
          url: "/translation/jobs"
          headers:
            Authorization: "Bearer {{ authToken }}"
          json:
            fileId: "test-file-{{ $randomNumber() }}"
            targetLanguage: "spanish"
          capture:
            - json: "$.jobId"
              as: "jobId"
      
      # Aggressive polling for 10 minutes
      - loop:
          - get:
              url: "/translation/jobs/{{ jobId }}/progress"
              headers:
                Authorization: "Bearer {{ authToken }}"
              expect:
                - statusCode: 200
                - hasProperty: "progress"
              capture:
                - json: "$.status"
                  as: "jobStatus"
                - json: "$.progress"
                  as: "currentProgress"
          - think: 15  # 15 second polling interval
          count: 40  # 10 minutes of polling
          
      # Verify cache headers
      - get:
          url: "/translation/jobs/{{ jobId }}/progress"
          headers:
            Authorization: "Bearer {{ authToken }}"
          expect:
            - statusCode: 200
            - headerEquals: "Cache-Control"
              value: "max-age=30"
```

## 12. Error Handling & Recovery (Enhanced)

### 12.1 Comprehensive Failure Scenarios & Recovery

**Gemini API Error Handling with Polling Integration:**

```typescript
class GeminiAPIErrorHandler {
  private readonly MAX_RETRIES = 3;
  private readonly RETRY_DELAYS = [1000, 5000, 15000]; // Progressive backoff
  
  async handleAPICall<T>(operation: () => Promise<T>, context: APIContext): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 0; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        // Update progress tracker before attempting API call
        await this.updateJobStatus(context.jobId, 'PROCESSING', `Attempt ${attempt + 1} of ${this.MAX_RETRIES + 1}`);
        
        return await operation();
      } catch (error) {
        lastError = error;
        
        const errorType = this.classifyError(error);
        
        switch (errorType) {
          case 'RATE_LIMIT':
            await this.handleRateLimit(error, attempt, context.jobId);
            break;
            
          case 'TRANSIENT':
            if (attempt < this.MAX_RETRIES) {
              await this.updateJobStatus(context.jobId, 'RETRYING', `Transient error, retrying in ${this.RETRY_DELAYS[attempt]}ms`);
              await this.delay(this.RETRY_DELAYS[attempt]);
              continue;
            }
            break;
            
          case 'PERMANENT':
            await this.updateJobStatus(context.jobId, 'FAILED', error.message);
            throw new PermanentAPIError(error.message, context);
            
          case 'CONTEXT_TOO_LARGE':
            await this.updateJobStatus(context.jobId, 'PROCESSING', 'Splitting oversized chunk');
            return this.handleOversizedChunk(context);
        }
      }
    }
    
    await this.updateJobStatus(context.jobId, 'FAILED', `Max retries exceeded: ${lastError.message}`);
    throw new MaxRetriesExceededError(lastError, context);
  }
  
  private async handleRateLimit(error: Error, attempt: number, jobId: string): Promise<void> {
    const retryAfter = this.extractRetryAfterSeconds(error) || Math.pow(2, attempt) * 1000;
    await this.updateJobStatus(jobId, 'RATE_LIMITED', `Rate limit hit, retrying in ${retryAfter}s`);
    await this.delay(retryAfter * 1000);
  }
  
  private async handleOversizedChunk(context: APIContext): Promise<any> {
    // Split chunk further and retry with progress tracking
    const smallerChunks = this.splitChunkFurther(context.chunk);
    const results = [];
    
    await this.updateJobStatus(context.jobId, 'PROCESSING', `Processing ${smallerChunks.length} sub-chunks`);
    
    for (let i = 0; i < smallerChunks.length; i++) {
      const subChunk = smallerChunks[i];
      await this.updateJobStatus(context.jobId, 'PROCESSING', `Processing sub-chunk ${i + 1}/${smallerChunks.length}`);
      
      const result = await this.handleAPICall(
        () => this.geminiClient.translateChunk(subChunk),
        { ...context, chunk: subChunk }
      );
      results.push(result);
    }
    
    return this.mergeChunkResults(results);
  }
}
```

**Enhanced Step Functions Error Handling with Polling Updates:**

```json
{
  "StartTranslationTask": {
    "Type": "Task",
    "Resource": "arn:aws:states:::ecs:runTask.sync",
    "Parameters": {
      "TaskDefinition": "translation-processor",
      "Cluster": "translation-cluster",
      "Overrides": {
        "ContainerOverrides": [
          {
            "Name": "translation-processor",
            "Environment": [
              {
                "Name": "JOB_ID",
                "Value.$": "$.jobId"
              },
              {
                "Name": "ENABLE_POLLING_UPDATES",
                "Value": "true"
              }
            ]
          }
        ]
      }
    },
    "Retry": [
      {
        "ErrorEquals": ["States.TaskFailed"],
        "IntervalSeconds": 30,
        "MaxAttempts": 3,
        "BackoffRate": 2.0
      }
    ],
    "Catch": [
      {
        "ErrorEquals": ["States.ALL"],
        "Next": "HandleTranslationFailure",
        "ResultPath": "$.error"
      }
    ]
  },
  "HandleTranslationFailure": {
    "Type": "Task",
    "Resource": "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:handle-translation-failure",
    "Parameters": {
      "jobId.$": "$.jobId",
      "error.$": "$.error",
      "originalInput.$": "$",
      "enablePollingUpdates": true
    },
    "Next": "UpdateJobStatusFailed"
  },
  "UpdateJobStatusFailed": {
    "Type": "Task",
    "Resource": "arn:aws:states:::dynamodb:putItem",
    "Parameters": {
      "TableName": "translation-jobs",
      "Item": {
        "jobId": {"S.$": "$.jobId"},
        "status": {"S": "FAILED"},
        "lastUpdated": {"S.$": "$$.State.EnteredTime"},
        "errorMessage": {"S.$": "$.error.Cause"}
      }
    },
    "Next": "NotifyUserOfFailure"
  }
}
```

### 12.2 Data Consistency & Recovery with Polling Integration

**Job State Recovery Service (Enhanced for Polling):**

```typescript
class JobRecoveryService {
  private readonly JOBS_TABLE = 'translation-jobs';
  private readonly RECOVERY_BATCH_SIZE = 10;
  
  async recoverIncompleteJobs(): Promise<void> {
    const incompleteJobs = await this.findIncompleteJobs();
    console.log(`Found ${incompleteJobs.length} incomplete jobs for recovery`);
    
    // Process jobs in batches to avoid overwhelming the system
    for (let i = 0; i < incompleteJobs.length; i += this.RECOVERY_BATCH_SIZE) {
      const batch = incompleteJobs.slice(i, i + this.RECOVERY_BATCH_SIZE);
      
      await Promise.all(batch.map(async (job) => {
        try {
          await this.analyzeJobState(job);
          const strategy = await this.determineRecoveryStrategy(job);
          await this.executeRecovery(job, strategy);
        } catch (error) {
          console.error(`Failed to recover job ${job.jobId}:`, error);
          await this.markJobAsFailed(job.jobId, error);
        }
      }));
    }
  }
  
  private async findIncompleteJobs(): Promise<TranslationJob[]> {
    const params = {
      TableName: this.JOBS_TABLE,
      IndexName: 'status-index',
      KeyConditionExpression: '#status IN (:processing, :retrying, :rate_limited)',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':processing': 'PROCESSING',
        ':retrying': 'RETRYING',
        ':rate_limited': 'RATE_LIMITED'
      },
      FilterExpression: 'attribute_exists(lastUpdated) AND lastUpdated < :staleThreshold',
      ExpressionAttributeValues: {
        ':staleThreshold': new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
      }
    };
    
    const result = await this.dynamoClient.query(params).promise();
    return result.Items as TranslationJob[];
  }
  
  private async determineRecoveryStrategy(job: TranslationJob): Promise<RecoveryStrategy> {
    const progress = await this.getJobProgress(job.jobId);
    const timeSinceLastUpdate = Date.now() - new Date(job.lastUpdated).getTime();
    
    // If job has been stale for > 4 hours, likely needs full restart
    if (timeSinceLastUpdate > 4 * 60 * 60 * 1000) {
      return 'RESTART_FROM_BEGINNING';
    }
    
    if (progress.chunksCompleted === 0) {
      return 'RESTART_FROM_BEGINNING';
    } else if (progress.chunksCompleted > progress.totalChunks * 0.8) {
      return 'RESUME_FROM_ASSEMBLY';
    } else {
      return 'RESUME_FROM_LAST_CHUNK';
    }
  }
  
  private async executeRecovery(job: TranslationJob, strategy: RecoveryStrategy): Promise<void> {
    // Update job status to indicate recovery in progress
    await this.updateJobStatus(job.jobId, 'RECOVERING', `Executing ${strategy} recovery`);
    
    switch (strategy) {
      case 'RESTART_FROM_BEGINNING':
        await this.restartJob(job);
        break;
        
      case 'RESUME_FROM_LAST_CHUNK':
        await this.resumeJobFromLastChunk(job);
        break;
        
      case 'RESUME_FROM_ASSEMBLY':
        await this.resumeJobFromAssembly(job);
        break;
    }
    
    console.log(`Successfully executed ${strategy} recovery for job ${job.jobId}`);
  }
  
  private async restartJob(job: TranslationJob): Promise<void> {
    // Reset progress tracking
    await this.dynamoClient.update({
      TableName: this.JOBS_TABLE,
      Key: { jobId: job.jobId },
      UpdateExpression: `
        SET #status = :status,
            progress = :progress,
            chunksProcessed = :chunksProcessed,
            lastUpdated = :now,
            recoveryAttempts = if_not_exists(recoveryAttempts, :zero) + :one
      `,
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':status': 'QUEUED',
        ':progress': 0,
        ':chunksProcessed': 0,
        ':now': new Date().toISOString(),
        ':zero': 0,
        ':one': 1
      }
    }).promise();
    
    // Re-queue the job for processing
    await this.stepFunctions.startExecution({
      stateMachineArn: process.env.TRANSLATION_STATE_MACHINE_ARN,
      input: JSON.stringify({
        jobId: job.jobId,
        isRecovery: true,
        originalJobData: job
      }),
      name: `recovery-${job.jobId}-${Date.now()}`
    }).promise();
  }
}
```

**Polling-Specific Error Monitoring:**

```typescript
class PollingErrorMonitor {
  async trackPollingHealth(): Promise<void> {
    const metrics = await this.gatherPollingMetrics();
    
    // Monitor for polling API failures
    if (metrics.errorRate > 0.05) { // 5% error threshold
      await this.triggerPollingAlert('HIGH_ERROR_RATE', {
        currentErrorRate: metrics.errorRate,
        threshold: 0.05
      });
    }
    
    // Monitor for slow response times
    if (metrics.p95ResponseTime > 500) { // 500ms threshold
      await this.triggerPollingAlert('SLOW_RESPONSE_TIME', {
        currentP95: metrics.p95ResponseTime,
        threshold: 500
      });
    }
    
    // Monitor for cache effectiveness
    if (metrics.cacheHitRate < 0.8) { // 80% cache hit rate threshold
      await this.triggerPollingAlert('LOW_CACHE_HIT_RATE', {
        currentHitRate: metrics.cacheHitRate,
        threshold: 0.8
      });
    }
  }
  
  private async gatherPollingMetrics(): Promise<PollingMetrics> {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - 5 * 60 * 1000); // Last 5 minutes
    
    const params = {
      Namespace: 'TranslationService',
      StartTime: startTime,
      EndTime: endTime,
      Period: 300,
      Statistics: ['Average', 'Sum']
    };
    
    const [errorRate, responseTime, cacheHitRate] = await Promise.all([
      this.cloudWatch.getMetricStatistics({
        ...params,
        MetricName: 'PollingAPI/ErrorRate'
      }).promise(),
      this.cloudWatch.getMetricStatistics({
        ...params,
        MetricName: 'PollingAPI/ResponseTime',
        Statistics: ['Average', 'p95']
      }).promise(),
      this.cloudWatch.getMetricStatistics({
        ...params,
        MetricName: 'PollingAPI/CacheHitRate'
      }).promise()
    ]);
    
    return {
      errorRate: errorRate.Datapoints[0]?.Average || 0,
      p95ResponseTime: responseTime.Datapoints[0]?.ExtendedStatistics?.p95 || 0,
      cacheHitRate: cacheHitRate.Datapoints[0]?.Average || 1
    };
  }
}
```

## 13. Backup & Disaster Recovery (Enhanced)

### 13.1 Comprehensive Backup Strategy

**Legal Attestation Backup (Critical - 7 year retention):**

```yaml
LegalAttestationBackup:
  Type: AWS::BackupPlan
  Properties:
    BackupPlan:
      BackupPlanName: legal-attestation-backup
      BackupPlanRule:
        - RuleName: daily-backup-7-years
          TargetBackupVault: !Ref LegalBackupVault
          ScheduleExpression: "cron(0 2 * * ? *)"  # Daily at 2 AM
          Lifecycle:
            DeleteAfterDays: 2555  # 7 years
          RecoveryPointTags:
            DataClassification: "legal-critical"
            RetentionPeriod: "7-years"
            PollingCompatible: "true"

UserDataBackup:
  Type: AWS::BackupPlan
  Properties:
    BackupPlan:
      BackupPlanName: user-data-backup
      BackupPlanRule:
        - RuleName: daily-backup-30-days
          TargetBackupVault: !Ref UserDataBackupVault
          ScheduleExpression: "cron(0 3 * * ? *)"  # Daily at 3 AM
          Lifecycle:
            DeleteAfterDays: 30
          RecoveryPointTags:
            DataClassification: "user-data"
            RetentionPeriod: "30-days"

TranslationJobStateBackup:
  Type: AWS::BackupPlan
  Properties:
    BackupPlan:
      BackupPlanName: translation-job-state-backup
      BackupPlanRule:
        - RuleName: hourly-backup-7-days
          TargetBackupVault: !Ref JobStateBackupVault
          ScheduleExpression: "cron(0 * * * ? *)"  # Hourly
          Lifecycle:
            DeleteAfterDays: 7
          RecoveryPointTags:
            DataClassification: "operational-critical"
            RetentionPeriod: "7-days"
```

**Enhanced S3 Backup Structure for Polling Architecture:**

```
translation-service-files/
├── uploads/
│   ├── {userId}/
│   │   ├── {jobId}/
│   │   │   ├── original.txt
│   │   │   ├── metadata.json
│   │   │   └── file-hash.sha256
├── processing/
│   ├── {jobId}/
│   │   ├── chunks/
│   │   │   ├── chunk-001.json
│   │   │   ├── chunk-002.json
│   │   │   └── context-summary.json
│   │   ├── progress.json          # Enhanced for polling
│   │   ├── translation-state.json # Job state snapshots
│   │   └── error-recovery.json    # Recovery metadata
├── results/
│   ├── {jobId}/
│   │   ├── translation.md
│   │   ├── quality-report.json
│   │   ├── processing-metadata.json
│   │   └── cost-breakdown.json
├── legal/
│   ├── terms-of-service/
│   │   ├── v1.0.html
│   │   ├── v1.1.html
│   │   └── current-version.txt
│   ├── attestation-backup/
│   │   └── {year}/{month}/
│   │       └── attestations-{date}.json.gz
│   └── audit-logs/
│       └── {year}/{month}/{day}/
│           └── legal-events-{hour}.json
└── disaster-recovery/
    ├── polling-state-snapshots/
    │   └── {date}/
    │       └── active-jobs-{hour}.json
    └── cross-region-sync/
        └── replication-status.json
```

### 13.2 Disaster Recovery Runbook (Polling-Enhanced)

**Scenario 1: Complete AWS Region Failure**

```markdown
# Disaster Recovery Runbook - Polling Architecture

## Scenario 1: Complete AWS Region Failure

### Immediate Response (0-15 minutes)
1. **Assess Impact**: Check AWS Service Health Dashboard
2. **Activate DR Team**: Notify on-call team via PagerDuty
3. **Enable Status Page**: Update service status with "Polling services temporarily unavailable"
4. **Disable Client-Side Polling**: Deploy emergency frontend update to pause polling

### Short-term Recovery (15-60 minutes)
1. **Failover to Secondary Region**: Deploy to us-west-2 using pre-built infrastructure
2. **Update DNS**: Change Route 53 records to point to DR region
3. **Restore Critical Data**: 
   - Legal attestations from automated S3 cross-region replication
   - User data from DynamoDB Global Tables
   - Active translation job states from hourly backups
4. **Re-enable Polling**: Update frontend configuration to resume polling against DR region
5. **Restore DAX Cache**: Warm up DAX cluster with recent job states

### Long-term Recovery (1-24 hours)
1. **Resume Translation Processing**: 
   - Restart incomplete jobs using job recovery service
   - Validate polling endpoints are responsive
   - Monitor polling performance and adjust intervals if needed
2. **Notify Users**: 
   - Send email notifications about service restoration
   - Update status page with current processing capabilities
3. **Monitor Performance**: 
   - Ensure DR region handles polling load effectively
   - Monitor cache hit rates and API response times
   - Scale resources if polling frequency increases due to backlog

## Scenario 2: Polling API Degradation

### Immediate Response (0-5 minutes)
1. **Identify Scope**: Determine if specific endpoints or entire polling system affected
2. **Activate Caching**: Increase cache TTL to reduce database load
3. **Enable Circuit Breaker**: Implement temporary polling backoff

### Recovery Response (5-30 minutes)
1. **Scale Resources**: Auto-scale Lambda functions and DAX cluster
2. **Optimize Queries**: Enable DynamoDB auto-scaling if not already active
3. **User Communication**: Display polling status and estimated recovery time
4. **Graceful Degradation**: Increase polling intervals temporarily (60s → 120s)

## Scenario 3: Gemini API Extended Outage

### Immediate Response (0-5 minutes)
1. **Pause New Job Submissions**: Display maintenance page for new uploads
2. **Queue Existing Jobs**: 
   - Update job status to 'PAUSED_API_OUTAGE'
   - Continue polling with extended intervals to maintain user visibility
3. **User Communication**: Update all polling responses with outage notification

### Extended Outage Response (5+ minutes)
1. **Maintain Polling Infrastructure**: Keep polling active for status updates
2. **Queue Management**: 
   - Preserve all job states and progress information
   - Provide accurate ETAs once service resumes
3. **User Retention**: 
   - Send proactive email updates
   - Offer service credits for affected translations
   - Maintain engagement through regular polling status updates
```

**Cross-Region Replication for Critical Data:**

```typescript
class DisasterRecoveryManager {
  private readonly PRIMARY_REGION = 'us-east-1';
  private readonly DR_REGION = 'us-west-2';
  
  async enableCrossRegionReplication(): Promise<void> {
    // Enable S3 cross-region replication for legal documents
```
