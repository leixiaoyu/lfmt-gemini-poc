# Low-Level Design Document 5: Gemini API Integration Layer

## 1. Component Overview & Responsibilities

The Gemini API Integration Layer serves as the core translation engine, managing all interactions with Google's Gemini API. It implements intelligent rate limiting, retry logic, cost optimization, and quality assurance to ensure reliable, high-quality translations while staying within budget constraints.

**Key Responsibilities:**
- Gemini API request/response management
- Rate limiting compliance
- Circuit breaker pattern for API degradation
- Cost tracking and budget enforcement
- Translation quality validation and retry logic
- Token usage optimization and monitoring

**Why This Design:** Direct Gemini integration maximizes translation quality while the layered approach provides fault tolerance, cost control, and performance optimization essential for production workloads.

## 2. API Design & Interfaces

### Gemini API Integration Endpoints
```typescript
// POST /gemini/translate
interface GeminiTranslationRequest {
  chunkId: string;
  content: string;
  targetLanguage: string;
  contextWindow?: {
    preceding: string;
    following: string;
  };
  translationHints?: TranslationHint[];
  retryAttempt?: number;
}

interface GeminiTranslationResponse {
  chunkId: string;
  translatedContent: string;
  confidence: number; // 0-1 quality score
  tokenUsage: {
    inputTokens: number;
    outputTokens: number;
    cost: number;
  };
  processingTime: number;
  geminiModel: string;
  translationMetadata: {
    detectedLanguage?: string;
    preservedFormatting: string[];
    qualityFlags: QualityFlag[];
  };
}

// GET /gemini/usage
interface UsageRequest {
  timeRange: 'hour' | 'day' | 'month';
  startDate?: string;
  endDate?: string;
}

interface UsageResponse {
  totalRequests: number;
  totalTokensInput: number;
  totalTokensOutput: number;
  totalCost: number;
  rateLimitStatus: {
    requestsRemaining: number;
    tokensRemaining: number;
    resetTime: string;
  };
  costProjection: {
    daily: number;
    monthly: number;
  };
}
```

### Gemini API Client Configuration
```typescript
interface GeminiConfig {
  apiKey: string;
  model: string;
  baseURL: string;
  rateLimits: {
    requestsPerMinute: number;
    inputTokensPerMinute: number;
    outputTokensPerMinute: number;
  };
  timeouts: {
    connectionTimeout: number; // 10s
    requestTimeout: number;   // 2 minutes
  };
  retryConfig: {
    maxRetries: number;
    backoffMultiplier: number;
    maxBackoffDelay: number;
  };
  costLimits: {
    dailyBudget: number;     // $10/day
    monthlyBudget: number;  // $300/month
    emergencyThreshold: number; // 90% of budget
  };
}
```

## 3. Data Models & Storage

### Gemini Request/Response Storage
```typescript
// DynamoDB Schema for Gemini API Calls
interface GeminiAPIRecord {
  PK: string; // GEMINI_CALL#{callId}
  SK: string; // TIMESTAMP#{timestamp}
  callId: string;
  chunkId: string;
  documentId: string;
  requestTimestamp: string;
  responseTimestamp?: string;
  status: 'PENDING' | 'SUCCESS' | 'FAILED' | 'RATE_LIMITED' | 'TIMEOUT';
  
  // Request data
  inputTokens: number;
  inputContent: string; // Encrypted
  targetLanguage: string;
  modelUsed: string;
  
  // Response data
  outputTokens?: number;
  translatedContent?: string; // Encrypted
  confidence?: number;
  cost?: number;
  
  // Error handling
  errorCode?: string;
  errorMessage?: string;
  retryAttempt: number;
  
  // Performance metrics
  latency?: number;
  rateLimitHeaders?: RateLimitHeaders;
  
  ttl: number; // Auto-delete after 7 years for legal compliance
}

// GSI: CallsByStatus for monitoring
interface CallsByStatus {
  GSI1PK: string; // STATUS#{status}
  GSI1SK: string; // TIMESTAMP#{timestamp}
  callId: string;
  status: string;
  documentId: string;
  cost?: number;
}

// GSI: CallsByDocument for cost tracking
interface CallsByDocument {
  GSI2PK: string; // DOCUMENT#{documentId}
  GSI2SK: string; // TIMESTAMP#{timestamp}
  callId: string;
  chunkId: string;
  cost?: number;
  status: string;
}
```

### Rate Limiting and Usage Tracking
```typescript
interface RateLimitState {
  windowStart: number;
  requestCount: number;
  inputTokensUsed: number;
  outputTokensUsed: number;
  nextResetTime: number;
}

interface CostTracker {
  daily: {
    date: string;
    totalCost: number;
    requestCount: number;
    tokenCount: number;
  };
  monthly: {
    month: string;
    totalCost: number;
    requestCount: number;
    tokenCount: number;
  };
  realTime: {
    currentCost: number;
    budgetRemaining: number;
    projectedDailyCost: number;
  };
}
```

## 4. Core Gemini Integration Logic

### Gemini API Client Implementation
```typescript
class GeminiAPIClient {
  private config: GeminiConfig;
  private rateLimiter: RateLimiter;
  private costTracker: CostTracker;
  private circuitBreaker: CircuitBreaker;
  private retryHandler: RetryHandler;

  constructor(config: GeminiConfig) {
    this.config = config;
    this.rateLimiter = new SlidingWindowRateLimiter(config.rateLimits);
    this.costTracker = new RealTimeCostTracker(config.costLimits);
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 5,
      recoveryTimeout: 30000,
      monitoringPeriod: 60000
    });
    this.retryHandler = new ExponentialBackoffRetry(config.retryConfig);
  }

  async translateChunk(request: GeminiTranslationRequest): Promise<GeminiTranslationResponse> {
    // Pre-flight checks
    await this.validateRequest(request);
    await this.checkBudgetConstraints(request);
    await this.rateLimiter.acquirePermit(this.estimateTokens(request.content));

    // Circuit breaker check
    if (this.circuitBreaker.isOpen()) {
      throw new ServiceUnavailableError('Gemini API circuit breaker is open');
    }

    return this.retryHandler.execute(async () => {
      const callId = this.generateCallId();
      const startTime = Date.now();

      try {
        // Log request
        await this.logAPICall(callId, request, 'PENDING');

        // Make Gemini API call
        const geminiRequest = this.buildGeminiRequest(request);
        const geminiResponse = await this.callGemini(geminiRequest);

        // Process response
        const response = await this.processGeminiResponse(
          callId,
          request,
          geminiResponse,
          Date.now() - startTime
        );

        // Update tracking
        await this.updateUsageTracking(response.tokenUsage);
        await this.logAPICall(callId, request, 'SUCCESS', response);

        this.circuitBreaker.recordSuccess();
        return response;

      } catch (error) {
        this.circuitBreaker.recordFailure();
        await this.logAPICall(callId, request, 'FAILED', undefined, error);
        throw error;
      }
    });
  }

  private async callGemini(request: GeminiRequest): Promise<GeminiResponse> {
    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': this.config.apiKey,
      'User-Agent': 'LongFormTranslationService/1.0'
    };

    const response = await fetch(`${this.config.baseURL}/v1/messages`, {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.config.timeouts.requestTimeout)
    });

    if (!response.ok) {
      await this.handleAPIError(response);
    }

    // Track rate limit headers
    this.updateRateLimitHeaders(response.headers);

    return response.json();
  }

  private buildGeminiRequest(request: GeminiTranslationRequest): GeminiRequest {
    const systemPrompt = this.buildSystemPrompt(request.targetLanguage, request.translationHints);
    const userPrompt = this.buildUserPrompt(request.content, request.contextWindow);

    return {
      model: this.config.model,
      max_tokens: Math.min(4096, this.estimateOutputTokens(request.content)),
      messages: [
        {
          role: 'user',
          content: userPrompt
        }
      ],
      system: systemPrompt,
      temperature: 0.1, // Low temperature for consistent translations
      metadata: {
        user_id: `chunk-${request.chunkId}`,
        custom_id: this.generateCallId()
      }
    };
  }

  private buildSystemPrompt(targetLanguage: string, hints?: TranslationHint[]): string {
    let prompt = `You are a professional translator specializing in long-form document translation. 

TRANSLATION REQUIREMENTS:
- Translate the provided text to ${targetLanguage}
- Maintain the original formatting, structure, and tone
- Preserve technical terms, proper nouns, and specialized vocabulary
- Ensure cultural appropriateness for the target language
- Maintain consistency with any provided context

FORMATTING PRESERVATION:
- Keep all markdown formatting (headers, lists, links, code blocks)
- Preserve line breaks and paragraph structure
- Maintain special characters and symbols
- Do not translate code snippets, URLs, or technical identifiers

QUALITY STANDARDS:
- Provide natural, fluent translations
- Ensure grammatical correctness
- Maintain the original meaning and intent
- Use appropriate register and style for the content type`;

    if (hints && hints.length > 0) {
      prompt += '\n\nSPECIAL INSTRUCTIONS:\n';
      hints.forEach(hint => {
        prompt += `- ${hint.description}\n`;
      });
    }

    prompt += '\n\nRespond with ONLY the translated text, maintaining all original formatting.`;

    return prompt;
  }

  private buildUserPrompt(content: string, context?: ContextWindow): string {
    let prompt = '';

    if (context?.preceding) {
      prompt += `PRECEDING CONTEXT (for reference only, do not translate):\n${context.preceding}\n\n`;
    }

    prompt += `TEXT TO TRANSLATE:\n${content}`;

    if (context?.following) {
      prompt += `\n\nFOLLOWING CONTEXT (for reference only, do not translate):\n${context.following}`;
    }

    return prompt;
  }

  private async processGeminiResponse(
    callId: string,
    request: GeminiTranslationRequest,
    geminiResponse: GeminiResponse,
    processingTime: number
  ): Promise<GeminiTranslationResponse> {
    const translatedContent = geminiResponse.content[0].text;
    
    // Calculate token usage and cost
    const inputTokens = geminiResponse.usage.input_tokens;
    const outputTokens = geminiResponse.usage.output_tokens;
    const cost = this.calculateCost(inputTokens, outputTokens);

    // Quality assessment
    const confidence = await this.assessTranslationQuality(
      request.content,
      translatedContent,
      request.targetLanguage
    );

    // Extract metadata
    const metadata = await this.extractTranslationMetadata(
      request.content,
      translatedContent
    );

    return {
      chunkId: request.chunkId,
      translatedContent,
      confidence,
      tokenUsage: {
        inputTokens,
        outputTokens,
        cost
      },
      processingTime,
      geminiModel: this.config.model,
      translationMetadata: metadata
    };
  }

  private calculateCost(inputTokens: number, outputTokens: number): number {
    // Gemini API pricing (as of 2024)
    const inputCostPer1M = 3.00;   // $3.00 per 1M input tokens
    const outputCostPer1M = 15.00; // $15.00 per 1M output tokens

    const inputCost = (inputTokens / 1_000_000) * inputCostPer1M;
    const outputCost = (outputTokens / 1_000_000) * outputCostPer1M;

    return inputCost + outputCost;
  }

  private async assessTranslationQuality(
    original: string,
    translated: string,
    targetLanguage: string
  ): Promise<number> {
    let confidence = 0.8; // Base confidence

    // Length ratio check (reasonable translations should be similar length)
    const lengthRatio = translated.length / original.length;
    if (lengthRatio < 0.5 || lengthRatio > 2.0) {
      confidence -= 0.2;
    }

    // Formatting preservation check
    if (this.preservesFormatting(original, translated)) {
      confidence += 0.1;
    } else {
      confidence -= 0.3;
    }

    // Language detection (ensure output is in target language)
    const detectedLanguage = await this.detectLanguage(translated);
    if (detectedLanguage === targetLanguage) {
      confidence += 0.1;
    } else {
      confidence -= 0.4;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  private preservesFormatting(original: string, translated: string): boolean {
    // Check for markdown headers
    const originalHeaders = (original.match(/^#{1,6}\s/gm) || []).length;
    const translatedHeaders = (translated.match(/^#{1,6}\s/gm) || []).length;

    // Check for lists
    const originalLists = (original.match(/^\s*[-*+]\s/gm) || []).length;
    const translatedLists = (translated.match(/^\s*[-*+]\s/gm) || []).length;

    // Check for code blocks
    const originalCodeBlocks = (original.match(/```[\s\S]*?```/g) || []).length;
    const translatedCodeBlocks = (translated.match(/```[\s\S]*?```/g) || []).length;

    return (
      Math.abs(originalHeaders - translatedHeaders) <= 1 &&
      Math.abs(originalLists - translatedLists) <= 2 &&
      originalCodeBlocks === translatedCodeBlocks
    );
  }
}
```

### Rate Limiting Implementation
```typescript
class SlidingWindowRateLimiter {
  private requestWindow: number[] = [];
  private tokenWindow: Array<{ timestamp: number; tokens: number }> = [];
  private readonly windowSizeMs = 60000; // 1 minute

  constructor(private limits: RateLimits) {}

  async acquirePermit(estimatedTokens: number): Promise<void> {
    const now = Date.now();
    
    // Clean old entries
    this.cleanupWindows(now);
    
    // Check request limit
    if (this.requestWindow.length >= this.limits.requestsPerMinute) {
      const oldestRequest = Math.min(...this.requestWindow);
      const waitTime = oldestRequest + this.windowSizeMs - now;
      if (waitTime > 0) {
        throw new RateLimitError(`Request rate limit exceeded. Wait ${waitTime}ms`);
      }
    }
    
    // Check token limit
    const currentTokenUsage = this.tokenWindow.reduce((sum, entry) => sum + entry.tokens, 0);
    if (currentTokenUsage + estimatedTokens > this.limits.inputTokensPerMinute) {
      const oldestTokenUsage = this.tokenWindow[0];
      const waitTime = oldestTokenUsage.timestamp + this.windowSizeMs - now;
      if (waitTime > 0) {
        throw new RateLimitError(`Token rate limit exceeded. Wait ${waitTime}ms`);
      }
    }
    
    // Record usage
    this.requestWindow.push(now);
    this.tokenWindow.push({ timestamp: now, tokens: estimatedTokens });
  }

  private cleanupWindows(now: number): void {
    const cutoff = now - this.windowSizeMs;
    
    this.requestWindow = this.requestWindow.filter(timestamp => timestamp > cutoff);
    this.tokenWindow = this.tokenWindow.filter(entry => entry.timestamp > cutoff);
  }

  getRemainingCapacity(): { requests: number; tokens: number } {
    const now = Date.now();
    this.cleanupWindows(now);
    
    const usedTokens = this.tokenWindow.reduce((sum, entry) => sum + entry.tokens, 0);
    
    return {
      requests: this.limits.requestsPerMinute - this.requestWindow.length,
      tokens: this.limits.inputTokensPerMinute - usedTokens
    };
  }
}
```

### Circuit Breaker Implementation
```typescript
class CircuitBreaker {
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  private failureCount = 0;
  private lastFailureTime = 0;
  private successCount = 0;

  constructor(private config: CircuitBreakerConfig) {}

  isOpen(): boolean {
    if (this.state === 'OPEN') {
      // Check if we should transition to HALF_OPEN
      if (Date.now() - this.lastFailureTime > this.config.recoveryTimeout) {
        this.state = 'HALF_OPEN';
        this.successCount = 0;
        return false;
      }
      return true;
    }
    return false;
  }

  recordSuccess(): void {
    this.failureCount = 0;
    
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.config.successThreshold) {
        this.state = 'CLOSED';
      }
    }
  }

  recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.config.failureThreshold) {
      this.state = 'OPEN';
    }
  }

  getState(): { state: string; failureCount: number; lastFailureTime: number } {
    return {
      state: this.state,
      failureCount: this.failureCount,
      lastFailureTime: this.lastFailureTime
    };
  }
}
```

## 5. Error Handling & Recovery

### Gemini API Error Classification
```typescript
class GeminiErrorHandler {
  async handleAPIError(response: Response): Promise<never> {
    const status = response.status;
    const errorData = await response.json().catch(() => ({}));
    
    switch (status) {
      case 400:
        throw new BadRequestError(`Invalid request: ${errorData.error?.message || 'Unknown error'}`);
      
      case 401:
        throw new AuthenticationError('Invalid API key or authentication failed');
      
      case 403:
        throw new AuthorizationError('Insufficient permissions or quota exceeded');
      
      case 429:
        const retryAfter = response.headers.get('retry-after');
        throw new RateLimitError(
          `Rate limit exceeded. Retry after ${retryAfter || 'unknown'} seconds`,
          retryAfter ? parseInt(retryAfter) * 1000 : 60000
        );
      
      case 500:
      case 502:
      case 503:
      case 504:
        throw new ServiceUnavailableError(
          `Gemini API service error: ${status}. This may be temporary.`
        );
      
      default:
        throw new GeminiAPIError(
          `Unexpected error: ${status} - ${errorData.error?.message || 'Unknown error'}`
        );
    }
  }

  shouldRetry(error: Error, attempt: number, maxRetries: number): boolean {
    if (attempt >= maxRetries) return false;
    
    // Retry on network errors
    if (error instanceof NetworkError) return true;
    
    // Retry on service unavailable
    if (error instanceof ServiceUnavailableError) return true;
    
    // Retry on rate limit (after delay)
    if (error instanceof RateLimitError) return true;
    
    // Don't retry on authentication or bad request errors
    if (error instanceof AuthenticationError || error instanceof BadRequestError) {
      return false;
    }
    
    return false;
  }

  calculateBackoffDelay(attempt: number, baseDelay: number, maxDelay: number): number {
    const delay = baseDelay * Math.pow(2, attempt - 1);
    const jitter = Math.random() * 0.1 * delay; // Add 10% jitter
    return Math.min(delay + jitter, maxDelay);
  }
}
```

### Retry Logic with Exponential Backoff
```typescript
class ExponentialBackoffRetry {
  constructor(private config: RetryConfig) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= this.config.maxRetries + 1; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt > this.config.maxRetries) {
          throw error;
        }
        
        if (!this.shouldRetry(error, attempt)) {
          throw error;
        }
        
        const delay = this.calculateDelay(attempt);
        console.warn(`Attempt ${attempt} failed, retrying in ${delay}ms:`, error.message);
        
        await this.sleep(delay);
      }
    }
    
    throw lastError!;
  }

  private shouldRetry(error: unknown, attempt: number): boolean {
    if (error instanceof AuthenticationError) return false;
    if (error instanceof BadRequestError) return false;
    if (error instanceof AuthorizationError) return false;
    
    return true;
  }

  private calculateDelay(attempt: number): number {
    const exponentialDelay = 1000 * Math.pow(this.config.backoffMultiplier, attempt - 1);
    const jitter = Math.random() * 0.1 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, this.config.maxBackoffDelay);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

## 6. Performance & Monitoring

### Gemini API Performance Metrics
```typescript
class GeminiPerformanceMonitor {
  private metrics: Map<string, PerformanceMetric[]> = new Map();

  recordAPICall(
    operation: string,
    duration: number,
    tokenUsage: TokenUsage,
    success: boolean
  ): void {
    const metric: PerformanceMetric = {
      timestamp: Date.now(),
      operation,
      duration,
      inputTokens: tokenUsage.inputTokens,
      outputTokens: tokenUsage.outputTokens,
      cost: tokenUsage.cost,
      success,
      rateLimitHeaders: this.getCurrentRateLimitStatus()
    };

    if (!this.metrics.has(operation)) {
      this.metrics.set(operation, []);
    }
    
    this.metrics.get(operation)!.push(metric);
    
    // Keep only last 1000 metrics per operation
    const operationMetrics = this.metrics.get(operation)!;
    if (operationMetrics.length > 1000) {
      operationMetrics.splice(0, operationMetrics.length - 1000);
    }

    // Publish to CloudWatch
    this.publishMetrics(metric);
  }

  getPerformanceStats(operation: string, timeWindowMs: number = 3600000): PerformanceStats {
    const metrics = this.metrics.get(operation) || [];
    const cutoff = Date.now() - timeWindowMs;
    const recentMetrics = metrics.filter(m => m.timestamp > cutoff);

    if (recentMetrics.length === 0) {
      return this.getEmptyStats();
    }

    const successfulMetrics = recentMetrics.filter(m => m.success);
    const durations = successfulMetrics.map(m => m.duration);
    const costs = recentMetrics.map(m => m.cost);

    return {
      totalRequests: recentMetrics.length,
      successfulRequests: successfulMetrics.length,
      errorRate: (recentMetrics.length - successfulMetrics.length) / recentMetrics.length,
      averageLatency: durations.reduce((sum, d) => sum + d, 0) / durations.length,
      medianLatency: this.calculateMedian(durations),
      p95Latency: this.calculatePercentile(durations, 0.95),
      totalCost: costs.reduce((sum, c) => sum + c, 0),
      averageCost: costs.reduce((sum, c) => sum + c, 0) / costs.length,
      totalTokensInput: recentMetrics.reduce((sum, m) => sum + m.inputTokens, 0),
      totalTokensOutput: recentMetrics.reduce((sum, m) => sum + m.outputTokens, 0),
      requestsPerMinute: recentMetrics.length / (timeWindowMs / 60000)
    };
  }

  private async publishMetrics(metric: PerformanceMetric): Promise<void> {
    const cloudWatch = new AWS.CloudWatch();
    
    const params: AWS.CloudWatch.PutMetricDataRequest = {
      Namespace: 'TranslationService/Gemini',
      MetricData: [
        {
          MetricName: 'RequestLatency',
          Value: metric.duration,
          Unit: 'Milliseconds',
          Dimensions: [
            { Name: 'Operation', Value: metric.operation },
            { Name: 'Status', Value: metric.success ? 'Success' : 'Error' }
          ]
        },
        {
          MetricName: 'TokenUsage',
          Value: metric.inputTokens + metric.outputTokens,
          Unit: 'Count',
          Dimensions: [
            { Name: 'TokenType', Value: 'Total' }
          ]
        },
        {
          MetricName: 'Cost',
          Value: metric.cost,
          Unit: 'None',
          Dimensions: [
            { Name: 'Operation', Value: metric.operation }
          ]
        }
      ]
    };

    try {
      await cloudWatch.putMetricData(params).promise();
    } catch (error) {
      console.error('Failed to publish CloudWatch metrics:', error);
    }
  }
}
```

### Real-time Cost Tracking
```typescript
class RealTimeCostTracker {
  private currentCosts: Map<string, DailyCost> = new Map();
  private monthlyTracking: Map<string, MonthlyCost> = new Map();

  constructor(private limits: CostLimits) {}

  async trackUsage(tokenUsage: TokenUsage, documentId: string): Promise<void> {
    const today = new Date().toISOString().split('T')[0];
    const thisMonth = new Date().toISOString().substring(0, 7);

    // Update daily tracking
    const dailyKey = `${today}`;
    const dailyCost = this.currentCosts.get(dailyKey) || {
      date: today,
      totalCost: 0,
      requestCount: 0,
      tokenCount: 0,
      documents: new Set()
    };

    dailyCost.totalCost += tokenUsage.cost;
    dailyCost.requestCount += 1;
    dailyCost.tokenCount += tokenUsage.inputTokens + tokenUsage.outputTokens;
    dailyCost.documents.add(documentId);

    this.currentCosts.set(dailyKey, dailyCost);

    // Update monthly tracking
    const monthlyKey = thisMonth;
    const monthlyCost = this.monthlyTracking.get(monthlyKey) || {
      month: thisMonth,
      totalCost: 0,
      requestCount: 0,
      tokenCount: 0,
      documentsProcessed: new Set()
    };

    monthlyCost.totalCost += tokenUsage.cost;
    monthlyCost.requestCount += 1;
    monthlyCost.tokenCount += tokenUsage.inputTokens + tokenUsage.outputTokens;
    monthlyCost.documentsProcessed.add(documentId);

    this.monthlyTracking.set(monthlyKey, monthlyCost);

    // Check budget alerts
    await this.checkBudgetAlerts(dailyCost, monthlyCost);

    // Persist to storage
    await this.persistCostData(dailyCost, monthlyCost);
  }

  async checkBudgetConstraints(estimatedCost: number): Promise<void> {
    const today = new Date().toISOString().split('T')[0];
    const thisMonth = new Date().toISOString().substring(0, 7);

    const dailyCost = this.currentCosts.get(today)?.totalCost || 0;
    const monthlyCost = this.monthlyTracking.get(thisMonth)?.totalCost || 0;

    // Check daily budget
    if (dailyCost + estimatedCost > this.limits.dailyBudget) {
      throw new BudgetExceededError(
        `Daily budget exceeded. Current: $${dailyCost.toFixed(2)}, Estimated: $${estimatedCost.toFixed(2)}, Limit: $${this.limits.dailyBudget.toFixed(2)}`
      );
    }

    // Check monthly budget
    if (monthlyCost + estimatedCost > this.limits.monthlyBudget) {
      throw new BudgetExceededError(
        `Monthly budget exceeded. Current: $${monthlyCost.toFixed(2)}, Estimated: $${estimatedCost.toFixed(2)}, Limit: $${this.limits.monthlyBudget.toFixed(2)}`
      );
    }

    // Check emergency threshold
    const dailyThreshold = this.limits.dailyBudget * this.limits.emergencyThreshold;
    const monthlyThreshold = this.limits.monthlyBudget * this.limits.emergencyThreshold;

    if (dailyCost + estimatedCost > dailyThreshold || monthlyCost + estimatedCost > monthlyThreshold) {
      console.warn('Approaching budget limit:', { dailyCost, monthlyCost, estimatedCost });
      
      // Send alert to monitoring system
      await this.sendBudgetAlert({
        type: 'APPROACHING_LIMIT',
        dailyCost: dailyCost + estimatedCost,
        monthlyCost: monthlyCost + estimatedCost,
        dailyLimit: this.limits.dailyBudget,
        monthlyLimit: this.limits.monthlyBudget
      });
    }
  }

  private async sendBudgetAlert(alert: BudgetAlert): Promise<void> {
    // Implement SNS notification or similar
    console.warn('Budget Alert:', alert);
  }
}
```

## 7. Implementation Examples

### Complete Lambda Handler for Gemini Integration
```typescript
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

export const translateChunkHandler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  const startTime = Date.now();
  let geminiClient: GeminiAPIClient;
  
  try {
    const request: GeminiTranslationRequest = JSON.parse(event.body || '{}');
    
    // Validate request
    if (!request.chunkId || !request.content || !request.targetLanguage) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: 'Missing required fields: chunkId, content, targetLanguage'
        })
      };
    }

    // Initialize Gemini client
    const config: GeminiConfig = {
      apiKey: process.env.GEMINI_API_KEY!,
      model: 'gemini-pro',
      baseURL: 'https://generativelanguage.googleapis.com',
      rateLimits: {
        requestsPerMinute: 60,
        inputTokensPerMinute: 1000000,
        outputTokensPerMinute: 1000000
      },
      timeouts: {
        connectionTimeout: 10000,
        requestTimeout: 120000
      },
      retryConfig: {
        maxRetries: 3,
        backoffMultiplier: 2,
        maxBackoffDelay: 30000
      },
      costLimits: {
        dailyBudget: parseFloat(process.env.DAILY_BUDGET || '10'),
        monthlyBudget: parseFloat(process.env.MONTHLY_BUDGET || '300'),
        emergencyThreshold: 0.9
      }
    };

    geminiClient = new GeminiAPIClient(config);

    // Process translation
    const response = await geminiClient.translateChunk(request);

    // Update job progress
    await updateChunkProgress(request.chunkId, response);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache'
      },
      body: JSON.stringify(response)
    };

  } catch (error) {
    const duration = Date.now() - startTime;
    
    // Log error with context
    console.error('Gemini translation error:', {
      error: error.message,
      stack: error.stack,
      chunkId: JSON.parse(event.body || '{}').chunkId,
      duration
    });

    // Determine appropriate error response
    if (error instanceof RateLimitError) {
      return {
        statusCode: 429,
        headers: {
          'Retry-After': '60'
        },
        body: JSON.stringify({
          error: 'Rate limit exceeded',
          message: error.message,
          retryAfter: 60
        })
      };
    }

    if (error instanceof BudgetExceededError) {
      return {
        statusCode: 402,
        body: JSON.stringify({
          error: 'Budget exceeded',
          message: error.message
        })
      };
    }

    if (error instanceof ServiceUnavailableError) {
      return {
        statusCode: 503,
        headers: {
          'Retry-After': '30'
        },
        body: JSON.stringify({
          error: 'Service temporarily unavailable',
          message: error.message,
          retryAfter: 30
        })
      };
    }

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Internal server error',
        message: 'Translation processing failed'
      })
    };
  }
};

async function updateChunkProgress(
  chunkId: string, 
  response: GeminiTranslationResponse
): Promise<void> {
  // Update DynamoDB with translation result
  const params = {
    TableName: process.env.CHUNKS_TABLE!,
    Key: {
      PK: `CHUNK#${chunkId}`,
      SK: 'METADATA'
    },
    UpdateExpression: 'SET #status = :status, translatedContent = :content, confidence = :confidence, tokenUsage = :usage, updatedAt = :timestamp',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':status': 'TRANSLATED',
      ':content': response.translatedContent,
      ':confidence': response.confidence,
      ':usage': response.tokenUsage,
      ':timestamp': new Date().toISOString()
    }
  };

  await dynamoClient.update(params).promise();

  // Store detailed result in S3
  const s3Key = `translations/${chunkId}/result.json`;
  await s3Client.putObject({
    Bucket: process.env.RESULTS_BUCKET!,
    Key: s3Key,
    Body: JSON.stringify(response, null, 2),
    ContentType: 'application/json'
  }).promise();
}
```

## 8. Testing Strategy

### Unit Testing for Gemini Integration
```typescript
describe('GeminiAPIClient', () => {
  let client: GeminiAPIClient;
  let mockFetch: jest.MockedFunction<typeof fetch>;

  beforeEach(() => {
    mockFetch = jest.fn();
    global.fetch = mockFetch;
    
    const config: GeminiConfig = {
      apiKey: 'test-key',
      model: 'gemini-pro',
      baseURL: 'https://generativelanguage.googleapis.com',
      rateLimits: { requestsPerMinute: 60, inputTokensPerMinute: 1000000, outputTokensPerMinute: 1000000 },
      timeouts: { connectionTimeout: 10000, requestTimeout: 120000 },
      retryConfig: { maxRetries: 3, backoffMultiplier: 2, maxBackoffDelay: 30000 },
      costLimits: { dailyBudget: 10, monthlyBudget: 300, emergencyThreshold: 0.9 }
    };
    
    client = new GeminiAPIClient(config);
  });

  it('successfully translates a chunk', async () => {
    const mockResponse = {
      id: 'msg_test',
      content: [{ text: 'Translated content' }],
      usage: { input_tokens: 100, output_tokens: 120 },
      model: 'gemini-pro'
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
      headers: new Headers({
        'x-ratelimit-requests-remaining': '59',
        'x-ratelimit-tokens-remaining': '999900'
      })
    } as Response);

    const request: GeminiTranslationRequest = {
      chunkId: 'test-chunk-1',
      content: 'Test content to translate',
      targetLanguage: 'spanish'
    };

    const result = await client.translateChunk(request);

    expect(result.chunkId).toBe('test-chunk-1');
    expect(result.translatedContent).toBe('Translated content');
    expect(result.tokenUsage.inputTokens).toBe(100);
    expect(result.tokenUsage.outputTokens).toBe(120);
    expect(result.confidence).toBeGreaterThan(0);
  });

  it('handles rate limiting correctly', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      json: async () => ({ error: { message: 'Rate limited' } }),
      headers: new Headers({ 'retry-after': '60' })
    } as Response);

    const request: GeminiTranslationRequest = {
      chunkId: 'test-chunk-1',
      content: 'Test content',
      targetLanguage: 'french'
    };

    await expect(client.translateChunk(request)).rejects.toThrow(RateLimitError);
  });

  it('respects budget constraints', async () => {
    // Mock high daily usage
    jest.spyOn(client['costTracker'], 'checkBudgetConstraints')
      .mockRejectedValueOnce(new BudgetExceededError('Daily budget exceeded'));

    const request: GeminiTranslationRequest = {
      chunkId: 'test-chunk-1',
      content: 'Test content',
      targetLanguage: 'german'
    };

    await expect(client.translateChunk(request)).rejects.toThrow(BudgetExceededError);
  });
});

describe('RateLimiter', () => {
  let rateLimiter: SlidingWindowRateLimiter;

  beforeEach(() => {
    rateLimiter = new SlidingWindowRateLimiter({
      requestsPerMinute: 10,
      inputTokensPerMinute: 1000,
      outputTokensPerMinute: 1000
    });
  });

  it('allows requests within limits', async () => {
    await expect(rateLimiter.acquirePermit(100)).resolves.not.toThrow();
  });

  it('blocks requests exceeding token limits', async () => {
    await rateLimiter.acquirePermit(900);
    await expect(rateLimiter.acquirePermit(200)).rejects.toThrow(RateLimitError);
  });

  it('resets after time window', async () => {
    // Fill up the rate limit
    for (let i = 0; i < 10; i++) {
      await rateLimiter.acquirePermit(50);
    }

    // Should be blocked
    await expect(rateLimiter.acquirePermit(50)).rejects.toThrow(RateLimitError);

    // Mock time passage
    jest.advanceTimersByTime(61000); // 61 seconds

    // Should be allowed again
    await expect(rateLimiter.acquirePermit(50)).resolves.not.toThrow();
  });
});
```

### Integration Testing
```typescript
describe('Gemini API Integration', () => {
  let client: GeminiAPIClient;

  beforeAll(() => {
    // Use test API key or mock service
    const config = getTestConfig();
    client = new GeminiAPIClient(config);
  });

  it('handles real Gemini API translation', async () => {
    const request: GeminiTranslationRequest = {
      chunkId: 'integration-test-1',
      content: 'Hello, this is a test document for translation.',
      targetLanguage: 'spanish',
      contextWindow: {
        preceding: 'This is the previous context.',
        following: 'This is the following context.'
      }
    };

    const result = await client.translateChunk(request);

    expect(result.translatedContent).toContain('Hola');
    expect(result.confidence).toBeGreaterThan(0.5);
    expect(result.tokenUsage.cost).toBeGreaterThan(0);
  }, 30000); // 30 second timeout for real API calls

  it('preserves markdown formatting', async () => {
    const markdownContent = `
# Title
This is **bold** and *italic* text.

- Item 1
- Item 2

\`\`\`javascript
console.log('test');
\`\`\`
`;

    const request: GeminiTranslationRequest = {
      chunkId: 'markdown-test',
      content: markdownContent,
      targetLanguage: 'french'
    };

    const result = await client.translateChunk(request);

    expect(result.translatedContent).toMatch(/^# /m); // Header preserved
    expect(result.translatedContent).toContain('**'); // Bold formatting preserved
    expect(result.translatedContent).toContain('```javascript'); // Code block preserved
  }, 30000);
});
```

## 9. Configuration & Deployment

### CloudFormation Template for Gemini Integration
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Gemini API Integration Layer Infrastructure'

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, staging, prod]
  
  GeminiAPIKey:
    Type: String
    NoEcho: true
    Description: 'Gemini API key from Google'

Resources:
  # Lambda Function for Gemini Integration
  GeminiIntegrationFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'translation-gemini-${Environment}'
      Runtime: nodejs18.x
      Handler: dist/gemini.translateChunkHandler
      Code:
        S3Bucket: !Ref DeploymentBucket
        S3Key: !Sub 'gemini-integration-${Environment}.zip'
      MemorySize: 1024
      Timeout: 300
      Environment:
        Variables:
          GEMINI_API_KEY: !Ref GeminiAPIKey
          USAGE_TABLE: !Ref UsageTable
          RESULTS_BUCKET: !Ref ResultsBucket
          DAILY_BUDGET: !If [IsProd, '50', '10']
          MONTHLY_BUDGET: !If [IsProd, '1500', '300']
          LOG_LEVEL: !If [IsProd, 'INFO', 'DEBUG']
      ReservedConcurrencyLimit: 20 # Limit concurrent executions
      DeadLetterQueue:
        TargetArn: !GetAtt DeadLetterQueue.Arn

  # DynamoDB Table for Usage Tracking
  UsageTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub 'gemini-usage-${Environment}'
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
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES

  # CloudWatch Alarms
  HighErrorRateAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub 'gemini-high-error-rate-${Environment}'
      AlarmDescription: 'High error rate in Gemini API calls'
      MetricName: Errors
      Namespace: AWS/Lambda
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 2
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref GeminiIntegrationFunction
      AlarmActions:
        - !Ref AlertTopic

  BudgetExceededAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub 'gemini-budget-exceeded-${Environment}'
      AlarmDescription: 'Gemini API budget exceeded'
      MetricName: Cost
      Namespace: TranslationService/Gemini
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: !If [IsProd, '50', '10']
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic

Conditions:
  IsProd: !Equals [!Ref Environment, 'prod']

Outputs:
  GeminiIntegrationArn:
    Description: 'ARN of Gemini integration function'
    Value: !GetAtt GeminiIntegrationFunction.Arn
    Export:
      Name: !Sub '${AWS::StackName}-GeminiIntegrationArn'
```

## 10. Security & Compliance

### API Key Management and Encryption
```typescript
class SecureGeminiClient extends GeminiAPIClient {
  private encryptionKey: string;

  constructor(config: GeminiConfig, encryptionKey: string) {
    super(config);
    this.encryptionKey = encryptionKey;
  }

  protected async logAPICall(
    callId: string,
    request: GeminiTranslationRequest,
    status: string,
    response?: GeminiTranslationResponse,
    error?: Error
  ): Promise<void> {
    // Encrypt sensitive content before logging
    const encryptedRequest = {
      ...request,
      content: await this.encrypt(request.content)
    };

    const encryptedResponse = response ? {
      ...response,
      translatedContent: await this.encrypt(response.translatedContent)
    } : undefined;

    await super.logAPICall(callId, encryptedRequest, status, encryptedResponse, error);
  }

  private async encrypt(content: string): Promise<string> {
    const crypto = require('crypto');
    const algorithm = 'aes-256-gcm';
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, this.encryptionKey);
    
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return `${iv.toString('hex')}:${encrypted}`;
  }

  private async decrypt(encryptedContent: string): Promise<string> {
    const crypto = require('crypto');
    const algorithm = 'aes-256-gcm';
    const [ivHex, encrypted] = encryptedContent.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipher(algorithm, this.encryptionKey);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

---

This comprehensive Gemini API Integration Layer design provides robust, secure, and cost-effective translation capabilities while ensuring compliance with rate limits, budget constraints, and quality standards for the Long-Form Translation Service.
