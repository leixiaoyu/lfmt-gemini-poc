# Low-Level Design Document 4: Document Chunking Engine

## 1. Component Overview & Responsibilities

The Document Chunking Engine intelligently divides 65K-400K word documents into optimal chunks for Gemini API processing while maintaining translation context and semantic coherence. It implements a sliding context window with sentence-boundary preservation to ensure high-quality translations.

**Key Responsibilities:**
- Sentence-boundary aware chunking with 3,500 token target size
- 250-token sliding context overlap for translation consistency
- Token estimation and validation for Gemini API limits
- Metadata preservation for translation context
- Progress tracking integration for real-time updates

**Why This Design:** Intelligent chunking preserves document coherence while staying within Gemini's token limits. The sliding context window ensures translations maintain consistency across chunk boundaries, critical for long-form document quality.

## 2. API Design & Interfaces

### Chunking Service Endpoints
```typescript
// POST /chunking/prepare
interface ChunkingRequest {
  documentId: string;
  content: string;
  targetLanguage: string;
  chunkSize?: number; // Default: 3500 tokens
  overlapSize?: number; // Default: 250 tokens
}

interface ChunkingResponse {
  documentId: string;
  totalChunks: number;
  estimatedTokens: number;
  chunks: DocumentChunk[];
  metadata: ChunkingMetadata;
}

// GET /chunking/{documentId}/chunks
interface ChunksRequest {
  documentId: string;
  startIndex?: number;
  endIndex?: number;
}

interface ChunksResponse {
  chunks: DocumentChunk[];
  totalCount: number;
  hasMore: boolean;
}
```

### Core Data Structures
```typescript
interface DocumentChunk {
  chunkId: string;
  documentId: string;
  index: number;
  content: string;
  tokenCount: number;
  startOffset: number;
  endOffset: number;
  contextWindow: {
    preceding: string; // 250 tokens from previous chunk
    following: string; // 250 tokens from next chunk
  };
  sentenceBoundaries: {
    startSentence: number;
    endSentence: number;
  };
  metadata: {
    paragraphCount: number;
    hasCodeBlocks: boolean;
    hasSpecialFormatting: boolean;
    estimatedComplexity: 'LOW' | 'MEDIUM' | 'HIGH';
  };
}

interface ChunkingMetadata {
  documentWordCount: number;
  estimatedTokenCount: number;
  chunkingStrategy: 'SENTENCE_BOUNDARY' | 'PARAGRAPH_BOUNDARY' | 'SLIDING_WINDOW';
  preservedElements: string[]; // Headers, lists, code blocks, etc.
  processingTime: number;
  qualityScore: number; // 0-100 based on coherence metrics
}
```

## 3. Data Models & Storage

### DynamoDB Schema for Chunks
```typescript
// Primary Table: DocumentChunks
interface DocumentChunkRecord {
  PK: string; // DOCUMENT#{documentId}
  SK: string; // CHUNK#{chunkIndex:03d}
  documentId: string;
  chunkIndex: number;
  content: string;
  tokenCount: number;
  startOffset: number;
  endOffset: number;
  contextBefore: string;
  contextAfter: string;
  sentenceStart: number;
  sentenceEnd: number;
  metadata: ChunkMetadata;
  createdAt: string;
  ttl: number; // Auto-delete after 30 days
}

// GSI: ChunksByStatus
interface ChunkProcessingStatus {
  GSI1PK: string; // STATUS#{status}
  GSI1SK: string; // CREATED#{timestamp}#{chunkId}
  chunkId: string;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  processingStartTime?: string;
  processingEndTime?: string;
  translationResult?: string;
  errorMessage?: string;
}
```

### S3 Storage Structure
```typescript
// S3 Key Structure for Chunked Documents
const s3Structure = {
  originalDocuments: 'documents/original/{documentId}/{filename}',
  chunkStorage: 'documents/chunks/{documentId}/chunk-{index:03d}.json',
  chunkingMetadata: 'documents/metadata/{documentId}/chunking-metadata.json',
  translationResults: 'documents/translated/{documentId}/chunk-{index:03d}-{targetLang}.json',
  finalDocument: 'documents/final/{documentId}/{filename}-{targetLang}.{ext}'
};

interface ChunkStorageFormat {
  chunkId: string;
  originalText: string;
  tokenCount: number;
  contextWindow: ContextWindow;
  sentenceBoundaries: SentenceBoundary[];
  preservedFormatting: FormattingElement[];
  translationHints: TranslationHint[];
}
```

## 4. Chunking Algorithms & Logic

### Sentence-Boundary Preservation Algorithm
```typescript
interface SentenceDetector {
  detectSentences(text: string): SentenceBoundary[];
  validateBoundary(text: string, position: number): boolean;
  preserveFormatting(text: string): FormattingElement[];
}

class AdvancedSentenceDetector implements SentenceDetector {
  private readonly sentenceEndRegex = /[.!?]+(\s+|$)/g;
  private readonly abbreviationPatterns = [
    /\b(?:Dr|Mr|Mrs|Ms|Prof|Inc|Ltd|Corp|etc|vs|i\.e|e\.g)\./gi,
    /\b[A-Z]\./g, // Single letter abbreviations
    /\d+\.\d+/g,  // Decimal numbers
  ];

  detectSentences(text: string): SentenceBoundary[] {
    const sentences: SentenceBoundary[] = [];
    let currentStart = 0;
    
    // Remove abbreviations temporarily
    const protectedText = this.protectAbbreviations(text);
    
    const matches = Array.from(protectedText.matchAll(this.sentenceEndRegex));
    
    for (const match of matches) {
      const endPosition = match.index! + match[0].length;
      
      // Validate this is a real sentence boundary
      if (this.isValidSentenceBoundary(text, endPosition)) {
        sentences.push({
          start: currentStart,
          end: endPosition,
          text: text.substring(currentStart, endPosition).trim(),
          confidence: this.calculateBoundaryConfidence(text, endPosition)
        });
        currentStart = endPosition;
      }
    }
    
    // Add final sentence if exists
    if (currentStart < text.length) {
      sentences.push({
        start: currentStart,
        end: text.length,
        text: text.substring(currentStart).trim(),
        confidence: 1.0
      });
    }
    
    return sentences;
  }

  private protectAbbreviations(text: string): string {
    let protectedText = text;
    this.abbreviationPatterns.forEach((pattern, index) => {
      protectedText = protectedText.replace(pattern, `__ABBREV_${index}__`);
    });
    return protectedText;
  }

  private isValidSentenceBoundary(text: string, position: number): boolean {
    const before = text.substring(Math.max(0, position - 10), position);
    const after = text.substring(position, Math.min(text.length, position + 10));
    
    // Check for common false positives
    if (/\d+\.\s*\d+/.test(before + after)) return false; // Decimal numbers
    if (/[A-Z]\.\s*[a-z]/.test(before + after)) return false; // Abbreviations
    if (/\w\.\s*\w/.test(before + after) && !/[.!?]\s+[A-Z]/.test(before + after)) return false;
    
    return true;
  }

  private calculateBoundaryConfidence(text: string, position: number): number {
    const context = text.substring(Math.max(0, position - 20), Math.min(text.length, position + 20));
    let confidence = 0.5; // Base confidence
    
    // Increase confidence for clear sentence endings
    if (/[.!?]\s+[A-Z]/.test(context)) confidence += 0.3;
    if (/\.\s*$/.test(context.substring(0, context.indexOf('.')))) confidence += 0.2;
    
    return Math.min(1.0, confidence);
  }
}
```

### Smart Chunking Algorithm
```typescript
interface ChunkingStrategy {
  chunkDocument(
    content: string, 
    targetTokens: number, 
    overlapTokens: number
  ): DocumentChunk[];
}

class SlidingWindowChunker implements ChunkingStrategy {
  constructor(
    private tokenizer: TokenCounter,
    private sentenceDetector: SentenceDetector
  ) {}

  chunkDocument(
    content: string,
    targetTokens: number = 3500,
    overlapTokens: number = 250
  ): DocumentChunk[] {
    const sentences = this.sentenceDetector.detectSentences(content);
    const chunks: DocumentChunk[] = [];
    
    let currentChunk: string[] = [];
    let currentTokens = 0;
    let chunkIndex = 0;
    let sentenceIndex = 0;
    
    for (let i = 0; i < sentences.length; i++) {
      const sentence = sentences[i];
      const sentenceTokens = this.tokenizer.countTokens(sentence.text);
      
      // Check if adding this sentence exceeds target
      if (currentTokens + sentenceTokens > targetTokens && currentChunk.length > 0) {
        // Create chunk with current sentences
        const chunk = this.createChunk({
          index: chunkIndex++,
          sentences: currentChunk,
          startSentence: sentenceIndex,
          endSentence: sentenceIndex + currentChunk.length - 1,
          allSentences: sentences,
          overlapTokens
        });
        
        chunks.push(chunk);
        
        // Prepare overlap for next chunk
        const overlap = this.calculateOverlap(currentChunk, overlapTokens);
        currentChunk = overlap.sentences;
        currentTokens = overlap.tokens;
        sentenceIndex += currentChunk.length - overlap.sentences.length;
      }
      
      currentChunk.push(sentence.text);
      currentTokens += sentenceTokens;
    }
    
    // Handle final chunk
    if (currentChunk.length > 0) {
      const chunk = this.createChunk({
        index: chunkIndex,
        sentences: currentChunk,
        startSentence: sentenceIndex,
        endSentence: sentences.length - 1,
        allSentences: sentences,
        overlapTokens
      });
      chunks.push(chunk);
    }
    
    return this.addContextWindows(chunks);
  }

  private createChunk(params: ChunkCreationParams): DocumentChunk {
    const content = params.sentences.join(' ');
    const tokenCount = this.tokenizer.countTokens(content);
    
    return {
      chunkId: `chunk-${params.index.toString().padStart(3, '0')}`,
      documentId: '', // Set by caller
      index: params.index,
      content,
      tokenCount,
      startOffset: this.calculateOffset(params.allSentences, params.startSentence),
      endOffset: this.calculateOffset(params.allSentences, params.endSentence + 1),
      contextWindow: { preceding: '', following: '' }, // Added later
      sentenceBoundaries: {
        startSentence: params.startSentence,
        endSentence: params.endSentence
      },
      metadata: this.analyzeChunkComplexity(content)
    };
  }

  private calculateOverlap(sentences: string[], targetTokens: number): OverlapResult {
    const overlapSentences: string[] = [];
    let overlapTokens = 0;
    
    // Take sentences from the end until we reach target overlap
    for (let i = sentences.length - 1; i >= 0; i--) {
      const sentenceTokens = this.tokenizer.countTokens(sentences[i]);
      if (overlapTokens + sentenceTokens <= targetTokens) {
        overlapSentences.unshift(sentences[i]);
        overlapTokens += sentenceTokens;
      } else {
        break;
      }
    }
    
    return {
      sentences: overlapSentences,
      tokens: overlapTokens
    };
  }

  private addContextWindows(chunks: DocumentChunk[]): DocumentChunk[] {
    return chunks.map((chunk, index) => ({
      ...chunk,
      contextWindow: {
        preceding: index > 0 ? this.extractContextTokens(chunks[index - 1].content, 250, 'end') : '',
        following: index < chunks.length - 1 ? this.extractContextTokens(chunks[index + 1].content, 250, 'start') : ''
      }
    }));
  }

  private extractContextTokens(text: string, maxTokens: number, direction: 'start' | 'end'): string {
    const words = text.split(/\s+/);
    const targetWords = Math.floor(maxTokens * 0.75); // Approximate token-to-word ratio
    
    if (direction === 'start') {
      return words.slice(0, targetWords).join(' ');
    } else {
      return words.slice(-targetWords).join(' ');
    }
  }

  private analyzeChunkComplexity(content: string): ChunkMetadata {
    const paragraphCount = content.split(/\n\s*\n/).length;
    const hasCodeBlocks = /```[\s\S]*?```|`[^`]+`/.test(content);
    const hasSpecialFormatting = /[*_]{1,3}[^*_]+[*_]{1,3}|\s*\[.+?\]\(.+?\)/.test(content);
    
    let complexity: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
    if (hasCodeBlocks || hasSpecialFormatting) complexity = 'MEDIUM';
    if (hasCodeBlocks && hasSpecialFormatting && paragraphCount > 5) complexity = 'HIGH';
    
    return {
      paragraphCount,
      hasCodeBlocks,
      hasSpecialFormatting,
      estimatedComplexity: complexity
    };
  }
}
```

### Token Counting Implementation
```typescript
interface TokenCounter {
  countTokens(text: string): number;
  estimateTokens(text: string): number;
  validateTokenLimit(text: string, maxTokens: number): boolean;
}

class GeminiTokenCounter implements TokenCounter {
  private readonly avgTokensPerWord = 1.3;
  private readonly avgCharsPerToken = 4;

  countTokens(text: string): number {
    // Precise token counting using tiktoken-like algorithm
    return this.preciseTokenCount(text);
  }

  estimateTokens(text: string): number {
    // Fast estimation for initial chunking
    const wordCount = text.split(/\s+/).length;
    return Math.ceil(wordCount * this.avgTokensPerWord);
  }

  validateTokenLimit(text: string, maxTokens: number): boolean {
    return this.countTokens(text) <= maxTokens;
  }

  private preciseTokenCount(text: string): number {
    // Tokenization rules similar to Gemini's tokenizer
    let tokens = 0;
    
    // Split by whitespace and punctuation
    const segments = text.split(/(\s+|[^\w\s])/);
    
    for (const segment of segments) {
      if (segment.trim()) {
        if (/^\s+$/.test(segment)) {
          tokens += 1; // Whitespace token
        } else if (segment.length <= 4) {
          tokens += 1; // Short segments are usually single tokens
        } else {
          tokens += Math.ceil(segment.length / this.avgCharsPerToken);
        }
      }
    }
    
    return tokens;
  }
}
```

## 5. Error Handling & Edge Cases

### Chunking Validation and Recovery
```typescript
class ChunkingValidator {
  validateChunks(chunks: DocumentChunk[], originalContent: string): ValidationResult {
    const issues: ValidationIssue[] = [];
    
    // Check token limits
    for (const chunk of chunks) {
      if (chunk.tokenCount > 4000) {
        issues.push({
          type: 'TOKEN_LIMIT_EXCEEDED',
          chunkId: chunk.chunkId,
          severity: 'ERROR',
          message: `Chunk exceeds token limit: ${chunk.tokenCount} tokens`
        });
      }
    }
    
    // Check content coverage
    const totalCoverage = this.calculateContentCoverage(chunks, originalContent);
    if (totalCoverage < 0.95) {
      issues.push({
        type: 'INCOMPLETE_COVERAGE',
        severity: 'ERROR',
        message: `Content coverage too low: ${(totalCoverage * 100).toFixed(1)}%`
      });
    }
    
    // Check overlap quality
    const overlapIssues = this.validateOverlaps(chunks);
    issues.push(...overlapIssues);
    
    return {
      isValid: issues.filter(i => i.severity === 'ERROR').length === 0,
      issues,
      coverage: totalCoverage,
      recommendations: this.generateRecommendations(issues)
    };
  }

  private calculateContentCoverage(chunks: DocumentChunk[], original: string): number {
    let coveredLength = 0;
    for (const chunk of chunks) {
      coveredLength += chunk.endOffset - chunk.startOffset;
    }
    return coveredLength / original.length;
  }

  private validateOverlaps(chunks: DocumentChunk[]): ValidationIssue[] {
    const issues: ValidationIssue[] = [];
    
    for (let i = 0; i < chunks.length - 1; i++) {
      const current = chunks[i];
      const next = chunks[i + 1];
      
      const overlapStart = Math.max(current.startOffset, next.startOffset);
      const overlapEnd = Math.min(current.endOffset, next.endOffset);
      const overlapLength = Math.max(0, overlapEnd - overlapStart);
      
      if (overlapLength < 100) { // Minimum overlap threshold
        issues.push({
          type: 'INSUFFICIENT_OVERLAP',
          chunkId: current.chunkId,
          severity: 'WARNING',
          message: `Insufficient overlap between chunks ${i} and ${i + 1}: ${overlapLength} characters`
        });
      }
    }
    
    return issues;
  }
}

// Error Recovery Strategies
class ChunkingErrorRecovery {
  async repairChunks(chunks: DocumentChunk[], issues: ValidationIssue[]): Promise<DocumentChunk[]> {
    let repairedChunks = [...chunks];
    
    for (const issue of issues) {
      switch (issue.type) {
        case 'TOKEN_LIMIT_EXCEEDED':
          repairedChunks = await this.splitOversizedChunk(repairedChunks, issue.chunkId!);
          break;
        case 'INSUFFICIENT_OVERLAP':
          repairedChunks = await this.addOverlap(repairedChunks, issue.chunkId!);
          break;
        case 'INCOMPLETE_COVERAGE':
          repairedChunks = await this.fillGaps(repairedChunks);
          break;
      }
    }
    
    return repairedChunks;
  }

  private async splitOversizedChunk(chunks: DocumentChunk[], chunkId: string): Promise<DocumentChunk[]> {
    const chunkIndex = chunks.findIndex(c => c.chunkId === chunkId);
    if (chunkIndex === -1) return chunks;
    
    const oversizedChunk = chunks[chunkIndex];
    const sentences = this.sentenceDetector.detectSentences(oversizedChunk.content);
    
    // Split into two chunks at the midpoint
    const midpoint = Math.floor(sentences.length / 2);
    const firstHalf = sentences.slice(0, midpoint).map(s => s.text).join(' ');
    const secondHalf = sentences.slice(midpoint).map(s => s.text).join(' ');
    
    const newChunks = [
      {
        ...oversizedChunk,
        chunkId: `${chunkId}-a`,
        content: firstHalf,
        tokenCount: this.tokenizer.countTokens(firstHalf)
      },
      {
        ...oversizedChunk,
        chunkId: `${chunkId}-b`,
        index: oversizedChunk.index + 0.5,
        content: secondHalf,
        tokenCount: this.tokenizer.countTokens(secondHalf)
      }
    ];
    
    // Replace original chunk with split chunks
    const result = [...chunks];
    result.splice(chunkIndex, 1, ...newChunks);
    
    // Renumber subsequent chunks
    for (let i = chunkIndex + 2; i < result.length; i++) {
      result[i] = { ...result[i], index: result[i].index + 1 };
    }
    
    return result;
  }
}
```

## 6. Performance & Monitoring

### Chunking Performance Metrics
```typescript
interface ChunkingMetrics {
  processingTime: number;
  chunksPerSecond: number;
  averageChunkSize: number;
  tokenAccuracy: number; // Actual vs estimated tokens
  memoryUsage: number;
  qualityScore: number;
}

class ChunkingPerformanceMonitor {
  private metrics: ChunkingMetrics[] = [];

  trackChunkingOperation(operation: () => Promise<DocumentChunk[]>): Promise<DocumentChunk[]> {
    const startTime = Date.now();
    const startMemory = process.memoryUsage().heapUsed;
    
    return operation().then(chunks => {
      const endTime = Date.now();
      const endMemory = process.memoryUsage().heapUsed;
      
      const metrics: ChunkingMetrics = {
        processingTime: endTime - startTime,
        chunksPerSecond: chunks.length / ((endTime - startTime) / 1000),
        averageChunkSize: chunks.reduce((sum, chunk) => sum + chunk.tokenCount, 0) / chunks.length,
        tokenAccuracy: this.calculateTokenAccuracy(chunks),
        memoryUsage: endMemory - startMemory,
        qualityScore: this.calculateQualityScore(chunks)
      };
      
      this.metrics.push(metrics);
      this.logMetrics(metrics);
      
      return chunks;
    });
  }

  private calculateTokenAccuracy(chunks: DocumentChunk[]): number {
    let totalAccuracy = 0;
    for (const chunk of chunks) {
      const estimatedTokens = this.tokenizer.estimateTokens(chunk.content);
      const actualTokens = chunk.tokenCount;
      const accuracy = 1 - Math.abs(estimatedTokens - actualTokens) / actualTokens;
      totalAccuracy += accuracy;
    }
    return totalAccuracy / chunks.length;
  }

  private calculateQualityScore(chunks: DocumentChunk[]): number {
    let score = 100;
    
    // Penalize for poor sentence boundaries
    const sentenceBoundaryScore = this.evaluateSentenceBoundaries(chunks);
    score -= (100 - sentenceBoundaryScore) * 0.3;
    
    // Penalize for poor overlap
    const overlapScore = this.evaluateOverlapQuality(chunks);
    score -= (100 - overlapScore) * 0.2;
    
    // Penalize for size variation
    const sizeConsistencyScore = this.evaluateSizeConsistency(chunks);
    score -= (100 - sizeConsistencyScore) * 0.1;
    
    return Math.max(0, score);
  }
}
```

### Caching Strategy
```typescript
class ChunkingCache {
  private cache = new Map<string, CachedChunking>();
  private readonly maxCacheSize = 100;
  private readonly cacheTimeout = 3600000; // 1 hour

  async getOrCreateChunks(
    documentHash: string,
    content: string,
    options: ChunkingOptions
  ): Promise<DocumentChunk[]> {
    const cacheKey = this.generateCacheKey(documentHash, options);
    const cached = this.cache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.chunks;
    }
    
    const chunks = await this.chunker.chunkDocument(content, options.targetTokens, options.overlapTokens);
    
    this.cache.set(cacheKey, {
      chunks,
      timestamp: Date.now(),
      contentHash: documentHash
    });
    
    this.evictExpiredEntries();
    return chunks;
  }

  private generateCacheKey(documentHash: string, options: ChunkingOptions): string {
    return `${documentHash}-${options.targetTokens}-${options.overlapTokens}`;
  }

  private evictExpiredEntries(): void {
    if (this.cache.size <= this.maxCacheSize) return;
    
    const entries = Array.from(this.cache.entries());
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    
    // Remove oldest entries
    const toRemove = entries.slice(0, entries.length - this.maxCacheSize);
    toRemove.forEach(([key]) => this.cache.delete(key));
  }
}
```

## 7. Implementation Examples

### Complete Chunking Service Implementation
```typescript
export class DocumentChunkingService {
  constructor(
    private tokenizer: TokenCounter,
    private sentenceDetector: SentenceDetector,
    private chunker: ChunkingStrategy,
    private validator: ChunkingValidator,
    private cache: ChunkingCache,
    private metrics: ChunkingPerformanceMonitor
  ) {}

  async chunkDocument(request: ChunkingRequest): Promise<ChunkingResponse> {
    const documentHash = this.calculateDocumentHash(request.content);
    
    return this.metrics.trackChunkingOperation(async () => {
      // Check cache first
      const cachedChunks = await this.cache.getOrCreateChunks(
        documentHash,
        request.content,
        {
          targetTokens: request.chunkSize || 3500,
          overlapTokens: request.overlapSize || 250
        }
      );
      
      if (cachedChunks.length > 0) {
        return this.buildResponse(request.documentId, cachedChunks, request.content);
      }
      
      // Perform chunking
      const chunks = await this.chunker.chunkDocument(
        request.content,
        request.chunkSize || 3500,
        request.overlapSize || 250
      );
      
      // Add document ID to chunks
      const chunksWithId = chunks.map(chunk => ({
        ...chunk,
        documentId: request.documentId
      }));
      
      // Validate chunks
      const validation = this.validator.validateChunks(chunksWithId, request.content);
      if (!validation.isValid) {
        const repairedChunks = await this.errorRecovery.repairChunks(chunksWithId, validation.issues);
        return this.buildResponse(request.documentId, repairedChunks, request.content);
      }
      
      return this.buildResponse(request.documentId, chunksWithId, request.content);
    });
  }

  private buildResponse(
    documentId: string,
    chunks: DocumentChunk[],
    originalContent: string
  ): ChunkingResponse {
    const totalTokens = chunks.reduce((sum, chunk) => sum + chunk.tokenCount, 0);
    
    return {
      documentId,
      totalChunks: chunks.length,
      estimatedTokens: totalTokens,
      chunks,
      metadata: {
        documentWordCount: originalContent.split(/\s+/).length,
        estimatedTokenCount: totalTokens,
        chunkingStrategy: 'SLIDING_WINDOW',
        preservedElements: this.identifyPreservedElements(originalContent),
        processingTime: Date.now(),
        qualityScore: this.metrics.calculateQualityScore(chunks)
      }
    };
  }

  private calculateDocumentHash(content: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  private identifyPreservedElements(content: string): string[] {
    const elements: string[] = [];
    
    if (/^#{1,6}\s/.test(content)) elements.push('headers');
    if (/^\s*[-*+]\s/.test(content)) elements.push('lists');
    if (/```[\s\S]*?```/.test(content)) elements.push('code_blocks');
    if (/\[.+?\]\(.+?\)/.test(content)) elements.push('links');
    if (/!\[.*?\]\(.+?\)/.test(content)) elements.push('images');
    
    return elements;
  }
}
```

### Lambda Handler Implementation
```typescript
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

export const chunkDocumentHandler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  try {
    const request: ChunkingRequest = JSON.parse(event.body || '{}');
    
    // Validate request
    if (!request.documentId || !request.content) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: 'Missing required fields: documentId, content'
        })
      };
    }
    
    // Initialize services
    const tokenizer = new GeminiTokenCounter();
    const sentenceDetector = new AdvancedSentenceDetector();
    const chunker = new SlidingWindowChunker(tokenizer, sentenceDetector);
    const validator = new ChunkingValidator();
    const cache = new ChunkingCache();
    const metrics = new ChunkingPerformanceMonitor();
    
    const service = new DocumentChunkingService(
      tokenizer,
      sentenceDetector,
      chunker,
      validator,
      cache,
      metrics
    );
    
    // Process chunking request
    const response = await service.chunkDocument(request);
    
    // Store chunks in DynamoDB and S3
    await storeChunks(response.documentId, response.chunks);
    
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache'
      },
      body: JSON.stringify(response)
    };
    
  } catch (error) {
    console.error('Chunking error:', error);
    
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Internal server error during document chunking',
        message: error instanceof Error ? error.message : 'Unknown error'
      })
    };
  }
};

async function storeChunks(documentId: string, chunks: DocumentChunk[]): Promise<void> {
  // Store in DynamoDB for quick access
  const dynamoItems = chunks.map(chunk => ({
    PK: `DOCUMENT#${documentId}`,
    SK: `CHUNK#${chunk.index.toString().padStart(3, '0')}`,
    documentId,
    chunkIndex: chunk.index,
    content: chunk.content,
    tokenCount: chunk.tokenCount,
    startOffset: chunk.startOffset,
    endOffset: chunk.endOffset,
    contextBefore: chunk.contextWindow.preceding,
    contextAfter: chunk.contextWindow.following,
    sentenceStart: chunk.sentenceBoundaries.startSentence,
    sentenceEnd: chunk.sentenceBoundaries.endSentence,
    metadata: chunk.metadata,
    createdAt: new Date().toISOString(),
    ttl: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60 // 30 days
  }));
  
  // Batch write to DynamoDB
  await dynamoClient.batchWrite({
    RequestItems: {
      [CHUNKS_TABLE]: dynamoItems.map(item => ({
        PutRequest: { Item: item }
      }))
    }
  }).promise();
  
  // Store detailed chunks in S3 for backup
  for (const chunk of chunks) {
    const s3Key = `documents/chunks/${documentId}/chunk-${chunk.index.toString().padStart(3, '0')}.json`;
    await s3Client.putObject({
      Bucket: CHUNKS_BUCKET,
      Key: s3Key,
      Body: JSON.stringify(chunk, null, 2),
      ContentType: 'application/json'
    }).promise();
  }
}
```

## 8. Testing Strategy

### Unit Testing for Chunking Logic
```typescript
describe('SlidingWindowChunker', () => {
  let chunker: SlidingWindowChunker;
  let tokenizer: jest.Mocked<TokenCounter>;
  let sentenceDetector: jest.Mocked<SentenceDetector>;

  beforeEach(() => {
    tokenizer = {
      countTokens: jest.fn(),
      estimateTokens: jest.fn(),
      validateTokenLimit: jest.fn()
    };
    
    sentenceDetector = {
      detectSentences: jest.fn(),
      validateBoundary: jest.fn(),
      preserveFormatting: jest.fn()
    };
    
    chunker = new SlidingWindowChunker(tokenizer, sentenceDetector);
  });

  it('creates chunks with proper token limits', async () => {
    const content = 'First sentence. Second sentence. Third sentence. Fourth sentence.';
    const sentences = [
      { start: 0, end: 15, text: 'First sentence.', confidence: 1.0 },
      { start: 16, end: 32, text: 'Second sentence.', confidence: 1.0 },
      { start: 33, end: 48, text: 'Third sentence.', confidence: 1.0 },
      { start: 49, end: 65, text: 'Fourth sentence.', confidence: 1.0 }
    ];
    
    sentenceDetector.detectSentences.mockReturnValue(sentences);
    tokenizer.countTokens.mockImplementation(text => Math.ceil(text.length / 4));
    
    const chunks = chunker.chunkDocument(content, 10, 3);
    
    expect(chunks).toHaveLength(3);
    expect(chunks[0].tokenCount).toBeLessThanOrEqual(10);
    expect(chunks[1].tokenCount).toBeLessThanOrEqual(10);
    expect(chunks[2].tokenCount).toBeLessThanOrEqual(10);
  });

  it('maintains sentence boundaries', async () => {
    const content = 'Complete sentence one. Incomplete sent';
    const sentences = [
      { start: 0, end: 22, text: 'Complete sentence one.', confidence: 1.0 }
    ];
    
    sentenceDetector.detectSentences.mockReturnValue(sentences);
    tokenizer.countTokens.mockReturnValue(5);
    
    const chunks = chunker.chunkDocument(content, 20, 2);
    
    expect(chunks[0].content).toEqual('Complete sentence one.');
  });

  it('handles overlap correctly', async () => {
    const content = 'Sentence one. Sentence two. Sentence three. Sentence four.';
    const sentences = [
      { start: 0, end: 13, text: 'Sentence one.', confidence: 1.0 },
      { start: 14, end: 27, text: 'Sentence two.', confidence: 1.0 },
      { start: 28, end: 43, text: 'Sentence three.', confidence: 1.0 },
      { start: 44, end: 58, text: 'Sentence four.', confidence: 1.0 }
    ];
    
    sentenceDetector.detectSentences.mockReturnValue(sentences);
    tokenizer.countTokens.mockImplementation(text => text.split(' ').length);
    
    const chunks = chunker.chunkDocument(content, 6, 3);
    
    // Verify overlap exists between consecutive chunks
    expect(chunks).toHaveLength(2);
    const firstChunkEnd = chunks[0].content.split(' ').slice(-2).join(' ');
    const secondChunkStart = chunks[1].content.split(' ').slice(0, 2).join(' ');
    expect(firstChunkEnd).toEqual(secondChunkStart);
  });
});

describe('ChunkingValidator', () => {
  let validator: ChunkingValidator;

  beforeEach(() => {
    validator = new ChunkingValidator();
  });

  it('validates token limits correctly', () => {
    const chunks: DocumentChunk[] = [
      createMockChunk({ tokenCount: 3500 }),
      createMockChunk({ tokenCount: 4500 }) // Exceeds limit
    ];
    
    const result = validator.validateChunks(chunks, 'original content');
    
    expect(result.isValid).toBe(false);
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].type).toBe('TOKEN_LIMIT_EXCEEDED');
  });

  it('detects insufficient overlap', () => {
    const chunks: DocumentChunk[] = [
      createMockChunk({ startOffset: 0, endOffset: 100 }),
      createMockChunk({ startOffset: 95, endOffset: 200 }) // Only 5 char overlap
    ];
    
    const result = validator.validateChunks(chunks, 'x'.repeat(200));
    
    expect(result.issues.some(issue => issue.type === 'INSUFFICIENT_OVERLAP')).toBe(true);
  });
});

function createMockChunk(overrides: Partial<DocumentChunk>): DocumentChunk {
  return {
    chunkId: 'test-chunk',
    documentId: 'test-doc',
    index: 0,
    content: 'Test content',
    tokenCount: 100,
    startOffset: 0,
    endOffset: 100,
    contextWindow: { preceding: '', following: '' },
    sentenceBoundaries: { startSentence: 0, endSentence: 1 },
    metadata: {
      paragraphCount: 1,
      hasCodeBlocks: false,
      hasSpecialFormatting: false,
      estimatedComplexity: 'LOW'
    },
    ...overrides
  };
}
```

### Integration Testing
```typescript
describe('Document Chunking Integration', () => {
  let service: DocumentChunkingService;
  
  beforeAll(async () => {
    // Setup test environment
    service = createTestChunkingService();
  });

  it('handles large documents correctly', async () => {
    const largeDocument = generateTestDocument(100000); // 100K words
    
    const request: ChunkingRequest = {
      documentId: 'large-test-doc',
      content: largeDocument,
      targetLanguage: 'spanish'
    };
    
    const response = await service.chunkDocument(request);
    
    expect(response.totalChunks).toBeGreaterThan(20);
    expect(response.estimatedTokens).toBeGreaterThan(100000);
    
    // Verify all chunks are within token limits
    response.chunks.forEach(chunk => {
      expect(chunk.tokenCount).toBeLessThanOrEqual(3500);
    });
  });

  it('preserves document formatting', async () => {
    const formattedDocument = `
# Main Title

This is a paragraph with **bold** and *italic* text.

- List item 1
- List item 2

```javascript
console.log('code block');
```

Another paragraph.
`;
    
    const request: ChunkingRequest = {
      documentId: 'formatted-doc',
      content: formattedDocument,
      targetLanguage: 'french'
    };
    
    const response = await service.chunkDocument(request);
    
    expect(response.metadata.preservedElements).toContain('headers');
    expect(response.metadata.preservedElements).toContain('lists');
    expect(response.metadata.preservedElements).toContain('code_blocks');
  });
});
```

## 9. Configuration & Deployment

### CloudFormation Template for Chunking Service
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Document Chunking Engine Infrastructure'

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, staging, prod]

Resources:
  # Lambda Function for Chunking
  ChunkingFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'translation-chunking-${Environment}'
      Runtime: nodejs18.x
      Handler: dist/chunking.chunkDocumentHandler
      Code:
        S3Bucket: !Ref DeploymentBucket
        S3Key: !Sub 'chunking-service-${Environment}.zip'
      MemorySize: 1024
      Timeout: 300
      Environment:
        Variables:
          CHUNKS_TABLE: !Ref ChunksTable
          CHUNKS_BUCKET: !Ref ChunksBucket
          LOG_LEVEL: !If [IsProd, 'INFO', 'DEBUG']
      ReservedConcurrencyLimit: 10

  # DynamoDB Table for Chunk Metadata
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
        - AttributeName: GSI1PK
          AttributeType: S
        - AttributeName: GSI1SK
          AttributeType: S
      KeySchema:
        - AttributeName: PK
          KeyType: HASH
        - AttributeName: SK
          KeyType: RANGE
      GlobalSecondaryIndexes:
        - IndexName: ChunksByStatus
          KeySchema:
            - AttributeName: GSI1PK
              KeyType: HASH
            - AttributeName: GSI1SK
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
      TimeToLiveSpecification:
        AttributeName: ttl
        Enabled: true
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES

  # S3 Bucket for Chunk Storage
  ChunksBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub 'translation-chunks-${Environment}-${AWS::AccountId}'
      VersioningConfiguration:
        Status: Enabled
      LifecycleConfiguration:
        Rules:
          - Id: DeleteOldChunks
            Status: Enabled
            ExpirationInDays: 30
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true

  # API Gateway Integration
  ChunkingAPI:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref TranslationAPI
      ResourceId: !Ref ChunkingResource
      HttpMethod: POST
      AuthorizationType: AWS_IAM
      Integration:
        Type: AWS_PROXY
        IntegrationHttpMethod: POST
        Uri: !Sub 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${ChunkingFunction.Arn}/invocations'
      RequestValidatorId: !Ref RequestValidator

Conditions:
  IsProd: !Equals [!Ref Environment, 'prod']

Outputs:
  ChunkingFunctionArn:
    Description: 'ARN of the chunking Lambda function'
    Value: !GetAtt ChunkingFunction.Arn
    Export:
      Name: !Sub '${AWS::StackName}-ChunkingFunctionArn'
      
  ChunksTableName:
    Description: 'Name of the chunks DynamoDB table'
    Value: !Ref ChunksTable
    Export:
      Name: !Sub '${AWS::StackName}-ChunksTableName'
      
  ChunksBucketName:
    Description: 'Name of the chunks S3 bucket'
    Value: !Ref ChunksBucket
    Export:
      Name: !Sub '${AWS::StackName}-ChunksBucketName'
```

## 10. Performance Optimization & Monitoring

### CloudWatch Metrics and Alarms
```typescript
class ChunkingMetrics {
  private cloudWatch = new AWS.CloudWatch();
  
  async publishMetrics(metrics: ChunkingMetrics): Promise<void> {
    const params: AWS.CloudWatch.PutMetricDataRequest = {
      Namespace: 'TranslationService/Chunking',
      MetricData: [
        {
          MetricName: 'ProcessingTime',
          Value: metrics.processingTime,
          Unit: 'Milliseconds',
          Dimensions: [
            { Name: 'Environment', Value: process.env.ENVIRONMENT || 'dev' }
          ]
        },
        {
          MetricName: 'ChunksPerSecond',
          Value: metrics.chunksPerSecond,
          Unit: 'Count/Second'
        },
        {
          MetricName: 'AverageChunkSize',
          Value: metrics.averageChunkSize,
          Unit: 'Count'
        },
        {
          MetricName: 'TokenAccuracy',
          Value: metrics.tokenAccuracy * 100,
          Unit: 'Percent'
        },
        {
          MetricName: 'QualityScore',
          Value: metrics.qualityScore,
          Unit: 'None'
        }
      ]
    };
    
    await this.cloudWatch.putMetricData(params).promise();
  }
}

// CloudWatch Alarms (CloudFormation)
const alarms = `
ChunkingErrorRate:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmName: !Sub 'chunking-error-rate-${Environment}'
    AlarmDescription: 'High error rate in document chunking'
    MetricName: Errors
    Namespace: AWS/Lambda
    Statistic: Sum
    Period: 300
    EvaluationPeriods: 2
    Threshold: 5
    ComparisonOperator: GreaterThanThreshold
    Dimensions:
      - Name: FunctionName
        Value: !Ref ChunkingFunction

ChunkingLatency:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmName: !Sub 'chunking-latency-${Environment}'
    AlarmDescription: 'High latency in document chunking'
    MetricName: Duration
    Namespace: AWS/Lambda
    Statistic: Average
    Period: 300
    EvaluationPeriods: 3
    Threshold: 30000
    ComparisonOperator: GreaterThanThreshold
    Dimensions:
      - Name: FunctionName
        Value: !Ref ChunkingFunction
`;
```

---

This comprehensive Document Chunking Engine design provides the foundation for intelligent document processing with Gemini API, ensuring high-quality translations through sentence-boundary preservation and sliding context windows while maintaining performance and reliability standards for the Long-Form Translation Service.
