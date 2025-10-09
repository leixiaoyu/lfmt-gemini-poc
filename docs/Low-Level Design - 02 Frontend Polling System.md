# Low-Level Design Document 2: Frontend Polling System

## 1. Component Overview & Responsibilities

The Frontend Polling System provides intelligent, adaptive polling for near real-time progress tracking, officially adopted over WebSocket complexity for POC implementation. It automatically adjusts polling intervals based on job age, page visibility, and system performance to optimize user experience while minimizing server load and operational complexity.

**Key Responsibilities:**
- Adaptive polling interval management (15s → 30s → 60s → 120s)
- Page Visibility API integration for background optimization
- Circuit breaker pattern for API degradation scenarios
- Cache-aware polling to respect 30-second API cache TTL
- Near real-time UI updates with optimistic state management
- Job cancellation state coordination and cleanup

**Why This Design:** After comprehensive architecture review, polling was officially chosen over WebSocket for POC scope. This eliminates WebSocket session management complexity, reduces operational overhead, and provides cost-effective progress tracking suitable for long-running translation jobs (30 minutes to 6 hours). The adaptive intervals balance responsive updates with infrastructure efficiency.

## 2. API Design & Interfaces

### Progress Polling Endpoints
```typescript
// GET /translation/jobs/{jobId}/progress
interface ProgressResponse {
  jobId: string;
  status: JobStatus;
  progress: number; // 0-100
  chunksProcessed: number;
  totalChunks: number;
  estimatedTimeRemaining?: number; // seconds
  lastUpdated: string; // ISO 8601
  processingSpeed?: number; // words per minute
  currentStage?: string; // human-readable stage description
}

// GET /translation/jobs/{jobId}/status  
interface StatusResponse {
  jobId: string;
  status: JobStatus;
  lastUpdated: string;
  errorMessage?: string;
}

// Response Headers for Cache Control
interface PollingHeaders {
  'Cache-Control': 'max-age=30'; // 30 second cache
  'Content-Type': 'application/json';
  'X-RateLimit-Remaining': string;
  'X-RateLimit-Reset': string;
}
```

### Polling Configuration Types
```typescript
interface PollingConfig {
  intervals: {
    initial: number;    // 15000ms - first 5 minutes
    medium: number;     // 30000ms - 5-30 minutes  
    extended: number;   // 60000ms - 30+ minutes
    background: number; // 120000ms - when page not visible
  };
  thresholds: {
    mediumThreshold: number;  // 5 minutes
    extendedThreshold: number; // 30 minutes
  };
  circuit: {
    errorThreshold: number;     // 5 consecutive errors
    timeoutThreshold: number;   // 10 seconds
    recoveryTime: number;       // 30 seconds
  };
}
```

## 3. Data Models & Storage

### Polling State Management
```typescript
interface PollingState {
  jobId: string;
  isActive: boolean;
  interval: number;
  startTime: number;
  lastSuccess: number;
  errorCount: number;
  circuitState: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  pageVisible: boolean;
  performanceMetrics: {
    averageResponseTime: number;
    successRate: number;
    cacheHitRate: number;
  };
}

interface AdaptivePollingManager {
  activePollers: Map<string, PollingState>;
  globalConfig: PollingConfig;
  performanceMonitor: PerformanceMonitor;
}

// React Query Cache Structure
interface PollingCacheEntry {
  data: ProgressResponse;
  timestamp: number;
  cacheStatus: 'fresh' | 'stale' | 'expired';
  source: 'cache' | 'network';
}
```

## 4. User Interface Design

### Polling Status Indicators
```typescript
interface PollingStatusProps {
  jobId: string;
  pollingState: PollingState;
}

const PollingStatusIndicator: React.FC<PollingStatusProps> = ({ jobId, pollingState }) => {
  const getStatusColor = (state: PollingState) => {
    if (state.circuitState === 'OPEN') return 'error.main';
    if (state.errorCount > 0) return 'warning.main';
    return 'success.main';
  };

  const getStatusText = (state: PollingState) => {
    if (state.circuitState === 'OPEN') return 'Connection issues - retrying...';
    if (state.errorCount > 0) return `Retrying... (${state.errorCount} errors)`;
    if (!state.pageVisible) return 'Background monitoring';
    return `Checking every ${(state.interval / 1000).toFixed(0)}s`;
  };

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Circle sx={{ fontSize: 8, color: getStatusColor(pollingState) }} />
      <Typography variant="caption" color="text.secondary">
        {getStatusText(pollingState)}
      </Typography>
    </Box>
  );
};
```

## 5. Core Algorithms & Logic

### Adaptive Interval Calculation
```typescript
class AdaptivePollingCalculator {
  private config: PollingConfig;

  constructor(config: PollingConfig) {
    this.config = config;
  }

  calculateInterval(
    startTime: number,
    pageVisible: boolean,
    errorCount: number,
    lastResponseTime: number
  ): number {
    const elapsedTime = Date.now() - startTime;

    // Background polling when page not visible
    if (!pageVisible) {
      return this.config.intervals.background;
    }

    // Error backoff - exponential increase
    if (errorCount > 0) {
      const backoffMultiplier = Math.min(Math.pow(2, errorCount), 8);
      return this.config.intervals.initial * backoffMultiplier;
    }

    // Performance-based adjustment
    if (lastResponseTime > 2000) { // Slow API responses
      return Math.min(this.config.intervals.extended, 
                     this.getCurrentInterval(elapsedTime) * 1.5);
    }

    // Time-based adaptive intervals
    return this.getCurrentInterval(elapsedTime);
  }

  private getCurrentInterval(elapsedTime: number): number {
    if (elapsedTime < this.config.thresholds.mediumThreshold) {
      return this.config.intervals.initial;
    } else if (elapsedTime < this.config.thresholds.extendedThreshold) {
      return this.config.intervals.medium;
    } else {
      return this.config.intervals.extended;
    }
  }
}
```

### Circuit Breaker Implementation
```typescript
class PollingCircuitBreaker {
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  private errorCount = 0;
  private lastFailureTime = 0;
  private config: PollingConfig['circuit'];

  constructor(config: PollingConfig['circuit']) {
    this.config = config;
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (this.shouldAttemptRecovery()) {
        this.state = 'HALF_OPEN';
        console.log('Circuit breaker: Attempting recovery');
      } else {
        throw new CircuitBreakerError('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await this.withTimeout(operation(), this.config.timeoutThreshold);
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Request timeout')), timeoutMs);
    });

    return Promise.race([promise, timeout]);
  }

  private onSuccess(): void {
    this.errorCount = 0;
    this.state = 'CLOSED';
  }

  private onFailure(): void {
    this.errorCount++;
    this.lastFailureTime = Date.now();

    if (this.errorCount >= this.config.errorThreshold) {
      this.state = 'OPEN';
      console.warn(`Circuit breaker opened after ${this.errorCount} failures`);
    }
  }

  private shouldAttemptRecovery(): boolean {
    return Date.now() - this.lastFailureTime >= this.config.recoveryTime;
  }
}
```

### Page Visibility Integration
```typescript
class PageVisibilityManager {
  private listeners: Set<(isVisible: boolean) => void> = new Set();
  private isVisible: boolean = !document.hidden;

  constructor() {
    this.initialize();
  }

  private initialize() {
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    window.addEventListener('focus', this.handleFocus);
    window.addEventListener('blur', this.handleBlur);
  }

  private handleVisibilityChange = () => {
    const wasVisible = this.isVisible;
    this.isVisible = !document.hidden;
    
    if (wasVisible !== this.isVisible) {
      console.log(`Page visibility changed: ${this.isVisible ? 'visible' : 'hidden'}`);
      this.notifyListeners(this.isVisible);
    }
  };

  private handleFocus = () => {
    if (!this.isVisible) {
      this.isVisible = true;
      this.notifyListeners(true);
    }
  };

  private handleBlur = () => {
    // Don't immediately mark as invisible on blur - wait for visibility change
  };

  private notifyListeners(isVisible: boolean) {
    this.listeners.forEach(listener => listener(isVisible));
  }

  public addListener(callback: (isVisible: boolean) => void): () => void {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  public getIsVisible(): boolean {
    return this.isVisible;
  }

  public destroy() {
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    window.removeEventListener('focus', this.handleFocus);
    window.removeEventListener('blur', this.handleBlur);
    this.listeners.clear();
  }
}
```

## 6. Implementation Examples

### Main Polling Hook
```typescript
interface UseAdaptivePollingOptions {
  enabled?: boolean;
  onStatusChange?: (status: JobStatus) => void;
  onError?: (error: Error) => void;
  onComplete?: (result: ProgressResponse) => void;
  onCancelled?: (result: ProgressResponse) => void;
}

export const useAdaptivePolling = (
  jobId: string,
  options: UseAdaptivePollingOptions = {}
) => {
  const { enabled = true, onStatusChange, onError, onComplete, onCancelled } = options;
  
  const [pollingState, setPollingState] = useState<PollingState>({
    jobId,
    isActive: false,
    interval: 15000,
    startTime: Date.now(),
    lastSuccess: 0,
    errorCount: 0,
    circuitState: 'CLOSED',
    pageVisible: true,
    performanceMetrics: {
      averageResponseTime: 0,
      successRate: 100,
      cacheHitRate: 0,
    }
  });

  const circuitBreaker = useRef(new PollingCircuitBreaker(pollingConfig.circuit));
  const intervalCalculator = useRef(new AdaptivePollingCalculator(pollingConfig));
  const visibilityManager = useRef(new PageVisibilityManager());

  // Page Visibility API integration
  useEffect(() => {
    const unsubscribe = visibilityManager.current.addListener((isVisible) => {
      setPollingState(prev => ({ ...prev, pageVisible: isVisible }));
      
      if (isVisible) {
        console.log('Page visible: Resuming active polling');
        // Immediately poll when page becomes visible
        queryClient.invalidateQueries(['job-progress', jobId]);
      } else {
        console.log('Page hidden: Switching to background polling');
      }
    });

    return unsubscribe;
  }, [jobId]);

  // React Query with adaptive polling
  const { data, error, isError, isLoading } = useQuery({
    queryKey: ['job-progress', jobId],
    queryFn: () => circuitBreaker.current.execute(async () => {
      const startTime = Date.now();
      const response = await translationAPI.getJobProgress(jobId);
      const responseTime = Date.now() - startTime;
      
      // Update performance metrics
      setPollingState(prev => ({
        ...prev,
        performanceMetrics: {
          ...prev.performanceMetrics,
          averageResponseTime: (prev.performanceMetrics.averageResponseTime + responseTime) / 2,
        }
      }));
      
      return response;
    }),
    enabled: enabled && pollingState.isActive,
    refetchInterval: () => {
      const shouldContinuePolling = 
        enabled && 
        pollingState.isActive && 
        data?.status && 
        !['COMPLETED', 'FAILED'].includes(data.status);
        
      if (!shouldContinuePolling) {
        return false;
      }

      const newInterval = intervalCalculator.current.calculateInterval(
        pollingState.startTime,
        pollingState.pageVisible,
        pollingState.errorCount,
        pollingState.performanceMetrics.averageResponseTime
      );

      // Update state with new interval
      setPollingState(prev => ({ ...prev, interval: newInterval }));
      
      console.log(`Polling ${jobId}: Next poll in ${newInterval}ms`);
      return newInterval;
    },
    onSuccess: (data) => {
      // Update polling state on success
      setPollingState(prev => ({
        ...prev,
        lastSuccess: Date.now(),
        errorCount: 0,
        circuitState: 'CLOSED'
      }));

      // Trigger callbacks
      if (onStatusChange && data.status !== prev?.status) {
        onStatusChange(data.status);
      }

      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(data.status)) {
        if (data.status === 'COMPLETED' && onComplete) {
          onComplete(data);
        }
        if (data.status === 'CANCELLED' && onCancelled) {
          onCancelled(data);
        }
        if (data.status === 'FAILED' && onError) {
          onError(new Error(data.errorMessage || 'Job failed'));
        }
        setPollingState(prev => ({ ...prev, isActive: false }));
      }
    },
    onError: (error) => {
      setPollingState(prev => ({
        ...prev,
        errorCount: prev.errorCount + 1,
        circuitState: error instanceof CircuitBreakerError ? 'OPEN' : prev.circuitState
      }));

      if (onError) {
        onError(error as Error);
      }

      console.error(`Polling error for job ${jobId}:`, error);
    },
    retry: (failureCount, error) => {
      // Let circuit breaker handle retries
      if (error instanceof CircuitBreakerError) {
        return false;
      }
      return failureCount < 3;
    },
    retryDelay: (attemptIndex) => Math.min(1000 * Math.pow(2, attemptIndex), 10000),
  });

  // Start/stop polling control
  const startPolling = useCallback(() => {
    setPollingState(prev => ({ 
      ...prev, 
      isActive: true, 
      startTime: Date.now(),
      errorCount: 0 
    }));
    console.log(`Started adaptive polling for job ${jobId}`);
  }, [jobId]);

  const stopPolling = useCallback(() => {
    setPollingState(prev => ({ ...prev, isActive: false }));
    console.log(`Stopped polling for job ${jobId}`);
  }, [jobId]);

  // Auto-start polling when enabled
  useEffect(() => {
    if (enabled) {
      startPolling();
    } else {
      stopPolling();
    }
  }, [enabled, startPolling, stopPolling]);

  return {
    data,
    error,
    isError,
    isLoading,
    isPolling: pollingState.isActive,
    pollingState,
    startPolling,
    stopPolling,
    circuitBreakerState: circuitBreaker.current.state,
  };
};
```

### Performance Monitoring Integration
```typescript
class PollingPerformanceMonitor {
  private metrics: Map<string, PerformanceMetrics> = new Map();

  recordRequest(jobId: string, startTime: number, success: boolean, fromCache: boolean) {
    const responseTime = Date.now() - startTime;
    const existing = this.metrics.get(jobId) || this.getDefaultMetrics();

    const newMetrics: PerformanceMetrics = {
      ...existing,
      requestCount: existing.requestCount + 1,
      totalResponseTime: existing.totalResponseTime + responseTime,
      successCount: existing.successCount + (success ? 1 : 0),
      cacheHits: existing.cacheHits + (fromCache ? 1 : 0),
    };

    // Calculate derived metrics
    newMetrics.averageResponseTime = newMetrics.totalResponseTime / newMetrics.requestCount;
    newMetrics.successRate = (newMetrics.successCount / newMetrics.requestCount) * 100;
    newMetrics.cacheHitRate = (newMetrics.cacheHits / newMetrics.requestCount) * 100;

    this.metrics.set(jobId, newMetrics);

    // Log performance warnings
    if (newMetrics.successRate < 90) {
      console.warn(`Low success rate for job ${jobId}: ${newMetrics.successRate.toFixed(1)}%`);
    }

    if (newMetrics.averageResponseTime > 2000) {
      console.warn(`Slow polling for job ${jobId}: ${newMetrics.averageResponseTime.toFixed(0)}ms avg`);
    }
  }

  getMetrics(jobId: string): PerformanceMetrics {
    return this.metrics.get(jobId) || this.getDefaultMetrics();
  }

  private getDefaultMetrics(): PerformanceMetrics {
    return {
      requestCount: 0,
      totalResponseTime: 0,
      successCount: 0,
      cacheHits: 0,
      averageResponseTime: 0,
      successRate: 100,
      cacheHitRate: 0,
    };
  }
}
```

### Multi-Job Polling Manager
```typescript
interface MultiJobPollingManagerProps {
  jobIds: string[];
  onJobComplete: (jobId: string, result: ProgressResponse) => void;
  onJobError: (jobId: string, error: Error) => void;
}

const MultiJobPollingManager: React.FC<MultiJobPollingManagerProps> = ({
  jobIds,
  onJobComplete,
  onJobError,
}) => {
  const [activeJobs, setActiveJobs] = useState<Set<string>>(new Set(jobIds));

  const handleJobComplete = useCallback((jobId: string, result: ProgressResponse) => {
    setActiveJobs(prev => {
      const newSet = new Set(prev);
      newSet.delete(jobId);
      return newSet;
    });
    onJobComplete(jobId, result);
  }, [onJobComplete]);

  const handleJobError = useCallback((jobId: string, error: Error) => {
    onJobError(jobId, error);
  }, [onJobError]);

  return (
    <Box>
      {Array.from(activeJobs).map(jobId => (
        <JobPollingInstance
          key={jobId}
          jobId={jobId}
          onComplete={handleJobComplete}
          onError={handleJobError}
        />
      ))}
      
      <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
        Monitoring {activeJobs.size} active translation{activeJobs.size !== 1 ? 's' : ''}
      </Typography>
    </Box>
  );
};

const JobPollingInstance: React.FC<{
  jobId: string;
  onComplete: (jobId: string, result: ProgressResponse) => void;
  onError: (jobId: string, error: Error) => void;
}> = ({ jobId, onComplete, onError }) => {
  const { data, pollingState } = useAdaptivePolling(jobId, {
    enabled: true,
    onComplete: (result) => onComplete(jobId, result),
    onError: (error) => onError(jobId, error),
  });

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">Job {jobId.slice(-8)}</Typography>
          <PollingStatusIndicator jobId={jobId} pollingState={pollingState} />
        </Box>
        
        {data && (
          <Box sx={{ mt: 2 }}>
            <LinearProgress 
              variant="determinate" 
              value={data.progress} 
              sx={{ mb: 1 }}
            />
            <Typography variant="body2" color="text.secondary">
              {data.status} - {data.progress}% complete
              {data.estimatedTimeRemaining && (
                <span> • {Math.ceil(data.estimatedTimeRemaining / 60)} min remaining</span>
              )}
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};
```

### Job Cancellation Handling
```typescript
interface CancellationAwarePolling {
  stopPolling: () => void;
  resumePolling: () => void;
  handleCancellation: (jobId: string) => Promise<void>;
}

export const useCancellationAwarePolling = (
  jobId: string,
  options: UseAdaptivePollingOptions = {}
): CancellationAwarePolling & ReturnType<typeof useAdaptivePolling> => {
  const pollingResult = useAdaptivePolling(jobId, {
    ...options,
    onCancelled: (result) => {
      // Stop polling immediately when job is cancelled
      stopPolling();
      if (options.onCancelled) {
        options.onCancelled(result);
      }
    }
  });

  const stopPolling = useCallback(() => {
    // Disable polling by setting enabled to false
    pollingResult.setEnabled(false);
  }, [pollingResult]);

  const resumePolling = useCallback(() => {
    // Re-enable polling
    pollingResult.setEnabled(true);
  }, [pollingResult]);

  const handleCancellation = useCallback(async (cancelledJobId: string) => {
    if (cancelledJobId === jobId) {
      // Immediately stop polling for cancelled job
      stopPolling();
      
      // Clear any cached data for this job
      queryClient.removeQueries(['translationProgress', jobId]);
      
      // Optionally trigger a final status check to confirm cancellation
      setTimeout(() => {
        queryClient.invalidateQueries(['translationProgress', jobId]);
      }, 1000);
    }
  }, [jobId, stopPolling]);

  return {
    ...pollingResult,
    stopPolling,
    resumePolling,
    handleCancellation,
  };
};

// Usage example for coordinated cancellation
const MultiJobPollingManager: React.FC = () => {
  const [activeJobs, setActiveJobs] = useState<string[]>(['job1', 'job2', 'job3']);
  
  const handleJobCancellation = useCallback(async (jobId: string) => {
    // Remove from active jobs list
    setActiveJobs(prev => prev.filter(id => id !== jobId));
    
    // Notify all polling instances about the cancellation
    pollingInstances.forEach(instance => {
      instance.handleCancellation(jobId);
    });
  }, []);

  return (
    <Box>
      {activeJobs.map(jobId => (
        <JobPollingCard 
          key={jobId}
          jobId={jobId}
          onCancellation={handleJobCancellation}
        />
      ))}
    </Box>
  );
};
```

## 7. Error Handling & Edge Cases

### Comprehensive Error Classification
```typescript
interface PollingError {
  type: 'NETWORK' | 'SERVER' | 'TIMEOUT' | 'RATE_LIMIT' | 'CIRCUIT_BREAKER';
  message: string;
  retryable: boolean;
  backoffTime: number;
}

class PollingErrorHandler {
  static classifyError(error: unknown): PollingError {
    if (error instanceof CircuitBreakerError) {
      return {
        type: 'CIRCUIT_BREAKER',
        message: 'Service temporarily unavailable',
        retryable: true,
        backoffTime: 30000,
      };
    }

    if (error instanceof TypeError || error?.message?.includes('fetch')) {
      return {
        type: 'NETWORK',
        message: 'Network connection issue',
        retryable: true,
        backoffTime: 5000,
      };
    }

    if (error?.status === 429) {
      return {
        type: 'RATE_LIMIT',
        message: 'Rate limit exceeded',
        retryable: true,
        backoffTime: parseInt(error.headers?.['retry-after'] || '60') * 1000,
      };
    }

    if (error?.status >= 500) {
      return {
        type: 'SERVER',
        message: 'Server error',
        retryable: true,
        backoffTime: 10000,
      };
    }

    return {
      type: 'SERVER',
      message: error?.message || 'Unknown error',
      retryable: false,
      backoffTime: 0,
    };
  }

  static handlePollingError(error: unknown, jobId: string): void {
    const pollingError = this.classifyError(error);
    
    console.error(`Polling error for job ${jobId}:`, {
      type: pollingError.type,
      message: pollingError.message,
      retryable: pollingError.retryable,
    });

    // Send to monitoring service
    if (window.analytics) {
      window.analytics.track('polling_error', {
        jobId,
        errorType: pollingError.type,
        retryable: pollingError.retryable,
      });
    }

    // Show user notification for non-transient errors
    if (!pollingError.retryable) {
      showNotification({
        type: 'error',
        title: 'Connection Issue',
        message: 'Unable to get translation progress. Please refresh the page.',
        actions: ['Refresh', 'Dismiss'],
      });
    }
  }
}
```

### Edge Case Handling
```typescript
const usePollingEdgeCaseHandler = (jobId: string) => {
  const [consecutiveErrors, setConsecutiveErrors] = useState(0);
  const [lastKnownStatus, setLastKnownStatus] = useState<JobStatus | null>(null);

  const handleEdgeCase = useCallback((error: unknown, currentData?: ProgressResponse) => {
    // Handle stale data scenarios
    if (currentData) {
      const dataAge = Date.now() - new Date(currentData.lastUpdated).getTime();
      if (dataAge > 5 * 60 * 1000) { // 5 minutes
        console.warn(`Stale data detected for job ${jobId}: ${dataAge}ms old`);
        // Force refresh by invalidating cache
        queryClient.invalidateQueries(['job-progress', jobId]);
      }
    }

    // Handle job state inconsistencies
    if (currentData?.status && lastKnownStatus) {
      const invalidTransitions = [
        ['COMPLETED', 'PROCESSING'],
        ['FAILED', 'QUEUED'],
        ['COMPLETED', 'FAILED'],
      ];

      const transition = [lastKnownStatus, currentData.status];
      if (invalidTransitions.some(invalid => 
        invalid[0] === transition[0] && invalid[1] === transition[1]
      )) {
        console.error(`Invalid job state transition: ${lastKnownStatus} → ${currentData.status}`);
        // Trigger job state recovery
        queryClient.invalidateQueries(['job-progress', jobId]);
      }
    }

    setLastKnownStatus(currentData?.status || null);

    // Handle excessive errors
    setConsecutiveErrors(prev => {
      const newCount = prev + 1;
      if (newCount >= 10) { // Too many consecutive errors
        console.error(`Excessive polling errors for job ${jobId}, stopping`);
        showNotification({
          type: 'error',
          title: 'Connection Problems',
          message: 'Unable to track translation progress. Please check your connection and refresh.',
          persistent: true,
        });
        return 0; // Reset count
      }
      return newCount;
    });
  }, [jobId, lastKnownStatus]);

  return handleEdgeCase;
};
```

## 8. Performance & Monitoring

### React Query Optimization
```typescript
// Query client configuration optimized for polling
export const pollingQueryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Align with API cache TTL
      staleTime: 30 * 1000, // 30 seconds
      gcTime: 5 * 60 * 1000, // 5 minutes
      
      // Background refetch optimization
      refetchOnWindowFocus: true,
      refetchOnReconnect: true,
      refetchOnMount: true,
      
      // Retry configuration
      retry: (failureCount, error) => {
        const pollingError = PollingErrorHandler.classifyError(error);
        return pollingError.retryable && failureCount < 3;
      },
      
      retryDelay: (attemptIndex, error) => {
        const pollingError = PollingErrorHandler.classifyError(error);
        return Math.max(pollingError.backoffTime, 1000 * Math.pow(2, attemptIndex));
      },
    },
  },
});

// Background sync for improved UX
const usePollingBackgroundSync = (jobId: string) => {
  useEffect(() => {
    const handleFocus = () => {
      // Immediately fetch fresh data when user returns
      queryClient.invalidateQueries(['job-progress', jobId]);
    };

    const handleOnline = () => {
      // Refresh data when connection restored
      queryClient.refetchQueries(['job-progress', jobId]);
    };

    window.addEventListener('focus', handleFocus);
    window.addEventListener('online', handleOnline);

    return () => {
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('online', handleOnline);
    };
  }, [jobId]);
};
```

### Performance Metrics Dashboard
```typescript
const PollingMetricsDisplay: React.FC<{ jobId: string }> = ({ jobId }) => {
  const { pollingState } = useAdaptivePolling(jobId);
  const performanceMonitor = useRef(new PollingPerformanceMonitor());

  return (
    <Card sx={{ mt: 2 }}>
      <CardContent>
        <Typography variant="h6">Polling Performance</Typography>
        <Grid container spacing={2}>
          <Grid item xs={6}>
            <Typography variant="body2" color="text.secondary">
              Current Interval
            </Typography>
            <Typography variant="h6">
              {(pollingState.interval / 1000).toFixed(1)}s
            </Typography>
          </Grid>
          
          <Grid item xs={6}>
            <Typography variant="body2" color="text.secondary">
              Success Rate
            </Typography>
            <Typography 
              variant="h6"
              color={pollingState.performanceMetrics.successRate > 95 ? 'success.main' : 'warning.main'}
            >
              {pollingState.performanceMetrics.successRate.toFixed(1)}%
            </Typography>
          </Grid>
          
          <Grid item xs={6}>
            <Typography variant="body2" color="text.secondary">
              Avg Response Time
            </Typography>
            <Typography variant="body1">
              {pollingState.performanceMetrics.averageResponseTime.toFixed(0)}ms
            </Typography>
          </Grid>
          
          <Grid item xs={6}>
            <Typography variant="body2" color="text.secondary">
              Cache Hit Rate
            </Typography>
            <Typography variant="body1">
              {pollingState.performanceMetrics.cacheHitRate.toFixed(1)}%
            </Typography>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
};
```

## 9. Testing Strategy

### Unit Tests for Polling Logic
```typescript
// __tests__/hooks/useAdaptivePolling.test.ts
describe('useAdaptivePolling', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    mockAPI.getJobProgress.mockResolvedValue({
      jobId: 'test-job-1',
      status: 'PROCESSING',
      progress: 50,
      chunksProcessed: 5,
      totalChunks: 10,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.clearAllMocks();
  });

  it('starts with initial polling interval', async () => {
    const { result } = renderHook(() => 
      useAdaptivePolling('test-job-1', { enabled: true })
    );

    await act(() => {
      result.current.startPolling();
    });

    expect(result.current.pollingState.interval).toBe(15000);
    expect(result.current.isPolling).toBe(true);
  });

  it('adapts interval based on elapsed time', async () => {
    const { result } = renderHook(() => 
      useAdaptivePolling('test-job-1', { enabled: true })
    );

    await act(() => {
      result.current.startPolling();
    });

    // Simulate 6 minutes elapsed (should trigger medium interval)
    act(() => {
      jest.advanceTimersByTime(6 * 60 * 1000);
    });

    await waitFor(() => {
      expect(result.current.pollingState.interval).toBe(30000);
    });
  });

  it('switches to background polling when page hidden', async () => {
    const { result } = renderHook(() => 
      useAdaptivePolling('test-job-1', { enabled: true })
    );

    await act(() => {
      result.current.startPolling();
    });

    // Simulate page becoming hidden
    Object.defineProperty(document, 'hidden', { value: true, writable: true });
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    await waitFor(() => {
      expect(result.current.pollingState.pageVisible).toBe(false);
      expect(result.current.pollingState.interval).toBe(120000);
    });
  });

  it('handles circuit breaker errors correctly', async () => {
    mockAPI.getJobProgress.mockRejectedValue(new CircuitBreakerError('Circuit open'));

    const onError = jest.fn();
    const { result } = renderHook(() => 
      useAdaptivePolling('test-job-1', { enabled: true, onError })
    );

    await act(() => {
      result.current.startPolling();
    });

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.any(CircuitBreakerError));
      expect(result.current.circuitBreakerState).toBe('OPEN');
    });
  });
});

// Circuit breaker tests
describe('PollingCircuitBreaker', () => {
  let circuitBreaker: PollingCircuitBreaker;
  const mockOperation = jest.fn();

  beforeEach(() => {
    circuitBreaker = new PollingCircuitBreaker({
      errorThreshold: 3,
      timeoutThreshold: 5000,
      recoveryTime: 10000,
    });
    mockOperation.mockResolvedValue('success');
  });

  it('opens circuit after error threshold', async () => {
    mockOperation.mockRejectedValue(new Error('API error'));

    // Trigger errors up to threshold
    for (let i = 0; i < 3; i++) {
      try {
        await circuitBreaker.execute(mockOperation);
      } catch (error) {
        // Expected
      }
    }

    // Circuit should be open now
    await expect(circuitBreaker.execute(mockOperation))
      .rejects.toThrow(CircuitBreakerError);
  });

  it('attempts recovery after timeout', async () => {
    // Open the circuit
    mockOperation.mockRejectedValue(new Error('API error'));
    for (let i = 0; i < 3; i++) {
      try {
        await circuitBreaker.execute(mockOperation);
      } catch (error) {
        // Expected
      }
    }

    // Wait for recovery time
    jest.advanceTimersByTime(11000);
    
    // Should attempt recovery
    mockOperation.mockResolvedValue('recovered');
    const result = await circuitBreaker.execute(mockOperation);
    expect(result).toBe('recovered');
  });
});
```

### Integration Tests
```typescript
// __tests__/integration/polling-system.test.tsx
describe('Polling System Integration', () => {
  it('manages complete polling lifecycle', async () => {
    const mockProgressData = [
      { status: 'QUEUED', progress: 0 },
      { status: 'PROCESSING', progress: 25 },
      { status: 'PROCESSING', progress: 75 },
      { status: 'COMPLETED', progress: 100 },
    ];

    let callCount = 0;
    mockAPI.getJobProgress.mockImplementation(() => 
      Promise.resolve({
        jobId: 'test-job',
        ...mockProgressData[callCount++],
        chunksProcessed: callCount * 2,
        totalChunks: 8,
        lastUpdated: new Date().toISOString(),
      })
    );

    const onComplete = jest.fn();
    const { result } = renderHook(() => 
      useAdaptivePolling('test-job', { 
        enabled: true,
        onComplete 
      })
    );

    // Start polling
    await act(() => {
      result.current.startPolling();
    });

    // Advance through polling cycles
    for (let i = 0; i < mockProgressData.length; i++) {
      act(() => {
        jest.advanceTimersByTime(15000);
      });

      await waitFor(() => {
        expect(result.current.data?.status).toBe(mockProgressData[i].status);
      });
    }

    // Should stop polling and trigger completion
    expect(result.current.isPolling).toBe(false);
    expect(onComplete).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'COMPLETED' })
    );
  });
});
```

## 10. Deployment & Configuration

### Environment-Specific Configuration
```typescript
// config/polling.ts
interface PollingEnvironmentConfig {
  development: PollingConfig;
  staging: PollingConfig;
  production: PollingConfig;
}

export const pollingConfigs: PollingEnvironmentConfig = {
  development: {
    intervals: {
      initial: 5000,   // Faster polling for development
      medium: 10000,
      extended: 20000,
      background: 30000,
    },
    thresholds: {
      mediumThreshold: 2 * 60 * 1000,  // 2 minutes
      extendedThreshold: 10 * 60 * 1000, // 10 minutes
    },
    circuit: {
      errorThreshold: 3,
      timeoutThreshold: 5000,
      recoveryTime: 10000,
    }
  },
  production: {
    intervals: {
      initial: 15000,
      medium: 30000,
      extended: 60000,
      background: 120000,
    },
    thresholds: {
      mediumThreshold: 5 * 60 * 1000,   // 5 minutes
      extendedThreshold: 30 * 60 * 1000, // 30 minutes
    },
    circuit: {
      errorThreshold: 5,
      timeoutThreshold: 10000,
      recoveryTime: 30000,
    }
  },
  staging: {
    // Staging config similar to production but with faster recovery
    intervals: {
      initial: 10000,
      medium: 20000,
      extended: 45000,
      background: 90000,
    },
    thresholds: {
      mediumThreshold: 3 * 60 * 1000,
      extendedThreshold: 20 * 60 * 1000,
    },
    circuit: {
      errorThreshold: 4,
      timeoutThreshold: 8000,
      recoveryTime: 20000,
    }
  }
};

export const getPollingConfig = (): PollingConfig => {
  const env = process.env.NODE_ENV as keyof PollingEnvironmentConfig;
  return pollingConfigs[env] || pollingConfigs.production;
};
```

### Monitoring and Analytics Integration
```typescript
// utils/polling-analytics.ts
interface PollingAnalytics {
  trackPollingStart(jobId: string): void;
  trackPollingSuccess(jobId: string, responseTime: number, fromCache: boolean): void;
  trackPollingError(jobId: string, error: PollingError): void;
  trackIntervalChange(jobId: string, oldInterval: number, newInterval: number): void;
  trackCircuitBreakerEvent(jobId: string, event: 'OPENED' | 'CLOSED' | 'HALF_OPEN'): void;
}

export const createPollingAnalytics = (): PollingAnalytics => ({
  trackPollingStart(jobId: string) {
    if (window.gtag) {
      window.gtag('event', 'polling_start', {
        job_id: jobId,
        timestamp: Date.now(),
      });
    }
  },

  trackPollingSuccess(jobId: string, responseTime: number, fromCache: boolean) {
    if (window.gtag) {
      window.gtag('event', 'polling_success', {
        job_id: jobId,
        response_time: responseTime,
        from_cache: fromCache,
      });
    }
  },

  trackPollingError(jobId: string, error: PollingError) {
    if (window.gtag) {
      window.gtag('event', 'polling_error', {
        job_id: jobId,
        error_type: error.type,
        retryable: error.retryable,
      });
    }
  },

  trackIntervalChange(jobId: string, oldInterval: number, newInterval: number) {
    if (window.gtag) {
      window.gtag('event', 'polling_interval_change', {
        job_id: jobId,
        old_interval: oldInterval,
        new_interval: newInterval,
      });
    }
  },

  trackCircuitBreakerEvent(jobId: string, event: 'OPENED' | 'CLOSED' | 'HALF_OPEN') {
    if (window.gtag) {
      window.gtag('event', 'circuit_breaker', {
        job_id: jobId,
        event: event.toLowerCase(),
      });
    }
  },
});
```

---

This comprehensive Frontend Polling System design provides robust, intelligent polling with adaptive intervals, circuit breaker protection, and comprehensive monitoring. The system optimizes user experience while minimizing server load and handling various failure scenarios gracefully.