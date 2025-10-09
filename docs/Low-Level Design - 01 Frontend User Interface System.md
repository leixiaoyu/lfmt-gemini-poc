# Low-Level Design Document 1: Frontend User Interface System

## 1. Component Overview & Responsibilities

The Frontend User Interface System serves as the primary user interaction layer for the Long-Form Translation Service. It provides a comprehensive React-based SPA that handles user authentication, legal compliance workflows, file management, and real-time progress tracking through polling.

**Key Responsibilities:**
- User authentication and session management
- Legal attestation compliance with audit tracking
- File upload, validation, and cost estimation
- Translation job configuration and submission
- Real-time progress monitoring via adaptive polling
- User dashboard with history and usage statistics

**Why This Design:** The polling-only architecture eliminates WebSocket complexity while maintaining near real-time user experience. React Query optimizes API calls with intelligent caching, and Material-UI ensures consistent, accessible design. Job cancellation capabilities provide users full control over long-running processes.

## 2. API Design & Interfaces

### Authentication Endpoints
```typescript
// POST /auth/login
interface LoginRequest {
  email: string;
  password: string;
}

interface AuthResponse {
  token: string;
  refreshToken: string;
  user: {
    userId: string;
    email: string;
    createdAt: string;
  };
  expiresIn: number;
}

// POST /auth/register
interface RegisterRequest {
  email: string;
  password: string;
  confirmPassword: string;
}

// POST /auth/reset-password
interface ResetPasswordRequest {
  email: string;
}
```

### Job Management Endpoints
```typescript
// DELETE /translation/jobs/{jobId}
interface CancelJobRequest {
  jobId: string;
  reason?: string;
  forceCancel?: boolean; // For jobs that are hard to stop
}

interface CancelJobResponse {
  jobId: string;
  status: 'CANCELLED' | 'CANCELLING' | 'CANNOT_CANCEL';
  message: string;
  refundAmount?: number;
  estimatedStopTime?: string;
}

// GET /translation/jobs/user/{userId}
interface UserJobsRequest {
  userId: string;
  status?: JobStatus[];
  limit?: number;
  cursor?: string;
}

interface UserJobsResponse {
  jobs: TranslationJob[];
  nextCursor?: string;
  totalCount: number;
}

// POST /translation/jobs/{jobId}/email-notification
interface EmailNotificationRequest {
  jobId: string;
  email: string;
  notificationTypes: ('COMPLETION' | 'FAILURE' | 'PROGRESS_MILESTONE')[];
}
```

### Legal Compliance Endpoints
```typescript
// GET /legal/terms/{version}
interface TermsResponse {
  version: string;
  content: string;
  updatedAt: string;
  requiresAttestation: boolean;
}

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
}
```

## 3. Data Models & Storage

### Frontend State Management
```typescript
// React Query Cache Keys
export const queryKeys = {
  auth: ['auth'] as const,
  user: ['user'] as const,
  jobs: ['jobs'] as const,
  jobProgress: (jobId: string) => ['jobs', jobId, 'progress'] as const,
  userHistory: ['user', 'history'] as const,
  legalTerms: (version: string) => ['legal', 'terms', version] as const,
};

// Global State Interface
interface AppState {
  user: {
    isAuthenticated: boolean;
    profile: UserProfile | null;
    hasValidAttestation: boolean;
  };
  ui: {
    isLoading: boolean;
    currentJob: string | null;
    notifications: Notification[];
  };
  settings: {
    pollingInterval: number;
    theme: 'light' | 'dark';
  };
}

// Job State Interface
interface TranslationJob {
  jobId: string;
  status: JobStatus;
  progress: number;
  fileName: string;
  targetLanguage: string;
  wordCount: number;
  estimatedCost: number;
  chunksProcessed: number;
  totalChunks: number;
  estimatedTimeRemaining?: number;
  createdAt: string;
  lastUpdated: string;
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

## 4. User Interface Design

### Component Architecture
```typescript
// Main App Component Structure
const App: React.FC = () => {
  return (
    <QueryClient client={queryClient}>
      <AuthProvider>
        <Router>
          <ThemeProvider theme={theme}>
            <CssBaseline />
            <Routes>
              <Route path="/auth" element={<AuthLayout />} />
              <Route path="/dashboard" element={<DashboardLayout />} />
              <Route path="/translate" element={<TranslationWorkflow />} />
            </Routes>
          </ThemeProvider>
        </Router>
      </AuthProvider>
    </QueryClient>
  );
};

// Authentication Components
interface LoginFormProps {
  onSuccess: (authData: AuthResponse) => void;
  onError: (error: string) => void;
}

const LoginForm: React.FC<LoginFormProps> = ({ onSuccess, onError }) => {
  const [formData, setFormData] = useState<LoginRequest>({
    email: '',
    password: ''
  });

  const { mutate: login, isLoading } = useMutation({
    mutationFn: authAPI.login,
    onSuccess,
    onError: (error: ApiError) => onError(error.message)
  });

  return (
    <Card sx={{ maxWidth: 400, mx: 'auto', mt: 4 }}>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Sign In
        </Typography>
        <Box component="form" onSubmit={handleSubmit}>
          <TextField
            fullWidth
            margin="normal"
            label="Email"
            type="email"
            value={formData.email}
            onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
            required
          />
          <TextField
            fullWidth
            margin="normal"
            label="Password"
            type="password"
            value={formData.password}
            onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
            required
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            disabled={isLoading}
            sx={{ mt: 2 }}
          >
            {isLoading ? <CircularProgress size={24} /> : 'Sign In'}
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};
```

### Legal Attestation Component
```typescript
interface LegalAttestationProps {
  onComplete: (attestationId: string) => void;
  documentHash: string;
}

const LegalAttestationForm: React.FC<LegalAttestationProps> = ({ 
  onComplete, 
  documentHash 
}) => {
  const [startTime] = useState(Date.now());
  const [scrollPercentage, setScrollPercentage] = useState(0);
  const [attestationData, setAttestationData] = useState({
    copyrightOwnership: false,
    translationRights: false,
    liabilityAcceptance: false,
    publicDomainAcknowledgment: false,
  });

  // Scroll tracking for audit trail
  useEffect(() => {
    const handleScroll = () => {
      const scrollTop = window.pageYOffset;
      const docHeight = document.body.scrollHeight - window.innerHeight;
      const scrollPercent = (scrollTop / docHeight) * 100;
      setScrollPercentage(Math.max(scrollPercentage, scrollPercent));
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [scrollPercentage]);

  const handleSubmit = async () => {
    const auditTrail = {
      pageViewDuration: Date.now() - startTime,
      scrollCompletionPercentage: Math.round(scrollPercentage),
      attestationMethod: 'checkbox' as const,
      browserFingerprint: await generateBrowserFingerprint(),
    };

    const attestationRequest: AttestationRequest = {
      legalStatements: attestationData,
      auditTrail,
      documentHash,
    };

    // Submit attestation
    await legalAPI.createAttestation(attestationRequest);
    onComplete(attestationId);
  };

  return (
    <Container maxWidth="md">
      <Typography variant="h4" gutterBottom>
        Legal Attestation Required
      </Typography>
      
      {/* Terms of Service Display */}
      <Paper sx={{ p: 3, mb: 3, maxHeight: 400, overflow: 'auto' }}>
        <TermsOfServiceContent />
      </Paper>

      {/* Required Attestations */}
      <FormGroup>
        <FormControlLabel
          control={
            <Checkbox
              checked={attestationData.copyrightOwnership}
              onChange={(e) => setAttestationData(prev => ({
                ...prev,
                copyrightOwnership: e.target.checked
              }))}
              required
            />
          }
          label="I confirm that I own the copyright to this document or have explicit permission to translate it."
        />
        
        <FormControlLabel
          control={
            <Checkbox
              checked={attestationData.translationRights}
              onChange={(e) => setAttestationData(prev => ({
                ...prev,
                translationRights: e.target.checked
              }))}
              required
            />
          }
          label="I have the legal right to create derivative works (translations) of this content."
        />
        
        {/* Additional checkboxes for other required statements */}
      </FormGroup>

      <Box sx={{ mt: 3 }}>
        <Button
          variant="contained"
          size="large"
          onClick={handleSubmit}
          disabled={!allStatementsAccepted}
        >
          Submit Legal Attestation
        </Button>
      </Box>
    </Container>
  );
};
```

### File Upload Component
```typescript
interface FileUploadProps {
  onFileValidated: (file: File, metadata: FileMetadata) => void;
  maxSizeBytes: number;
  acceptedTypes: string[];
}

const FileUploadArea: React.FC<FileUploadProps> = ({
  onFileValidated,
  maxSizeBytes,
  acceptedTypes
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [validationResults, setValidationResults] = useState<ValidationResult | null>(null);

  const { mutate: validateFile } = useMutation({
    mutationFn: fileAPI.validateFile,
    onSuccess: (result) => {
      setValidationResults(result);
      if (result.isValid && result.metadata) {
        onFileValidated(result.file, result.metadata);
      }
    }
  });

  const handleFileDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    // Immediate client-side validation
    const clientValidation = validateFileClientSide(file, maxSizeBytes, acceptedTypes);
    if (!clientValidation.isValid) {
      setValidationResults(clientValidation);
      return;
    }

    // Server-side validation
    validateFile(file);
  }, [validateFile, maxSizeBytes, acceptedTypes]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: handleFileDrop,
    accept: acceptedTypes.reduce((acc, type) => ({ ...acc, [type]: [] }), {}),
    maxSize: maxSizeBytes,
    multiple: false,
  });

  return (
    <Box>
      <Paper
        {...getRootProps()}
        sx={{
          p: 4,
          textAlign: 'center',
          border: '2px dashed',
          borderColor: isDragActive ? 'primary.main' : 'grey.300',
          bgcolor: isDragActive ? 'primary.50' : 'background.paper',
          cursor: 'pointer',
          '&:hover': {
            borderColor: 'primary.main',
            bgcolor: 'primary.50',
          }
        }}
      >
        <input {...getInputProps()} />
        <CloudUploadIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
        <Typography variant="h6" gutterBottom>
          {isDragActive ? 'Drop your file here' : 'Drag and drop your file here, or click to browse'}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Supports .txt files • 65K-400K words • Max 100MB
        </Typography>
      </Paper>

      {/* Validation Results Display */}
      {validationResults && (
        <ValidationResultsDisplay results={validationResults} />
      )}

      {/* Cost Estimation */}
      {validationResults?.isValid && validationResults.metadata && (
        <CostEstimationDisplay metadata={validationResults.metadata} />
      )}
    </Box>
  );
};
```

### Job Cancellation Component
```typescript
interface JobCancellationProps {
  jobId: string;
  currentStatus: JobStatus;
  onCancellationComplete: (result: CancelJobResponse) => void;
}

const JobCancellationDialog: React.FC<JobCancellationProps> = ({
  jobId,
  currentStatus,
  onCancellationComplete
}) => {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [forceCancel, setForceCancel] = useState(false);

  const { mutate: cancelJob, isLoading } = useMutation({
    mutationFn: (request: CancelJobRequest) => jobAPI.cancelJob(request),
    onSuccess: (result) => {
      onCancellationComplete(result);
      setOpen(false);
    },
    onError: (error) => {
      console.error('Failed to cancel job:', error);
    }
  });

  const canCancel = ['QUEUED', 'PROCESSING', 'RETRYING'].includes(currentStatus);

  const handleCancel = () => {
    cancelJob({
      jobId,
      reason: reason.trim() || undefined,
      forceCancel
    });
  };

  return (
    <>
      <Button
        variant="outlined"
        color="error"
        onClick={() => setOpen(true)}
        disabled={!canCancel}
        startIcon={<CancelIcon />}
      >
        Cancel Job
      </Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Cancel Translation Job</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Job ID: {jobId}
          </Typography>
          <Typography variant="body1" gutterBottom>
            Are you sure you want to cancel this translation job?
          </Typography>
          
          {currentStatus === 'PROCESSING' && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              This job is currently being processed. Cancellation may take a few moments.
            </Alert>
          )}

          <TextField
            fullWidth
            label="Reason for cancellation (optional)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            margin="normal"
            multiline
            rows={2}
          />

          {currentStatus === 'PROCESSING' && (
            <FormControlLabel
              control={
                <Checkbox
                  checked={forceCancel}
                  onChange={(e) => setForceCancel(e.target.checked)}
                />
              }
              label="Force cancellation (may result in partial charges)"
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>
            Keep Job Running
          </Button>
          <Button
            onClick={handleCancel}
            color="error"
            variant="contained"
            disabled={isLoading}
          >
            {isLoading ? <CircularProgress size={24} /> : 'Cancel Job'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};
```

### Progress Tracking with Cancellation
```typescript
const TranslationProgressTracker: React.FC<{ jobId: string }> = ({ jobId }) => {
  const { data: progress } = useAdaptivePolling(jobId);
  const [showCancellation, setShowCancellation] = useState(false);

  const handleCancellationComplete = (result: CancelJobResponse) => {
    if (result.status === 'CANCELLED') {
      // Show success message and redirect
      showNotification({
        type: 'success',
        message: `Job cancelled successfully. ${result.refundAmount ? `Refund: $${result.refundAmount}` : ''}`
      });
    }
  };

  return (
    <Card sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h6">Translation Progress</Typography>
        <JobCancellationDialog
          jobId={jobId}
          currentStatus={progress?.status || 'QUEUED'}
          onCancellationComplete={handleCancellationComplete}
        />
      </Box>
      
      <LinearProgress 
        variant="determinate" 
        value={progress?.progress || 0} 
        sx={{ mb: 2 }}
      />
      
      <Grid container spacing={2}>
        <Grid item xs={6}>
          <Typography variant="body2" color="text.secondary">
            Status: {progress?.status}
          </Typography>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="body2" color="text.secondary">
            Progress: {progress?.progress || 0}%
          </Typography>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="body2" color="text.secondary">
            Chunks: {progress?.chunksProcessed || 0}/{progress?.totalChunks || 0}
          </Typography>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="body2" color="text.secondary">
            ETA: {progress?.estimatedTimeRemaining ? 
              `${Math.round(progress.estimatedTimeRemaining / 60)} min` : 'Calculating...'}
          </Typography>
        </Grid>
      </Grid>
    </Card>
  );
};
```

## 5. Core Algorithms & Logic

### Browser Fingerprinting
```typescript
const generateBrowserFingerprint = async (): Promise<string> => {
  const fingerprint = {
    userAgent: navigator.userAgent,
    language: navigator.language,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth,
    },
    canvas: await getCanvasFingerprint(),
    webgl: getWebGLFingerprint(),
    timestamp: Date.now(),
  };

  return btoa(JSON.stringify(fingerprint));
};

const getCanvasFingerprint = async (): Promise<string> => {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d')!;
  
  ctx.textBaseline = 'top';
  ctx.font = '14px Arial';
  ctx.fillText('Translation Service Fingerprint', 2, 2);
  
  return canvas.toDataURL();
};
```

### Cost Estimation Algorithm
```typescript
interface CostEstimation {
  estimatedCost: number;
  breakdown: {
    geminiAPICost: number;
    awsInfrastructureCost: number;
  };
  processingTime: {
    estimated: number; // minutes
    range: { min: number; max: number };
  };
}

const calculateTranslationCost = (
  wordCount: number,
  targetLanguage: string
): CostEstimation => {
  // Gemini API cost calculation
  const tokensPerWord = 1.3;
  const inputTokens = wordCount * tokensPerWord;
  
  // Language-specific output multipliers
  const outputMultipliers = {
    spanish: 1.15,
    french: 1.20,
    german: 1.25,
    italian: 1.18,
    chinese: 0.85,
  };
  
  const outputTokens = inputTokens * (outputMultipliers[targetLanguage] || 1.2);
  
  // Gemini API pricing (per 1M tokens)
  const geminiInputCost = (inputTokens / 1_000_000) * 3.00;
  const geminiOutputCost = (outputTokens / 1_000_000) * 15.00;
  const geminiAPICost = geminiInputCost + geminiOutputCost;
  
  // AWS infrastructure cost (estimated per job)
  const awsInfrastructureCost = Math.max(0.001, wordCount / 100_000 * 0.01);
  
  // Processing time estimation
  const baseProcessingTime = wordCount / 1000; // 1000 words per minute
  const chunkingOverhead = Math.ceil(wordCount / 3500) * 0.5; // 0.5 min per chunk
  const estimatedTime = baseProcessingTime + chunkingOverhead;
  
  return {
    estimatedCost: geminiAPICost + awsInfrastructureCost,
    breakdown: {
      geminiAPICost,
      awsInfrastructureCost,
    },
    processingTime: {
      estimated: Math.round(estimatedTime),
      range: {
        min: Math.round(estimatedTime * 0.8),
        max: Math.round(estimatedTime * 1.5),
      }
    }
  };
};
```

## 6. Error Handling & Edge Cases

### Error Classification and UI Response
```typescript
interface UIError {
  code: string;
  message: string;
  severity: 'error' | 'warning' | 'info';
  actionable: boolean;
  retryable: boolean;
}

const errorHandler = {
  classifyError(error: unknown): UIError {
    if (error instanceof NetworkError) {
      return {
        code: 'NETWORK_ERROR',
        message: 'Connection lost. Please check your internet connection.',
        severity: 'error',
        actionable: true,
        retryable: true,
      };
    }
    
    if (error instanceof AuthenticationError) {
      return {
        code: 'AUTH_EXPIRED',
        message: 'Your session has expired. Please sign in again.',
        severity: 'warning',
        actionable: true,
        retryable: false,
      };
    }
    
    if (error instanceof ValidationError) {
      return {
        code: 'VALIDATION_FAILED',
        message: error.details.join(', '),
        severity: 'error',
        actionable: true,
        retryable: false,
      };
    }
    
    return {
      code: 'UNKNOWN_ERROR',
      message: 'An unexpected error occurred. Please try again.',
      severity: 'error',
      actionable: false,
      retryable: true,
    };
  },

  handleError(error: unknown, context: string) {
    const uiError = this.classifyError(error);
    
    // Log error for debugging
    console.error(`Error in ${context}:`, error);
    
    // Show user-friendly notification
    showNotification({
      type: uiError.severity,
      message: uiError.message,
      actions: uiError.actionable ? ['Retry', 'Dismiss'] : ['Dismiss'],
    });
    
    // Auto-retry for retryable errors
    if (uiError.retryable && context.includes('polling')) {
      setTimeout(() => {
        // Retry the failed operation
      }, 5000);
    }
  }
};
```

### File Validation Edge Cases
```typescript
const validateFileClientSide = (
  file: File, 
  maxSizeBytes: number, 
  acceptedTypes: string[]
): ValidationResult => {
  const errors: string[] = [];
  
  // File type validation
  if (!acceptedTypes.includes(file.type) && !file.name.endsWith('.txt')) {
    errors.push('Only .txt files are supported');
  }
  
  // File size validation
  if (file.size > maxSizeBytes) {
    errors.push(`File size exceeds ${formatFileSize(maxSizeBytes)} limit`);
  }
  
  if (file.size < 1000) {
    errors.push('File appears to be empty or too small');
  }
  
  // File name validation
  if (file.name.length > 255) {
    errors.push('File name is too long');
  }
  
  if (!/^[a-zA-Z0-9._-]+\.txt$/.test(file.name)) {
    errors.push('File name contains invalid characters');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
    file,
  };
};
```

## 7. Performance & Monitoring

### React Query Configuration
```typescript
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000, // 30 seconds - align with API cache
      gcTime: 5 * 60 * 1000, // 5 minutes
      retry: (failureCount, error) => {
        if (error instanceof AuthenticationError) return false;
        return failureCount < 3;
      },
      retryDelay: attemptIndex => Math.min(1000 * 2 ** attemptIndex, 30000),
    },
    mutations: {
      retry: 1,
      retryDelay: 2000,
    }
  }
});

// Performance monitoring hooks
const usePerformanceMonitor = (componentName: string) => {
  useEffect(() => {
    const startTime = performance.now();
    
    return () => {
      const renderTime = performance.now() - startTime;
      if (renderTime > 100) { // Log slow renders
        console.warn(`Slow render in ${componentName}: ${renderTime.toFixed(2)}ms`);
      }
    };
  });
};
```

### Bundle Optimization
```typescript
// Code splitting for routes
const DashboardLayout = lazy(() => import('./layouts/DashboardLayout'));
const TranslationWorkflow = lazy(() => import('./workflows/TranslationWorkflow'));

// Chunk splitting configuration (webpack.config.js)
module.exports = {
  optimization: {
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all',
        },
        mui: {
          test: /[\\/]node_modules[\\/]@mui[\\/]/,
          name: 'mui',
          chunks: 'all'
        }
      }
    }
  }
};
```

## 8. Implementation Examples

### Complete Authentication Hook
```typescript
interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<void>;
}

export const useAuth = (): AuthContextType => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const login = async (credentials: LoginRequest) => {
    try {
      const response = await authAPI.login(credentials);
      
      // Store tokens
      localStorage.setItem('authToken', response.token);
      localStorage.setItem('refreshToken', response.refreshToken);
      
      setUser(response.user);
      
      // Setup token refresh
      scheduleTokenRefresh(response.expiresIn);
    } catch (error) {
      throw new Error('Login failed');
    }
  };

  const refreshToken = async () => {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) throw new Error('No refresh token');

      const response = await authAPI.refreshToken(refreshToken);
      localStorage.setItem('authToken', response.token);
      
      scheduleTokenRefresh(response.expiresIn);
    } catch (error) {
      logout();
      throw new Error('Token refresh failed');
    }
  };

  const logout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('refreshToken');
    setUser(null);
  };

  // Auto-login on app load
  useEffect(() => {
    const initializeAuth = async () => {
      const token = localStorage.getItem('authToken');
      if (token) {
        try {
          const user = await authAPI.verifyToken(token);
          setUser(user);
        } catch {
          logout();
        }
      }
      setIsLoading(false);
    };

    initializeAuth();
  }, []);

  return {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    refreshToken,
  };
};
```

## 9. Testing Strategy

### Unit Testing Examples
```typescript
// __tests__/components/FileUpload.test.tsx
describe('FileUploadArea', () => {
  it('validates file size correctly', async () => {
    const onFileValidated = jest.fn();
    render(
      <FileUploadArea 
        onFileValidated={onFileValidated}
        maxSizeBytes={100 * 1024 * 1024}
        acceptedTypes={['text/plain']}
      />
    );

    const file = new File(['test content'], 'test.txt', { type: 'text/plain' });
    const input = screen.getByRole('textbox', { hidden: true });
    
    fireEvent.change(input, { target: { files: [file] } });
    
    await waitFor(() => {
      expect(onFileValidated).toHaveBeenCalledWith(file, expect.any(Object));
    });
  });

  it('rejects oversized files', async () => {
    const onFileValidated = jest.fn();
    render(
      <FileUploadArea 
        onFileValidated={onFileValidated}
        maxSizeBytes={1000}
        acceptedTypes={['text/plain']}
      />
    );

    const largeFile = new File(['x'.repeat(2000)], 'large.txt', { type: 'text/plain' });
    const input = screen.getByRole('textbox', { hidden: true });
    
    fireEvent.change(input, { target: { files: [largeFile] } });
    
    await waitFor(() => {
      expect(screen.getByText(/exceeds.*limit/i)).toBeInTheDocument();
      expect(onFileValidated).not.toHaveBeenCalled();
    });
  });
});

// Integration testing with React Query
describe('Auth Integration', () => {
  it('handles login flow correctly', async () => {
    const mockLogin = jest.fn().mockResolvedValue({
      token: 'test-token',
      user: { userId: '1', email: 'test@test.com' }
    });
    
    authAPI.login = mockLogin;
    
    render(
      <QueryClient client={new QueryClient()}>
        <AuthProvider>
          <LoginForm />
        </AuthProvider>
      </QueryClient>
    );
    
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@test.com' }
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'password123' }
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
    
    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith({
        email: 'test@test.com',
        password: 'password123'
      });
    });
  });
});
```

### E2E Testing Strategy
```typescript
// cypress/e2e/translation-workflow.cy.ts
describe('Translation Workflow', () => {
  beforeEach(() => {
    cy.login('test@example.com', 'password123');
  });

  it('completes full translation workflow', () => {
    // Navigate to translation page
    cy.visit('/translate');
    
    // Complete legal attestation
    cy.get('[data-testid="legal-attestation"]').should('be.visible');
    cy.get('[data-testid="copyright-checkbox"]').check();
    cy.get('[data-testid="translation-rights-checkbox"]').check();
    cy.get('[data-testid="liability-checkbox"]').check();
    cy.get('[data-testid="public-domain-checkbox"]').check();
    cy.get('[data-testid="submit-attestation"]').click();
    
    // Upload file
    cy.get('[data-testid="file-upload"]').selectFile('fixtures/sample-document.txt');
    cy.get('[data-testid="validation-success"]').should('be.visible');
    
    // Configure translation
    cy.get('[data-testid="language-selector"]').select('spanish');
    cy.get('[data-testid="submit-translation"]').click();
    
    // Monitor progress
    cy.get('[data-testid="progress-tracker"]').should('be.visible');
    cy.get('[data-testid="job-status"]').should('contain', 'QUEUED');
    
    // Wait for completion (with timeout)
    cy.get('[data-testid="job-status"]', { timeout: 120000 })
      .should('contain', 'COMPLETED');
      
    // Download results
    cy.get('[data-testid="download-button"]').click();
    cy.verifyDownload('translation.md');
  });
});
```

## 10. Deployment & Configuration

### Environment Configuration
```typescript
// config/environment.ts
interface EnvironmentConfig {
  API_BASE_URL: string;
  AUTH_DOMAIN: string;
  MAX_FILE_SIZE: number;
  POLLING_INTERVALS: {
    initial: number;
    medium: number;
    extended: number;
    background: number;
  };
  SENTRY_DSN?: string;
  ANALYTICS_ID?: string;
}

const environments: Record<string, EnvironmentConfig> = {
  development: {
    API_BASE_URL: 'http://localhost:3001/api',
    AUTH_DOMAIN: 'dev-auth.translation-service.local',
    MAX_FILE_SIZE: 100 * 1024 * 1024,
    POLLING_INTERVALS: { initial: 5000, medium: 10000, extended: 30000, background: 60000 },
  },
  production: {
    API_BASE_URL: 'https://api.translation-service.com',
    AUTH_DOMAIN: 'auth.translation-service.com',
    MAX_FILE_SIZE: 100 * 1024 * 1024,
    POLLING_INTERVALS: { initial: 15000, medium: 30000, extended: 60000, background: 120000 },
    SENTRY_DSN: process.env.REACT_APP_SENTRY_DSN,
    ANALYTICS_ID: process.env.REACT_APP_ANALYTICS_ID,
  }
};

export const config = environments[process.env.NODE_ENV] || environments.development;
```

### CloudFront Distribution Configuration
```yaml
# cloudformation/frontend-distribution.yaml
Resources:
  FrontendDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Origins:
          - DomainName: !GetAtt FrontendBucket.RegionalDomainName
            Id: FrontendS3Origin
            S3OriginConfig:
              OriginAccessIdentity: !Sub "origin-access-identity/cloudfront/${OriginAccessIdentity}"
        DefaultCacheBehavior:
          TargetOriginId: FrontendS3Origin
          ViewerProtocolPolicy: redirect-to-https
          CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad # Managed-CachingOptimized
          Compress: true
        CustomErrorResponses:
          - ErrorCode: 404
            ResponseCode: 200
            ResponsePagePath: /index.html
            ErrorCachingMinTTL: 300
        DefaultRootObject: index.html
        Enabled: true
        HttpVersion: http2
        PriceClass: PriceClass_100
        ViewerCertificate:
          AcmCertificateArn: !Ref SSLCertificate
          SslSupportMethod: sni-only
          MinimumProtocolVersion: TLSv1.2_2021
```

### Build and Deployment Script
```bash
#!/bin/bash
# scripts/deploy-frontend.sh

set -e

ENVIRONMENT=${1:-development}
BUILD_DIR="build"
S3_BUCKET="translation-frontend-${ENVIRONMENT}"
CLOUDFRONT_DISTRIBUTION_ID=${CLOUDFRONT_DISTRIBUTION_ID}

echo "Building for environment: $ENVIRONMENT"

# Install dependencies
npm ci

# Run tests
npm run test -- --coverage --watchAll=false

# Build application
REACT_APP_ENV=$ENVIRONMENT npm run build

# Optimize build
npm run analyze

# Deploy to S3
aws s3 sync $BUILD_DIR s3://$S3_BUCKET --delete \
  --cache-control "public, max-age=31536000" \
  --exclude "*.html" \
  --exclude "service-worker.js"

# Deploy HTML with no-cache
aws s3 sync $BUILD_DIR s3://$S3_BUCKET --delete \
  --cache-control "no-cache" \
  --include "*.html" \
  --include "service-worker.js"

# Invalidate CloudFront cache
if [ -n "$CLOUDFRONT_DISTRIBUTION_ID" ]; then
  aws cloudfront create-invalidation \
    --distribution-id $CLOUDFRONT_DISTRIBUTION_ID \
    --paths "/*"
fi

echo "Frontend deployment complete"
```

---

This comprehensive low-level design document provides junior engineers with detailed implementation guidance for the Frontend User Interface System, including complete code examples, testing strategies, and deployment procedures. The design emphasizes polling-based architecture, legal compliance, and robust error handling while maintaining excellent user experience.
