# Low-Level Design Document 10: User Management & Authentication

## 1. Component Overview & Responsibilities

The User Management & Authentication system provides secure user registration, authentication, authorization, and profile management for the Long-Form Translation Service. It implements JWT-based authentication, role-based access control, secure session management, and comprehensive audit trails while ensuring compliance with data protection regulations.

**Key Responsibilities:**
- Secure user registration and email verification
- JWT-based authentication with refresh token rotation
- Role-based access control (RBAC) and authorization
- User profile management and preferences
- Session management and security monitoring
- Password security with proper hashing and policies
- Multi-factor authentication (MFA) support
- Audit logging and compliance tracking

**Why This Design:** JWT-based authentication provides stateless, scalable authentication suitable for distributed systems. The design emphasizes security best practices, user experience, and compliance requirements while maintaining performance and reliability.

## 2. API Design & Interfaces

### Authentication Endpoints
```typescript
// POST /auth/register
interface RegisterRequest {
  email: string;
  password: string;
  confirmPassword: string;
  firstName: string;
  lastName: string;
  organization?: string;
  acceptedTerms: boolean;
  acceptedPrivacy: boolean;
  marketingConsent?: boolean;
}

interface RegisterResponse {
  userId: string;
  message: string;
  verificationRequired: boolean;
  verificationExpiresAt: string;
}

// POST /auth/verify-email
interface EmailVerificationRequest {
  token: string;
  email: string;
}

interface EmailVerificationResponse {
  success: boolean;
  message: string;
  user?: UserProfile;
}

// POST /auth/login
interface LoginRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
  mfaCode?: string;
}

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: UserProfile;
  requiresMfa: boolean;
  mfaRequired?: boolean;
}

// POST /auth/refresh
interface RefreshTokenRequest {
  refreshToken: string;
}

interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// POST /auth/logout
interface LogoutRequest {
  refreshToken: string;
  logoutFromAllDevices?: boolean;
}

// POST /auth/forgot-password
interface ForgotPasswordRequest {
  email: string;
}

interface ForgotPasswordResponse {
  message: string;
  resetTokenExpiresAt: string;
}

// POST /auth/reset-password
interface ResetPasswordRequest {
  token: string;
  email: string;
  newPassword: string;
  confirmPassword: string;
}
```

### User Management Endpoints
```typescript
// GET /users/profile
interface UserProfile {
  userId: string;
  email: string;
  firstName: string;
  lastName: string;
  organization?: string;
  role: UserRole;
  status: UserStatus;
  preferences: UserPreferences;
  subscription: SubscriptionInfo;
  securitySettings: SecuritySettings;
  createdAt: string;
  lastLoginAt?: string;
  emailVerified: boolean;
  mfaEnabled: boolean;
}

// PUT /users/profile
interface UpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  organization?: string;
  preferences?: Partial<UserPreferences>;
}

// PUT /users/change-password
interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

// PUT /users/preferences
interface UserPreferences {
  language: string;
  timezone: string;
  emailNotifications: {
    jobCompleted: boolean;
    jobFailed: boolean;
    weeklyReport: boolean;
    securityAlerts: boolean;
  };
  uiSettings: {
    theme: 'light' | 'dark' | 'auto';
    pollingInterval: number;
    defaultTargetLanguage: string;
  };
}

// POST /users/enable-mfa
interface EnableMfaRequest {
  password: string;
}

interface EnableMfaResponse {
  secretKey: string;
  qrCode: string;
  backupCodes: string[];
}

// POST /users/verify-mfa
interface VerifyMfaRequest {
  code: string;
  secretKey: string;
}
```

### Authorization and Roles
```typescript
type UserRole = 'USER' | 'PREMIUM_USER' | 'ADMIN' | 'SUPER_ADMIN';

type UserStatus = 'PENDING_VERIFICATION' | 'ACTIVE' | 'SUSPENDED' | 'DEACTIVATED';

interface Permission {
  resource: string;
  action: string;
  conditions?: Record<string, any>;
}

interface RoleDefinition {
  role: UserRole;
  permissions: Permission[];
  limits: {
    maxJobsPerDay: number;
    maxFileSize: number;
    maxConcurrentJobs: number;
    allowedLanguages: string[];
  };
}

const ROLE_DEFINITIONS: RoleDefinition[] = [
  {
    role: 'USER',
    permissions: [
      { resource: 'translation:job', action: 'create' },
      { resource: 'translation:job', action: 'read', conditions: { owner: true } },
      { resource: 'translation:job', action: 'cancel', conditions: { owner: true } },
      { resource: 'user:profile', action: 'read', conditions: { self: true } },
      { resource: 'user:profile', action: 'update', conditions: { self: true } }
    ],
    limits: {
      maxJobsPerDay: 10,
      maxFileSize: 50 * 1024 * 1024, // 50MB
      maxConcurrentJobs: 2,
      allowedLanguages: ['spanish', 'french', 'german', 'italian']
    }
  },
  {
    role: 'PREMIUM_USER',
    permissions: [
      { resource: 'translation:job', action: 'create' },
      { resource: 'translation:job', action: 'read', conditions: { owner: true } },
      { resource: 'translation:job', action: 'cancel', conditions: { owner: true } },
      { resource: 'translation:job', action: 'priority', conditions: { owner: true } },
      { resource: 'user:profile', action: 'read', conditions: { self: true } },
      { resource: 'user:profile', action: 'update', conditions: { self: true } },
      { resource: 'analytics:usage', action: 'read', conditions: { self: true } }
    ],
    limits: {
      maxJobsPerDay: 100,
      maxFileSize: 200 * 1024 * 1024, // 200MB
      maxConcurrentJobs: 10,
      allowedLanguages: [] // All languages
    }
  }
];
```

## 3. Data Models & Storage

### DynamoDB Schema for User Management
```typescript
// Primary Table: Users
interface UserRecord {
  PK: string; // USER#{userId}
  SK: string; // PROFILE
  userId: string;
  email: string;
  emailLowercase: string; // For case-insensitive lookups
  firstName: string;
  lastName: string;
  organization?: string;
  
  // Security
  passwordHash: string;
  passwordSalt: string;
  passwordLastChanged: string;
  mfaSecret?: string;
  mfaEnabled: boolean;
  mfaBackupCodes?: string[]; // Encrypted
  
  // Status and verification
  status: UserStatus;
  role: UserRole;
  emailVerified: boolean;
  emailVerificationToken?: string;
  emailVerificationExpires?: string;
  
  // Session management
  refreshTokenVersion: number; // For token invalidation
  lastLoginAt?: string;
  lastLoginIP?: string;
  failedLoginAttempts: number;
  lockedUntil?: string;
  
  // Preferences
  preferences: UserPreferences;
  
  // Subscription and limits
  subscription: SubscriptionInfo;
  usageLimits: UsageLimits;
  
  // Audit
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
  
  // Compliance
  acceptedTermsVersion: string;
  acceptedPrivacyVersion: string;
  marketingConsent: boolean;
  dataRetentionConsent: boolean;
  
  ttl?: number; // For deactivated users
}

// GSI: UsersByEmail
interface UsersByEmail {
  GSI1PK: string; // EMAIL#{emailLowercase}
  GSI1SK: string; // USER
  userId: string;
  status: UserStatus;
  emailVerified: boolean;
}

// GSI: UsersByRole
interface UsersByRole {
  GSI2PK: string; // ROLE#{role}
  GSI2SK: string; // STATUS#{status}#CREATED#{createdAt}
  userId: string;
  email: string;
  firstName: string;
  lastName: string;
  createdAt: string;
}

// Separate table for sensitive data
interface UserSecurityRecord {
  PK: string; // USER#{userId}
  SK: string; // SECURITY
  userId: string;
  
  // Password security
  passwordHash: string;
  passwordSalt: string;
  passwordHistory: string[]; // Last 5 password hashes
  passwordLastChanged: string;
  
  // MFA
  mfaSecret?: string; // Encrypted
  mfaBackupCodes?: string[]; // Encrypted
  mfaEnabled: boolean;
  mfaEnabledAt?: string;
  
  // Session security
  refreshTokenVersion: number;
  activeSessions: SessionInfo[];
  
  // Security events
  failedLoginAttempts: number;
  lastFailedLogin?: string;
  lockedUntil?: string;
  lockReason?: string;
  
  // Audit trail
  securityEvents: SecurityEvent[];
  
  ttl?: number; // Longer retention for security data
}

// Sessions table for active session tracking
interface UserSessionRecord {
  PK: string; // USER#{userId}
  SK: string; // SESSION#{sessionId}
  userId: string;
  sessionId: string;
  refreshToken: string; // Hashed
  deviceInfo: {
    userAgent: string;
    deviceType: 'mobile' | 'desktop' | 'tablet';
    platform: string;
    browser: string;
  };
  ipAddress: string;
  location?: {
    country: string;
    city: string;
    coordinates?: { lat: number; lng: number };
  };
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  isActive: boolean;
  ttl: number; // Auto-cleanup expired sessions
}
```

### Password Reset and Email Verification
```typescript
interface PasswordResetRecord {
  PK: string; // RESET#{token}
  SK: string; // EMAIL#{email}
  token: string;
  email: string;
  userId: string;
  createdAt: string;
  expiresAt: string;
  used: boolean;
  usedAt?: string;
  ipAddress: string;
  ttl: number; // Auto-cleanup after expiration
}

interface EmailVerificationRecord {
  PK: string; // VERIFICATION#{token}
  SK: string; // EMAIL#{email}
  token: string;
  email: string;
  userId: string;
  verificationType: 'REGISTRATION' | 'EMAIL_CHANGE';
  createdAt: string;
  expiresAt: string;
  used: boolean;
  usedAt?: string;
  ttl: number;
}
```

## 4. Core Authentication Logic

### User Authentication Service
```typescript
class UserAuthenticationService {
  private passwordService: PasswordService;
  private jwtService: JWTService;
  private mfaService: MFAService;
  private auditService: AuditService;

  constructor() {
    this.passwordService = new PasswordService();
    this.jwtService = new JWTService();
    this.mfaService = new MFAService();
    this.auditService = new AuditService();
  }

  async registerUser(request: RegisterRequest, clientInfo: ClientInfo): Promise<RegisterResponse> {
    // Validate registration data
    await this.validateRegistrationData(request);
    
    // Check if email already exists
    await this.checkEmailAvailability(request.email);
    
    // Generate user ID
    const userId = this.generateUserId();
    
    // Hash password
    const { hash, salt } = await this.passwordService.hashPassword(request.password);
    
    // Generate email verification token
    const verificationToken = this.generateSecureToken();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    // Create user record
    const userRecord: UserRecord = {
      PK: `USER#${userId}`,
      SK: 'PROFILE',
      userId,
      email: request.email,
      emailLowercase: request.email.toLowerCase(),
      firstName: request.firstName,
      lastName: request.lastName,
      organization: request.organization,
      
      // Security
      passwordHash: hash,
      passwordSalt: salt,
      passwordLastChanged: new Date().toISOString(),
      mfaEnabled: false,
      
      // Status
      status: 'PENDING_VERIFICATION',
      role: 'USER',
      emailVerified: false,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: verificationExpires.toISOString(),
      
      // Session management
      refreshTokenVersion: 1,
      failedLoginAttempts: 0,
      
      // Preferences
      preferences: this.getDefaultPreferences(),
      
      // Subscription
      subscription: this.getDefaultSubscription(),
      usageLimits: this.getUserLimits('USER'),
      
      // Audit
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      
      // Compliance
      acceptedTermsVersion: process.env.CURRENT_TERMS_VERSION!,
      acceptedPrivacyVersion: process.env.CURRENT_PRIVACY_VERSION!,
      marketingConsent: request.marketingConsent || false,
      dataRetentionConsent: true
    };

    // Store user record
    await this.dynamoClient.put({
      TableName: process.env.USERS_TABLE!,
      Item: userRecord,
      ConditionExpression: 'attribute_not_exists(PK)'
    }).promise();

    // Create email verification record
    await this.createEmailVerificationRecord(
      verificationToken,
      request.email,
      userId,
      'REGISTRATION'
    );

    // Create GSI records
    await this.createUserGSIRecords(userRecord);

    // Send verification email
    await this.sendVerificationEmail(request.email, verificationToken, request.firstName);

    // Audit log
    await this.auditService.logUserEvent(userId, 'USER_REGISTERED', {
      email: request.email,
      ipAddress: clientInfo.ipAddress,
      userAgent: clientInfo.userAgent
    });

    return {
      userId,
      message: 'Registration successful. Please check your email to verify your account.',
      verificationRequired: true,
      verificationExpiresAt: verificationExpires.toISOString()
    };
  }

  async loginUser(request: LoginRequest, clientInfo: ClientInfo): Promise<LoginResponse> {
    // Get user by email
    const user = await this.getUserByEmail(request.email);
    if (!user) {
      // Log failed attempt
      await this.auditService.logSecurityEvent('FAILED_LOGIN_UNKNOWN_EMAIL', {
        email: request.email,
        ipAddress: clientInfo.ipAddress
      });
      throw new AuthenticationError('Invalid email or password');
    }

    // Check account status
    await this.checkAccountStatus(user);

    // Check for account lockout
    await this.checkAccountLockout(user);

    // Verify password
    const passwordValid = await this.passwordService.verifyPassword(
      request.password,
      user.passwordHash,
      user.passwordSalt
    );

    if (!passwordValid) {
      await this.handleFailedLogin(user, clientInfo);
      throw new AuthenticationError('Invalid email or password');
    }

    // Reset failed login attempts on successful password verification
    await this.resetFailedLoginAttempts(user.userId);

    // Check MFA requirement
    if (user.mfaEnabled) {
      if (!request.mfaCode) {
        return {
          accessToken: '',
          refreshToken: '',
          expiresIn: 0,
          user: this.sanitizeUserProfile(user),
          requiresMfa: true,
          mfaRequired: true
        };
      }

      // Verify MFA code
      const mfaValid = await this.mfaService.verifyCode(user.mfaSecret!, request.mfaCode);
      if (!mfaValid) {
        await this.auditService.logSecurityEvent('FAILED_MFA_VERIFICATION', {
          userId: user.userId,
          ipAddress: clientInfo.ipAddress
        });
        throw new AuthenticationError('Invalid MFA code');
      }
    }

    // Generate tokens
    const tokenExpiresIn = request.rememberMe ? 7 * 24 * 60 * 60 : 24 * 60 * 60; // 7 days or 1 day
    const accessToken = await this.jwtService.generateAccessToken(user, tokenExpiresIn);
    const refreshToken = await this.jwtService.generateRefreshToken(user);

    // Create session record
    const sessionId = this.generateSessionId();
    await this.createUserSession(user.userId, sessionId, refreshToken, clientInfo);

    // Update last login
    await this.updateLastLogin(user.userId, clientInfo);

    // Audit log
    await this.auditService.logUserEvent(user.userId, 'USER_LOGIN', {
      ipAddress: clientInfo.ipAddress,
      userAgent: clientInfo.userAgent,
      mfaUsed: user.mfaEnabled
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: tokenExpiresIn,
      user: this.sanitizeUserProfile(user),
      requiresMfa: false
    };
  }

  async refreshAccessToken(refreshToken: string, clientInfo: ClientInfo): Promise<RefreshTokenResponse> {
    // Verify refresh token
    const tokenPayload = await this.jwtService.verifyRefreshToken(refreshToken);
    
    // Get user
    const user = await this.getUserById(tokenPayload.userId);
    if (!user) {
      throw new AuthenticationError('Invalid refresh token');
    }

    // Check token version (for token invalidation)
    if (tokenPayload.tokenVersion !== user.refreshTokenVersion) {
      throw new AuthenticationError('Refresh token has been invalidated');
    }

    // Verify session exists and is active
    const session = await this.getActiveSession(user.userId, refreshToken);
    if (!session) {
      throw new AuthenticationError('Session not found or expired');
    }

    // Generate new tokens
    const newAccessToken = await this.jwtService.generateAccessToken(user);
    const newRefreshToken = await this.jwtService.generateRefreshToken(user);

    // Update session with new refresh token
    await this.updateSessionToken(session.sessionId, newRefreshToken);

    // Audit log
    await this.auditService.logUserEvent(user.userId, 'TOKEN_REFRESHED', {
      ipAddress: clientInfo.ipAddress,
      sessionId: session.sessionId
    });

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: 24 * 60 * 60 // 24 hours
    };
  }

  async logoutUser(refreshToken: string, logoutFromAllDevices: boolean = false): Promise<void> {
    const tokenPayload = await this.jwtService.verifyRefreshToken(refreshToken);
    const userId = tokenPayload.userId;

    if (logoutFromAllDevices) {
      // Invalidate all sessions by incrementing refresh token version
      await this.invalidateAllUserSessions(userId);
    } else {
      // Invalidate only current session
      await this.invalidateSession(userId, refreshToken);
    }

    // Audit log
    await this.auditService.logUserEvent(userId, 'USER_LOGOUT', {
      logoutFromAllDevices
    });
  }

  private async checkAccountStatus(user: UserRecord): Promise<void> {
    switch (user.status) {
      case 'PENDING_VERIFICATION':
        throw new AuthenticationError('Please verify your email address before logging in');
      case 'SUSPENDED':
        throw new AuthenticationError('Your account has been suspended. Please contact support.');
      case 'DEACTIVATED':
        throw new AuthenticationError('Your account has been deactivated');
    }
  }

  private async checkAccountLockout(user: UserRecord): Promise<void> {
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      const unlockTime = new Date(user.lockedUntil).toLocaleString();
      throw new AuthenticationError(`Account is locked until ${unlockTime} due to too many failed login attempts`);
    }
  }

  private async handleFailedLogin(user: UserRecord, clientInfo: ClientInfo): Promise<void> {
    const failedAttempts = user.failedLoginAttempts + 1;
    const maxAttempts = 5;
    
    let lockedUntil: string | undefined;
    if (failedAttempts >= maxAttempts) {
      // Lock account for 30 minutes
      lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    }

    // Update failed login attempts
    await this.dynamoClient.update({
      TableName: process.env.USERS_TABLE!,
      Key: { PK: `USER#${user.userId}`, SK: 'PROFILE' },
      UpdateExpression: 'SET failedLoginAttempts = :attempts, lastFailedLogin = :timestamp' + 
                       (lockedUntil ? ', lockedUntil = :lockTime' : ''),
      ExpressionAttributeValues: {
        ':attempts': failedAttempts,
        ':timestamp': new Date().toISOString(),
        ...(lockedUntil && { ':lockTime': lockedUntil })
      }
    }).promise();

    // Audit log
    await this.auditService.logSecurityEvent('FAILED_LOGIN', {
      userId: user.userId,
      email: user.email,
      failedAttempts,
      isLocked: !!lockedUntil,
      ipAddress: clientInfo.ipAddress
    });
  }

  private async validateRegistrationData(request: RegisterRequest): Promise<void> {
    const errors: string[] = [];

    // Email validation
    if (!this.isValidEmail(request.email)) {
      errors.push('Invalid email format');
    }

    // Password validation
    const passwordValidation = this.passwordService.validatePassword(request.password);
    if (!passwordValidation.isValid) {
      errors.push(...passwordValidation.errors);
    }

    // Confirm password
    if (request.password !== request.confirmPassword) {
      errors.push('Passwords do not match');
    }

    // Terms acceptance
    if (!request.acceptedTerms) {
      errors.push('Terms of service must be accepted');
    }

    if (!request.acceptedPrivacy) {
      errors.push('Privacy policy must be accepted');
    }

    // Name validation
    if (!request.firstName?.trim()) {
      errors.push('First name is required');
    }

    if (!request.lastName?.trim()) {
      errors.push('Last name is required');
    }

    if (errors.length > 0) {
      throw new ValidationError('Registration validation failed', errors);
    }
  }

  private async checkEmailAvailability(email: string): Promise<void> {
    const existingUser = await this.getUserByEmail(email);
    if (existingUser) {
      throw new ValidationError('Email address is already registered');
    }
  }

  private getDefaultPreferences(): UserPreferences {
    return {
      language: 'en',
      timezone: 'UTC',
      emailNotifications: {
        jobCompleted: true,
        jobFailed: true,
        weeklyReport: false,
        securityAlerts: true
      },
      uiSettings: {
        theme: 'light',
        pollingInterval: 30000,
        defaultTargetLanguage: 'spanish'
      }
    };
  }

  private getUserLimits(role: UserRole): UsageLimits {
    const roleDefinition = ROLE_DEFINITIONS.find(r => r.role === role);
    return roleDefinition?.limits || ROLE_DEFINITIONS[0].limits;
  }
}
```

### Password Service Implementation
```typescript
class PasswordService {
  private readonly saltRounds = 12;
  private readonly passwordHistory = 5;

  async hashPassword(password: string): Promise<{ hash: string; salt: string }> {
    const salt = await bcrypt.genSalt(this.saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return { hash, salt };
  }

  async verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  validatePassword(password: string): PasswordValidationResult {
    const errors: string[] = [];
    
    // Length requirement
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    
    if (password.length > 128) {
      errors.push('Password must be less than 128 characters');
    }

    // Character requirements
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Common password check
    if (this.isCommonPassword(password)) {
      errors.push('Password is too common, please choose a stronger password');
    }

    // Sequential character check
    if (this.hasSequentialCharacters(password)) {
      errors.push('Password cannot contain sequential characters (e.g., 123, abc)');
    }

    return {
      isValid: errors.length === 0,
      errors,
      strength: this.calculatePasswordStrength(password)
    };
  }

  async canChangePassword(userId: string, newPassword: string): Promise<boolean> {
    // Get password history
    const user = await this.getUserSecurityData(userId);
    if (!user.passwordHistory) return true;

    // Check against recent passwords
    for (const oldHash of user.passwordHistory) {
      if (await bcrypt.compare(newPassword, oldHash)) {
        return false;
      }
    }

    return true;
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    // Get current user data
    const user = await this.getUserSecurityData(userId);
    
    // Verify current password
    const currentValid = await this.verifyPassword(
      currentPassword,
      user.passwordHash,
      user.passwordSalt
    );
    
    if (!currentValid) {
      throw new AuthenticationError('Current password is incorrect');
    }

    // Validate new password
    const validation = this.validatePassword(newPassword);
    if (!validation.isValid) {
      throw new ValidationError('New password does not meet requirements', validation.errors);
    }

    // Check password history
    const canChange = await this.canChangePassword(userId, newPassword);
    if (!canChange) {
      throw new ValidationError('Cannot reuse a recent password');
    }

    // Hash new password
    const { hash, salt } = await this.hashPassword(newPassword);

    // Update password and history
    const passwordHistory = user.passwordHistory || [];
    passwordHistory.unshift(user.passwordHash);
    
    // Keep only last N passwords
    if (passwordHistory.length > this.passwordHistory) {
      passwordHistory.splice(this.passwordHistory);
    }

    await this.dynamoClient.update({
      TableName: process.env.USERS_SECURITY_TABLE!,
      Key: { PK: `USER#${userId}`, SK: 'SECURITY' },
      UpdateExpression: 'SET passwordHash = :hash, passwordSalt = :salt, passwordHistory = :history, passwordLastChanged = :timestamp, refreshTokenVersion = refreshTokenVersion + :inc',
      ExpressionAttributeValues: {
        ':hash': hash,
        ':salt': salt,
        ':history': passwordHistory,
        ':timestamp': new Date().toISOString(),
        ':inc': 1
      }
    }).promise();

    // Audit log
    await this.auditService.logSecurityEvent('PASSWORD_CHANGED', { userId });
  }

  private isCommonPassword(password: string): boolean {
    const commonPasswords = [
      'password', '123456', '123456789', 'qwerty', 'abc123',
      'password123', 'admin', 'letmein', 'welcome', 'monkey'
    ];
    
    return commonPasswords.includes(password.toLowerCase());
  }

  private hasSequentialCharacters(password: string): boolean {
    // Check for 3+ sequential characters
    for (let i = 0; i <= password.length - 3; i++) {
      const char1 = password.charCodeAt(i);
      const char2 = password.charCodeAt(i + 1);
      const char3 = password.charCodeAt(i + 2);
      
      if (char2 === char1 + 1 && char3 === char2 + 1) {
        return true;
      }
    }
    
    return false;
  }

  private calculatePasswordStrength(password: string): PasswordStrength {
    let score = 0;
    
    // Length score
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    
    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1;
    
    // Complexity bonus
    const uniqueChars = new Set(password).size;
    if (uniqueChars >= password.length * 0.7) score += 1;
    
    if (score <= 3) return 'WEAK';
    if (score <= 5) return 'MEDIUM';
    if (score <= 7) return 'STRONG';
    return 'VERY_STRONG';
  }
}
```

### JWT Service Implementation
```typescript
class JWTService {
  private readonly accessTokenSecret = process.env.JWT_ACCESS_SECRET!;
  private readonly refreshTokenSecret = process.env.JWT_REFRESH_SECRET!;
  private readonly accessTokenExpiry = '1h';
  private readonly refreshTokenExpiry = '7d';

  async generateAccessToken(user: UserRecord, customExpiry?: number): Promise<string> {
    const payload: AccessTokenPayload = {
      userId: user.userId,
      email: user.email,
      role: user.role,
      emailVerified: user.emailVerified,
      permissions: this.getUserPermissions(user.role),
      iat: Math.floor(Date.now() / 1000)
    };

    const options: jwt.SignOptions = {
      expiresIn: customExpiry ? `${customExpiry}s` : this.accessTokenExpiry,
      issuer: 'translation-service',
      audience: 'translation-api',
      subject: user.userId
    };

    return jwt.sign(payload, this.accessTokenSecret, options);
  }

  async generateRefreshToken(user: UserRecord): Promise<string> {
    const payload: RefreshTokenPayload = {
      userId: user.userId,
      tokenVersion: user.refreshTokenVersion,
      iat: Math.floor(Date.now() / 1000)
    };

    const options: jwt.SignOptions = {
      expiresIn: this.refreshTokenExpiry,
      issuer: 'translation-service',
      audience: 'translation-refresh',
      subject: user.userId
    };

    return jwt.sign(payload, this.refreshTokenSecret, options);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret, {
        issuer: 'translation-service',
        audience: 'translation-api'
      }) as AccessTokenPayload;

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthenticationError('Access token expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthenticationError('Invalid access token');
      }
      throw error;
    }
  }

  async verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    try {
      const decoded = jwt.verify(token, this.refreshTokenSecret, {
        issuer: 'translation-service',
        audience: 'translation-refresh'
      }) as RefreshTokenPayload;

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthenticationError('Refresh token expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthenticationError('Invalid refresh token');
      }
      throw error;
    }
  }

  private getUserPermissions(role: UserRole): Permission[] {
    const roleDefinition = ROLE_DEFINITIONS.find(r => r.role === role);
    return roleDefinition?.permissions || [];
  }
}
```

### Multi-Factor Authentication Service
```typescript
class MFAService {
  private readonly appName = 'Translation Service';

  async generateMFASecret(userId: string): Promise<MFASetupInfo> {
    const secret = authenticator.generateSecret();
    const user = await this.getUserById(userId);
    
    const otpauthUrl = authenticator.keyuri(
      user.email,
      this.appName,
      secret
    );

    const qrCode = await qrcode.toDataURL(otpauthUrl);
    const backupCodes = this.generateBackupCodes();

    return {
      secret,
      qrCode,
      backupCodes,
      manualEntryKey: secret
    };
  }

  async enableMFA(userId: string, secret: string, verificationCode: string): Promise<void> {
    // Verify the setup code
    const isValid = this.verifyCode(secret, verificationCode);
    if (!isValid) {
      throw new ValidationError('Invalid verification code');
    }

    // Generate backup codes
    const backupCodes = this.generateBackupCodes();
    const encryptedSecret = await this.encryptSecret(secret);
    const encryptedBackupCodes = await this.encryptBackupCodes(backupCodes);

    // Update user record
    await this.dynamoClient.update({
      TableName: process.env.USERS_SECURITY_TABLE!,
      Key: { PK: `USER#${userId}`, SK: 'SECURITY' },
      UpdateExpression: 'SET mfaSecret = :secret, mfaBackupCodes = :codes, mfaEnabled = :enabled, mfaEnabledAt = :timestamp',
      ExpressionAttributeValues: {
        ':secret': encryptedSecret,
        ':codes': encryptedBackupCodes,
        ':enabled': true,
        ':timestamp': new Date().toISOString()
      }
    }).promise();

    // Update main user record
    await this.dynamoClient.update({
      TableName: process.env.USERS_TABLE!,
      Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
      UpdateExpression: 'SET mfaEnabled = :enabled',
      ExpressionAttributeValues: {
        ':enabled': true
      }
    }).promise();

    // Audit log
    await this.auditService.logSecurityEvent('MFA_ENABLED', { userId });
  }

  async disableMFA(userId: string, password: string, verificationCode: string): Promise<void> {
    // Verify password
    const user = await this.getUserSecurityData(userId);
    const passwordValid = await this.passwordService.verifyPassword(
      password,
      user.passwordHash,
      user.passwordSalt
    );

    if (!passwordValid) {
      throw new AuthenticationError('Invalid password');
    }

    // Verify MFA code or backup code
    const mfaValid = await this.verifyMFAWithBackup(userId, verificationCode);
    if (!mfaValid) {
      throw new AuthenticationError('Invalid MFA code');
    }

    // Remove MFA data
    await this.dynamoClient.update({
      TableName: process.env.USERS_SECURITY_TABLE!,
      Key: { PK: `USER#${userId}`, SK: 'SECURITY' },
      UpdateExpression: 'REMOVE mfaSecret, mfaBackupCodes SET mfaEnabled = :disabled',
      ExpressionAttributeValues: {
        ':disabled': false
      }
    }).promise();

    // Update main user record
    await this.dynamoClient.update({
      TableName: process.env.USERS_TABLE!,
      Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
      UpdateExpression: 'SET mfaEnabled = :disabled',
      ExpressionAttributeValues: {
        ':disabled': false
      }
    }).promise();

    // Audit log
    await this.auditService.logSecurityEvent('MFA_DISABLED', { userId });
  }

  verifyCode(secret: string, code: string): boolean {
    // Remove spaces and convert to uppercase
    const cleanCode = code.replace(/\s/g, '').toUpperCase();
    
    // Verify TOTP code with time window tolerance
    return authenticator.verify({
      token: cleanCode,
      secret: secret,
      window: 2 // Allow 1 time step before and after
    });
  }

  private async verifyMFAWithBackup(userId: string, code: string): Promise<boolean> {
    const user = await this.getUserSecurityData(userId);
    
    if (!user.mfaSecret) {
      return false;
    }

    // First try regular TOTP code
    const decryptedSecret = await this.decryptSecret(user.mfaSecret);
    if (this.verifyCode(decryptedSecret, code)) {
      return true;
    }

    // Try backup codes
    if (user.mfaBackupCodes) {
      const decryptedBackupCodes = await this.decryptBackupCodes(user.mfaBackupCodes);
      const codeIndex = decryptedBackupCodes.findIndex(backupCode => backupCode === code);
      
      if (codeIndex !== -1) {
        // Remove used backup code
        decryptedBackupCodes.splice(codeIndex, 1);
        const encryptedUpdatedCodes = await this.encryptBackupCodes(decryptedBackupCodes);
        
        await this.dynamoClient.update({
          TableName: process.env.USERS_SECURITY_TABLE!,
          Key: { PK: `USER#${userId}`, SK: 'SECURITY' },
          UpdateExpression: 'SET mfaBackupCodes = :codes',
          ExpressionAttributeValues: {
            ':codes': encryptedUpdatedCodes
          }
        }).promise();

        // Audit log backup code usage
        await this.auditService.logSecurityEvent('BACKUP_CODE_USED', {
          userId,
          remainingCodes: decryptedBackupCodes.length
        });

        return true;
      }
    }

    return false;
  }

  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < 10; i++) {
      // Generate 8-character backup codes
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(code);
    }
    return codes;
  }

  private async encryptSecret(secret: string): Promise<string> {
    // Encrypt using AWS KMS
    const result = await kmsClient.encrypt({
      KeyId: process.env.MFA_ENCRYPTION_KEY!,
      Plaintext: secret
    }).promise();

    return result.CiphertextBlob!.toString('base64');
  }

  private async decryptSecret(encryptedSecret: string): Promise<string> {
    const result = await kmsClient.decrypt({
      CiphertextBlob: Buffer.from(encryptedSecret, 'base64')
    }).promise();

    return result.Plaintext!.toString();
  }
}
```

## 5. Authorization System

### Role-Based Access Control
```typescript
class AuthorizationService {
  async checkPermission(
    user: UserRecord,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): Promise<boolean> {
    const permissions = this.getUserPermissions(user.role);
    
    for (const permission of permissions) {
      if (this.matchesPermission(permission, resource, action)) {
        // Check conditions if any
        if (permission.conditions) {
          return this.evaluateConditions(permission.conditions, user, context);
        }
        return true;
      }
    }
    
    return false;
  }

  async enforcePermission(
    user: UserRecord,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): Promise<void> {
    const hasPermission = await this.checkPermission(user, resource, action, context);
    
    if (!hasPermission) {
      // Audit unauthorized access attempt
      await this.auditService.logSecurityEvent('UNAUTHORIZED_ACCESS', {
        userId: user.userId,
        resource,
        action,
        context
      });
      
      throw new AuthorizationError(`Access denied: insufficient permissions for ${action} on ${resource}`);
    }
  }

  async checkUsageLimits(userId: string, operation: string): Promise<UsageLimitResult> {
    const user = await this.getUserById(userId);
    const limits = user.usageLimits;
    const usage = await this.getCurrentUsage(userId);

    switch (operation) {
      case 'CREATE_JOB':
        const todayJobs = await this.getTodayJobCount(userId);
        if (todayJobs >= limits.maxJobsPerDay) {
          return {
            allowed: false,
            limitType: 'DAILY_JOBS',
            current: todayJobs,
            limit: limits.maxJobsPerDay,
            resetsAt: this.getTomorrowMidnight()
          };
        }
        
        const activeJobs = await this.getActiveJobCount(userId);
        if (activeJobs >= limits.maxConcurrentJobs) {
          return {
            allowed: false,
            limitType: 'CONCURRENT_JOBS',
            current: activeJobs,
            limit: limits.maxConcurrentJobs
          };
        }
        break;
        
      case 'UPLOAD_FILE':
        // File size is checked during upload
        break;
    }

    return { allowed: true };
  }

  private matchesPermission(permission: Permission, resource: string, action: string): boolean {
    // Support wildcards in permissions
    const resourceMatch = permission.resource === '*' || 
                         permission.resource === resource ||
                         resource.startsWith(permission.resource.replace('*', ''));
                         
    const actionMatch = permission.action === '*' || permission.action === action;
    
    return resourceMatch && actionMatch;
  }

  private evaluateConditions(
    conditions: Record<string, any>,
    user: UserRecord,
    context?: Record<string, any>
  ): boolean {
    for (const [condition, value] of Object.entries(conditions)) {
      switch (condition) {
        case 'owner':
          if (value && (!context?.owner || context.owner !== user.userId)) {
            return false;
          }
          break;
        case 'self':
          if (value && (!context?.userId || context.userId !== user.userId)) {
            return false;
          }
          break;
        case 'role':
          if (!this.hasRole(user.role, value)) {
            return false;
          }
          break;
        case 'emailVerified':
          if (value && !user.emailVerified) {
            return false;
          }
          break;
      }
    }
    
    return true;
  }

  private hasRole(userRole: UserRole, requiredRole: UserRole | UserRole[]): boolean {
    const roleHierarchy: Record<UserRole, number> = {
      'USER': 1,
      'PREMIUM_USER': 2,
      'ADMIN': 3,
      'SUPER_ADMIN': 4
    };

    const userLevel = roleHierarchy[userRole];
    
    if (Array.isArray(requiredRole)) {
      return requiredRole.some(role => userLevel >= roleHierarchy[role]);
    }
    
    return userLevel >= roleHierarchy[requiredRole];
  }
}
```

### Authorization Middleware
```typescript
class AuthorizationMiddleware {
  static requireAuth() {
    return async (req: any, res: any, next: any) => {
      try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Missing or invalid authorization header' });
        }

        const token = authHeader.substring(7);
        const jwtService = new JWTService();
        const payload = await jwtService.verifyAccessToken(token);

        // Get full user data
        const authService = new UserAuthenticationService();
        const user = await authService.getUserById(payload.userId);
        
        if (!user || user.status !== 'ACTIVE') {
          return res.status(401).json({ error: 'User account not active' });
        }

        req.user = user;
        req.tokenPayload = payload;
        next();
      } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
    };
  }

  static requirePermission(resource: string, action: string) {
    return async (req: any, res: any, next: any) => {
      try {
        if (!req.user) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const authzService = new AuthorizationService();
        const context = {
          ...req.params,
          ...req.query,
          owner: req.params.userId,
          userId: req.user.userId
        };

        await authzService.enforcePermission(req.user, resource, action, context);
        next();
      } catch (error) {
        if (error instanceof AuthorizationError) {
          return res.status(403).json({ error: error.message });
        }
        return res.status(500).json({ error: 'Authorization check failed' });
      }
    };
  }

  static requireRole(roles: UserRole | UserRole[]) {
    return (req: any, res: any, next: any) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const userRole = req.user.role;
      const requiredRoles = Array.isArray(roles) ? roles : [roles];
      
      if (!requiredRoles.includes(userRole)) {
        return res.status(403).json({ error: 'Insufficient role privileges' });
      }

      next();
    };
  }

  static requireEmailVerified() {
    return (req: any, res: any, next: any) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      if (!req.user.emailVerified) {
        return res.status(403).json( {
          error: 'Email verification required',
          requiresVerification: true
        });
      }

      next();
    };
  }
}

// Usage examples:
// app.get('/users/profile', AuthorizationMiddleware.requireAuth(), getUserProfile);
// app.put('/users/:userId/profile', AuthorizationMiddleware.requireAuth(), AuthorizationMiddleware.requirePermission('user:profile', 'update'), updateUserProfile);
// app.get('/admin/users', AuthorizationMiddleware.requireAuth(), AuthorizationMiddleware.requireRole(['ADMIN', 'SUPER_ADMIN']), getUsers);
```

## 6. Performance & Monitoring

### Authentication Metrics
```typescript
class AuthenticationMetrics {
  private cloudWatch: AWS.CloudWatch;

  async publishAuthMetrics(event: AuthEvent): Promise<void> {
    const metrics: AWS.CloudWatch.MetricDatum[] = [
      {
        MetricName: 'AuthenticationAttempts',
        Value: 1,
        Unit: 'Count',
        Dimensions: [
          { Name: 'EventType', Value: event.type },
          { Name: 'Success', Value: event.success ? 'true' : 'false' }
        ]
      }
    ];

    if (event.type === 'LOGIN') {
      metrics.push({
        MetricName: 'LoginDuration',
        Value: event.duration || 0,
        Unit: 'Milliseconds'
      });

      if (event.mfaUsed) {
        metrics.push({
          MetricName: 'MFAUsage',
          Value: 1,
          Unit: 'Count',
          Dimensions: [
            { Name: 'MFAType', Value: event.mfaType || 'TOTP' }
          ]
        });
      }
    }

    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/Authentication',
      MetricData: metrics
    }).promise();
  }

  async trackSecurityEvent(eventType: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'): Promise<void> {
    await this.cloudWatch.putMetricData({
      Namespace: 'TranslationService/Security',
      MetricData: [{
        MetricName: 'SecurityEvents',
        Value: 1,
        Unit: 'Count',
        Dimensions: [
          { Name: 'EventType', Value: eventType },
          { Name: 'Severity', Value: severity }
        ]
      }]
    }).promise();
  }
}
```

## 7. Implementation Examples

### Complete User Registration Flow
```typescript
export const registerUserHandler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  try {
    const request: RegisterRequest = JSON.parse(event.body || '{}');
    const clientInfo: ClientInfo = {
      ipAddress: event.requestContext.identity.sourceIp || '',
      userAgent: event.headers['User-Agent'] || '',
      deviceType: this.detectDeviceType(event.headers['User-Agent'] || '')
    };

    const authService = new UserAuthenticationService();
    const result = await authService.registerUser(request, clientInfo);

    return {
      statusCode: 201,
      headers: {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
      },
      body: JSON.stringify(result)
    };

  } catch (error) {
    console.error('Registration error:', error);

    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: 'Validation failed',
          details: error.details
        })
      };
    }

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Internal server error'
      })
    };
  }
};

export const loginUserHandler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  const startTime = Date.now();
  
  try {
    const request: LoginRequest = JSON.parse(event.body || '{}');
    const clientInfo: ClientInfo = {
      ipAddress: event.requestContext.identity.sourceIp || '',
      userAgent: event.headers['User-Agent'] || '',
      deviceType: this.detectDeviceType(event.headers['User-Agent'] || '')
    };

    const authService = new UserAuthenticationService();
    const result = await authService.loginUser(request, clientInfo);

    // Publish metrics
    const metrics = new AuthenticationMetrics();
    await metrics.publishAuthMetrics({
      type: 'LOGIN',
      success: true,
      duration: Date.now() - startTime,
      mfaUsed: !result.requiresMfa && result.user.mfaEnabled
    });

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': `refreshToken=${result.refreshToken}; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`, // 7 days
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
      },
      body: JSON.stringify({
        accessToken: result.accessToken,
        expiresIn: result.expiresIn,
        user: result.user,
        requiresMfa: result.requiresMfa
      })
    };

  } catch (error) {
    console.error('Login error:', error);

    // Publish failure metrics
    const metrics = new AuthenticationMetrics();
    await metrics.publishAuthMetrics({
      type: 'LOGIN',
      success: false,
      duration: Date.now() - startTime
    });

    if (error instanceof AuthenticationError) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          error: error.message
        })
      };
    }

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Internal server error'
      })
    };
  }
};
```

## 8. Testing Strategy

### Authentication Testing
```typescript
describe('UserAuthenticationService', () => {
  let authService: UserAuthenticationService;
  let mockPasswordService: jest.Mocked<PasswordService>;
  let mockJWTService: jest.Mocked<JWTService>;

  beforeEach(() => {
    mockPasswordService = {
      hashPassword: jest.fn(),
      verifyPassword: jest.fn(),
      validatePassword: jest.fn()
    } as any;

    mockJWTService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      verifyAccessToken: jest.fn(),
      verifyRefreshToken: jest.fn()
    } as any;

    authService = new UserAuthenticationService();
    (authService as any).passwordService = mockPasswordService;
    (authService as any).jwtService = mockJWTService;
  });

  describe('registerUser', () => {
    it('successfully registers a new user', async () => {
      const request: RegisterRequest = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        confirmPassword: 'SecurePass123!',
        firstName: 'John',
        lastName: 'Doe',
        acceptedTerms: true,
        acceptedPrivacy: true
      };

      mockPasswordService.validatePassword.mockReturnValue({
        isValid: true,
        errors: [],
        strength: 'STRONG'
      });

      mockPasswordService.hashPassword.mockResolvedValue({
        hash: 'hashed-password',
        salt: 'salt'
      });

      jest.spyOn(authService as any, 'getUserByEmail').mockResolvedValue(null);
      jest.spyOn(authService as any, 'createEmailVerificationRecord').mockResolvedValue(undefined);
      jest.spyOn(authService as any, 'sendVerificationEmail').mockResolvedValue(undefined);

      const clientInfo: ClientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
        deviceType: 'desktop'
      };

      const result = await authService.registerUser(request, clientInfo);

      expect(result.userId).toBeDefined();
      expect(result.verificationRequired).toBe(true);
      expect(mockPasswordService.hashPassword).toHaveBeenCalledWith('SecurePass123!');
    });

    it('rejects registration with weak password', async () => {
      const request: RegisterRequest = {
        email: 'test@example.com',
        password: '123',
        confirmPassword: '123',
        firstName: 'John',
        lastName: 'Doe',
        acceptedTerms: true,
        acceptedPrivacy: true
      };

      mockPasswordService.validatePassword.mockReturnValue({
        isValid: false,
        errors: ['Password must be at least 8 characters long'],
        strength: 'WEAK'
      });

      const clientInfo: ClientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
        deviceType: 'desktop'
      };

      await expect(authService.registerUser(request, clientInfo))
        .rejects.toThrow(ValidationError);
    });

    it('rejects registration with existing email', async () => {
      const request: RegisterRequest = {
        email: 'existing@example.com',
        password: 'SecurePass123!',
        confirmPassword: 'SecurePass123!',
        firstName: 'John',
        lastName: 'Doe',
        acceptedTerms: true,
        acceptedPrivacy: true
      };

      mockPasswordService.validatePassword.mockReturnValue({
        isValid: true,
        errors: [],
        strength: 'STRONG'
      });

      jest.spyOn(authService as any, 'getUserByEmail').mockResolvedValue({
        userId: 'existing-user',
        email: 'existing@example.com'
      });

      const clientInfo: ClientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
        deviceType: 'desktop'
      };

      await expect(authService.registerUser(request, clientInfo))
        .rejects.toThrow(ValidationError);
    });
  });

  describe('loginUser', () => {
    it('successfully logs in valid user', async () => {
      const request: LoginRequest = {
        email: 'test@example.com',
        password: 'SecurePass123!'
      };

      const mockUser = createMockUser({
        email: 'test@example.com',
        status: 'ACTIVE',
        emailVerified: true,
        mfaEnabled: false
      });

      jest.spyOn(authService as any, 'getUserByEmail').mockResolvedValue(mockUser);
      jest.spyOn(authService as any, 'checkAccountStatus').mockResolvedValue(undefined);
      jest.spyOn(authService as any, 'checkAccountLockout').mockResolvedValue(undefined);
      mockPasswordService.verifyPassword.mockResolvedValue(true);
      mockJWTService.generateAccessToken.mockResolvedValue('access-token');
      mockJWTService.generateRefreshToken.mockResolvedValue('refresh-token');

      const clientInfo: ClientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
        deviceType: 'desktop'
      };

      const result = await authService.loginUser(request, clientInfo);

      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBe('refresh-token');
      expect(result.requiresMfa).toBe(false);
    });

    it('requires MFA when enabled', async () => {
      const request: LoginRequest = {
        email: 'test@example.com',
        password: 'SecurePass123!'
      };

      const mockUser = createMockUser({
        email: 'test@example.com',
        status: 'ACTIVE',
        emailVerified: true,
        mfaEnabled: true
      });

      jest.spyOn(authService as any, 'getUserByEmail').mockResolvedValue(mockUser);
      jest.spyOn(authService as any, 'checkAccountStatus').mockResolvedValue(undefined);
      jest.spyOn(authService as any, 'checkAccountLockout').mockResolvedValue(undefined);
      mockPasswordService.verifyPassword.mockResolvedValue(true);

      const clientInfo: ClientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
        deviceType: 'desktop'
      };

      const result = await authService.loginUser(request, clientInfo);

      expect(result.requiresMfa).toBe(true);
      expect(result.mfaRequired).toBe(true);
      expect(result.accessToken).toBe('');
    });

    it('rejects invalid password', async () => {
      const request: LoginRequest = {
        email: 'test@example.com',
        password: 'wrong-password'
      };

      const mockUser = createMockUser({
        email: 'test@example.com',
        status: 'ACTIVE'
      });

      jest.spyOn(authService as any, 'getUserByEmail').mockResolvedValue(mockUser);
      jest.spyOn(authService as any, 'checkAccountStatus').mockResolvedValue(undefined);
      jest.spyOn(authService as any, 'checkAccountLockout').mockResolvedValue(undefined);
      mockPasswordService.verifyPassword.mockResolvedValue(false);
      jest.spyOn(authService as any, 'handleFailedLogin').mockResolvedValue(undefined);

      const clientInfo: ClientInfo = {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent',
        deviceType: 'desktop'
      };

      await expect(authService.loginUser(request, clientInfo))
        .rejects.toThrow(AuthenticationError);
    });
  });
});

function createMockUser(overrides: Partial<UserRecord>): UserRecord {
  return {
    PK: 'USER#test-user',
    SK: 'PROFILE',
    userId: 'test-user',
    email: 'test@example.com',
    emailLowercase: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    passwordHash: 'hashed-password',
    passwordSalt: 'salt',
    passwordLastChanged: new Date().toISOString(),
    mfaEnabled: false,
    status: 'ACTIVE',
    role: 'USER',
    emailVerified: true,
    refreshTokenVersion: 1,
    failedLoginAttempts: 0,
    preferences: {
      language: 'en',
      timezone: 'UTC',
      emailNotifications: {
        jobCompleted: true,
        jobFailed: true,
        weeklyReport: false,
        securityAlerts: true
      },
      uiSettings: {
        theme: 'light',
        pollingInterval: 30000,
        defaultTargetLanguage: 'spanish'
      }
    },
    subscription: {
      tier: 'FREE',
      status: 'ACTIVE'
    },
    usageLimits: {
      maxJobsPerDay: 10,
      maxFileSize: 50 * 1024 * 1024,
      maxConcurrentJobs: 2,
      allowedLanguages: ['spanish', 'french']
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    acceptedTermsVersion: '1.0',
    acceptedPrivacyVersion: '1.0',
    marketingConsent: false,
    dataRetentionConsent: true,
    ...overrides
  };
}
```

## 9. Configuration & Deployment

### CloudFormation Template for User Management
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'User Management & Authentication Infrastructure'

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, staging, prod]

Resources:
  # KMS Key for MFA Encryption
  MFAEncryptionKey:
    Type: AWS::KMS::Key
    Properties:
      Description: 'KMS key for MFA secret encryption'
      KeyPolicy:
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'

  MFAEncryptionKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub 'alias/mfa-encryption-${Environment}'
      TargetKeyId: !Ref MFAEncryptionKey
```