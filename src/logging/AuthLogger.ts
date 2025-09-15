/**
 * T028: Auth package logging integration in packages/auth/src/logging/AuthLogger.ts
 *
 * Specialized logger for authentication and authorization events
 * Provides domain-specific logging methods for security and audit compliance
 */

import {
  LoggerFactory,
  CorrelationService,
  AuditTrailClass as AuditTrail,
  AuditAction,
  AuditEventType,
  LogLevel,
  LogDomain,
  globalAuditTrail,
  type Logger
} from '@cvplus/logging/backend';

/**
 * Authentication event types
 */
export enum AuthEventType {
  LOGIN_ATTEMPT = 'auth.login.attempt',
  LOGIN_SUCCESS = 'auth.login.success',
  LOGIN_FAILURE = 'auth.login.failure',
  LOGOUT = 'auth.logout',
  TOKEN_REFRESH = 'auth.token.refresh',
  PASSWORD_CHANGE = 'auth.password.change',
  PASSWORD_RESET = 'auth.password.reset',
  MFA_SETUP = 'auth.mfa.setup',
  MFA_VERIFY = 'auth.mfa.verify',
  SESSION_CREATE = 'auth.session.create',
  SESSION_DESTROY = 'auth.session.destroy',
  PERMISSION_CHECK = 'auth.permission.check',
  ROLE_ASSIGN = 'auth.role.assign',
  ACCOUNT_LOCK = 'auth.account.lock',
  ACCOUNT_UNLOCK = 'auth.account.unlock',
  SUSPICIOUS_ACTIVITY = 'auth.suspicious.activity'
}

/**
 * Login attempt result
 */
export enum LoginResult {
  SUCCESS = 'success',
  INVALID_CREDENTIALS = 'invalid_credentials',
  ACCOUNT_LOCKED = 'account_locked',
  MFA_REQUIRED = 'mfa_required',
  PASSWORD_EXPIRED = 'password_expired',
  RATE_LIMITED = 'rate_limited',
  ACCOUNT_DISABLED = 'account_disabled'
}

/**
 * Authentication context interface
 */
export interface AuthContext {
  userId?: string;
  userEmail?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  method?: 'email' | 'oauth' | 'sso' | 'api_key';
  provider?: string;
  mfaEnabled?: boolean;
  roles?: string[];
  permissions?: string[];
  loginAttempts?: number;
  lastLoginAt?: Date;
  deviceFingerprint?: string;
  location?: {
    country?: string;
    region?: string;
    city?: string;
  };
}

/**
 * Specialized authentication logger
 */
export class AuthLogger {
  private readonly logger: Logger;
  private readonly packageName = '@cvplus/auth';

  constructor() {
    this.logger = LoggerFactory.createLogger(this.packageName, {
      level: LogLevel.INFO,
      enableConsole: true,
      enableFirebase: true,
      enablePiiRedaction: true
    });
  }

  /**
   * Log successful login
   */
  loginSuccess(context: AuthContext): string {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.info('User login successful', {
      event: AuthEventType.LOGIN_SUCCESS,
      userId: context.userId,
      userEmail: context.userEmail,
      sessionId: context.sessionId,
      method: context.method,
      provider: context.provider,
      mfaEnabled: context.mfaEnabled,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      location: context.location,
      correlationId
    });

    // Create audit trail entry
    return globalAuditTrail.logEvent(
      AuditEventType.USER_LOGIN,
      AuditAction.LOGIN,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        sessionId: context.sessionId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        result: 'SUCCESS',
        description: `User ${context.userEmail} logged in successfully`,
        context: {
          method: context.method,
          provider: context.provider,
          mfaEnabled: context.mfaEnabled,
          location: context.location
        },
        complianceTags: ['auth', 'login', 'gdpr']
      }
    );
  }

  /**
   * Log failed login attempt
   */
  loginFailure(context: AuthContext, reason: LoginResult, error?: Error): string {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.warn('User login failed', {
      event: AuthEventType.LOGIN_FAILURE,
      userId: context.userId,
      userEmail: context.userEmail,
      reason,
      loginAttempts: context.loginAttempts,
      method: context.method,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      location: context.location,
      correlationId,
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack
      } : undefined
    });

    // Create audit trail entry for failed login
    return globalAuditTrail.logEvent(
      AuditEventType.USER_LOGIN_FAILED,
      AuditAction.LOGIN,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        result: 'FAILURE',
        description: `Login failed for ${context.userEmail}: ${reason}`,
        context: {
          reason,
          method: context.method,
          loginAttempts: context.loginAttempts,
          location: context.location
        },
        error: error ? {
          code: reason,
          message: error.message,
          stack: error.stack
        } : undefined,
        complianceTags: ['auth', 'security', 'failed_login']
      }
    );
  }

  /**
   * Log user logout
   */
  logout(context: AuthContext): string {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.info('User logout', {
      event: AuthEventType.LOGOUT,
      userId: context.userId,
      userEmail: context.userEmail,
      sessionId: context.sessionId,
      correlationId
    });

    return globalAuditTrail.logEvent(
      AuditEventType.USER_LOGOUT,
      AuditAction.LOGOUT,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        sessionId: context.sessionId,
        result: 'SUCCESS',
        description: `User ${context.userEmail} logged out`,
        complianceTags: ['auth', 'logout']
      }
    );
  }

  /**
   * Log password change
   */
  passwordChange(context: AuthContext, success: boolean, error?: Error): string {
    const correlationId = CorrelationService.getCurrentId();

    if (success) {
      this.logger.info('Password changed successfully', {
        event: AuthEventType.PASSWORD_CHANGE,
        userId: context.userId,
        userEmail: context.userEmail,
        correlationId
      });
    } else {
      this.logger.warn('Password change failed', {
        event: AuthEventType.PASSWORD_CHANGE,
        userId: context.userId,
        userEmail: context.userEmail,
        correlationId,
        error: error ? {
          name: error.name,
          message: error.message
        } : undefined
      });
    }

    return globalAuditTrail.logEvent(
      AuditEventType.USER_PASSWORD_CHANGED,
      AuditAction.UPDATE,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        result: success ? 'SUCCESS' : 'FAILURE',
        description: `Password change ${success ? 'successful' : 'failed'} for ${context.userEmail}`,
        error: error ? {
          code: 'PASSWORD_CHANGE_FAILED',
          message: error.message
        } : undefined,
        complianceTags: ['auth', 'password', 'security']
      }
    );
  }

  /**
   * Log permission check
   */
  permissionCheck(
    permission: string,
    resource: string,
    context: AuthContext,
    granted: boolean
  ): void {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.debug('Permission check performed', {
      event: AuthEventType.PERMISSION_CHECK,
      userId: context.userId,
      permission,
      resource,
      granted,
      roles: context.roles,
      correlationId
    });

    if (!granted) {
      // Log permission denied as a warning
      this.logger.warn('Permission denied', {
        userId: context.userId,
        permission,
        resource,
        roles: context.roles,
        ipAddress: context.ipAddress,
        correlationId
      });
    }
  }

  /**
   * Log role assignment
   */
  roleAssign(targetUserId: string, role: string, context: AuthContext): string {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.info('Role assigned to user', {
      event: AuthEventType.ROLE_ASSIGN,
      adminUserId: context.userId,
      targetUserId,
      role,
      correlationId
    });

    return globalAuditTrail.logEvent(
      AuditEventType.USER_PERMISSION_GRANTED,
      AuditAction.UPDATE,
      {
        userId: context.userId,
        result: 'SUCCESS',
        resource: `user:${targetUserId}`,
        description: `Role '${role}' assigned to user ${targetUserId}`,
        context: {
          targetUserId,
          role,
          assignedBy: context.userId
        },
        complianceTags: ['auth', 'role', 'permission']
      }
    );
  }

  /**
   * Log suspicious activity
   */
  suspiciousActivity(
    activityType: string,
    context: AuthContext,
    details: Record<string, any>
  ): string {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.error('Suspicious authentication activity detected', {
      event: AuthEventType.SUSPICIOUS_ACTIVITY,
      activityType,
      userId: context.userId,
      userEmail: context.userEmail,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      details,
      correlationId
    });

    return globalAuditTrail.logEvent(
      AuditEventType.SECURITY_BREACH_DETECTED,
      AuditAction.ACCESS,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        result: 'FAILURE',
        description: `Suspicious activity: ${activityType}`,
        context: {
          activityType,
          ...details
        },
        complianceTags: ['security', 'suspicious', 'threat']
      }
    );
  }

  /**
   * Log MFA setup
   */
  mfaSetup(context: AuthContext, method: string, success: boolean): string {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.info('MFA setup attempted', {
      event: AuthEventType.MFA_SETUP,
      userId: context.userId,
      userEmail: context.userEmail,
      method,
      success,
      correlationId
    });

    return globalAuditTrail.logEvent(
      AuditEventType.USER_PASSWORD_CHANGED, // Using closest available type
      AuditAction.CONFIGURE,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        result: success ? 'SUCCESS' : 'FAILURE',
        description: `MFA ${method} setup ${success ? 'completed' : 'failed'}`,
        context: { method },
        complianceTags: ['auth', 'mfa', 'security']
      }
    );
  }

  /**
   * Log session creation
   */
  sessionCreate(context: AuthContext): void {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.debug('Session created', {
      event: AuthEventType.SESSION_CREATE,
      userId: context.userId,
      sessionId: context.sessionId,
      correlationId
    });
  }

  /**
   * Log session destruction
   */
  sessionDestroy(context: AuthContext, reason: string): void {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.debug('Session destroyed', {
      event: AuthEventType.SESSION_DESTROY,
      userId: context.userId,
      sessionId: context.sessionId,
      reason,
      correlationId
    });
  }

  /**
   * Log account lock
   */
  accountLock(context: AuthContext, reason: string): string {
    const correlationId = CorrelationService.getCurrentId();

    this.logger.warn('Account locked', {
      event: AuthEventType.ACCOUNT_LOCK,
      userId: context.userId,
      userEmail: context.userEmail,
      reason,
      correlationId
    });

    return globalAuditTrail.logEvent(
      AuditEventType.SYSTEM_USER_DELETED, // Using closest available type
      AuditAction.UPDATE,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        result: 'SUCCESS',
        description: `Account locked: ${reason}`,
        context: { reason },
        complianceTags: ['auth', 'security', 'account_lock']
      }
    );
  }

  /**
   * Log with correlation context
   */
  withCorrelation<T>(correlationId: string, callback: () => T): T | Promise<T> {
    return CorrelationService.withCorrelationId(correlationId, callback);
  }

  /**
   * Create child logger with additional context
   */
  createChildLogger(context: Partial<AuthContext>): AuthLogger {
    // For now, return the same logger
    // In a full implementation, you'd create a logger with bound context
    return this;
  }

  /**
   * Get logger statistics
   */
  getStats(): {
    totalLogs: number;
    logsByLevel: Record<string, number>;
    recentActivity: Date;
  } {
    // Placeholder implementation
    return {
      totalLogs: 0,
      logsByLevel: {},
      recentActivity: new Date()
    };
  }
}

/**
 * Global auth logger instance
 */
export const authLogger = new AuthLogger();

/**
 * Convenience functions for common auth logging scenarios
 */
export const authLogging = {
  /**
   * Log user login attempt
   */
  loginAttempt: (userEmail: string, context: Partial<AuthContext> = {}) => {
    return authLogger.loginSuccess({
      userEmail,
      ...context
    });
  },

  /**
   * Log failed login
   */
  loginFailed: (userEmail: string, reason: LoginResult, context: Partial<AuthContext> = {}) => {
    return authLogger.loginFailure({
      userEmail,
      ...context
    }, reason);
  },

  /**
   * Log permission denied
   */
  permissionDenied: (permission: string, resource: string, context: Partial<AuthContext> = {}) => {
    authLogger.permissionCheck(permission, resource, context as AuthContext, false);
  },

  /**
   * Log security incident
   */
  securityIncident: (type: string, details: Record<string, any>, context: Partial<AuthContext> = {}) => {
    return authLogger.suspiciousActivity(type, context as AuthContext, details);
  }
};

/**
 * Auth logger middleware for Express
 */
export const authLoggerMiddleware = (req: any, res: any, next: any) => {
  // Add auth context to request
  req.authLogger = authLogger;
  req.authContext = {
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    userId: req.user?.id,
    userEmail: req.user?.email
  };

  next();
};

/**
 * Default export
 */
export default AuthLogger;