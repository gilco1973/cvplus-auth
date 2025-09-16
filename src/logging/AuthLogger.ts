/**
 * T028: Auth package logging integration in packages/auth/src/logging/AuthLogger.ts
 *
 * Specialized logger for authentication and authorization events
 * Provides domain-specific logging methods for security and audit compliance
 */

// Import logging directly from Layer 0 (correct architectural dependency)
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
 * Specialized authentication logger using CVPlus logging system
 */
export class AuthLogger {
  private readonly logger: Logger;
  private readonly packageName = '@cvplus/auth';

  constructor() {
    this.logger = LoggerFactory.createLogger(this.packageName, {
      level: LogLevel.INFO,
      domain: LogDomain.AUTH
    });
  }

  /**
   * Log authentication events
   */
  logAuthEvent(eventType: AuthEventType, context: Partial<AuthContext>, details?: any): void {
    const correlationId = CorrelationService.getCurrentCorrelationId();
    const auditAction = this.mapEventTypeToAuditAction(eventType);

    const metadata = {
      ...context,
      details,
      correlationId,
      eventType,
      auditAction
    };

    // Log to standard logger
    switch (eventType) {
      case AuthEventType.LOGIN_SUCCESS:
      case AuthEventType.LOGOUT:
      case AuthEventType.TOKEN_REFRESH:
        this.logger.info(`Auth Event: ${eventType}`, metadata);
        break;
      case AuthEventType.LOGIN_FAILURE:
      case AuthEventType.ACCOUNT_LOCK:
      case AuthEventType.SUSPICIOUS_ACTIVITY:
        this.logger.warn(`Security Event: ${eventType}`, metadata);
        break;
      default:
        this.logger.info(`Auth Event: ${eventType}`, metadata);
    }

    // Add to audit trail for security events
    if (auditAction && context.userId) {
      globalAuditTrail.addEvent({
        userId: context.userId,
        action: auditAction,
        resourceType: 'authentication',
        resourceId: context.sessionId || 'unknown',
        metadata: {
          eventType,
          ...details
        },
        correlationId
      });
    }
  }

  /**
   * Log login attempts
   */
  logLoginAttempt(userEmail: string, result: LoginResult, context: Partial<AuthContext> = {}): void {
    const eventType = result === LoginResult.SUCCESS ? AuthEventType.LOGIN_SUCCESS : AuthEventType.LOGIN_FAILURE;

    this.logAuthEvent(eventType, {
      ...context,
      userEmail,
      loginResult: result
    });
  }

  /**
   * Log session events
   */
  logSessionEvent(eventType: AuthEventType.SESSION_CREATE | AuthEventType.SESSION_DESTROY, context: Partial<AuthContext>): void {
    this.logAuthEvent(eventType, context);
  }

  /**
   * Log permission checks
   */
  logPermissionCheck(userId: string, permission: string, granted: boolean, context: Partial<AuthContext> = {}): void {
    this.logAuthEvent(AuthEventType.PERMISSION_CHECK, {
      ...context,
      userId,
      permission,
      granted
    });
  }

  /**
   * Log suspicious activity
   */
  logSuspiciousActivity(description: string, context: Partial<AuthContext>): void {
    const correlationId = CorrelationService.getCurrentCorrelationId();

    this.logger.warn(`Suspicious Activity: ${description}`, {
      ...context,
      correlationId
    });

    // Add to audit trail
    if (context.userId) {
      globalAuditTrail.addEvent({
        userId: context.userId,
        action: AuditAction.SECURITY_VIOLATION,
        resourceType: 'authentication',
        resourceId: context.sessionId || 'unknown',
        metadata: {
          description,
          ...context
        },
        correlationId
      });
    }
  }

  /**
   * Log security events
   */
  logSecurityEvent(message: string, context: Partial<AuthContext> = {}): void {
    const correlationId = CorrelationService.getCurrentCorrelationId();

    this.logger.warn(`Security Event: ${message}`, {
      ...context,
      correlationId
    });

    // Add to audit trail
    if (context.userId) {
      globalAuditTrail.addEvent({
        userId: context.userId,
        action: AuditAction.SECURITY_VIOLATION,
        resourceType: 'authentication',
        resourceId: context.sessionId || 'unknown',
        metadata: {
          message,
          ...context
        },
        correlationId
      });
    }
  }

  /**
   * Log errors with context
   */
  logError(error: Error, context: Partial<AuthContext> = {}): void {
    const correlationId = CorrelationService.getCurrentCorrelationId();

    this.logger.error(`Auth Error: ${error.message}`, {
      ...context,
      error: error.stack,
      correlationId
    });
  }

  /**
   * Map authentication event types to audit actions
   */
  private mapEventTypeToAuditAction(eventType: AuthEventType): AuditAction | null {
    switch (eventType) {
      case AuthEventType.LOGIN_SUCCESS:
        return AuditAction.LOGIN;
      case AuthEventType.LOGOUT:
        return AuditAction.LOGOUT;
      case AuthEventType.LOGIN_FAILURE:
        return AuditAction.LOGIN_FAILED;
      case AuthEventType.PASSWORD_CHANGE:
        return AuditAction.PASSWORD_CHANGE;
      case AuthEventType.ACCOUNT_LOCK:
        return AuditAction.ACCOUNT_LOCK;
      case AuthEventType.ACCOUNT_UNLOCK:
        return AuditAction.ACCOUNT_UNLOCK;
      case AuthEventType.ROLE_ASSIGN:
        return AuditAction.ROLE_ASSIGNMENT;
      case AuthEventType.SUSPICIOUS_ACTIVITY:
        return AuditAction.SECURITY_VIOLATION;
      default:
        return null;
    }
  }
}

// Default auth logger instance
export const authLogger = new AuthLogger();