/**
 * Authentication Module Types
 * 
 * Core type definitions for the CVPlus authentication system.
 * Provides comprehensive typing for all authentication-related functionality.
 * 
 * @author Gil Klainert
 * @version 1.0.0
 */

// Export all types, resolving conflicts by prioritizing error.types for error definitions
export * from './user.types';
export * from './permissions.types';
// Export specific premium types to avoid component name conflicts
export type { 
  PremiumSubscription,
  SubscriptionStatus, 
  PremiumTier, 
  PremiumFeatures, 
  FeatureAccess,
  FeatureLimit,
  FeatureRestriction,
  BillingInfo,
  PaymentMethod,
  BillingCycle,
  MonetaryAmount,
  Invoice,
  UsageMetrics,
  DailyUsage,
  SubscriptionMetadata,
  PremiumPlan,
  PlanLimits,
  SubscriptionChange,
  FeatureUsageEvent,
  PremiumStatus,
  FeatureGateConfig,
  UsageAlert
} from './premium.types';
export * from './config.types';

// Export session types excluding conflicting ones
export type { AuthSession, SessionState, SessionDeviceInfo, SessionLocation, SessionFlags, SessionToken } from './session.types';

// Export auth types excluding conflicting error types 
export type { AuthState, AuthConfig, AuthCredentials, AuthEvents, AuthValidationResult, AuthTokenInfo, AuthProvider } from './auth.types';

// Error types take precedence (these will be the primary error definitions)
export * from './error.types';

// Firebase authentication types (Phase 4 Deduplication) - specific exports to avoid conflicts
export type {
  AuthenticatedCallableRequest,
  AuthenticatedExpressRequest,
  AuthValidationOptions as FirebaseAuthValidationOptions,
  AuthValidationResult as FirebaseAuthValidationResult,
  JobOwnershipValidationOptions,
  BasicAuthMiddlewareConfig,
  RoleMiddlewareConfig,
  PremiumMiddlewareConfig,
  ResourceOwnershipConfig,
  CompositeMiddlewareConfig,
  AuthEventType,
  AuthEvent,
  UserSubscription,
  SubscriptionLimits,
  CacheConfig,
  CacheEntry,
  AuthMigrationMapping,
  MigrationResult,
  RateLimitConfig,
  SecurityHeadersConfig
} from './firebase-auth.types';

// Re-export overlapping types with prefixes to avoid conflicts
export type { 
  UserRole as FirebaseUserRole,
  Permission as FirebasePermission,
  PermissionCondition as FirebasePermissionCondition,
  AuthError as FirebaseAuthError,
  AuthErrorCode as FirebaseAuthErrorCode
} from './firebase-auth.types';