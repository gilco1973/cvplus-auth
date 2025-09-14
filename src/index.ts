/**
 * CVPlus Authentication Module
 * 
 * A comprehensive authentication and authorization module for the CVPlus platform.
 * Provides secure user management, session handling, premium features, and role-based access control.
 * 
 * @author Gil Klainert
 * @version 1.0.0
 */

// ============================================================================
// TYPE EXPORTS
// ============================================================================
export * from './types';

// ============================================================================
// CORE SERVICES
// ============================================================================
export { AuthService } from './services/auth.service';
export { TokenService } from './services/token.service';
export { SessionService } from './services/session.service';
export { PermissionsService } from './services/permissions.service';
export { PremiumService } from './services/premium.service';
export { CalendarService } from './services/calendar.service';

// ============================================================================
// CONSOLIDATED BACKEND SERVICES (Phase 4 Deduplication)
// ============================================================================
export {
  FirebaseAuthenticationService,
  firebaseAuth as firebaseAuthService,
  requireAuth as requireAuthService,
  requireAuthWithJobOwnership,
  requireAuthExpress
} from './services/authentication.service';

export {
  FirebaseAuthorizationService,
  firebaseAuth as firebaseAuthzService,
  hasPermission,
  requirePermission
} from './services/authorization.service';

// Note: requireRole, requireAdminAccess, requirePremiumAccess, requireEnterpriseAccess
// are exported from middleware to avoid duplication

export {
  MiddlewareFactory
} from './services/middleware-factory.service';

// Note: Factory functions are exported from middleware to avoid duplication

// ============================================================================
// CONSOLIDATED MIDDLEWARE (Phase 4 Deduplication)
// ============================================================================
export {
  // Auth middleware functions
  requireAuth,
  requireEmailVerification,
  requireAdmin,
  requirePremium,
  requireEnterprise,
  requireRole,
  
  // Firebase Functions validators
  validateAuth,
  validateAuthWithEmail,
  validateAdmin,
  validatePremium,
  validatePremiumFeature,
  validateRole,
  
  // Utility middleware
  createComposite,
  authErrorHandler,
  authLogger,
  
  // Factory exports
  middlewareFactory,
  createAuthMiddleware,
  createRoleMiddleware,
  createPremiumMiddleware,
  createCallableAuth,
  createCallableRole,
  createCallableAdmin,
  createCallablePremium,
  createResourceOwnership,
  
  // Migration helpers
  migrationHelpers,
  authMiddleware
} from './middleware';

// ============================================================================
// UTILITIES
// ============================================================================
export * from './utils/validation';
export * from './utils/encryption';
export * from './utils/storage';
export * from './utils/cache';
export * from './utils/errors';

// Auth helpers (specific exports to avoid conflicts)
export {
  extractBearerToken,
  validateIdToken,
  hasAnyRole,
  hasAllRoles,
  getUserRoles,
  isEmailVerified,
  getUserDisplayInfo,
  checkResourceOwnership,
  RateLimiter,
  logAuthEvent,
  addSecurityHeaders,
  sanitizeForLogging
} from './utils/auth-helpers';

// ============================================================================
// CONSTANTS
// ============================================================================
export * from './constants/auth.constants';
export * from './constants/permissions.constants';
export * from './constants/premium.constants';

// ============================================================================
// FRONTEND COMPONENTS & HOOKS (Client-side React)
// ============================================================================
// Primary exports for shell application and frontend consumers
export { AuthProvider, useAuth } from './frontend';
export type { UseAuthReturn } from './frontend';

// Additional frontend exports
export { useAuthContext } from './frontend';
export type { AuthContextState, AuthContextActions, AuthContextValue } from './frontend';

// Legacy root exports for backward compatibility
export * from './hooks';
export * from './components';

// Legacy compatibility exports for smooth migration from root repository
export { useAuth as useLegacyAuth } from './hooks/useAuth';
export { usePremium as useLegacyPremium } from './hooks/usePremium';
export { AuthProvider as LegacyAuthProvider } from './context/AuthContext';

// ============================================================================
// GOOGLE OAUTH INTEGRATION
// ============================================================================
export { useGoogleAuth, type UseGoogleAuthReturn } from './hooks/useGoogleAuth';

// ============================================================================
// FIREBASE FUNCTIONS MIDDLEWARE (Migrated from Root Repository)
// ============================================================================
export {
  requireAuth as requireAuthFirebase,
  requireAdmin as requireAdminFirebase,
  createRateLimit,
  standardRateLimit,
  strictRateLimit,
  apiRateLimit,
  requireClaim,
  type AuthenticatedRequest
} from './middleware/firebase-auth.middleware';

// ============================================================================
// MIGRATION UTILITIES
// ============================================================================
export {
  createLegacyAuthWrapper,
  importMappings,
  componentMappings,
  migrationChecklist,
  type LegacyAuthContextType
} from './migration/authMigration';

// ============================================================================
// MODULE INITIALIZATION
// ============================================================================
export { initializeAuth } from './services/auth.service';

// ============================================================================
// VERSION INFORMATION
// ============================================================================
export const VERSION = '1.0.0';
export const MODULE_NAME = '@cvplus/auth';

// Default configuration for easy setup
export { defaultAuthConfig } from './constants/auth.constants';