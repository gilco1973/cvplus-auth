/**
 * Consolidated Authentication Middleware
 * 
 * Replaces scattered middleware patterns from authGuard.ts (539 lines) and
 * enhancedPremiumGuard.ts (572 lines) with consolidated, reusable middleware.
 * 
 * Author: Gil Klainert
 * Date: August 28, 2025
 */

import { Response, NextFunction } from 'express';
import { HttpsError, CallableRequest } from 'firebase-functions/v2/https';
import { logger } from 'firebase-functions';
import { AuthenticatedExpressRequest } from '../types/firebase-auth.types';
import { 
  middlewareFactory,
  createAuthMiddleware,
  createRoleMiddleware,
  createPremiumMiddleware,
  createCallableAuth,
  createCallableRole,
  createCallableAdmin,
  createCallablePremium,
  BasicAuthMiddlewareConfig,
  RoleMiddlewareConfig,
  PremiumMiddlewareConfig
} from '../services/middleware-factory.service';

// Re-export types for convenience
export type {
  BasicAuthMiddlewareConfig,
  RoleMiddlewareConfig,
  PremiumMiddlewareConfig
} from '../services/middleware-factory.service';

/**
 * Standard authentication middleware - replaces basic auth patterns
 * 
 * Usage in Express:
 * app.use('/api/protected', requireAuth());
 * 
 * Replaces patterns like:
 * ```
 * const token = req.headers.authorization?.replace('Bearer ', '');
 * if (!token) throw new Error('No token provided');
 * ```
 */
export const requireAuth = (config?: BasicAuthMiddlewareConfig) => 
  createAuthMiddleware(config);

/**
 * Email verification middleware
 */
export const requireEmailVerification = () => 
  createAuthMiddleware({ requireEmailVerification: true });

/**
 * Admin access middleware - replaces admin checking patterns
 * 
 * Usage:
 * app.use('/api/admin', requireAuth(), requireAdmin());
 * 
 * Replaces patterns like:
 * ```
 * if (!userData.roles.includes('admin')) {
 *   throw new Error('Admin access required');
 * }
 * ```
 */
export const requireAdmin = () => 
  createRoleMiddleware({ 
    roles: ['admin', 'superadmin'],
    logAccess: true
  });

/**
 * Premium access middleware - consolidates enhancedPremiumGuard patterns
 * 
 * Usage:
 * app.use('/api/premium', requireAuth(), requirePremium());
 */
export const requirePremium = (config?: PremiumMiddlewareConfig) =>
  createPremiumMiddleware(config);

/**
 * Enterprise access middleware
 */
export const requireEnterprise = () =>
  createRoleMiddleware({
    roles: ['enterprise', 'admin', 'superadmin'],
    hierarchyLevel: 80,
    logAccess: true
  });

/**
 * Role-based middleware factory
 * 
 * Usage:
 * const moderatorAccess = requireRole(['moderator', 'admin']);
 * app.use('/api/moderation', requireAuth(), moderatorAccess);
 */
export const requireRole = (roles: string | string[], config?: Partial<RoleMiddlewareConfig>) =>
  createRoleMiddleware({ roles, ...config });

/**
 * Firebase Functions callable auth validators
 * 
 * These replace the scattered "if (!request.auth)" patterns in 50+ functions
 */

/**
 * Basic Firebase Functions auth validator
 * 
 * Usage in Firebase Function:
 * export const myFunction = onCall(async (request) => {
 *   const user = await validateAuth(request);
 *   // ... function logic
 * });
 * 
 * Replaces patterns like:
 * ```
 * if (!request.auth) {
 *   throw new HttpsError('unauthenticated', 'User must be authenticated');
 * }
 * ```
 */
export const validateAuth = createCallableAuth();

/**
 * Firebase Functions auth with email verification
 */
export const validateAuthWithEmail = createCallableAuth({
  requireEmailVerification: true
});

/**
 * Firebase Functions admin validator
 * 
 * Usage:
 * const user = await validateAdmin(request);
 */
export const validateAdmin = createCallableAdmin();

/**
 * Firebase Functions premium validator
 * 
 * Usage:
 * const user = await validatePremium(request);
 * const user = await validatePremiumFeature(request, 'advanced_analytics');
 */
export const validatePremium = createCallablePremium();
export const validatePremiumFeature = (feature: string) => createCallablePremium(feature);

/**
 * Firebase Functions role validator
 * 
 * Usage:
 * const user = await validateRole(request, ['moderator', 'admin']);
 */
export const validateRole = (roles: string | string[]) => createCallableRole(roles);

/**
 * Composite middleware for complex auth requirements
 * 
 * Usage:
 * const premiumAdminAccess = createComposite([
 *   requireAuth(),
 *   requirePremium(),
 *   requireAdmin()
 * ]);
 * app.use('/api/premium-admin', premiumAdminAccess);
 */
export const createComposite = (middlewares: Array<(req: AuthenticatedExpressRequest, res: Response, next: NextFunction) => void>) =>
  middlewareFactory.createCompositeMiddleware(middlewares);

/**
 * Enhanced error handling middleware
 * 
 * Place this after your routes to catch auth errors
 */
export const authErrorHandler = (error: any, req: AuthenticatedExpressRequest, res: Response, next: NextFunction): void => {
  if (error instanceof HttpsError) {
    const statusCode = error.code === 'unauthenticated' ? 401 : 
                      error.code === 'permission-denied' ? 403 : 500;
    
    logger.error('Auth error handled', {
      code: error.code,
      message: error.message,
      path: req.path,
      uid: req.user?.uid,
      timestamp: new Date().toISOString()
    });
    
    res.status(statusCode).json({
      error: error.message,
      code: error.code.toUpperCase().replace('-', '_')
    });
    return;
  }
  
  next(error);
};

/**
 * Logging middleware for auth events
 */
export const authLogger = (req: AuthenticatedExpressRequest, res: Response, next: NextFunction) => {
  logger.info('Auth request', {
    path: req.path,
    method: req.method,
    uid: req.user?.uid,
    hasAuth: !!req.user,
    timestamp: new Date().toISOString()
  });
  next();
};

// Default exports for backwards compatibility
export default {
  requireAuth,
  requireEmailVerification,
  requireAdmin,
  requirePremium,
  requireEnterprise,
  requireRole,
  validateAuth,
  validateAuthWithEmail,
  validateAdmin,
  validatePremium,
  validatePremiumFeature,
  validateRole,
  createComposite,
  authErrorHandler,
  authLogger
};