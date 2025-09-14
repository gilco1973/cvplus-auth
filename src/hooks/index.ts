/**
 * Auth Module Hooks
 * 
 * Exports all authentication-related React hooks.
 * 
 * @author Gil Klainert
 * @version 1.0.0 - CVPlus Auth Module
 */

export { useAuth } from './useAuth';
export { usePermissions } from './usePermissions';
export { usePremium } from './usePremium';
export { useSession } from './useSession';
export { useGoogleAuth } from './useGoogleAuth';

// Re-export the context hook for advanced usage
export { useAuthContext } from '../context/AuthContext';

// Type exports for better developer experience
export type { UseAuthReturn } from './useAuth';
export type { UsePermissionsReturn } from './usePermissions';
export type { UsePremiumReturn } from './usePremium';
export type { UseGoogleAuthReturn } from './useGoogleAuth';