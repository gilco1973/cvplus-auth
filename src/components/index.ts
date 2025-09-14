/**
 * Auth Module Components
 * 
 * Exports all authentication-related React components.
 * 
 * @author Gil Klainert
 * @version 1.0.0 - CVPlus Auth Module
 */

export { AuthGuard } from './AuthGuard';
export { PermissionGate, AdminOnly, ModeratorOnly, PremiumOnly, FeatureGate } from './PermissionGate';
export { SignInDialog } from './SignInDialog';

// TODO: Add more components as needed
// export { UserMenu } from './UserMenu';
// export { UserProfile } from './UserProfile';
// export { PremiumBadge } from './PremiumBadge';