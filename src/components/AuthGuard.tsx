/**
 * AuthGuard Component
 * 
 * Protects routes and components by ensuring user is authenticated
 * and has required permissions before rendering children.
 * 
 * @author Gil Klainert
 * @version 1.0.0 - CVPlus Auth Module
 */

import React, { ReactNode } from 'react';
import { useAuth } from '../hooks/useAuth';
import { usePermissions, RoleName } from '../hooks/usePermissions';

export interface AuthGuardProps {
  /** Content to render when user is authenticated and authorized */
  children: ReactNode;
  
  /** Content to render when user is not authenticated */
  fallback?: ReactNode;
  
  /** Content to render when user lacks required permissions */
  unauthorizedFallback?: ReactNode;
  
  /** Content to render while authentication is loading */
  loadingFallback?: ReactNode;
  
  /** Required permissions (user must have ALL listed permissions) */
  requiredPermissions?: string[];
  
  /** Required permissions (user must have ANY of the listed permissions) */
  anyPermissions?: string[];
  
  /** Required role (user must have this role or higher) */
  requiredRole?: RoleName;
  
  /** Required premium features */
  requiredFeatures?: string[];
  
  /** Whether to redirect to sign-in page instead of showing fallback */
  redirectToSignIn?: boolean;
  
  /** Custom validation function */
  customValidation?: (user: any, profile: any) => boolean;
  
  /** Whether to show loading state while checking permissions */
  showLoadingWhileChecking?: boolean;
}

const defaultLoadingFallback = (
  <div className="flex items-center justify-center min-h-[200px]">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
  </div>
);

const defaultUnauthenticatedFallback = (
  <div className="flex flex-col items-center justify-center min-h-[400px] p-6">
    <div className="text-center">
      <svg
        className="mx-auto h-12 w-12 text-gray-400"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
        />
      </svg>
      <h3 className="mt-2 text-sm font-medium text-gray-900">Authentication required</h3>
      <p className="mt-1 text-sm text-gray-500">
        Please sign in to access this content.
      </p>
    </div>
  </div>
);

const defaultUnauthorizedFallback = (
  <div className="flex flex-col items-center justify-center min-h-[400px] p-6">
    <div className="text-center">
      <svg
        className="mx-auto h-12 w-12 text-red-400"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L5.636 5.636"
        />
      </svg>
      <h3 className="mt-2 text-sm font-medium text-gray-900">Access denied</h3>
      <p className="mt-1 text-sm text-gray-500">
        You don't have permission to access this content.
      </p>
    </div>
  </div>
);

export const AuthGuard: React.FC<AuthGuardProps> = ({
  children,
  fallback = defaultUnauthenticatedFallback,
  unauthorizedFallback = defaultUnauthorizedFallback,
  loadingFallback = defaultLoadingFallback,
  requiredPermissions = [],
  anyPermissions = [],
  requiredRole,
  requiredFeatures = [],
  redirectToSignIn = false,
  customValidation,
  showLoadingWhileChecking = true
}) => {
  const { 
    isAuthenticated, 
    isLoading, 
    user, 
    profile, 
    isInitialized 
  } = useAuth();
  
  const { 
    hasAnyPermission, 
    hasAllPermissions, 
    hasRole, 
    checkFeatureAccess 
  } = usePermissions();

  // Show loading state while auth is initializing
  if (!isInitialized || (isLoading && showLoadingWhileChecking)) {
    return <>{loadingFallback}</>;
  }

  // Check authentication
  if (!isAuthenticated || !user) {
    if (redirectToSignIn) {
      // In a real app, you might use react-router or next/router here
      window.location.href = '/auth/signin';
      return null;
    }
    return <>{fallback}</>;
  }

  // Check required role
  if (requiredRole && !hasRole(requiredRole)) {
    return <>{unauthorizedFallback}</>;
  }

  // Check required permissions (ALL must be satisfied)
  if (requiredPermissions.length > 0 && !hasAllPermissions(requiredPermissions)) {
    return <>{unauthorizedFallback}</>;
  }

  // Check any permissions (ANY must be satisfied)
  if (anyPermissions.length > 0 && !hasAnyPermission(anyPermissions)) {
    return <>{unauthorizedFallback}</>;
  }

  // Check required features
  if (requiredFeatures.length > 0) {
    const hasRequiredFeatures = requiredFeatures.every(feature => 
      checkFeatureAccess(feature)
    );
    
    if (!hasRequiredFeatures) {
      return <>{unauthorizedFallback}</>;
    }
  }

  // Custom validation
  if (customValidation && !customValidation(user, profile)) {
    return <>{unauthorizedFallback}</>;
  }

  // All checks passed, render children
  return <>{children}</>;
};