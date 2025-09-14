/**
 * usePremium Hook
 * 
 * Hook for managing premium features and subscription status.
 * 
 * @author Gil Klainert
 * @version 1.0.0 - CVPlus Auth Module
 */

import { useAuthContext } from '../context/AuthContext';
import { PremiumFeatures, SubscriptionPlan, UsageStats } from '../types';

export interface UsePremiumReturn {
  // State
  features: PremiumFeatures | null;
  isLoading: boolean;
  isPremium: boolean;
  plan: SubscriptionPlan | null;
  subscription: any | null; // Could be more specific based on your subscription model

  // Feature checking
  hasFeature: (feature: string) => boolean;
  hasAnyFeature: (features: string[]) => boolean;
  hasAllFeatures: (features: string[]) => boolean;
  
  // Usage tracking
  canUseFeature: (feature: string) => boolean;
  getRemainingUsage: (feature: string) => number | null;
  getUsagePercentage: (feature: string) => number;
  isFeatureLimited: (feature: string) => boolean;

  // Subscription actions
  upgradeToPremium: () => Promise<void>;
  cancelSubscription: () => Promise<void>;
  changeplan: (planId: string) => Promise<void>;
  refreshSubscription: () => Promise<void>;

  // Computed properties
  expiresAt: Date | null;
  daysRemaining: number | null;
  isExpired: boolean;
  isTrialUser: boolean;
  canDowngrade: boolean;
}

/**
 * Premium features management hook
 */
export function usePremium(): UsePremiumReturn {
  const { state, actions } = useAuthContext();

  const features = state.premiumFeatures;
  const isPremium = features?.isActive || false;
  const plan = features?.plan || null;
  const subscription = features?.subscription || null;

  // Feature checking methods
  const hasFeature = (feature: string): boolean => {
    return actions.hasPremiumFeature(feature);
  };

  const hasAnyFeature = (featureList: string[]): boolean => {
    return featureList.some(feature => hasFeature(feature));
  };

  const hasAllFeatures = (featureList: string[]): boolean => {
    return featureList.every(feature => hasFeature(feature));
  };

  // Usage tracking methods
  const canUseFeature = (feature: string): boolean => {
    if (!hasFeature(feature)) {
      return false;
    }

    // Check usage limits
    if (features?.usage && features.limits) {
      const currentUsage = features.usage[feature] || 0;
      const limit = features.limits[feature];
      
      if (limit && currentUsage >= limit) {
        return false;
      }
    }

    return true;
  };

  const getRemainingUsage = (feature: string): number | null => {
    if (!features?.limits || !features?.usage) {
      return null;
    }

    const limit = features.limits[feature];
    const currentUsage = features.usage[feature] || 0;

    if (!limit) {
      return null; // Unlimited
    }

    return Math.max(0, limit - currentUsage);
  };

  const getUsagePercentage = (feature: string): number => {
    if (!features?.limits || !features?.usage) {
      return 0;
    }

    const limit = features.limits[feature];
    const currentUsage = features.usage[feature] || 0;

    if (!limit) {
      return 0; // Unlimited
    }

    return Math.min(100, Math.round((currentUsage / limit) * 100));
  };

  const isFeatureLimited = (feature: string): boolean => {
    return !!(features?.limits && features.limits[feature]);
  };

  // Subscription actions
  const upgradeToPremium = async (): Promise<void> => {
    if (!state.user) {
      throw new Error('User must be authenticated to upgrade to premium');
    }

    // This would typically redirect to payment flow or open payment modal
    // Implementation depends on your payment provider (Stripe, etc.)
    console.log('Upgrading to premium...');
    
    // Placeholder implementation
    throw new Error('Premium upgrade flow not implemented');
  };

  const cancelSubscription = async (): Promise<void> => {
    if (!state.user || !subscription) {
      throw new Error('No active subscription to cancel');
    }

    // Cancel subscription via your payment provider
    console.log('Cancelling subscription...');
    
    // Placeholder implementation
    throw new Error('Subscription cancellation not implemented');
  };

  const changeplan = async (planId: string): Promise<void> => {
    if (!state.user) {
      throw new Error('User must be authenticated to change plan');
    }

    // Change subscription plan
    console.log(`Changing to plan: ${planId}`);
    
    // Placeholder implementation
    throw new Error('Plan change not implemented');
  };

  const refreshSubscription = async (): Promise<void> => {
    if (!state.user) {
      return;
    }

    try {
      // Refresh subscription data from your backend
      await actions.refreshSession();
    } catch (error) {
      console.error('Failed to refresh subscription:', error);
    }
  };

  // Computed properties
  const expiresAt = features?.expiresAt ? new Date(features.expiresAt) : null;
  const daysRemaining = expiresAt ? 
    Math.ceil((expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : null;
  const isExpired = expiresAt ? expiresAt.getTime() < Date.now() : false;
  const isTrialUser = features?.isTrial || false;
  const canDowngrade = isPremium && !isTrialUser && plan !== 'free';

  // Helper methods for common feature checks
  const premiumFeatures = {
    canGenerateUnlimitedCVs: () => hasFeature('unlimited-cv-generation'),
    canUsePremiumTemplates: () => hasFeature('premium-templates'),
    canAccessAdvancedAnalytics: () => hasFeature('advanced-analytics'),
    canBulkProcess: () => hasFeature('bulk-processing'),
    canUseAPIAccess: () => hasFeature('api-access'),
    canRemoveBranding: () => hasFeature('remove-branding'),
    canExportToPDF: () => hasFeature('pdf-export'),
    canScheduleProcessing: () => hasFeature('scheduled-processing')
  };

  return {
    // State
    features,
    isLoading: state.isLoading,
    isPremium,
    plan,
    subscription,

    // Feature checking
    hasFeature,
    hasAnyFeature,
    hasAllFeatures,

    // Usage tracking
    canUseFeature,
    getRemainingUsage,
    getUsagePercentage,
    isFeatureLimited,

    // Subscription actions
    upgradeToPremium,
    cancelSubscription,
    changeplan,
    refreshSubscription,

    // Computed properties
    expiresAt,
    daysRemaining,
    isExpired,
    isTrialUser,
    canDowngrade,

    // Premium feature helpers (spread for easy access)
    ...premiumFeatures
  };
}