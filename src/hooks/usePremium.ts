/**
 * usePremium Hook
 * 
 * Hook for premium feature access and subscription management
 * 
 * @author Gil Klainert
 * @version 1.0.0 - CVPlus Auth Module
 */

import { useAuthContext } from '../context/AuthContext';
import { PremiumFeatures, PremiumTier } from '../types';

export interface UsePremiumReturn {
  isPremium: boolean;
  premiumFeatures: PremiumFeatures | null;
  subscriptionTier: PremiumTier | null;
  hasFeature: (feature: string) => boolean;
  canUseFeature: (feature: string) => boolean;
  getRemainingUsage: (feature: string) => number | null;
  isFeatureEnabled: (feature: string) => boolean;
  upgradeRequired: (feature: string) => boolean;
}

/**
 * Hook for premium feature access and subscription management
 * 
 * @returns Premium state and utilities
 * @throws Error if used outside AuthProvider
 * 
 * @example
 * ```tsx
 * function PremiumFeature() {
 *   const { hasFeature, upgradeRequired } = usePremium();
 *   
 *   if (upgradeRequired('advanced_analytics')) {
 *     return <UpgradePrompt feature="advanced_analytics" />;
 *   }
 *   
 *   return (
 *     <div>
 *       {hasFeature('advanced_analytics') && (
 *         <AdvancedAnalyticsDashboard />
 *       )}
 *     </div>
 *   );
 * }
 * ```
 */
export const usePremium = (): UsePremiumReturn => {
  const { state, actions } = useAuthContext();
  const { premiumFeatures, profile } = state;
  
  const isPremium = !!premiumFeatures;
  
  const subscriptionTier: PremiumTier | null = null; // Note: subscriptionTier not available in current UserProfile
  
  const hasFeature = (feature: string): boolean => {
    return actions.hasPremiumFeature(feature);
  };
  
  const canUseFeature = (feature: string): boolean => {
    if (!premiumFeatures) return false;
    
    const featureAccess = premiumFeatures[feature as keyof PremiumFeatures];
    if (!featureAccess || typeof featureAccess !== 'object') return false;
    
    if (!('enabled' in featureAccess) || !featureAccess.enabled) return false;
    
    if ('remainingUsage' in featureAccess) {
      const usage = featureAccess.remainingUsage;
      return usage !== null && usage !== undefined && typeof usage === 'number' && usage > 0;
    }
    
    return true;
  };
  
  const getRemainingUsage = (feature: string): number | null => {
    if (!premiumFeatures) return null;
    
    const featureAccess = premiumFeatures[feature as keyof PremiumFeatures];
    if (!featureAccess || typeof featureAccess !== 'object') return null;
    
    if ('remainingUsage' in featureAccess) {
      const usage = featureAccess.remainingUsage;
      return usage !== null && usage !== undefined && typeof usage === 'number' ? usage : null;
    }
    
    return null;
  };
  
  const isFeatureEnabled = (feature: string): boolean => {
    if (!premiumFeatures) return false;
    
    const featureAccess = premiumFeatures[feature as keyof PremiumFeatures];
    if (!featureAccess || typeof featureAccess !== 'object') return false;
    
    return 'enabled' in featureAccess && featureAccess.enabled;
  };
  
  const upgradeRequired = (feature: string): boolean => {
    return !hasFeature(feature) && !isPremium;
  };
  
  return {
    isPremium,
    premiumFeatures,
    subscriptionTier,
    hasFeature,
    canUseFeature,
    getRemainingUsage,
    isFeatureEnabled,
    upgradeRequired
  };
};