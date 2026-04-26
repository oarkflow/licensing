package licensing

import "strings"

func applyCouponPatches(entitlements *LicenseEntitlements, coupons []*CouponCode) {
	if entitlements == nil || len(coupons) == 0 {
		return
	}
	for _, coupon := range coupons {
		if coupon == nil {
			continue
		}
		for _, featurePatch := range coupon.Features {
			featureKey, featureGrant, ok := findCouponFeatureGrant(entitlements, featurePatch)
			if !ok {
				continue
			}
			if featurePatch.Enabled != nil {
				featureGrant.Enabled = *featurePatch.Enabled
			}
			if len(featurePatch.Metadata) > 0 {
				featureGrant.Metadata = mergeStringMaps(featureGrant.Metadata, featurePatch.Metadata)
				flags, settings, limits, usage, _ := parseEntitlementDecorations(featureGrant.Metadata)
				featureGrant.Flags = mergeBoolMaps(featureGrant.Flags, flags)
				featureGrant.Settings = mergeStringMaps(featureGrant.Settings, settings)
				featureGrant.Limits = mergeIntMaps(featureGrant.Limits, limits)
				featureGrant.Usage = mergeUsageGrants(featureGrant.Usage, usage)
			}
			for _, scopePatch := range featurePatch.Scopes {
				scopeKey, scopeGrant, exists := findCouponScopeGrant(featureGrant, scopePatch)
				if !exists {
					continue
				}
				if strings.TrimSpace(string(scopePatch.Permission)) != "" {
					scopeGrant.Permission = normalizeScopePermission(scopePatch.Permission)
				}
				if scopePatch.Limit != nil {
					scopeGrant.Limit = *scopePatch.Limit
				}
				if len(scopePatch.Metadata) > 0 {
					scopeGrant.Metadata = mergeStringMaps(scopeGrant.Metadata, scopePatch.Metadata)
					flags, settings, limits, usage, restrictions := parseEntitlementDecorations(scopeGrant.Metadata)
					scopeGrant.Flags = mergeBoolMaps(scopeGrant.Flags, flags)
					scopeGrant.Settings = mergeStringMaps(scopeGrant.Settings, settings)
					scopeGrant.Limits = mergeIntMaps(scopeGrant.Limits, limits)
					scopeGrant.Usage = mergeUsageGrants(scopeGrant.Usage, usage)
					if len(restrictions) > 0 {
						scopeGrant.Restrictions = restrictions
					}
				}
				featureGrant.Scopes[scopeKey] = scopeGrant
			}
			entitlements.Features[featureKey] = featureGrant
		}
	}
}

func findCouponFeatureGrant(entitlements *LicenseEntitlements, patch CouponFeaturePatch) (string, FeatureGrant, bool) {
	if slug := strings.TrimSpace(patch.FeatureSlug); slug != "" {
		grant, ok := entitlements.Features[slug]
		return slug, grant, ok
	}
	if id := strings.TrimSpace(patch.FeatureID); id != "" {
		for slug, grant := range entitlements.Features {
			if grant.FeatureID == id {
				return slug, grant, true
			}
		}
	}
	return "", FeatureGrant{}, false
}

func findCouponScopeGrant(featureGrant FeatureGrant, patch CouponScopePatch) (string, ScopeGrant, bool) {
	if slug := strings.TrimSpace(patch.ScopeSlug); slug != "" {
		scope, ok := featureGrant.Scopes[slug]
		return slug, scope, ok
	}
	if id := strings.TrimSpace(patch.ScopeID); id != "" {
		for slug, scope := range featureGrant.Scopes {
			if scope.ScopeID == id {
				return slug, scope, true
			}
		}
	}
	return "", ScopeGrant{}, false
}

func mergeBoolMaps(base, overlay map[string]bool) map[string]bool {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	result := map[string]bool{}
	for k, v := range base {
		result[k] = v
	}
	for k, v := range overlay {
		result[k] = v
	}
	return result
}

func mergeIntMaps(base, overlay map[string]int) map[string]int {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	result := map[string]int{}
	for k, v := range base {
		result[k] = v
	}
	for k, v := range overlay {
		result[k] = v
	}
	return result
}

func mergeUsageGrants(base, overlay map[string]UsageGrant) map[string]UsageGrant {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	result := map[string]UsageGrant{}
	for k, v := range base {
		result[k] = v
	}
	for k, v := range overlay {
		result[k] = v
	}
	return result
}
