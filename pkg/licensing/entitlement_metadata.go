package licensing

import (
	"strconv"
	"strings"
	"time"
)

func normalizeFeatureType(value FeatureType) FeatureType {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case "", string(FeatureTypeBoolean):
		return FeatureTypeBoolean
	case string(FeatureTypeMetered):
		return FeatureTypeMetered
	case string(FeatureTypeScoped):
		return FeatureTypeScoped
	default:
		return FeatureTypeBoolean
	}
}

func normalizeScopePermission(value ScopePermission) ScopePermission {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case "", string(ScopePermissionAllow):
		return ScopePermissionAllow
	case string(ScopePermissionDeny):
		return ScopePermissionDeny
	case string(ScopePermissionLimit):
		return ScopePermissionLimit
	default:
		return ScopePermissionAllow
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func mergeStringMaps(base, overlay map[string]string) map[string]string {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	merged := cloneStringMap(base)
	if merged == nil {
		merged = make(map[string]string, len(overlay))
	}
	for k, v := range overlay {
		merged[k] = v
	}
	return merged
}

func parseEntitlementDecorations(metadata map[string]string) (flags map[string]bool, settings map[string]string, limits map[string]int, usage map[string]UsageGrant, restrictions []ScopeRestriction) {
	for rawKey, rawValue := range metadata {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if key == "" {
			continue
		}

		switch {
		case strings.HasPrefix(key, "flag:"):
			name := strings.TrimSpace(strings.TrimPrefix(key, "flag:"))
			if name == "" {
				continue
			}
			if flags == nil {
				flags = map[string]bool{}
			}
			flags[name] = parseBoolDefaultTrue(value)

		case strings.HasPrefix(key, "setting:"):
			name := strings.TrimSpace(strings.TrimPrefix(key, "setting:"))
			if name == "" {
				continue
			}
			if settings == nil {
				settings = map[string]string{}
			}
			settings[name] = value

		case strings.HasPrefix(key, "limit:"):
			name := strings.TrimSpace(strings.TrimPrefix(key, "limit:"))
			if name == "" {
				continue
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			if limits == nil {
				limits = map[string]int{}
			}
			limits[name] = n

		case strings.HasPrefix(key, "usage:"):
			metric, field, ok := splitUsageMetadataKey(key)
			if !ok {
				continue
			}
			if usage == nil {
				usage = map[string]UsageGrant{}
			}
			entry := usage[metric]
			switch field {
			case "limit":
				n, err := strconv.Atoi(value)
				if err != nil {
					continue
				}
				entry.Limit = n
			case "window_seconds":
				n, err := strconv.Atoi(value)
				if err != nil {
					continue
				}
				entry.WindowSeconds = n
			case "current":
				n, err := strconv.Atoi(value)
				if err != nil {
					continue
				}
				entry.Current = n
			case "reset_at":
				if ts, err := parseFlexibleTime(value); err == nil {
					entry.ResetAt = ts
				}
			case "strategy":
				entry.Strategy = value
			default:
				if entry.Metadata == nil {
					entry.Metadata = map[string]string{}
				}
				entry.Metadata[field] = value
			}
			usage[metric] = entry
		}
	}

	if restriction := extractRestriction(metadata); restriction != nil {
		restrictions = append(restrictions, *restriction)
	}
	return flags, settings, limits, usage, restrictions
}

func extractRestriction(metadata map[string]string) *ScopeRestriction {
	if len(metadata) == 0 {
		return nil
	}
	restrictionType := strings.TrimSpace(metadata["restriction_type"])
	if restrictionType == "" {
		return nil
	}
	restriction := &ScopeRestriction{Type: UsageRestrictionType(restrictionType)}
	if v, err := strconv.Atoi(strings.TrimSpace(metadata["restriction_limit"])); err == nil {
		restriction.Limit = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(metadata["restriction_window_seconds"])); err == nil {
		restriction.WindowSeconds = v
	}
	return restriction
}

func splitUsageMetadataKey(key string) (metric, field string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(key, "usage:"), ":")
	if len(parts) != 2 {
		return "", "", false
	}
	metric = strings.TrimSpace(parts[0])
	field = strings.TrimSpace(parts[1])
	return metric, field, metric != "" && field != ""
}

func parseBoolDefaultTrue(value string) bool {
	if value == "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func parseFlexibleTime(value string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, value); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, strconv.ErrSyntax
}

func buildFeatureGrant(feature *Feature) FeatureGrant {
	grant := FeatureGrant{
		FeatureID:   feature.ID,
		FeatureSlug: feature.Slug,
		Type:        normalizeFeatureType(feature.Type),
		Category:    feature.Category,
		Enabled:     true,
		Metadata:    cloneStringMap(feature.Metadata),
		Scopes:      make(map[string]ScopeGrant),
	}
	flags, settings, limits, usage, _ := parseEntitlementDecorations(feature.Metadata)
	grant.Flags = flags
	grant.Settings = settings
	grant.Limits = limits
	grant.Usage = usage
	return grant
}

func buildScopeGrant(scope *FeatureScope, override *ScopeOverride) ScopeGrant {
	metadata := cloneStringMap(scope.Metadata)
	permission := normalizeScopePermission(scope.Permission)
	limit := scope.Limit
	if override != nil {
		permission = normalizeScopePermission(override.Permission)
		limit = override.Limit
		metadata = mergeStringMaps(metadata, override.Metadata)
	}
	scopeGrant := ScopeGrant{
		ScopeID:    scope.ID,
		ScopeSlug:  scope.Slug,
		Permission: permission,
		Limit:      limit,
		Metadata:   metadata,
	}
	flags, settings, limits, usage, restrictions := parseEntitlementDecorations(metadata)
	scopeGrant.Flags = flags
	scopeGrant.Settings = settings
	scopeGrant.Limits = limits
	scopeGrant.Usage = usage
	scopeGrant.Restrictions = restrictions
	return scopeGrant
}
