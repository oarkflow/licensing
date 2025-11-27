package licensing

import (
	"time"
)

// ==================== Product Management ====================

// Product represents a software product that can be licensed.
type Product struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	LogoURL     string    `json:"logo_url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Plan represents a pricing/feature tier for a product.
type Plan struct {
	ID           string            `json:"id"`
	ProductID    string            `json:"product_id"`
	Name         string            `json:"name"`
	Slug         string            `json:"slug"`
	Description  string            `json:"description,omitempty"`
	Price        int64             `json:"price"`         // Price in cents
	Currency     string            `json:"currency"`      // ISO 4217 currency code (e.g., USD)
	BillingCycle string            `json:"billing_cycle"` // monthly, yearly, lifetime, one-time
	TrialDays    int               `json:"trial_days,omitempty"`
	IsActive     bool              `json:"is_active"`
	DisplayOrder int               `json:"display_order,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// Feature represents a capability or functionality that can be gated by plans.
type Feature struct {
	ID          string    `json:"id"`
	ProductID   string    `json:"product_id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	Category    string    `json:"category,omitempty"` // e.g., "gui", "cli", "api"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FeatureScope defines specific operations/permissions within a feature.
type FeatureScope struct {
	ID         string            `json:"id"`
	FeatureID  string            `json:"feature_id"`
	Name       string            `json:"name"` // e.g., "list", "create", "delete"
	Slug       string            `json:"slug"`
	Permission ScopePermission   `json:"permission"`         // allow, deny, limit
	Limit      int               `json:"limit,omitempty"`    // Used when permission is "limit"
	Metadata   map[string]string `json:"metadata,omitempty"` // Additional config like flags
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// ScopePermission defines the access level for a scope.
type ScopePermission string

const (
	ScopePermissionAllow ScopePermission = "allow"
	ScopePermissionDeny  ScopePermission = "deny"
	ScopePermissionLimit ScopePermission = "limit"
)

// PlanFeature represents the many-to-many relationship between plans and features,
// with optional scope overrides.
type PlanFeature struct {
	ID        string `json:"id"`
	PlanID    string `json:"plan_id"`
	FeatureID string `json:"feature_id"`
	Enabled   bool   `json:"enabled"`
	// ScopeOverrides allows plan-specific permission overrides for feature scopes
	ScopeOverrides map[string]ScopeOverride `json:"scope_overrides,omitempty"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
}

// ScopeOverride allows a plan to override the default scope permission.
type ScopeOverride struct {
	Permission ScopePermission   `json:"permission"`
	Limit      int               `json:"limit,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ==================== License Feature Entitlements ====================

// LicenseEntitlements represents the complete set of features and scopes
// granted to a license holder.
type LicenseEntitlements struct {
	ProductID   string                  `json:"product_id"`
	ProductSlug string                  `json:"product_slug"`
	PlanID      string                  `json:"plan_id"`
	PlanSlug    string                  `json:"plan_slug"`
	Features    map[string]FeatureGrant `json:"features"`
}

// FeatureGrant represents a specific feature granted to a license.
type FeatureGrant struct {
	FeatureID   string                `json:"feature_id"`
	FeatureSlug string                `json:"feature_slug"`
	Category    string                `json:"category,omitempty"`
	Enabled     bool                  `json:"enabled"`
	Scopes      map[string]ScopeGrant `json:"scopes,omitempty"`
}

// ScopeGrant represents a specific scope permission granted to a license.
type ScopeGrant struct {
	ScopeID    string            `json:"scope_id"`
	ScopeSlug  string            `json:"scope_slug"`
	Permission ScopePermission   `json:"permission"`
	Limit      int               `json:"limit,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ==================== Helper Functions ====================

func cloneProduct(p *Product) *Product {
	if p == nil {
		return nil
	}
	clone := *p
	return &clone
}

func clonePlan(p *Plan) *Plan {
	if p == nil {
		return nil
	}
	clone := *p
	if p.Metadata != nil {
		clone.Metadata = make(map[string]string, len(p.Metadata))
		for k, v := range p.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

func cloneFeature(f *Feature) *Feature {
	if f == nil {
		return nil
	}
	clone := *f
	return &clone
}

func cloneFeatureScope(s *FeatureScope) *FeatureScope {
	if s == nil {
		return nil
	}
	clone := *s
	if s.Metadata != nil {
		clone.Metadata = make(map[string]string, len(s.Metadata))
		for k, v := range s.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

func clonePlanFeature(pf *PlanFeature) *PlanFeature {
	if pf == nil {
		return nil
	}
	clone := *pf
	if pf.ScopeOverrides != nil {
		clone.ScopeOverrides = make(map[string]ScopeOverride, len(pf.ScopeOverrides))
		for k, v := range pf.ScopeOverrides {
			override := v
			if v.Metadata != nil {
				override.Metadata = make(map[string]string, len(v.Metadata))
				for mk, mv := range v.Metadata {
					override.Metadata[mk] = mv
				}
			}
			clone.ScopeOverrides[k] = override
		}
	}
	return &clone
}
