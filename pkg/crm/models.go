package crm

import "time"

// TenantStatus represents the lifecycle state of a tenant/account.
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusArchived  TenantStatus = "archived"
)

// Tenant models an organization that owns contacts, users, and product entitlements.
type Tenant struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Slug         string            `json:"slug"`
	Status       TenantStatus      `json:"status"`
	Industry     string            `json:"industry,omitempty"`
	Region       string            `json:"region,omitempty"`
	BillingEmail string            `json:"billing_email,omitempty"`
	SupportEmail string            `json:"support_email,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	DeletedAt    time.Time         `json:"deleted_at,omitempty"`
}

// CRMUserRole enumerates supported privilege levels for CRM logins.
type CRMUserRole string

const (
	CRMUserRoleOwner  CRMUserRole = "owner"
	CRMUserRoleAdmin  CRMUserRole = "admin"
	CRMUserRoleMember CRMUserRole = "member"
	CRMUserRoleViewer CRMUserRole = "viewer"
)

// CRMUserStatus tracks invitation and suspension state.
type CRMUserStatus string

const (
	CRMUserStatusActive   CRMUserStatus = "active"
	CRMUserStatusInvited  CRMUserStatus = "invited"
	CRMUserStatusDisabled CRMUserStatus = "disabled"
)

// CRMUser represents a human identity authenticated via CRM login endpoints.
type CRMUser struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id"`
	Email             string            `json:"email"`
	Username          string            `json:"username"`
	Role              CRMUserRole       `json:"role"`
	Status            CRMUserStatus     `json:"status"`
	PasswordHash      []byte            `json:"password_hash,omitempty"`
	MFAEnabled        bool              `json:"mfa_enabled"`
	MFAMethods        []string          `json:"mfa_methods,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
	LastLoginAt       time.Time         `json:"last_login_at,omitempty"`
	PasswordRotatedAt time.Time         `json:"password_rotated_at,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// Contact captures business contacts tied to a tenant (and optional licensing client record).
type Contact struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	ClientID   string            `json:"client_id,omitempty"`
	FirstName  string            `json:"first_name"`
	LastName   string            `json:"last_name"`
	Email      string            `json:"email"`
	Phone      string            `json:"phone,omitempty"`
	Title      string            `json:"title,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// CredentialSecretType categorizes stored secrets for rotation/auditing.
type CredentialSecretType string

const (
	CredentialSecretPassword CredentialSecretType = "password_hash"
	CredentialSecretAPIKey   CredentialSecretType = "api_key"
	CredentialSecretMFAToken CredentialSecretType = "mfa_token"
	CredentialSecretDevice   CredentialSecretType = "device_certificate"
)

// CredentialSecret stores hashed/encrypted secrets for users, contacts, or service accounts.
type CredentialSecret struct {
	ID             string               `json:"id"`
	TenantID       string               `json:"tenant_id"`
	UserID         string               `json:"user_id,omitempty"`
	ContactID      string               `json:"contact_id,omitempty"`
	Type           CredentialSecretType `json:"type"`
	Version        int                  `json:"version"`
	Hash           []byte               `json:"hash,omitempty"`
	EncryptedValue []byte               `json:"encrypted_value,omitempty"`
	Metadata       map[string]string    `json:"metadata,omitempty"`
	ExpiresAt      time.Time            `json:"expires_at,omitempty"`
	RotatedAt      time.Time            `json:"rotated_at,omitempty"`
	CreatedAt      time.Time            `json:"created_at"`
}

// SessionSubjectType differentiates token owners.
type SessionSubjectType string

const (
	SessionSubjectUser           SessionSubjectType = "user"
	SessionSubjectServiceAccount SessionSubjectType = "service_account"
	SessionSubjectDevice         SessionSubjectType = "device"
)

// SessionToken tracks refresh/access token metadata for revocation + auditing.
type SessionToken struct {
	ID                string             `json:"id"`
	TenantID          string             `json:"tenant_id"`
	SubjectID         string             `json:"subject_id"`
	SubjectType       SessionSubjectType `json:"subject_type"`
	Audience          []string           `json:"audience"`
	Scopes            []string           `json:"scopes"`
	IssuedAt          time.Time          `json:"issued_at"`
	ExpiresAt         time.Time          `json:"expires_at"`
	NotBefore         time.Time          `json:"not_before,omitempty"`
	RevokedAt         time.Time          `json:"revoked_at,omitempty"`
	RevokedBy         string             `json:"revoked_by,omitempty"`
	DeviceFingerprint string             `json:"device_fingerprint,omitempty"`
	ClientIP          string             `json:"client_ip,omitempty"`
	Metadata          map[string]string  `json:"metadata,omitempty"`
}

// EntitlementStatus represents the lifecycle of CRM entitlements.
type EntitlementStatus string

const (
	EntitlementStatusPending   EntitlementStatus = "pending"
	EntitlementStatusActive    EntitlementStatus = "active"
	EntitlementStatusSuspended EntitlementStatus = "suspended"
	EntitlementStatusRevoked   EntitlementStatus = "revoked"
)

// FeatureOverride customizes feature/scopes for a tenant/contact beyond the base plan.
type FeatureOverride struct {
	Enabled  *bool                    `json:"enabled,omitempty"`
	Scopes   map[string]ScopeOverride `json:"scopes,omitempty"`
	Metadata map[string]string        `json:"metadata,omitempty"`
}

// ScopeOverride refines a specific scope permission.
type ScopeOverride struct {
	Permission string            `json:"permission"`
	Limit      int               `json:"limit,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// EntitlementBinding links tenants/contacts to specific products/plans.
type EntitlementBinding struct {
	ID               string                     `json:"id"`
	TenantID         string                     `json:"tenant_id"`
	ContactID        string                     `json:"contact_id,omitempty"`
	ClientID         string                     `json:"client_id,omitempty"`
	ProductID        string                     `json:"product_id"`
	ProductSlug      string                     `json:"product_slug,omitempty"`
	PlanID           string                     `json:"plan_id"`
	PlanSlug         string                     `json:"plan_slug"`
	Status           EntitlementStatus          `json:"status"`
	FeatureOverrides map[string]FeatureOverride `json:"feature_overrides,omitempty"`
	EffectiveAt      time.Time                  `json:"effective_at"`
	ExpiresAt        time.Time                  `json:"expires_at,omitempty"`
	RevokedAt        time.Time                  `json:"revoked_at,omitempty"`
	RevocationReason string                     `json:"revocation_reason,omitempty"`
	CreatedAt        time.Time                  `json:"created_at"`
	UpdatedAt        time.Time                  `json:"updated_at"`
}

// ProductRelease tracks release channels and metadata surfaced to CRM/product views.
type ProductRelease struct {
	ID          string            `json:"id"`
	ProductID   string            `json:"product_id"`
	Channel     string            `json:"channel"`
	Version     string            `json:"version"`
	Summary     string            `json:"summary,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	PublishedAt time.Time         `json:"published_at"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// DeviceLedger records offline/online reconciliation data per device.
type DeviceLedger struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id"`
	ClientID          string            `json:"client_id,omitempty"`
	LicenseID         string            `json:"license_id,omitempty"`
	DeviceFingerprint string            `json:"device_fingerprint"`
	LastSeenAt        time.Time         `json:"last_seen_at"`
	LastSyncAt        time.Time         `json:"last_sync_at"`
	PendingRevocation bool              `json:"pending_revocation"`
	RevocationEpoch   int64             `json:"revocation_epoch"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// ServiceAccount is used for automation or partner integrations.
type ServiceAccount struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Scopes      []string  `json:"scopes"`
	CreatedBy   string    `json:"created_by"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TenantSettings aggregates configuration toggles for CRM-facing features.
type TenantSettings struct {
	TenantID       string            `json:"tenant_id"`
	LoginModes     []string          `json:"login_modes,omitempty"`
	AllowedOrigins []string          `json:"allowed_origins,omitempty"`
	PolicyVersion  string            `json:"policy_version,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// IsActive returns true when the tenant is currently active.
func (t Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// IsEnabled returns true when the CRM user may authenticate.
func (u CRMUser) IsEnabled() bool {
	return u.Status == CRMUserStatusActive
}
