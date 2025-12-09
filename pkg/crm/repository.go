package crm

import (
	"context"
	"errors"
)

var (
	ErrTenantExists          = errors.New("crm: tenant already exists")
	ErrTenantMissing         = errors.New("crm: tenant not found")
	ErrUserExists            = errors.New("crm: user already exists")
	ErrUserMissing           = errors.New("crm: user not found")
	ErrContactExists         = errors.New("crm: contact already exists")
	ErrContactMissing        = errors.New("crm: contact not found")
	ErrEntitlementExists     = errors.New("crm: entitlement already exists")
	ErrEntitlementMissing    = errors.New("crm: entitlement not found")
	ErrSecretMissing         = errors.New("crm: credential secret not found")
	ErrSessionMissing        = errors.New("crm: session token not found")
	ErrServiceAccountMissing = errors.New("crm: service account not found")
)

// Repository defines the persistence contract required by the CRM service.
type Repository interface {
	// Tenant operations
	CreateTenant(ctx context.Context, tenant *Tenant) error
	UpdateTenant(ctx context.Context, tenant *Tenant) error
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error)
	ListTenants(ctx context.Context, opts ListTenantsOptions) ([]*Tenant, error)
	SaveTenantSettings(ctx context.Context, settings *TenantSettings) error
	GetTenantSettings(ctx context.Context, tenantID string) (*TenantSettings, error)

	// CRM user operations
	CreateCRMUser(ctx context.Context, user *CRMUser) error
	UpdateCRMUser(ctx context.Context, user *CRMUser) error
	DeleteCRMUser(ctx context.Context, userID string) error
	GetCRMUser(ctx context.Context, userID string) (*CRMUser, error)
	GetCRMUserByEmail(ctx context.Context, tenantID, email string) (*CRMUser, error)
	FindCRMUserByIdentifier(ctx context.Context, identifier string) (*CRMUser, error)
	ListCRMUsers(ctx context.Context, tenantID string) ([]*CRMUser, error)

	// Contacts
	CreateContact(ctx context.Context, contact *Contact) error
	UpdateContact(ctx context.Context, contact *Contact) error
	DeleteContact(ctx context.Context, contactID string) error
	GetContact(ctx context.Context, contactID string) (*Contact, error)
	ListContacts(ctx context.Context, opts ListContactsOptions) ([]*Contact, error)

	// Credential secrets
	SaveCredentialSecret(ctx context.Context, secret *CredentialSecret) error
	GetLatestCredentialSecret(ctx context.Context, tenantID, subjectID string, subjectType SessionSubjectType, secretType CredentialSecretType) (*CredentialSecret, error)
	ListCredentialSecrets(ctx context.Context, tenantID, subjectID string, secretType CredentialSecretType) ([]*CredentialSecret, error)

	// Sessions
	CreateSessionToken(ctx context.Context, token *SessionToken) error
	UpdateSessionToken(ctx context.Context, token *SessionToken) error
	GetSessionToken(ctx context.Context, tokenID string) (*SessionToken, error)
	ListActiveSessionTokens(ctx context.Context, filter SessionTokenFilter) ([]*SessionToken, error)
	RevokeSessionTokens(ctx context.Context, filter SessionTokenFilter) (int, error)

	// Entitlements
	CreateEntitlementBinding(ctx context.Context, binding *EntitlementBinding) error
	UpdateEntitlementBinding(ctx context.Context, binding *EntitlementBinding) error
	GetEntitlementBinding(ctx context.Context, bindingID string) (*EntitlementBinding, error)
	ListEntitlementBindings(ctx context.Context, opts ListEntitlementsOptions) ([]*EntitlementBinding, error)

	// Product releases
	CreateProductRelease(ctx context.Context, release *ProductRelease) error
	UpdateProductRelease(ctx context.Context, release *ProductRelease) error
	DeleteProductRelease(ctx context.Context, releaseID string) error
	GetProductRelease(ctx context.Context, releaseID string) (*ProductRelease, error)
	ListProductReleases(ctx context.Context, productID string, limit int) ([]*ProductRelease, error)

	// Device ledger
	UpsertDeviceLedger(ctx context.Context, record *DeviceLedger) error
	GetDeviceLedgerByFingerprint(ctx context.Context, tenantID, fingerprint string) (*DeviceLedger, error)
	ListDeviceLedgers(ctx context.Context, filter DeviceLedgerFilter) ([]*DeviceLedger, error)

	// Service accounts
	CreateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	UpdateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	DeleteServiceAccount(ctx context.Context, serviceAccountID string) error
	GetServiceAccount(ctx context.Context, serviceAccountID string) (*ServiceAccount, error)
	ListServiceAccounts(ctx context.Context, tenantID string) ([]*ServiceAccount, error)
}

// ListTenantsOptions controls pagination/filtering when listing tenants.
type ListTenantsOptions struct {
	Query    string
	Statuses []TenantStatus
	Limit    int
	Offset   int
}

// ListContactsOptions controls filtering when listing contacts.
type ListContactsOptions struct {
	TenantID string
	ClientID string
	Query    string
	Tags     []string
	Limit    int
	Offset   int
}

// SessionTokenFilter scopes which session tokens are listed or revoked.
type SessionTokenFilter struct {
	TenantID       string
	SubjectID      string
	SubjectType    SessionSubjectType
	IncludeRevoked bool
}

// ListEntitlementsOptions filters entitlement bindings per tenant/product/contact.
type ListEntitlementsOptions struct {
	TenantID  string
	ContactID string
	ProductID string
	Statuses  []EntitlementStatus
}

// DeviceLedgerFilter narrows results for device reconciliation queries.
type DeviceLedgerFilter struct {
	TenantID    string
	ClientID    string
	LicenseID   string
	Fingerprint string
	PendingOnly bool
}
