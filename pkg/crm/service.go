package crm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidCredentials signals authentication failure without revealing details.
	ErrInvalidCredentials = errors.New("crm: invalid credentials")
	// ErrTenantSuspended indicates the tenant is not allowed to login.
	ErrTenantSuspended = errors.New("crm: tenant suspended")
	// ErrTokenExpired indicates an access or refresh token is no longer valid.
	ErrTokenExpired = errors.New("crm: token expired")
	// ErrTokenTypeMismatch indicates a misuse of access vs refresh tokens.
	ErrTokenTypeMismatch = errors.New("crm: token type mismatch")
	// ErrForbiddenScope indicates the caller requested scopes they do not own.
	ErrForbiddenScope = errors.New("crm: insufficient scope")
)

const (
	defaultAccessTTL    = 15 * time.Minute
	defaultRefreshTTL   = 30 * 24 * time.Hour
	defaultPasswordCost = bcrypt.DefaultCost
)

// Service coordinates CRM domain actions across repositories.
type Service struct {
	repo         Repository
	accessTTL    time.Duration
	refreshTTL   time.Duration
	passwordCost int
	now          func() time.Time
}

// Option customizes the CRM service configuration.
type Option func(*Service)

// WithAccessTTL overrides the default access token lifetime.
func WithAccessTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.accessTTL = ttl
		}
	}
}

// WithRefreshTTL overrides the default refresh token lifetime.
func WithRefreshTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.refreshTTL = ttl
		}
	}
}

// WithPasswordCost overrides the bcrypt cost factor.
func WithPasswordCost(cost int) Option {
	return func(s *Service) {
		if cost >= bcrypt.MinCost {
			s.passwordCost = cost
		}
	}
}

// WithNowFunc overrides the clock (useful for tests).
func WithNowFunc(fn func() time.Time) Option {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

// NewService builds a CRM service backed by the provided repository.
func NewService(repo Repository, opts ...Option) (*Service, error) {
	if repo == nil {
		return nil, fmt.Errorf("crm: repository is required")
	}
	svc := &Service{
		repo:         repo,
		accessTTL:    defaultAccessTTL,
		refreshTTL:   defaultRefreshTTL,
		passwordCost: defaultPasswordCost,
		now:          time.Now,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc, nil
}

// TenantProvisionRequest captures data needed to create a tenant and its first admin.
type TenantProvisionRequest struct {
	Name         string
	Slug         string
	Industry     string
	Region       string
	BillingEmail string
	SupportEmail string
	Metadata     map[string]string
	Admin        AdminSeed
}

// AdminSeed describes the bootstrap admin account for a tenant.
type AdminSeed struct {
	Email    string
	Username string
	Password string
	Role     CRMUserRole
}

// LoginRequest carries CRM login credentials from clients.
type LoginRequest struct {
	Identifier string
	Password   string
	Scope      string
	DeviceID   string
}

// LoginResult bundles tokens and subject metadata for CRM clients.
type LoginResult struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	Scope            string
	User             *CRMUser
	Tenant           *Tenant
}

// SessionProfile is returned during token introspection.
type SessionProfile struct {
	User      *CRMUser
	Tenant    *Tenant
	Products  []ProductAccess
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// ProductAccess mirrors the OpenAPI CRMProductAccess schema.
type ProductAccess struct {
	ProductID   string    `json:"product_id"`
	ProductSlug string    `json:"product_slug"`
	PlanID      string    `json:"plan_id"`
	PlanSlug    string    `json:"plan_slug"`
	Features    []string  `json:"features"`
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	EffectiveAt time.Time `json:"effective_at"`
}

// EntitlementAssignmentInput describes entitlement changes requested via API.
type EntitlementAssignmentInput struct {
	TenantID         string
	ContactID        string
	ClientID         string
	ProductID        string
	ProductSlug      string
	PlanID           string
	PlanSlug         string
	EffectiveAt      time.Time
	ExpiresAt        time.Time
	FeatureOverrides map[string]FeatureOverride
}

// ServiceAccountRequestInput carries creation data for service accounts.
type ServiceAccountRequestInput struct {
	TenantID    string
	Name        string
	Description string
	Scopes      []string
	CreatedBy   string
}

// ServiceAccountResult returns the created service account alongside its secret.
type ServiceAccountResult struct {
	Account *ServiceAccount
	Secret  string
}

// ProvisionTenant creates a tenant and bootstrap admin user.
func (s *Service) ProvisionTenant(ctx context.Context, req TenantProvisionRequest) (*Tenant, *CRMUser, error) {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Slug) == "" {
		return nil, nil, fmt.Errorf("tenant name and slug are required")
	}
	if strings.TrimSpace(req.Admin.Email) == "" || strings.TrimSpace(req.Admin.Username) == "" || strings.TrimSpace(req.Admin.Password) == "" {
		return nil, nil, fmt.Errorf("admin email, username, and password are required")
	}
	now := s.now()
	tenant := &Tenant{
		ID:           uuid.NewString(),
		Name:         strings.TrimSpace(req.Name),
		Slug:         strings.ToLower(strings.TrimSpace(req.Slug)),
		Status:       TenantStatusActive,
		Industry:     strings.TrimSpace(req.Industry),
		Region:       strings.TrimSpace(req.Region),
		BillingEmail: strings.TrimSpace(req.BillingEmail),
		SupportEmail: strings.TrimSpace(req.SupportEmail),
		Metadata:     cloneStringMap(req.Metadata),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.repo.CreateTenant(ctx, tenant); err != nil {
		return nil, nil, err
	}
	role := req.Admin.Role
	if role == "" {
		role = CRMUserRoleOwner
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Admin.Password), s.passwordCost)
	if err != nil {
		return nil, nil, err
	}
	user := &CRMUser{
		ID:           uuid.NewString(),
		TenantID:     tenant.ID,
		Email:        strings.TrimSpace(req.Admin.Email),
		Username:     strings.TrimSpace(req.Admin.Username),
		Role:         role,
		Status:       CRMUserStatusActive,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.repo.CreateCRMUser(ctx, user); err != nil {
		return tenant, nil, err
	}
	return tenant, user, nil
}

// Login authenticates a CRM user via identifier (email/username) + password.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || strings.TrimSpace(req.Password) == "" {
		return nil, ErrInvalidCredentials
	}
	user, err := s.repo.FindCRMUserByIdentifier(ctx, identifier)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	if !user.IsEnabled() {
		return nil, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}
	tenant, err := s.repo.GetTenant(ctx, user.TenantID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !tenant.IsActive() {
		return nil, ErrTenantSuspended
	}
	now := s.now()
	user.LastLoginAt = now
	user.UpdatedAt = now
	_ = s.repo.UpdateCRMUser(ctx, user)
	return s.issueTokens(ctx, user, tenant, req.Scope, req.DeviceID)
}

// Refresh exchanges a refresh token for a new access/refresh pair.
func (s *Service) Refresh(ctx context.Context, refreshToken, requestedScope, deviceID string) (*LoginResult, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, ErrInvalidCredentials
	}
	token, err := s.repo.GetSessionToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if token.Metadata == nil || token.Metadata["type"] != "refresh" {
		return nil, ErrTokenTypeMismatch
	}
	if s.isTokenExpired(token) {
		return nil, ErrTokenExpired
	}
	if !token.RevokedAt.IsZero() {
		return nil, ErrTokenExpired
	}
	scope := strings.TrimSpace(requestedScope)
	if scope == "" {
		scope = token.Metadata["scope"]
	}
	user, err := s.repo.GetCRMUser(ctx, token.SubjectID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	tenant, err := s.repo.GetTenant(ctx, token.TenantID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	now := s.now()
	token.RevokedAt = now
	token.RevokedBy = "refresh"
	if token.Metadata == nil {
		token.Metadata = map[string]string{}
	}
	token.Metadata["reason"] = "rotated"
	if err := s.repo.UpdateSessionToken(ctx, token); err != nil {
		return nil, err
	}
	return s.issueTokens(ctx, user, tenant, scope, deviceID)
}

// Logout revokes the provided access token and associated refresh token when available.
func (s *Service) Logout(ctx context.Context, accessTokenID, refreshTokenID string) error {
	if token, err := s.repo.GetSessionToken(ctx, strings.TrimSpace(accessTokenID)); err == nil {
		if token.Metadata != nil && token.Metadata["type"] == "access" {
			token.RevokedAt = s.now()
			token.RevokedBy = "logout"
			if err := s.repo.UpdateSessionToken(ctx, token); err != nil {
				return err
			}
			if refreshTokenID == "" && token.Metadata != nil {
				refreshTokenID = token.Metadata["refresh_id"]
			}
		}
	}
	if refreshTokenID != "" {
		if token, err := s.repo.GetSessionToken(ctx, strings.TrimSpace(refreshTokenID)); err == nil {
			token.RevokedAt = s.now()
			token.RevokedBy = "logout"
			return s.repo.UpdateSessionToken(ctx, token)
		}
	}
	return nil
}

// ValidateAccessToken ensures the bearer token exists, is active, and grants the required scopes.
func (s *Service) ValidateAccessToken(ctx context.Context, tokenID string, requiredScopes []string) (*SessionProfile, error) {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil, ErrInvalidCredentials
	}
	token, err := s.repo.GetSessionToken(ctx, tokenID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if token.Metadata == nil || token.Metadata["type"] != "access" {
		return nil, ErrTokenTypeMismatch
	}
	if s.isTokenExpired(token) || !token.RevokedAt.IsZero() {
		return nil, ErrTokenExpired
	}
	if !scopesContain(token.Scopes, requiredScopes) {
		return nil, ErrForbiddenScope
	}
	user, err := s.repo.GetCRMUser(ctx, token.SubjectID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	tenant, err := s.repo.GetTenant(ctx, token.TenantID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	bindings, _ := s.repo.ListEntitlementBindings(ctx, ListEntitlementsOptions{TenantID: tenant.ID})
	products := make([]ProductAccess, 0, len(bindings))
	for _, b := range bindings {
		products = append(products, ProductAccess{
			ProductID:   b.ProductID,
			ProductSlug: b.ProductSlug,
			PlanID:      b.PlanID,
			PlanSlug:    b.PlanSlug,
			Status:      string(b.Status),
			Features:    extractFeatureKeys(b.FeatureOverrides),
			ExpiresAt:   b.ExpiresAt,
			EffectiveAt: b.EffectiveAt,
		})
	}
	return &SessionProfile{
		User:      user,
		Tenant:    tenant,
		Products:  products,
		Scope:     strings.Join(token.Scopes, " "),
		IssuedAt:  token.IssuedAt,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// ListTenantProducts returns CRM product access info for the giventenant.
func (s *Service) ListTenantProducts(ctx context.Context, tenantID string) ([]ProductAccess, error) {
	bindings, err := s.repo.ListEntitlementBindings(ctx, ListEntitlementsOptions{TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	result := make([]ProductAccess, 0, len(bindings))
	for _, b := range bindings {
		result = append(result, ProductAccess{
			ProductID:   b.ProductID,
			ProductSlug: b.ProductSlug,
			PlanID:      b.PlanID,
			PlanSlug:    b.PlanSlug,
			Features:    extractFeatureKeys(b.FeatureOverrides),
			Status:      string(b.Status),
			ExpiresAt:   b.ExpiresAt,
			EffectiveAt: b.EffectiveAt,
		})
	}
	return result, nil
}

// AssignEntitlement persists an entitlement binding for a tenant/contact pair.
func (s *Service) AssignEntitlement(ctx context.Context, input EntitlementAssignmentInput) (*EntitlementBinding, error) {
	if strings.TrimSpace(input.TenantID) == "" || strings.TrimSpace(input.ProductID) == "" || strings.TrimSpace(input.PlanID) == "" {
		return nil, fmt.Errorf("tenant_id, product_id, and plan_id are required")
	}
	now := s.now()
	binding := &EntitlementBinding{
		ID:               uuid.NewString(),
		TenantID:         input.TenantID,
		ContactID:        strings.TrimSpace(input.ContactID),
		ClientID:         strings.TrimSpace(input.ClientID),
		ProductID:        input.ProductID,
		ProductSlug:      strings.TrimSpace(input.ProductSlug),
		PlanID:           input.PlanID,
		PlanSlug:         strings.TrimSpace(input.PlanSlug),
		Status:           EntitlementStatusActive,
		FeatureOverrides: cloneFeatureOverrides(input.FeatureOverrides),
		EffectiveAt:      coalesceTime(input.EffectiveAt, now),
		ExpiresAt:        input.ExpiresAt,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.repo.CreateEntitlementBinding(ctx, binding); err != nil {
		return nil, err
	}
	return binding, nil
}

// GetDeviceLedger retrieves a ledger entry by tenant and fingerprint.
func (s *Service) GetDeviceLedger(ctx context.Context, tenantID, fingerprint string) (*DeviceLedger, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(fingerprint) == "" {
		return nil, fmt.Errorf("tenant_id and fingerprint are required")
	}
	return s.repo.GetDeviceLedgerByFingerprint(ctx, tenantID, fingerprint)
}

// CreateServiceAccount provisions a new service account and returns its secret.
func (s *Service) CreateServiceAccount(ctx context.Context, input ServiceAccountRequestInput) (*ServiceAccountResult, error) {
	if strings.TrimSpace(input.TenantID) == "" || strings.TrimSpace(input.Name) == "" {
		return nil, fmt.Errorf("tenant_id and name are required")
	}
	if len(input.Scopes) == 0 {
		return nil, fmt.Errorf("scopes are required")
	}
	now := s.now()
	sa := &ServiceAccount{
		ID:          uuid.NewString(),
		TenantID:    input.TenantID,
		Name:        strings.TrimSpace(input.Name),
		Description: strings.TrimSpace(input.Description),
		Scopes:      cloneStringSlice(input.Scopes),
		CreatedBy:   strings.TrimSpace(input.CreatedBy),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.repo.CreateServiceAccount(ctx, sa); err != nil {
		return nil, err
	}
	secret, err := randomSecret(32)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), s.passwordCost)
	if err != nil {
		return nil, err
	}
	cred := &CredentialSecret{
		ID:        uuid.NewString(),
		TenantID:  sa.TenantID,
		Type:      CredentialSecretAPIKey,
		Version:   1,
		Hash:      hash,
		Metadata:  map[string]string{"service_account_id": sa.ID},
		CreatedAt: now,
	}
	if err := s.repo.SaveCredentialSecret(ctx, cred); err != nil {
		return nil, err
	}
	return &ServiceAccountResult{Account: sa, Secret: secret}, nil
}

func (s *Service) issueTokens(ctx context.Context, user *CRMUser, tenant *Tenant, requestedScope, deviceID string) (*LoginResult, error) {
	allowed := s.scopesForRole(user.Role)
	if len(allowed) == 0 {
		allowed = []string{"crm:read"}
	}
	requested := normalizeScopes(requestedScope)
	if len(requested) == 0 {
		requested = allowed
	}
	if !scopesContain(allowed, requested) {
		return nil, ErrForbiddenScope
	}
	scopeString := strings.Join(requested, " ")
	now := s.now()
	accessID := uuid.NewString()
	refreshID := uuid.NewString()
	accessToken := &SessionToken{
		ID:          accessID,
		TenantID:    tenant.ID,
		SubjectID:   user.ID,
		SubjectType: SessionSubjectUser,
		Audience:    []string{"crm"},
		Scopes:      requested,
		IssuedAt:    now,
		ExpiresAt:   now.Add(s.accessTTL),
		Metadata: map[string]string{
			"type":       "access",
			"scope":      scopeString,
			"refresh_id": refreshID,
		},
	}
	if deviceID != "" {
		accessToken.Metadata["device_id"] = deviceID
	}
	if err := s.repo.CreateSessionToken(ctx, accessToken); err != nil {
		return nil, err
	}
	refreshToken := &SessionToken{
		ID:          refreshID,
		TenantID:    tenant.ID,
		SubjectID:   user.ID,
		SubjectType: SessionSubjectUser,
		Audience:    []string{"crm"},
		Scopes:      requested,
		IssuedAt:    now,
		ExpiresAt:   now.Add(s.refreshTTL),
		Metadata: map[string]string{
			"type":  "refresh",
			"scope": scopeString,
		},
	}
	if deviceID != "" {
		refreshToken.Metadata["device_id"] = deviceID
	}
	if err := s.repo.CreateSessionToken(ctx, refreshToken); err != nil {
		// best-effort revoke access token to avoid leaked sessions
		accessToken.RevokedAt = s.now()
		accessToken.RevokedBy = "cleanup"
		_ = s.repo.UpdateSessionToken(ctx, accessToken)
		return nil, err
	}
	return &LoginResult{
		AccessToken:      accessID,
		RefreshToken:     refreshID,
		AccessExpiresAt:  accessToken.ExpiresAt,
		RefreshExpiresAt: refreshToken.ExpiresAt,
		Scope:            scopeString,
		User:             user,
		Tenant:           tenant,
	}, nil
}

func (s *Service) scopesForRole(role CRMUserRole) []string {
	switch role {
	case CRMUserRoleOwner:
		return []string{"crm:read", "crm:write", "licensing:manage"}
	case CRMUserRoleAdmin:
		return []string{"crm:read", "crm:write"}
	case CRMUserRoleMember:
		return []string{"crm:read"}
	case CRMUserRoleViewer:
		return []string{"crm:read"}
	default:
		return []string{"crm:read"}
	}
}

func (s *Service) isTokenExpired(token *SessionToken) bool {
	if token == nil {
		return true
	}
	return s.now().After(token.ExpiresAt)
}

func scopesContain(have, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, scope := range have {
		set[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}

func normalizeScopes(scopeString string) []string {
	if strings.TrimSpace(scopeString) == "" {
		return nil
	}
	parts := strings.Fields(scopeString)
	unique := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if _, ok := unique[p]; ok {
			continue
		}
		unique[p] = struct{}{}
		result = append(result, p)
	}
	return result
}

func extractFeatureKeys(overrides map[string]FeatureOverride) []string {
	if len(overrides) == 0 {
		return nil
	}
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	return keys
}

func cloneFeatureOverrides(src map[string]FeatureOverride) map[string]FeatureOverride {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]FeatureOverride, len(src))
	for k, v := range src {
		copy := v
		if v.Metadata != nil {
			copy.Metadata = cloneStringMap(v.Metadata)
		}
		if v.Scopes != nil {
			copy.Scopes = make(map[string]ScopeOverride, len(v.Scopes))
			for sk, sv := range v.Scopes {
				so := sv
				if sv.Metadata != nil {
					so.Metadata = cloneStringMap(sv.Metadata)
				}
				copy.Scopes[sk] = so
			}
		}
		dst[k] = copy
	}
	return dst
}

func coalesceTime(value time.Time, fallback time.Time) time.Time {
	if value.IsZero() {
		return fallback
	}
	return value
}

func randomSecret(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
