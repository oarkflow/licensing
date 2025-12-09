package licensing

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/crm"
)

const maxCRMPayloadBytes = 128 << 10

// === Request payloads ===

type crmLoginRequestPayload struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	Scope      string `json:"scope,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
}

type crmRefreshRequestPayload struct {
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
}

type crmLogoutRequestPayload struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
}

type crmTenantCreateRequest struct {
	Name         string            `json:"name"`
	Slug         string            `json:"slug"`
	Industry     string            `json:"industry,omitempty"`
	Region       string            `json:"region,omitempty"`
	BillingEmail string            `json:"billing_email,omitempty"`
	SupportEmail string            `json:"support_email,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	AdminUser    struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role,omitempty"`
	} `json:"admin_user"`
}

type crmEntitlementAssignmentPayload struct {
	TenantID         string                         `json:"tenant_id"`
	ContactID        string                         `json:"contact_id,omitempty"`
	ClientID         string                         `json:"client_id,omitempty"`
	ProductID        string                         `json:"product_id"`
	PlanID           string                         `json:"plan_id,omitempty"`
	PlanSlug         string                         `json:"plan_slug,omitempty"`
	EffectiveAt      string                         `json:"effective_at,omitempty"`
	ExpiresAt        string                         `json:"expires_at,omitempty"`
	Notes            string                         `json:"notes,omitempty"`
	FeatureOverrides map[string]crm.FeatureOverride `json:"feature_overrides,omitempty"`
}

type crmServiceAccountRequestPayload struct {
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Scopes      []string `json:"scopes"`
}

// === Response payloads ===

type crmLoginResponsePayload struct {
	AccessToken      string              `json:"access_token"`
	RefreshToken     string              `json:"refresh_token"`
	TokenType        string              `json:"token_type"`
	ExpiresIn        int                 `json:"expires_in"`
	RefreshExpiresIn int                 `json:"refresh_expires_in"`
	Scope            string              `json:"scope"`
	User             *crmUserView        `json:"user"`
	Tenant           *crmTenantView      `json:"tenant"`
	Products         []crm.ProductAccess `json:"products,omitempty"`
}

type crmSessionResponsePayload struct {
	User      *crmUserView        `json:"user"`
	Tenant    *crmTenantView      `json:"tenant"`
	Products  []crm.ProductAccess `json:"products,omitempty"`
	Scope     string              `json:"scope"`
	IssuedAt  time.Time           `json:"issued_at"`
	ExpiresAt time.Time           `json:"expires_at"`
}

type crmTenantProductsResponse struct {
	TenantID string              `json:"tenant_id"`
	Products []crm.ProductAccess `json:"products"`
}

type crmEntitlementResponse struct {
	BindingID string `json:"binding_id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}

type crmDeviceLedgerResponse struct {
	TenantID          string            `json:"tenant_id"`
	ClientID          string            `json:"client_id,omitempty"`
	LicenseID         string            `json:"license_id,omitempty"`
	Fingerprint       string            `json:"device_fingerprint"`
	LastSeenAt        time.Time         `json:"last_seen_at"`
	LastSyncAt        time.Time         `json:"last_sync_at"`
	PendingRevocation bool              `json:"pending_revocation"`
	RevocationEpoch   int64             `json:"revocation_epoch"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

type crmServiceAccountResponse struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id"`
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
	Secret   string   `json:"secret"`
}

type crmOfflineBundleResponse struct {
	LicenseID       string    `json:"license_id"`
	Version         string    `json:"version"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	RevocationEpoch int64     `json:"revocation_epoch"`
	Bundle          string    `json:"bundle"`
	Signature       string    `json:"signature"`
}

type crmUserView struct {
	ID          string            `json:"id"`
	Email       string            `json:"email"`
	Username    string            `json:"username"`
	Role        crm.CRMUserRole   `json:"role"`
	Roles       []string          `json:"roles"`
	Status      crm.CRMUserStatus `json:"status"`
	LastLoginAt *time.Time        `json:"last_login_at,omitempty"`
}

type crmTenantView struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Slug         string            `json:"slug"`
	Status       crm.TenantStatus  `json:"status"`
	Industry     string            `json:"industry,omitempty"`
	Region       string            `json:"region,omitempty"`
	BillingEmail string            `json:"billing_email,omitempty"`
	SupportEmail string            `json:"support_email,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// === Handlers ===

func (s *Server) handleCRMLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}
	if s.crmService == nil {
		s.respondError(w, http.StatusServiceUnavailable, "CRM service unavailable")
		return
	}
	var payload crmLoginRequestPayload
	if !s.decodeJSONBody(w, r, &payload, maxCRMPayloadBytes) {
		return
	}
	identifier := strings.TrimSpace(payload.Identifier)
	password := strings.TrimSpace(payload.Password)
	if identifier == "" || password == "" {
		s.respondError(w, http.StatusBadRequest, "identifier and password are required")
		return
	}
	result, err := s.crmService.Login(r.Context(), crm.LoginRequest{
		Identifier: identifier,
		Password:   password,
		Scope:      strings.TrimSpace(payload.Scope),
		DeviceID:   strings.TrimSpace(payload.DeviceID),
	})
	if err != nil {
		s.writeCRMError(w, err)
		return
	}
	products, err := s.crmService.ListTenantProducts(r.Context(), result.Tenant.ID)
	if err != nil {
		log.Printf("crm: failed to load tenant products: %v", err)
	}
	response := buildCRMLoginResponse(result, products)
	s.respondJSON(w, http.StatusOK, response)
}

func (s *Server) handleCRMTokenRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}
	if s.crmService == nil {
		s.respondError(w, http.StatusServiceUnavailable, "CRM service unavailable")
		return
	}
	var payload crmRefreshRequestPayload
	if !s.decodeJSONBody(w, r, &payload, maxCRMPayloadBytes) {
		return
	}
	refresh := strings.TrimSpace(payload.RefreshToken)
	if refresh == "" {
		s.respondError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}
	result, err := s.crmService.Refresh(r.Context(), refresh, strings.TrimSpace(payload.Scope), strings.TrimSpace(payload.DeviceID))
	if err != nil {
		s.writeCRMError(w, err)
		return
	}
	products, err := s.crmService.ListTenantProducts(r.Context(), result.Tenant.ID)
	if err != nil {
		log.Printf("crm: failed to load tenant products during refresh: %v", err)
	}
	response := buildCRMLoginResponse(result, products)
	s.respondJSON(w, http.StatusOK, response)
}

func (s *Server) handleCRMLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}
	_, token, ok := s.authorizeCRMRequest(w, r)
	if !ok {
		return
	}
	var payload crmLogoutRequestPayload
	if hasRequestBody(r) {
		data, err := readLimitedBody(w, r, maxCRMPayloadBytes)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &payload); err != nil {
				s.respondError(w, http.StatusBadRequest, "Invalid request body")
				return
			}
		}
	}
	if err := s.crmService.Logout(r.Context(), token, strings.TrimSpace(payload.RefreshToken)); err != nil {
		s.writeCRMError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCRMSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	profile, _, ok := s.authorizeCRMRequest(w, r, "crm:read")
	if !ok {
		return
	}
	s.respondJSON(w, http.StatusOK, crmSessionResponsePayload{
		User:      toCRMUserView(profile.User),
		Tenant:    toCRMTenantView(profile.Tenant),
		Products:  profile.Products,
		Scope:     profile.Scope,
		IssuedAt:  profile.IssuedAt,
		ExpiresAt: profile.ExpiresAt,
	})
}

func (s *Server) handleCRMTenants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}
	if _, _, ok := s.authorizeCRMRequest(w, r, "crm:write"); !ok {
		return
	}
	var payload crmTenantCreateRequest
	if !s.decodeJSONBody(w, r, &payload, maxCRMPayloadBytes) {
		return
	}
	tenant, _, err := s.crmService.ProvisionTenant(r.Context(), crm.TenantProvisionRequest{
		Name:         strings.TrimSpace(payload.Name),
		Slug:         strings.TrimSpace(payload.Slug),
		Industry:     strings.TrimSpace(payload.Industry),
		Region:       strings.TrimSpace(payload.Region),
		BillingEmail: strings.TrimSpace(payload.BillingEmail),
		SupportEmail: strings.TrimSpace(payload.SupportEmail),
		Metadata:     payload.Metadata,
		Admin: crm.AdminSeed{
			Email:    strings.TrimSpace(payload.AdminUser.Email),
			Username: strings.TrimSpace(payload.AdminUser.Username),
			Password: strings.TrimSpace(payload.AdminUser.Password),
			Role:     crm.CRMUserRole(strings.TrimSpace(payload.AdminUser.Role)),
		},
	})
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.respondJSON(w, http.StatusCreated, toCRMTenantView(tenant))
}

func (s *Server) handleCRMTenantProducts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	profile, _, ok := s.authorizeCRMRequest(w, r, "crm:read")
	if !ok {
		return
	}
	tenantID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/crm/tenants/"), "/")
	parts := strings.SplitN(tenantID, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	if len(parts) < 2 || parts[1] != "products" {
		http.NotFound(w, r)
		return
	}
	requestedTenant := parts[0]
	if requestedTenant == "" {
		requestedTenant = profile.Tenant.ID
	}
	if requestedTenant != profile.Tenant.ID {
		s.respondError(w, http.StatusForbidden, "Cross-tenant access is not permitted")
		return
	}
	products, err := s.crmService.ListTenantProducts(r.Context(), requestedTenant)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "Failed to load tenant products")
		return
	}
	s.respondJSON(w, http.StatusOK, crmTenantProductsResponse{TenantID: requestedTenant, Products: products})
}

func (s *Server) handleCRMEntitlements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	profile, _, ok := s.authorizeCRMRequest(w, r, "crm:write")
	if !ok {
		return
	}
	var payload crmEntitlementAssignmentPayload
	if !s.decodeJSONBody(w, r, &payload, maxCRMPayloadBytes) {
		return
	}
	tenantID := strings.TrimSpace(payload.TenantID)
	if tenantID == "" {
		tenantID = profile.Tenant.ID
	}
	if tenantID != profile.Tenant.ID {
		s.respondError(w, http.StatusForbidden, "Cross-tenant assignment is not permitted")
		return
	}
	effectiveAt, err := parseOptionalTime(payload.EffectiveAt)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid effective_at timestamp")
		return
	}
	expiresAt, err := parseOptionalTime(payload.ExpiresAt)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid expires_at timestamp")
		return
	}
	binding, err := s.crmService.AssignEntitlement(r.Context(), crm.EntitlementAssignmentInput{
		TenantID:         tenantID,
		ContactID:        strings.TrimSpace(payload.ContactID),
		ClientID:         strings.TrimSpace(payload.ClientID),
		ProductID:        strings.TrimSpace(payload.ProductID),
		PlanID:           strings.TrimSpace(payload.PlanID),
		PlanSlug:         strings.TrimSpace(payload.PlanSlug),
		EffectiveAt:      effectiveAt,
		ExpiresAt:        expiresAt,
		FeatureOverrides: payload.FeatureOverrides,
	})
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.respondJSON(w, http.StatusAccepted, crmEntitlementResponse{
		BindingID: binding.ID,
		Status:    string(binding.Status),
		Message:   "Entitlement recorded",
	})
}

func (s *Server) handleCRMDeviceLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	profile, _, ok := s.authorizeCRMRequest(w, r, "crm:read")
	if !ok {
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, "/api/crm/devices/")
	fingerprint := strings.Trim(tail, "/")
	if fingerprint == "" {
		http.NotFound(w, r)
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = profile.Tenant.ID
	}
	if tenantID != profile.Tenant.ID {
		s.respondError(w, http.StatusForbidden, "Cross-tenant access is not permitted")
		return
	}
	record, err := s.crmService.GetDeviceLedger(r.Context(), tenantID, fingerprint)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "Device ledger not found")
		return
	}
	s.respondJSON(w, http.StatusOK, crmDeviceLedgerResponse{
		TenantID:          record.TenantID,
		ClientID:          record.ClientID,
		LicenseID:         record.LicenseID,
		Fingerprint:       record.DeviceFingerprint,
		LastSeenAt:        record.LastSeenAt,
		LastSyncAt:        record.LastSyncAt,
		PendingRevocation: record.PendingRevocation,
		RevocationEpoch:   record.RevocationEpoch,
		Metadata:          record.Metadata,
	})
}

func (s *Server) handleCRMServiceAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	profile, _, ok := s.authorizeCRMRequest(w, r, "crm:write")
	if !ok {
		return
	}
	var payload crmServiceAccountRequestPayload
	if !s.decodeJSONBody(w, r, &payload, maxCRMPayloadBytes) {
		return
	}
	tenantID := strings.TrimSpace(payload.TenantID)
	if tenantID == "" {
		tenantID = profile.Tenant.ID
	}
	if tenantID != profile.Tenant.ID {
		s.respondError(w, http.StatusForbidden, "Cross-tenant access is not permitted")
		return
	}
	result, err := s.crmService.CreateServiceAccount(r.Context(), crm.ServiceAccountRequestInput{
		TenantID:    tenantID,
		Name:        strings.TrimSpace(payload.Name),
		Description: strings.TrimSpace(payload.Description),
		Scopes:      payload.Scopes,
		CreatedBy:   profile.User.ID,
	})
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.respondJSON(w, http.StatusCreated, crmServiceAccountResponse{
		ID:       result.Account.ID,
		TenantID: result.Account.TenantID,
		Name:     result.Account.Name,
		Scopes:   result.Account.Scopes,
		Secret:   result.Secret,
	})
}

func (s *Server) handleOfflineBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}
	if _, _, ok := s.authorizeCRMRequest(w, r, "licensing:manage"); !ok {
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, "/api/licensing/offline/bundles")
	licenseID := strings.Trim(tail, "/")
	if licenseID == "" {
		http.NotFound(w, r)
		return
	}
	license, err := s.lm.storage.GetLicense(r.Context(), licenseID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "License not found")
		return
	}
	if err := s.lm.ensureLicenseEntitlements(r.Context(), license); err != nil {
		log.Printf("offline bundle: failed to compute entitlements: %v", err)
	}
	payload := s.lm.buildLicensePayload(license, nil)
	envelope := map[string]interface{}{
		"license":          payload,
		"generated_at":     time.Now().UTC(),
		"revocation_epoch": license.LastActivatedAt.Unix(),
	}
	bundleBytes, err := json.Marshal(envelope)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to serialize bundle")
		return
	}
	digest := sha256.Sum256(bundleBytes)
	signature, err := s.lm.signer.Sign(digest[:])
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to sign bundle")
		return
	}
	response := crmOfflineBundleResponse{
		LicenseID:       license.ID,
		Version:         "v1",
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       license.ExpiresAt,
		RevocationEpoch: envelope["revocation_epoch"].(int64),
		Bundle:          base64.StdEncoding.EncodeToString(bundleBytes),
		Signature:       base64.StdEncoding.EncodeToString(signature),
	}
	s.respondJSON(w, http.StatusOK, response)
}

// === Helpers ===

func buildCRMLoginResponse(result *crm.LoginResult, products []crm.ProductAccess) crmLoginResponsePayload {
	return crmLoginResponsePayload{
		AccessToken:      result.AccessToken,
		RefreshToken:     result.RefreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        secondsUntil(result.AccessExpiresAt),
		RefreshExpiresIn: secondsUntil(result.RefreshExpiresAt),
		Scope:            result.Scope,
		User:             toCRMUserView(result.User),
		Tenant:           toCRMTenantView(result.Tenant),
		Products:         products,
	}
}

func secondsUntil(ts time.Time) int {
	if ts.IsZero() {
		return 0
	}
	delta := time.Until(ts).Seconds()
	if delta < 0 {
		return 0
	}
	return int(delta)
}

func toCRMUserView(user *crm.CRMUser) *crmUserView {
	if user == nil {
		return nil
	}
	view := &crmUserView{
		ID:       user.ID,
		Email:    user.Email,
		Username: user.Username,
		Role:     user.Role,
		Roles:    []string{string(user.Role)},
		Status:   user.Status,
	}
	if !user.LastLoginAt.IsZero() {
		view.LastLoginAt = &user.LastLoginAt
	}
	return view
}

func toCRMTenantView(tenant *crm.Tenant) *crmTenantView {
	if tenant == nil {
		return nil
	}
	meta := tenant.Metadata
	if len(meta) == 0 {
		meta = nil
	}
	return &crmTenantView{
		ID:           tenant.ID,
		Name:         tenant.Name,
		Slug:         tenant.Slug,
		Status:       tenant.Status,
		Industry:     tenant.Industry,
		Region:       tenant.Region,
		BillingEmail: tenant.BillingEmail,
		SupportEmail: tenant.SupportEmail,
		Metadata:     meta,
		CreatedAt:    tenant.CreatedAt,
		UpdatedAt:    tenant.UpdatedAt,
	}
}

func (s *Server) authorizeCRMRequest(w http.ResponseWriter, r *http.Request, scopes ...string) (*crm.SessionProfile, string, bool) {
	if s.crmService == nil {
		s.respondError(w, http.StatusServiceUnavailable, "CRM service unavailable")
		return nil, "", false
	}
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.respondError(w, http.StatusUnauthorized, "Missing bearer token")
		return nil, "", false
	}
	profile, err := s.crmService.ValidateAccessToken(r.Context(), token, scopes)
	if err != nil {
		s.writeCRMError(w, err)
		return nil, "", false
	}
	return profile, token, true
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (s *Server) writeCRMError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, crm.ErrInvalidCredentials):
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		s.respondError(w, http.StatusUnauthorized, "Invalid credentials")
	case errors.Is(err, crm.ErrTenantSuspended):
		s.respondError(w, http.StatusLocked, "Tenant suspended")
	case errors.Is(err, crm.ErrTokenExpired):
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"token expired\"")
		s.respondError(w, http.StatusUnauthorized, "Token expired")
	case errors.Is(err, crm.ErrTokenTypeMismatch):
		s.respondError(w, http.StatusBadRequest, "Token type mismatch")
	case errors.Is(err, crm.ErrForbiddenScope):
		s.respondError(w, http.StatusForbidden, "Insufficient scope")
	default:
		s.respondError(w, http.StatusBadRequest, err.Error())
	}
}

func parseOptionalTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return ts, nil
}

func hasRequestBody(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	if r.ContentLength == 0 {
		return false
	}
	return true
}

func readLimitedBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	reader := http.MaxBytesReader(w, r.Body, limit)
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return data, nil
}
