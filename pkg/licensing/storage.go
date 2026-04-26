package licensing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	email "github.com/oarkflow/licensing/pkg/email"
)

type Storage interface {
	SaveClient(ctx context.Context, client *Client) error
	UpdateClient(ctx context.Context, client *Client) error
	GetClient(ctx context.Context, clientID string) (*Client, error)
	GetClientByEmail(ctx context.Context, email string) (*Client, error)
	GetClientByUsername(ctx context.Context, username string) (*Client, error)
	ListClients(ctx context.Context) ([]*Client, error)
	SaveLicense(ctx context.Context, license *License) error
	UpdateLicense(ctx context.Context, license *License) error
	GetLicense(ctx context.Context, licenseID string) (*License, error)
	GetLicenseByKey(ctx context.Context, licenseKey string) (*License, error)
	ListLicenses(ctx context.Context) ([]*License, error)
	RecordActivation(ctx context.Context, record *ActivationRecord) error
	ListActivations(ctx context.Context, licenseID string) ([]*ActivationRecord, error)
	CreateAdminUser(ctx context.Context, user *AdminUser) error
	UpdateAdminUser(ctx context.Context, user *AdminUser) error
	DeleteAdminUser(ctx context.Context, userID string) error
	GetAdminUser(ctx context.Context, userID string) (*AdminUser, error)
	GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error)
	ListAdminUsers(ctx context.Context) ([]*AdminUser, error)
	SaveAPIKey(ctx context.Context, key *APIKeyRecord) error
	UpdateAPIKey(ctx context.Context, key *APIKeyRecord) error
	DeleteAPIKey(ctx context.Context, keyID string) error
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error)
	ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKeyRecord, error)
	ListAPIKeysByClient(ctx context.Context, clientID string) ([]*APIKeyRecord, error)

	// Product management
	SaveProduct(ctx context.Context, product *Product) error
	UpdateProduct(ctx context.Context, product *Product) error
	GetProduct(ctx context.Context, productID string) (*Product, error)
	GetProductBySlug(ctx context.Context, slug string) (*Product, error)
	ListProducts(ctx context.Context) ([]*Product, error)
	DeleteProduct(ctx context.Context, productID string) error

	// Plan management
	SavePlan(ctx context.Context, plan *Plan) error
	UpdatePlan(ctx context.Context, plan *Plan) error
	GetPlan(ctx context.Context, planID string) (*Plan, error)
	GetPlanBySlug(ctx context.Context, productID, slug string) (*Plan, error)
	FindPlanBySlug(ctx context.Context, slug string) (*Plan, error) // Search across all products
	ListPlansByProduct(ctx context.Context, productID string) ([]*Plan, error)
	GetTrialPlanForProduct(ctx context.Context, productID string) (*Plan, error) // Get the trial plan for a product (only one allowed)
	DeletePlan(ctx context.Context, planID string) error

	// Feature management
	SaveFeature(ctx context.Context, feature *Feature) error
	UpdateFeature(ctx context.Context, feature *Feature) error
	GetFeature(ctx context.Context, featureID string) (*Feature, error)
	GetFeatureBySlug(ctx context.Context, productID, slug string) (*Feature, error)
	ListFeaturesByProduct(ctx context.Context, productID string) ([]*Feature, error)
	DeleteFeature(ctx context.Context, featureID string) error

	// Feature scope management
	SaveFeatureScope(ctx context.Context, scope *FeatureScope) error
	UpdateFeatureScope(ctx context.Context, scope *FeatureScope) error
	GetFeatureScope(ctx context.Context, scopeID string) (*FeatureScope, error)
	ListFeatureScopes(ctx context.Context, featureID string) ([]*FeatureScope, error)
	DeleteFeatureScope(ctx context.Context, scopeID string) error

	// Plan-Feature relationship management
	SavePlanFeature(ctx context.Context, pf *PlanFeature) error
	UpdatePlanFeature(ctx context.Context, pf *PlanFeature) error
	GetPlanFeature(ctx context.Context, planID, featureID string) (*PlanFeature, error)
	ListPlanFeatures(ctx context.Context, planID string) ([]*PlanFeature, error)
	DeletePlanFeature(ctx context.Context, planID, featureID string) error

	// Entitlement computation
	ComputeLicenseEntitlements(ctx context.Context, productID, planID string) (*LicenseEntitlements, error)

	// Coupon management
	SaveCouponCode(ctx context.Context, coupon *CouponCode) error
	UpdateCouponCode(ctx context.Context, coupon *CouponCode) error
	GetCouponCode(ctx context.Context, couponID string) (*CouponCode, error)
	GetCouponCodeByCode(ctx context.Context, code string) (*CouponCode, error)
	ListCouponCodes(ctx context.Context) ([]*CouponCode, error)
	SaveCouponRedemption(ctx context.Context, redemption *CouponRedemption) error
	ListCouponRedemptionsByCoupon(ctx context.Context, couponID string) ([]*CouponRedemption, error)
	ListCouponRedemptionsByLicense(ctx context.Context, licenseID string) ([]*CouponRedemption, error)
	ListCouponRedemptionsByClient(ctx context.Context, clientID string) ([]*CouponRedemption, error)

	// Trial registry - tracks device fingerprints that have used trial licenses
	SaveDeviceTrial(ctx context.Context, trial *DeviceTrial) error
	GetDeviceTrial(ctx context.Context, deviceFingerprint string) (*DeviceTrial, error)
	HasDeviceUsedTrial(ctx context.Context, deviceFingerprint string) (bool, error)
	ListDeviceTrials(ctx context.Context) ([]*DeviceTrial, error)

	// Offline validation token management
	SaveOfflineValidationToken(ctx context.Context, token *OfflineValidationToken) error
	GetOfflineValidationToken(ctx context.Context, token string) (*OfflineValidationToken, error)
	UpdateOfflineValidationToken(ctx context.Context, token *OfflineValidationToken) error
	DeleteOfflineValidationToken(ctx context.Context, token string) error
	ListOfflineValidationTokens(ctx context.Context) ([]*OfflineValidationToken, error)
	FindOfflineValidationTokensByLicense(ctx context.Context, licenseKey string) ([]*OfflineValidationToken, error)
	FindOfflineValidationTokensByClient(ctx context.Context, clientID string) ([]*OfflineValidationToken, error)

	// Offline validation log management
	SaveOfflineValidationLog(ctx context.Context, log *OfflineValidationLog) error
	ListOfflineValidationLogs(ctx context.Context, token string) ([]*OfflineValidationLog, error)
	FindOfflineValidationLogsByLicense(ctx context.Context, licenseKey string) ([]*OfflineValidationLog, error)
	FindOfflineValidationLogsByClient(ctx context.Context, clientID string) ([]*OfflineValidationLog, error)

	// Signing keys used to sign offline bundles (asymmetric keys)
	SaveSigningKey(ctx context.Context, key *SigningKey) error
	GetSigningKey(ctx context.Context, keyID string) (*SigningKey, error)
	GetActiveSigningKey(ctx context.Context) (*SigningKey, error)
	ListSigningKeys(ctx context.Context) ([]*SigningKey, error)
	SetActiveSigningKey(ctx context.Context, keyID string) error

	// Subscription management
	SaveSubscription(ctx context.Context, sub *Subscription) error
	UpdateSubscription(ctx context.Context, sub *Subscription) error
	GetSubscription(ctx context.Context, subID string) (*Subscription, error)
	ListSubscriptions(ctx context.Context) ([]*Subscription, error)
	ListSubscriptionsByClient(ctx context.Context, clientID string) ([]*Subscription, error)
	DeleteSubscription(ctx context.Context, subID string) error

	// Email providers/templates/messages
	SaveEmailProvider(ctx context.Context, provider *email.EmailProvider) error
	UpdateEmailProvider(ctx context.Context, provider *email.EmailProvider) error
	ListEmailProviders(ctx context.Context, includeDisabled bool) ([]*email.EmailProvider, error)
	GetEmailProvider(ctx context.Context, providerID string) (*email.EmailProvider, error)
	DeleteEmailProvider(ctx context.Context, providerID string) error

	SaveEmailTemplate(ctx context.Context, tpl *email.EmailTemplate) error
	UpdateEmailTemplate(ctx context.Context, tpl *email.EmailTemplate) error
	ListEmailTemplates(ctx context.Context) ([]*email.EmailTemplate, error)
	GetEmailTemplate(ctx context.Context, templateID string) (*email.EmailTemplate, error)
	GetEmailTemplateBySlug(ctx context.Context, slug string) (*email.EmailTemplate, error)
	DeleteEmailTemplate(ctx context.Context, templateID string) error

	SaveEmailTemplateRoute(ctx context.Context, route *email.EmailTemplateRoute) error
	ListEmailTemplateRoutes(ctx context.Context, templateID, category string) ([]*email.EmailTemplateRoute, error)
	DeleteEmailTemplateRoute(ctx context.Context, routeID string) error

	EnqueueEmail(ctx context.Context, msg *email.EmailMessage) error
	UpdateEmailMessage(ctx context.Context, msg *email.EmailMessage) error
	GetEmailMessage(ctx context.Context, messageID string) (*email.EmailMessage, error)
	LeaseNextEmail(ctx context.Context, dueBefore time.Time) (*email.EmailMessage, error)
	AppendEmailEvent(ctx context.Context, event *email.EmailEvent) error
	ListEmailEvents(ctx context.Context, messageID string) ([]*email.EmailEvent, error)
}

var (
	errClientExists            = errors.New("client already exists")
	errClientMissing           = errors.New("client not found")
	errLicenseExists           = errors.New("license already exists")
	errLicenseMissing          = errors.New("license not found")
	errUserExists              = errors.New("user already exists")
	errUserMissing             = errors.New("user not found")
	errAPIKeyExists            = errors.New("api key already exists")
	errAPIKeyMissing           = errors.New("api key not found")
	errProductExists           = errors.New("product already exists")
	errProductMissing          = errors.New("product not found")
	errPlanExists              = errors.New("plan already exists")
	errPlanMissing             = errors.New("plan not found")
	errFeatureExists           = errors.New("feature already exists")
	errFeatureMissing          = errors.New("feature not found")
	errFeatureScopeExists      = errors.New("feature scope already exists")
	errFeatureScopeMissing     = errors.New("feature scope not found")
	errPlanFeatureExists       = errors.New("plan feature already exists")
	errPlanFeatureMissing      = errors.New("plan feature not found")
	errDeviceTrialExists       = errors.New("device has already used trial")
	errDeviceTrialMissing      = errors.New("device trial not found")
	errEmailProviderExists     = errors.New("email provider already exists")
	errEmailProviderMissing    = errors.New("email provider not found")
	errEmailTemplateExists     = errors.New("email template already exists")
	errEmailTemplateMissing    = errors.New("email template not found")
	errEmailRouteExists        = errors.New("email route already exists")
	errEmailRouteMissing       = errors.New("email route not found")
	errEmailMessageMissing     = errors.New("email message not found")
	errEmailStorageUnsupported = errors.New("email storage is not supported by this backend")
	errOfflineTokenExists      = errors.New("offline validation token already exists")
	errOfflineTokenMissing     = errors.New("offline validation token not found")
	errOfflineLogMissing       = errors.New("offline validation log not found")
	errCouponExists            = errors.New("coupon already exists")
	errCouponMissing           = errors.New("coupon not found")
	errCouponRedemptionExists  = errors.New("coupon redemption already exists")
)

// DeviceTrial tracks devices that have used a trial license.
// This prevents the same device from getting multiple trial licenses.
type DeviceTrial struct {
	DeviceFingerprint string    `json:"device_fingerprint"`
	LicenseID         string    `json:"license_id"`
	ClientID          string    `json:"client_id"`
	Email             string    `json:"email"`
	ProductID         string    `json:"product_id,omitempty"`
	TrialStartedAt    time.Time `json:"trial_started_at"`
	TrialExpiresAt    time.Time `json:"trial_expires_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// OfflineValidationToken represents a token for offline license validation
type OfflineValidationToken struct {
	Token             string    `json:"token"`
	LicenseKey        string    `json:"license_key"`
	ClientID          string    `json:"client_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	SigningKeyID      string    `json:"signing_key_id,omitempty"`
	ValidUntil        time.Time `json:"valid_until"`
	UsageCount        int       `json:"usage_count"`
	MaxUses           int       `json:"max_uses"`
	IsRevoked         bool      `json:"is_revoked"`
	CreatedAt         time.Time `json:"created_at"`
	RevokedAt         time.Time `json:"revoked_at,omitempty"`
	RevokedBy         string    `json:"revoked_by,omitempty"`
	RevokedReason     string    `json:"revoked_reason,omitempty"`
}

// OfflineValidationLog tracks usage of offline validation tokens
type OfflineValidationLog struct {
	ID                string    `json:"id"`
	Token             string    `json:"token"`
	LicenseKey        string    `json:"license_key"`
	ClientID          string    `json:"client_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	ValidationTime    time.Time `json:"validation_time"`
	Success           bool      `json:"success"`
	ErrorMessage      string    `json:"error_message,omitempty"`
	IPAddress         string    `json:"ip_address,omitempty"`
	UserAgent         string    `json:"user_agent,omitempty"`
	AppVersion        string    `json:"app_version,omitempty"`
	Metadata          string    `json:"metadata,omitempty"`
}

// SigningKey represents an offline signing key pair (Ed25519) stored in the server
type SigningKey struct {
	ID         string    `json:"id"`
	Name       string    `json:"name,omitempty"`
	PublicKey  []byte    `json:"public_key"`            // raw public key bytes
	PrivateKey []byte    `json:"private_key,omitempty"` // raw private key bytes (stored only in server storage)
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
}

type AdminUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash []byte    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type APIKeyRecord struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id,omitempty"`
	Hash      string    `json:"hash"`
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used_at,omitempty"`
}

func cloneAdminUser(user *AdminUser) *AdminUser {
	if user == nil {
		return nil
	}
	clone := *user
	if len(user.PasswordHash) > 0 {
		clone.PasswordHash = append([]byte(nil), user.PasswordHash...)
	}
	return &clone
}

func cloneAPIKeyRecord(key *APIKeyRecord) *APIKeyRecord {
	if key == nil {
		return nil
	}
	clone := *key
	return &clone
}

type InMemoryStorage struct {
	mu                sync.RWMutex
	clients           map[string]*Client
	clientsByEmail    map[string]string
	clientsByUsername map[string]string
	licenses          map[string]*License
	licensesByKey     map[string]string
	activations       map[string][]*ActivationRecord
	adminUsers        map[string]*AdminUser
	adminByName       map[string]string
	apiKeys           map[string]*APIKeyRecord
	apiKeysByHash     map[string]string
	apiKeysByUser     map[string]map[string]struct{}
	apiKeysByClient   map[string]map[string]struct{}
	// Product management
	products       map[string]*Product
	productsBySlug map[string]string
	plans          map[string]*Plan
	plansBySlug    map[string]string // key: "productID:slug"
	features       map[string]*Feature
	featuresBySlug map[string]string // key: "productID:slug"
	featureScopes  map[string]*FeatureScope
	planFeatures   map[string]*PlanFeature // key: "planID:featureID"
	// Trial registry
	deviceTrials map[string]*DeviceTrial // key: device fingerprint
	// Offline validation
	offlineValidationTokens map[string]*OfflineValidationToken // key: token
	offlineValidationLogs   map[string][]*OfflineValidationLog // key: token
	// Signing keys
	signingKeys        map[string]*SigningKey
	activeSigningKeyID string
	// Email management
	emailProviders             map[string]*email.EmailProvider
	emailProvidersBySlug       map[string]string
	emailTemplates             map[string]*email.EmailTemplate
	emailTemplatesBySlug       map[string]string
	emailRoutes                map[string]*email.EmailTemplateRoute
	emailMessages              map[string]*email.EmailMessage
	emailEvents                map[string][]*email.EmailEvent
	coupons                    map[string]*CouponCode
	couponsByCode              map[string]string
	couponRedemptions          map[string]*CouponRedemption
	couponRedemptionsByCoupon  map[string][]string
	couponRedemptionsByLicense map[string][]string
	couponRedemptionsByClient  map[string][]string
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		clients:                    make(map[string]*Client),
		clientsByEmail:             make(map[string]string),
		clientsByUsername:          make(map[string]string),
		licenses:                   make(map[string]*License),
		licensesByKey:              make(map[string]string),
		activations:                make(map[string][]*ActivationRecord),
		adminUsers:                 make(map[string]*AdminUser),
		adminByName:                make(map[string]string),
		apiKeys:                    make(map[string]*APIKeyRecord),
		apiKeysByHash:              make(map[string]string),
		apiKeysByUser:              make(map[string]map[string]struct{}),
		apiKeysByClient:            make(map[string]map[string]struct{}),
		products:                   make(map[string]*Product),
		productsBySlug:             make(map[string]string),
		plans:                      make(map[string]*Plan),
		plansBySlug:                make(map[string]string),
		features:                   make(map[string]*Feature),
		featuresBySlug:             make(map[string]string),
		featureScopes:              make(map[string]*FeatureScope),
		planFeatures:               make(map[string]*PlanFeature),
		deviceTrials:               make(map[string]*DeviceTrial),
		offlineValidationTokens:    make(map[string]*OfflineValidationToken),
		offlineValidationLogs:      make(map[string][]*OfflineValidationLog),
		emailProviders:             make(map[string]*email.EmailProvider),
		emailProvidersBySlug:       make(map[string]string),
		emailTemplates:             make(map[string]*email.EmailTemplate),
		emailTemplatesBySlug:       make(map[string]string),
		emailRoutes:                make(map[string]*email.EmailTemplateRoute),
		emailMessages:              make(map[string]*email.EmailMessage),
		emailEvents:                make(map[string][]*email.EmailEvent),
		coupons:                    make(map[string]*CouponCode),
		couponsByCode:              make(map[string]string),
		couponRedemptions:          make(map[string]*CouponRedemption),
		couponRedemptionsByCoupon:  make(map[string][]string),
		couponRedemptionsByLicense: make(map[string][]string),
		couponRedemptionsByClient:  make(map[string][]string),
		signingKeys:                make(map[string]*SigningKey),
		activeSigningKeyID:         "",
	}
}

type storageSnapshot struct {
	Clients            map[string]*Client                   `json:"clients"`
	Licenses           map[string]*License                  `json:"licenses"`
	Activations        map[string][]*ActivationRecord       `json:"activations"`
	AdminUsers         map[string]*AdminUser                `json:"admin_users"`
	APIKeys            map[string]*APIKeyRecord             `json:"api_keys"`
	EmailProviders     map[string]*email.EmailProvider      `json:"email_providers,omitempty"`
	EmailTemplates     map[string]*email.EmailTemplate      `json:"email_templates,omitempty"`
	EmailRoutes        map[string]*email.EmailTemplateRoute `json:"email_routes,omitempty"`
	EmailMessages      map[string]*email.EmailMessage       `json:"email_messages,omitempty"`
	EmailEvents        map[string][]*email.EmailEvent       `json:"email_events,omitempty"`
	SigningKeys        map[string]*SigningKey               `json:"signing_keys,omitempty"`
	ActiveSigningKeyID string                               `json:"active_signing_key_id,omitempty"`
	Coupons            map[string]*CouponCode               `json:"coupons,omitempty"`
	CouponRedemptions  map[string]*CouponRedemption         `json:"coupon_redemptions,omitempty"`
}

func (s *InMemoryStorage) SaveClient(_ context.Context, client *Client) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; exists {
		return errClientExists
	}
	emailKey := normalizeEmail(client.Email)
	usernameKey := strings.ToLower(strings.TrimSpace(client.Username))
	if emailKey != "" {
		if _, exists := s.clientsByEmail[emailKey]; exists {
			return errClientExists
		}
		s.clientsByEmail[emailKey] = client.ID
	}
	if usernameKey != "" {
		if _, exists := s.clientsByUsername[usernameKey]; exists {
			return fmt.Errorf("client username already exists")
		}
		s.clientsByUsername[usernameKey] = client.ID
	}
	s.clients[client.ID] = cloneClient(client)
	return nil
}

func (s *InMemoryStorage) UpdateClient(_ context.Context, client *Client) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.clients[client.ID]
	if !exists {
		return errClientMissing
	}
	oldEmail := normalizeEmail(current.Email)
	oldUsername := strings.ToLower(strings.TrimSpace(current.Username))
	newUsername := strings.ToLower(strings.TrimSpace(client.Username))
	newEmail := normalizeEmail(client.Email)
	if oldEmail != newEmail {
		if mappedID, taken := s.clientsByEmail[newEmail]; taken && mappedID != client.ID {
			return errClientExists
		}
		delete(s.clientsByEmail, oldEmail)
	}
	if oldUsername != newUsername {
		if mappedID, taken := s.clientsByUsername[newUsername]; taken && mappedID != client.ID {
			return fmt.Errorf("client username already exists")
		}
		delete(s.clientsByUsername, oldUsername)
	}
	s.clients[client.ID] = cloneClient(client)
	s.clientsByEmail[newEmail] = client.ID
	if newUsername != "" {
		s.clientsByUsername[newUsername] = client.ID
	}
	return nil
}

func (s *InMemoryStorage) GetClient(_ context.Context, clientID string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[clientID]
	if !ok {
		return nil, errClientMissing
	}
	return cloneClient(client), nil
}

func (s *InMemoryStorage) GetClientByEmail(_ context.Context, email string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clientID, ok := s.clientsByEmail[normalizeEmail(email)]
	if !ok {
		return nil, errClientMissing
	}
	return cloneClient(s.clients[clientID]), nil
}

func (s *InMemoryStorage) GetClientByUsername(_ context.Context, username string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clientID, ok := s.clientsByUsername[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return nil, errClientMissing
	}
	return cloneClient(s.clients[clientID]), nil
}

func (s *InMemoryStorage) ListClients(_ context.Context) ([]*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, cloneClient(client))
	}
	return clients, nil
}

func (s *InMemoryStorage) SaveLicense(_ context.Context, license *License) error {
	if license == nil {
		return fmt.Errorf("license is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.licenses[license.ID]; exists {
		return errLicenseExists
	}
	key := normalizeLicenseKey(license.LicenseKey)
	if key != "" {
		if _, exists := s.licensesByKey[key]; exists {
			return errLicenseExists
		}
		s.licensesByKey[key] = license.ID
	}
	s.licenses[license.ID] = cloneLicense(license)
	return nil
}

func (s *InMemoryStorage) UpdateLicense(_ context.Context, license *License) error {
	if license == nil {
		return fmt.Errorf("license is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.licenses[license.ID]
	if !exists {
		return errLicenseMissing
	}
	oldKey := normalizeLicenseKey(current.LicenseKey)
	newKey := normalizeLicenseKey(license.LicenseKey)
	if oldKey != newKey {
		if mappedID, taken := s.licensesByKey[newKey]; taken && mappedID != license.ID {
			return errLicenseExists
		}
		delete(s.licensesByKey, oldKey)
	}
	s.licenses[license.ID] = cloneLicense(license)
	s.licensesByKey[newKey] = license.ID
	return nil
}

func (s *InMemoryStorage) GetLicense(_ context.Context, licenseID string) (*License, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	license, exists := s.licenses[licenseID]
	if !exists {
		return nil, errLicenseMissing
	}
	return cloneLicense(license), nil
}

func (s *InMemoryStorage) GetLicenseByKey(_ context.Context, licenseKey string) (*License, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	licenseID, ok := s.licensesByKey[normalizeLicenseKey(licenseKey)]
	if !ok {
		return nil, errLicenseMissing
	}
	return cloneLicense(s.licenses[licenseID]), nil
}

func (s *InMemoryStorage) ListLicenses(_ context.Context) ([]*License, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	licenses := make([]*License, 0, len(s.licenses))
	for _, license := range s.licenses {
		licenses = append(licenses, cloneLicense(license))
	}
	return licenses, nil
}

func (s *InMemoryStorage) RecordActivation(_ context.Context, record *ActivationRecord) error {
	if record == nil {
		return fmt.Errorf("record is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := *record
	s.activations[record.LicenseID] = append(s.activations[record.LicenseID], &cloned)
	return nil
}

func (s *InMemoryStorage) ListActivations(_ context.Context, licenseID string) ([]*ActivationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.activations[licenseID]
	result := make([]*ActivationRecord, 0, len(records))
	for _, record := range records {
		result = append(result, cloneActivationRecord(record))
	}
	return result, nil
}

func (s *InMemoryStorage) CreateAdminUser(_ context.Context, user *AdminUser) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	if username == "" {
		return fmt.Errorf("username is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.adminUsers[user.ID]; exists {
		return errUserExists
	}
	if _, exists := s.adminByName[username]; exists {
		return errUserExists
	}
	clone := cloneAdminUser(user)
	s.adminUsers[user.ID] = clone
	s.adminByName[username] = user.ID
	return nil
}

func (s *InMemoryStorage) UpdateAdminUser(_ context.Context, user *AdminUser) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldUser, exists := s.adminUsers[user.ID]
	if !exists {
		return errUserMissing
	}
	oldKey := strings.ToLower(strings.TrimSpace(oldUser.Username))
	newKey := strings.ToLower(strings.TrimSpace(user.Username))
	if newKey == "" {
		return fmt.Errorf("username is required")
	}
	if existingID, taken := s.adminByName[newKey]; taken && existingID != user.ID {
		return errUserExists
	}
	delete(s.adminByName, oldKey)
	s.adminUsers[user.ID] = cloneAdminUser(user)
	s.adminByName[newKey] = user.ID
	return nil
}

func (s *InMemoryStorage) DeleteAdminUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, exists := s.adminUsers[userID]
	if !exists {
		return errUserMissing
	}
	usernameKey := strings.ToLower(strings.TrimSpace(user.Username))
	delete(s.adminUsers, userID)
	delete(s.adminByName, usernameKey)
	if keyIDs, ok := s.apiKeysByUser[userID]; ok {
		for keyID := range keyIDs {
			if key, exists := s.apiKeys[keyID]; exists {
				delete(s.apiKeysByHash, key.Hash)
			}
			delete(s.apiKeys, keyID)
		}
		delete(s.apiKeysByUser, userID)
	}
	return nil
}

func (s *InMemoryStorage) GetAdminUser(_ context.Context, userID string) (*AdminUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.adminUsers[userID]
	if !ok {
		return nil, errUserMissing
	}
	return cloneAdminUser(user), nil
}

func (s *InMemoryStorage) GetAdminUserByUsername(_ context.Context, username string) (*AdminUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.adminByName[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return nil, errUserMissing
	}
	return cloneAdminUser(s.adminUsers[id]), nil
}

func (s *InMemoryStorage) ListAdminUsers(_ context.Context) ([]*AdminUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]*AdminUser, 0, len(s.adminUsers))
	for _, user := range s.adminUsers {
		users = append(users, cloneAdminUser(user))
	}
	return users, nil
}

func (s *InMemoryStorage) SaveAPIKey(_ context.Context, key *APIKeyRecord) error {
	if key == nil {
		return fmt.Errorf("api key is nil")
	}
	if key.Hash == "" {
		return fmt.Errorf("api key hash required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.apiKeys[key.ID]; exists {
		return errAPIKeyExists
	}
	if _, exists := s.apiKeysByHash[key.Hash]; exists {
		return errAPIKeyExists
	}
	clone := cloneAPIKeyRecord(key)
	s.apiKeys[key.ID] = clone
	s.apiKeysByHash[key.Hash] = key.ID
	if _, ok := s.apiKeysByUser[key.UserID]; !ok {
		s.apiKeysByUser[key.UserID] = make(map[string]struct{})
	}
	s.apiKeysByUser[key.UserID][key.ID] = struct{}{}
	if key.ClientID != "" {
		if _, ok := s.apiKeysByClient[key.ClientID]; !ok {
			s.apiKeysByClient[key.ClientID] = make(map[string]struct{})
		}
		s.apiKeysByClient[key.ClientID][key.ID] = struct{}{}
	}
	return nil
}

func (s *InMemoryStorage) UpdateAPIKey(_ context.Context, key *APIKeyRecord) error {
	if key == nil {
		return fmt.Errorf("api key is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, exists := s.apiKeys[key.ID]
	if !exists {
		return errAPIKeyMissing
	}
	if stored.Hash != key.Hash {
		return fmt.Errorf("api key hash mismatch")
	}
	// Update apiKeys map
	prev := stored.ClientID
	s.apiKeys[key.ID] = cloneAPIKeyRecord(key)
	if prev != key.ClientID {
		if prev != "" {
			if keys, ok := s.apiKeysByClient[prev]; ok {
				delete(keys, key.ID)
			}
		}
		if key.ClientID != "" {
			if _, ok := s.apiKeysByClient[key.ClientID]; !ok {
				s.apiKeysByClient[key.ClientID] = make(map[string]struct{})
			}
			s.apiKeysByClient[key.ClientID][key.ID] = struct{}{}
		}
	}
	return nil
}

func (s *InMemoryStorage) DeleteAPIKey(_ context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, exists := s.apiKeys[keyID]
	if !exists {
		return errAPIKeyMissing
	}
	delete(s.apiKeys, keyID)
	delete(s.apiKeysByHash, key.Hash)
	if keys, ok := s.apiKeysByUser[key.UserID]; ok {
		delete(keys, keyID)
	}
	if key.ClientID != "" {
		if keys, ok := s.apiKeysByClient[key.ClientID]; ok {
			delete(keys, keyID)
		}
	}
	return nil
}

func (s *InMemoryStorage) GetAPIKeyByHash(_ context.Context, hash string) (*APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.apiKeysByHash[hash]
	if !ok {
		return nil, errAPIKeyMissing
	}
	return cloneAPIKeyRecord(s.apiKeys[id]), nil
}

func (s *InMemoryStorage) ListAPIKeysByUser(_ context.Context, userID string) ([]*APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keyIDs := s.apiKeysByUser[userID]
	if len(keyIDs) == 0 {
		return []*APIKeyRecord{}, nil
	}
	keys := make([]*APIKeyRecord, 0, len(keyIDs))
	for keyID := range keyIDs {
		if record, ok := s.apiKeys[keyID]; ok {
			keys = append(keys, cloneAPIKeyRecord(record))
		}
	}
	return keys, nil
}

func (s *InMemoryStorage) ListAPIKeysByClient(_ context.Context, clientID string) ([]*APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keyIDs := s.apiKeysByClient[clientID]
	if len(keyIDs) == 0 {
		return []*APIKeyRecord{}, nil
	}
	keys := make([]*APIKeyRecord, 0, len(keyIDs))
	for keyID := range keyIDs {
		if record, ok := s.apiKeys[keyID]; ok {
			keys = append(keys, cloneAPIKeyRecord(record))
		}
	}
	return keys, nil
}

// ==================== Email Provider/Template Methods ====================

func normalizeSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func (s *InMemoryStorage) SaveEmailProvider(_ context.Context, provider *email.EmailProvider) error {
	if provider == nil {
		return fmt.Errorf("email provider is nil")
	}
	slug := normalizeSlug(provider.Slug)
	if slug == "" {
		return fmt.Errorf("email provider slug is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emailProviders[provider.ID]; exists {
		return errEmailProviderExists
	}
	if _, exists := s.emailProvidersBySlug[slug]; exists {
		return errEmailProviderExists
	}
	s.emailProviders[provider.ID] = provider.Clone()
	s.emailProvidersBySlug[slug] = provider.ID
	return nil
}

func (s *InMemoryStorage) UpdateEmailProvider(_ context.Context, provider *email.EmailProvider) error {
	if provider == nil {
		return fmt.Errorf("email provider is nil")
	}
	slug := normalizeSlug(provider.Slug)
	if slug == "" {
		return fmt.Errorf("email provider slug is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.emailProviders[provider.ID]
	if !exists {
		return errEmailProviderMissing
	}
	oldSlug := normalizeSlug(current.Slug)
	if slug != oldSlug {
		if mappedID, taken := s.emailProvidersBySlug[slug]; taken && mappedID != provider.ID {
			return errEmailProviderExists
		}
		delete(s.emailProvidersBySlug, oldSlug)
		s.emailProvidersBySlug[slug] = provider.ID
	}
	s.emailProviders[provider.ID] = provider.Clone()
	return nil
}

func (s *InMemoryStorage) ListEmailProviders(_ context.Context, includeDisabled bool) ([]*email.EmailProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	providers := make([]*email.EmailProvider, 0, len(s.emailProviders))
	for _, provider := range s.emailProviders {
		if !includeDisabled && !provider.Enabled {
			continue
		}
		providers = append(providers, provider.Clone())
	}
	sort.Slice(providers, func(i, j int) bool {
		if providers[i].Priority == providers[j].Priority {
			return providers[i].Name < providers[j].Name
		}
		return providers[i].Priority < providers[j].Priority
	})
	return providers, nil
}

func (s *InMemoryStorage) GetEmailProvider(_ context.Context, providerID string) (*email.EmailProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	provider, ok := s.emailProviders[providerID]
	if !ok {
		return nil, errEmailProviderMissing
	}
	return provider.Clone(), nil
}

func (s *InMemoryStorage) DeleteEmailProvider(_ context.Context, providerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	provider, ok := s.emailProviders[providerID]
	if !ok {
		return errEmailProviderMissing
	}
	slug := normalizeSlug(provider.Slug)
	delete(s.emailProviders, providerID)
	delete(s.emailProvidersBySlug, slug)
	return nil
}

func (s *InMemoryStorage) SaveEmailTemplate(_ context.Context, tpl *email.EmailTemplate) error {
	if tpl == nil {
		return fmt.Errorf("email template is nil")
	}
	slug := normalizeSlug(tpl.Slug)
	if slug == "" {
		return fmt.Errorf("email template slug is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emailTemplates[tpl.ID]; exists {
		return errEmailTemplateExists
	}
	if _, exists := s.emailTemplatesBySlug[slug]; exists {
		return errEmailTemplateExists
	}
	s.emailTemplates[tpl.ID] = tpl.Clone()
	s.emailTemplatesBySlug[slug] = tpl.ID
	return nil
}

func (s *InMemoryStorage) UpdateEmailTemplate(_ context.Context, tpl *email.EmailTemplate) error {
	if tpl == nil {
		return fmt.Errorf("email template is nil")
	}
	slug := normalizeSlug(tpl.Slug)
	if slug == "" {
		return fmt.Errorf("email template slug is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.emailTemplates[tpl.ID]
	if !exists {
		return errEmailTemplateMissing
	}
	oldSlug := normalizeSlug(current.Slug)
	if slug != oldSlug {
		if mappedID, taken := s.emailTemplatesBySlug[slug]; taken && mappedID != tpl.ID {
			return errEmailTemplateExists
		}
		delete(s.emailTemplatesBySlug, oldSlug)
		s.emailTemplatesBySlug[slug] = tpl.ID
	}
	s.emailTemplates[tpl.ID] = tpl.Clone()
	return nil
}

func (s *InMemoryStorage) ListEmailTemplates(_ context.Context) ([]*email.EmailTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	templates := make([]*email.EmailTemplate, 0, len(s.emailTemplates))
	for _, tpl := range s.emailTemplates {
		templates = append(templates, tpl.Clone())
	}
	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Category == templates[j].Category {
			return templates[i].Name < templates[j].Name
		}
		return templates[i].Category < templates[j].Category
	})
	return templates, nil
}

func (s *InMemoryStorage) GetEmailTemplate(_ context.Context, templateID string) (*email.EmailTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tpl, ok := s.emailTemplates[templateID]
	if !ok {
		return nil, errEmailTemplateMissing
	}
	return tpl.Clone(), nil
}

func (s *InMemoryStorage) GetEmailTemplateBySlug(_ context.Context, slug string) (*email.EmailTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.emailTemplatesBySlug[normalizeSlug(slug)]
	if !ok {
		return nil, errEmailTemplateMissing
	}
	return s.emailTemplates[id].Clone(), nil
}

func (s *InMemoryStorage) DeleteEmailTemplate(_ context.Context, templateID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tpl, ok := s.emailTemplates[templateID]
	if !ok {
		return errEmailTemplateMissing
	}
	slug := normalizeSlug(tpl.Slug)
	delete(s.emailTemplates, templateID)
	delete(s.emailTemplatesBySlug, slug)
	return nil
}

func (s *InMemoryStorage) SaveEmailTemplateRoute(_ context.Context, route *email.EmailTemplateRoute) error {
	if route == nil {
		return fmt.Errorf("email route is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emailRoutes[route.ID]; exists {
		return errEmailRouteExists
	}
	s.emailRoutes[route.ID] = route.Clone()
	return nil
}

func (s *InMemoryStorage) ListEmailTemplateRoutes(_ context.Context, templateID, category string) ([]*email.EmailTemplateRoute, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	routes := make([]*email.EmailTemplateRoute, 0, len(s.emailRoutes))
	for _, route := range s.emailRoutes {
		if templateID != "" && route.TemplateID != templateID {
			continue
		}
		if templateID == "" && category != "" && !strings.EqualFold(route.Category, category) {
			continue
		}
		routes = append(routes, route.Clone())
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Priority == routes[j].Priority {
			return routes[i].CreatedAt.Before(routes[j].CreatedAt)
		}
		return routes[i].Priority < routes[j].Priority
	})
	return routes, nil
}

func (s *InMemoryStorage) DeleteEmailTemplateRoute(_ context.Context, routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.emailRoutes[routeID]; !ok {
		return errEmailRouteMissing
	}
	delete(s.emailRoutes, routeID)
	return nil
}

func (s *InMemoryStorage) EnqueueEmail(_ context.Context, msg *email.EmailMessage) error {
	if msg == nil {
		return fmt.Errorf("email message is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emailMessages[msg.ID]; exists {
		return fmt.Errorf("email message already exists")
	}
	s.emailMessages[msg.ID] = msg.Clone()
	return nil
}

func (s *InMemoryStorage) UpdateEmailMessage(_ context.Context, msg *email.EmailMessage) error {
	if msg == nil {
		return fmt.Errorf("email message is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emailMessages[msg.ID]; !exists {
		return errEmailMessageMissing
	}
	s.emailMessages[msg.ID] = msg.Clone()
	return nil
}

func (s *InMemoryStorage) GetEmailMessage(_ context.Context, messageID string) (*email.EmailMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	msg, ok := s.emailMessages[messageID]
	if !ok {
		return nil, errEmailMessageMissing
	}
	return msg.Clone(), nil
}

func (s *InMemoryStorage) LeaseNextEmail(_ context.Context, dueBefore time.Time) (*email.EmailMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var (
		selected   *email.EmailMessage
		selectedID string
	)
	for id, msg := range s.emailMessages {
		if msg.Status != email.MessageStatusQueued && msg.Status != email.MessageStatusRetrying {
			continue
		}
		if msg.NextAttemptAt.After(dueBefore) {
			continue
		}
		if selected == nil || msg.NextAttemptAt.Before(selected.NextAttemptAt) {
			selected = msg
			selectedID = id
		}
	}
	if selected == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	claimed := selected.Clone()
	claimed.Status = email.MessageStatusSending
	claimed.LastAttemptAt = now
	claimed.UpdatedAt = now
	s.emailMessages[selectedID] = claimed
	return claimed.Clone(), nil
}

func (s *InMemoryStorage) AppendEmailEvent(_ context.Context, event *email.EmailEvent) error {
	if event == nil {
		return fmt.Errorf("email event is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := event.Clone()
	s.emailEvents[event.MessageID] = append(s.emailEvents[event.MessageID], clone)
	return nil
}

func (s *InMemoryStorage) ListEmailEvents(_ context.Context, messageID string) ([]*email.EmailEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := s.emailEvents[messageID]
	result := make([]*email.EmailEvent, 0, len(events))
	for _, evt := range events {
		result = append(result, evt.Clone())
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

// DeviceTrial methods for InMemoryStorage

func cloneDeviceTrial(trial *DeviceTrial) *DeviceTrial {
	if trial == nil {
		return nil
	}
	clone := *trial
	return &clone
}

func cloneOfflineValidationToken(token *OfflineValidationToken) *OfflineValidationToken {
	if token == nil {
		return nil
	}
	clone := *token
	return &clone
}

func cloneOfflineValidationLog(log *OfflineValidationLog) *OfflineValidationLog {
	if log == nil {
		return nil
	}
	clone := *log
	return &clone
}

func (s *InMemoryStorage) SaveDeviceTrial(_ context.Context, trial *DeviceTrial) error {
	if trial == nil {
		return fmt.Errorf("device trial is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.deviceTrials[trial.DeviceFingerprint]; exists {
		return errDeviceTrialExists
	}
	s.deviceTrials[trial.DeviceFingerprint] = cloneDeviceTrial(trial)
	return nil
}

func (s *InMemoryStorage) GetDeviceTrial(_ context.Context, deviceFingerprint string) (*DeviceTrial, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	trial, exists := s.deviceTrials[deviceFingerprint]
	if !exists {
		return nil, errDeviceTrialMissing
	}
	return cloneDeviceTrial(trial), nil
}

func (s *InMemoryStorage) HasDeviceUsedTrial(_ context.Context, deviceFingerprint string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.deviceTrials[deviceFingerprint]
	return exists, nil
}

func (s *InMemoryStorage) ListDeviceTrials(_ context.Context) ([]*DeviceTrial, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	trials := make([]*DeviceTrial, 0, len(s.deviceTrials))
	for _, trial := range s.deviceTrials {
		trials = append(trials, cloneDeviceTrial(trial))
	}
	return trials, nil
}

// OfflineValidationToken methods for InMemoryStorage

func (s *InMemoryStorage) SaveOfflineValidationToken(_ context.Context, token *OfflineValidationToken) error {
	if token == nil {
		return fmt.Errorf("offline validation token is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.offlineValidationTokens[token.Token]; exists {
		return errOfflineTokenExists
	}
	s.offlineValidationTokens[token.Token] = cloneOfflineValidationToken(token)
	return nil
}

func (s *InMemoryStorage) GetOfflineValidationToken(_ context.Context, token string) (*OfflineValidationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	offlineToken, exists := s.offlineValidationTokens[token]
	if !exists {
		return nil, errOfflineTokenMissing
	}
	return cloneOfflineValidationToken(offlineToken), nil
}

func (s *InMemoryStorage) UpdateOfflineValidationToken(_ context.Context, token *OfflineValidationToken) error {
	if token == nil {
		return fmt.Errorf("offline validation token is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.offlineValidationTokens[token.Token]; !exists {
		return errOfflineTokenMissing
	}
	s.offlineValidationTokens[token.Token] = cloneOfflineValidationToken(token)
	return nil
}

func (s *InMemoryStorage) DeleteOfflineValidationToken(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.offlineValidationTokens[token]; !exists {
		return errOfflineTokenMissing
	}
	delete(s.offlineValidationTokens, token)
	return nil
}

func (s *InMemoryStorage) ListOfflineValidationTokens(_ context.Context) ([]*OfflineValidationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens := make([]*OfflineValidationToken, 0, len(s.offlineValidationTokens))
	for _, token := range s.offlineValidationTokens {
		tokens = append(tokens, cloneOfflineValidationToken(token))
	}
	return tokens, nil
}

func (s *InMemoryStorage) FindOfflineValidationTokensByLicense(_ context.Context, licenseKey string) ([]*OfflineValidationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var tokens []*OfflineValidationToken
	for _, token := range s.offlineValidationTokens {
		if token.LicenseKey == licenseKey {
			tokens = append(tokens, cloneOfflineValidationToken(token))
		}
	}
	return tokens, nil
}

func (s *InMemoryStorage) FindOfflineValidationTokensByClient(_ context.Context, clientID string) ([]*OfflineValidationToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var tokens []*OfflineValidationToken
	for _, token := range s.offlineValidationTokens {
		if token.ClientID == clientID {
			tokens = append(tokens, cloneOfflineValidationToken(token))
		}
	}
	return tokens, nil
}

// SigningKey methods for InMemoryStorage
func (s *InMemoryStorage) SaveSigningKey(_ context.Context, key *SigningKey) error {
	if key == nil {
		return fmt.Errorf("signing key is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.signingKeys[key.ID]; exists {
		return fmt.Errorf("signing key already exists")
	}
	// clone
	k := *key
	s.signingKeys[key.ID] = &k
	if key.IsActive {
		s.activeSigningKeyID = key.ID
	}
	return nil
}

func (s *InMemoryStorage) GetSigningKey(_ context.Context, keyID string) (*SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.signingKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("signing key not found")
	}
	k := *key
	return &k, nil
}

func (s *InMemoryStorage) GetActiveSigningKey(_ context.Context) (*SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeSigningKeyID == "" {
		return nil, fmt.Errorf("no active signing key")
	}
	key, ok := s.signingKeys[s.activeSigningKeyID]
	if !ok {
		return nil, fmt.Errorf("active signing key not found")
	}
	k := *key
	return &k, nil
}

func (s *InMemoryStorage) ListSigningKeys(_ context.Context) ([]*SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*SigningKey
	for _, key := range s.signingKeys {
		k := *key
		out = append(out, &k)
	}
	return out, nil
}

func (s *InMemoryStorage) SetActiveSigningKey(_ context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keyID == "" {
		s.activeSigningKeyID = ""
		return nil
	}
	if _, ok := s.signingKeys[keyID]; !ok {
		return fmt.Errorf("signing key not found")
	}
	s.activeSigningKeyID = keyID
	// update flags
	for id, k := range s.signingKeys {
		if id == keyID {
			k.IsActive = true
		} else {
			k.IsActive = false
		}
	}
	return nil
}

// OfflineValidationLog methods for InMemoryStorage

func (s *InMemoryStorage) SaveOfflineValidationLog(_ context.Context, log *OfflineValidationLog) error {
	if log == nil {
		return fmt.Errorf("offline validation log is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := cloneOfflineValidationLog(log)
	s.offlineValidationLogs[log.Token] = append(s.offlineValidationLogs[log.Token], cloned)
	return nil
}

func (s *InMemoryStorage) ListOfflineValidationLogs(_ context.Context, token string) ([]*OfflineValidationLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	logs := s.offlineValidationLogs[token]
	result := make([]*OfflineValidationLog, 0, len(logs))
	for _, log := range logs {
		result = append(result, cloneOfflineValidationLog(log))
	}
	return result, nil
}

func (s *InMemoryStorage) FindOfflineValidationLogsByLicense(_ context.Context, licenseKey string) ([]*OfflineValidationLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var logs []*OfflineValidationLog
	for _, tokenLogs := range s.offlineValidationLogs {
		for _, log := range tokenLogs {
			if log.LicenseKey == licenseKey {
				logs = append(logs, cloneOfflineValidationLog(log))
			}
		}
	}
	return logs, nil
}

func (s *InMemoryStorage) FindOfflineValidationLogsByClient(_ context.Context, clientID string) ([]*OfflineValidationLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var logs []*OfflineValidationLog
	for _, tokenLogs := range s.offlineValidationLogs {
		for _, log := range tokenLogs {
			if log.ClientID == clientID {
				logs = append(logs, cloneOfflineValidationLog(log))
			}
		}
	}
	return logs, nil
}

// Subscription methods for InMemoryStorage - not fully implemented for in-memory
func (s *InMemoryStorage) SaveSubscription(_ context.Context, _ *Subscription) error {
	return fmt.Errorf("subscriptions not supported in in-memory storage")
}

func (s *InMemoryStorage) UpdateSubscription(_ context.Context, _ *Subscription) error {
	return fmt.Errorf("subscriptions not supported in in-memory storage")
}

func (s *InMemoryStorage) GetSubscription(_ context.Context, _ string) (*Subscription, error) {
	return nil, fmt.Errorf("subscriptions not supported in in-memory storage")
}

func (s *InMemoryStorage) ListSubscriptions(_ context.Context) ([]*Subscription, error) {
	return []*Subscription{}, nil
}

func (s *InMemoryStorage) ListSubscriptionsByClient(_ context.Context, _ string) ([]*Subscription, error) {
	return []*Subscription{}, nil
}

func (s *InMemoryStorage) DeleteSubscription(_ context.Context, _ string) error {
	return fmt.Errorf("subscriptions not supported in in-memory storage")
}

func (s *InMemoryStorage) snapshot() *storageSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot := &storageSnapshot{
		Clients:        make(map[string]*Client, len(s.clients)),
		Licenses:       make(map[string]*License, len(s.licenses)),
		Activations:    make(map[string][]*ActivationRecord, len(s.activations)),
		AdminUsers:     make(map[string]*AdminUser, len(s.adminUsers)),
		APIKeys:        make(map[string]*APIKeyRecord, len(s.apiKeys)),
		EmailProviders: make(map[string]*email.EmailProvider, len(s.emailProviders)),
		EmailTemplates: make(map[string]*email.EmailTemplate, len(s.emailTemplates)),
		EmailRoutes:    make(map[string]*email.EmailTemplateRoute, len(s.emailRoutes)),
		EmailMessages:  make(map[string]*email.EmailMessage, len(s.emailMessages)),
		EmailEvents:    make(map[string][]*email.EmailEvent, len(s.emailEvents)),
	}
	for id, client := range s.clients {
		snapshot.Clients[id] = cloneClient(client)
	}
	for id, license := range s.licenses {
		snapshot.Licenses[id] = cloneLicense(license)
	}
	for id, records := range s.activations {
		clones := make([]*ActivationRecord, 0, len(records))
		for _, record := range records {
			clones = append(clones, cloneActivationRecord(record))
		}
		snapshot.Activations[id] = clones
	}
	for id, user := range s.adminUsers {
		snapshot.AdminUsers[id] = cloneAdminUser(user)
	}
	for id, key := range s.apiKeys {
		snapshot.APIKeys[id] = cloneAPIKeyRecord(key)
	}
	for id, provider := range s.emailProviders {
		snapshot.EmailProviders[id] = provider.Clone()
	}
	for id, tpl := range s.emailTemplates {
		snapshot.EmailTemplates[id] = tpl.Clone()
	}
	for id, route := range s.emailRoutes {
		snapshot.EmailRoutes[id] = route.Clone()
	}
	for id, msg := range s.emailMessages {
		snapshot.EmailMessages[id] = msg.Clone()
	}
	for id, events := range s.emailEvents {
		copies := make([]*email.EmailEvent, 0, len(events))
		for _, evt := range events {
			copies = append(copies, evt.Clone())
		}
		snapshot.EmailEvents[id] = copies
	}
	if len(s.coupons) > 0 {
		snapshot.Coupons = make(map[string]*CouponCode, len(s.coupons))
		for id, coupon := range s.coupons {
			snapshot.Coupons[id] = cloneCouponCode(coupon)
		}
	}
	if len(s.couponRedemptions) > 0 {
		snapshot.CouponRedemptions = make(map[string]*CouponRedemption, len(s.couponRedemptions))
		for id, redemption := range s.couponRedemptions {
			snapshot.CouponRedemptions[id] = cloneCouponRedemption(redemption)
		}
	}

	// Include signing keys - DO NOT persist private keys in the file snapshot
	if len(s.signingKeys) > 0 {
		snapshot.SigningKeys = make(map[string]*SigningKey, len(s.signingKeys))
		for id, key := range s.signingKeys {
			copy := *key
			copy.PrivateKey = nil
			snapshot.SigningKeys[id] = &copy
		}
	}
	snapshot.ActiveSigningKeyID = s.activeSigningKeyID
	return snapshot
}

func (s *InMemoryStorage) loadSnapshot(snapshot *storageSnapshot) {
	if snapshot == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = make(map[string]*Client, len(snapshot.Clients))
	s.clientsByEmail = make(map[string]string, len(snapshot.Clients))
	s.clientsByUsername = make(map[string]string, len(snapshot.Clients))
	for id, client := range snapshot.Clients {
		cloned := cloneClient(client)
		s.clients[id] = cloned
		s.clientsByEmail[normalizeEmail(cloned.Email)] = id
		if cloned.Username != "" {
			s.clientsByUsername[strings.ToLower(strings.TrimSpace(cloned.Username))] = id
		}
	}
	s.licenses = make(map[string]*License, len(snapshot.Licenses))
	s.licensesByKey = make(map[string]string, len(snapshot.Licenses))
	for id, license := range snapshot.Licenses {
		cloned := cloneLicense(license)
		s.licenses[id] = cloned
		s.licensesByKey[normalizeLicenseKey(cloned.LicenseKey)] = id
	}
	s.activations = make(map[string][]*ActivationRecord, len(snapshot.Activations))
	for id, records := range snapshot.Activations {
		clones := make([]*ActivationRecord, 0, len(records))
		for _, record := range records {
			clones = append(clones, cloneActivationRecord(record))
		}
		s.activations[id] = clones
	}
	s.adminUsers = make(map[string]*AdminUser, len(snapshot.AdminUsers))
	s.adminByName = make(map[string]string, len(snapshot.AdminUsers))
	for id, user := range snapshot.AdminUsers {
		cloned := cloneAdminUser(user)
		s.adminUsers[id] = cloned
		s.adminByName[strings.ToLower(strings.TrimSpace(cloned.Username))] = id
	}
	s.apiKeys = make(map[string]*APIKeyRecord, len(snapshot.APIKeys))
	s.apiKeysByHash = make(map[string]string, len(snapshot.APIKeys))
	s.apiKeysByUser = make(map[string]map[string]struct{})
	for id, key := range snapshot.APIKeys {
		cloned := cloneAPIKeyRecord(key)
		s.apiKeys[id] = cloned
		s.apiKeysByHash[cloned.Hash] = id
		if _, ok := s.apiKeysByUser[cloned.UserID]; !ok {
			s.apiKeysByUser[cloned.UserID] = make(map[string]struct{})
		}
		s.apiKeysByUser[cloned.UserID][id] = struct{}{}
	}
	s.emailProviders = make(map[string]*email.EmailProvider, len(snapshot.EmailProviders))
	s.emailProvidersBySlug = make(map[string]string, len(snapshot.EmailProviders))
	for id, provider := range snapshot.EmailProviders {
		cloned := provider.Clone()
		s.emailProviders[id] = cloned
		s.emailProvidersBySlug[strings.ToLower(strings.TrimSpace(cloned.Slug))] = id
	}
	s.emailTemplates = make(map[string]*email.EmailTemplate, len(snapshot.EmailTemplates))
	s.emailTemplatesBySlug = make(map[string]string, len(snapshot.EmailTemplates))
	for id, tpl := range snapshot.EmailTemplates {
		cloned := tpl.Clone()
		s.emailTemplates[id] = cloned
		s.emailTemplatesBySlug[strings.ToLower(strings.TrimSpace(cloned.Slug))] = id
	}
	s.emailRoutes = make(map[string]*email.EmailTemplateRoute, len(snapshot.EmailRoutes))
	for id, route := range snapshot.EmailRoutes {
		s.emailRoutes[id] = route.Clone()
	}
	s.emailMessages = make(map[string]*email.EmailMessage, len(snapshot.EmailMessages))
	for id, msg := range snapshot.EmailMessages {
		s.emailMessages[id] = msg.Clone()
	}
	s.emailEvents = make(map[string][]*email.EmailEvent, len(snapshot.EmailEvents))
	for id, events := range snapshot.EmailEvents {
		copies := make([]*email.EmailEvent, 0, len(events))
		for _, evt := range events {
			copies = append(copies, evt.Clone())
		}
		s.emailEvents[id] = copies
	}
	s.coupons = make(map[string]*CouponCode, len(snapshot.Coupons))
	s.couponsByCode = make(map[string]string, len(snapshot.Coupons))
	for id, coupon := range snapshot.Coupons {
		cloned := cloneCouponCode(coupon)
		s.coupons[id] = cloned
		s.couponsByCode[normalizeCouponCode(cloned.Code)] = id
	}
	s.couponRedemptions = make(map[string]*CouponRedemption, len(snapshot.CouponRedemptions))
	s.couponRedemptionsByCoupon = make(map[string][]string)
	s.couponRedemptionsByLicense = make(map[string][]string)
	s.couponRedemptionsByClient = make(map[string][]string)
	for id, redemption := range snapshot.CouponRedemptions {
		cloned := cloneCouponRedemption(redemption)
		s.couponRedemptions[id] = cloned
		s.couponRedemptionsByCoupon[cloned.CouponID] = append(s.couponRedemptionsByCoupon[cloned.CouponID], id)
		s.couponRedemptionsByLicense[cloned.LicenseID] = append(s.couponRedemptionsByLicense[cloned.LicenseID], id)
		s.couponRedemptionsByClient[cloned.ClientID] = append(s.couponRedemptionsByClient[cloned.ClientID], id)
	}

	// Load signing keys (public parts only if persisted). Private keys won't be present in snapshot.
	s.signingKeys = make(map[string]*SigningKey, len(snapshot.SigningKeys))
	for id, key := range snapshot.SigningKeys {
		copied := *key
		s.signingKeys[id] = &copied
	}
	s.activeSigningKeyID = snapshot.ActiveSigningKeyID
}

type PersistentStorage struct {
	backend *InMemoryStorage
	path    string
}

func NewPersistentStorage(path string) (*PersistentStorage, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("persistent storage path is required")
	}
	ps := &PersistentStorage{
		backend: NewInMemoryStorage(),
		path:    path,
	}
	if err := ps.loadFromDisk(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return ps, nil
}

func (ps *PersistentStorage) SaveClient(ctx context.Context, client *Client) error {
	if err := ps.backend.SaveClient(ctx, client); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateClient(ctx context.Context, client *Client) error {
	if err := ps.backend.UpdateClient(ctx, client); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetClient(ctx context.Context, clientID string) (*Client, error) {
	return ps.backend.GetClient(ctx, clientID)
}

func (ps *PersistentStorage) GetClientByEmail(ctx context.Context, email string) (*Client, error) {
	return ps.backend.GetClientByEmail(ctx, email)
}

func (ps *PersistentStorage) GetClientByUsername(ctx context.Context, username string) (*Client, error) {
	return ps.backend.GetClientByUsername(ctx, username)
}

func (ps *PersistentStorage) ListClients(ctx context.Context) ([]*Client, error) {
	return ps.backend.ListClients(ctx)
}

func (ps *PersistentStorage) SaveLicense(ctx context.Context, license *License) error {
	if err := ps.backend.SaveLicense(ctx, license); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateLicense(ctx context.Context, license *License) error {
	if err := ps.backend.UpdateLicense(ctx, license); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetLicense(ctx context.Context, licenseID string) (*License, error) {
	return ps.backend.GetLicense(ctx, licenseID)
}

func (ps *PersistentStorage) GetLicenseByKey(ctx context.Context, licenseKey string) (*License, error) {
	return ps.backend.GetLicenseByKey(ctx, licenseKey)
}

func (ps *PersistentStorage) ListLicenses(ctx context.Context) ([]*License, error) {
	return ps.backend.ListLicenses(ctx)
}

func (ps *PersistentStorage) RecordActivation(ctx context.Context, record *ActivationRecord) error {
	if err := ps.backend.RecordActivation(ctx, record); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListActivations(ctx context.Context, licenseID string) ([]*ActivationRecord, error) {
	return ps.backend.ListActivations(ctx, licenseID)
}

func (ps *PersistentStorage) CreateAdminUser(ctx context.Context, user *AdminUser) error {
	if err := ps.backend.CreateAdminUser(ctx, user); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateAdminUser(ctx context.Context, user *AdminUser) error {
	if err := ps.backend.UpdateAdminUser(ctx, user); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) DeleteAdminUser(ctx context.Context, userID string) error {
	if err := ps.backend.DeleteAdminUser(ctx, userID); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetAdminUser(ctx context.Context, userID string) (*AdminUser, error) {
	return ps.backend.GetAdminUser(ctx, userID)
}

func (ps *PersistentStorage) GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error) {
	return ps.backend.GetAdminUserByUsername(ctx, username)
}

func (ps *PersistentStorage) ListAdminUsers(ctx context.Context) ([]*AdminUser, error) {
	return ps.backend.ListAdminUsers(ctx)
}

func (ps *PersistentStorage) SaveAPIKey(ctx context.Context, key *APIKeyRecord) error {
	if err := ps.backend.SaveAPIKey(ctx, key); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateAPIKey(ctx context.Context, key *APIKeyRecord) error {
	if err := ps.backend.UpdateAPIKey(ctx, key); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) DeleteAPIKey(ctx context.Context, keyID string) error {
	if err := ps.backend.DeleteAPIKey(ctx, keyID); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error) {
	return ps.backend.GetAPIKeyByHash(ctx, hash)
}

func (ps *PersistentStorage) ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKeyRecord, error) {
	return ps.backend.ListAPIKeysByUser(ctx, userID)
}

func (ps *PersistentStorage) ListAPIKeysByClient(ctx context.Context, clientID string) ([]*APIKeyRecord, error) {
	return ps.backend.ListAPIKeysByClient(ctx, clientID)
}

// DeviceTrial methods for PersistentStorage

func (ps *PersistentStorage) SaveDeviceTrial(ctx context.Context, trial *DeviceTrial) error {
	if err := ps.backend.SaveDeviceTrial(ctx, trial); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetDeviceTrial(ctx context.Context, deviceFingerprint string) (*DeviceTrial, error) {
	return ps.backend.GetDeviceTrial(ctx, deviceFingerprint)
}

func (ps *PersistentStorage) HasDeviceUsedTrial(ctx context.Context, deviceFingerprint string) (bool, error) {
	return ps.backend.HasDeviceUsedTrial(ctx, deviceFingerprint)
}

func (ps *PersistentStorage) ListDeviceTrials(ctx context.Context) ([]*DeviceTrial, error) {
	return ps.backend.ListDeviceTrials(ctx)
}

// OfflineValidationToken methods for PersistentStorage

func (ps *PersistentStorage) SaveOfflineValidationToken(ctx context.Context, token *OfflineValidationToken) error {
	if err := ps.backend.SaveOfflineValidationToken(ctx, token); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetOfflineValidationToken(ctx context.Context, token string) (*OfflineValidationToken, error) {
	return ps.backend.GetOfflineValidationToken(ctx, token)
}

func (ps *PersistentStorage) UpdateOfflineValidationToken(ctx context.Context, token *OfflineValidationToken) error {
	if err := ps.backend.UpdateOfflineValidationToken(ctx, token); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) DeleteOfflineValidationToken(ctx context.Context, token string) error {
	if err := ps.backend.DeleteOfflineValidationToken(ctx, token); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListOfflineValidationTokens(ctx context.Context) ([]*OfflineValidationToken, error) {
	return ps.backend.ListOfflineValidationTokens(ctx)
}

// SigningKey methods for PersistentStorage
func (ps *PersistentStorage) SaveSigningKey(ctx context.Context, key *SigningKey) error {
	if err := ps.backend.SaveSigningKey(ctx, key); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetSigningKey(ctx context.Context, keyID string) (*SigningKey, error) {
	return ps.backend.GetSigningKey(ctx, keyID)
}

func (ps *PersistentStorage) GetActiveSigningKey(ctx context.Context) (*SigningKey, error) {
	return ps.backend.GetActiveSigningKey(ctx)
}

func (ps *PersistentStorage) ListSigningKeys(ctx context.Context) ([]*SigningKey, error) {
	return ps.backend.ListSigningKeys(ctx)
}

func (ps *PersistentStorage) SetActiveSigningKey(ctx context.Context, keyID string) error {
	if err := ps.backend.SetActiveSigningKey(ctx, keyID); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) FindOfflineValidationTokensByLicense(ctx context.Context, licenseKey string) ([]*OfflineValidationToken, error) {
	return ps.backend.FindOfflineValidationTokensByLicense(ctx, licenseKey)
}

func (ps *PersistentStorage) FindOfflineValidationTokensByClient(ctx context.Context, clientID string) ([]*OfflineValidationToken, error) {
	return ps.backend.FindOfflineValidationTokensByClient(ctx, clientID)
}

// OfflineValidationLog methods for PersistentStorage

func (ps *PersistentStorage) SaveOfflineValidationLog(ctx context.Context, log *OfflineValidationLog) error {
	if err := ps.backend.SaveOfflineValidationLog(ctx, log); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListOfflineValidationLogs(ctx context.Context, token string) ([]*OfflineValidationLog, error) {
	return ps.backend.ListOfflineValidationLogs(ctx, token)
}

func (ps *PersistentStorage) FindOfflineValidationLogsByLicense(ctx context.Context, licenseKey string) ([]*OfflineValidationLog, error) {
	return ps.backend.FindOfflineValidationLogsByLicense(ctx, licenseKey)
}

func (ps *PersistentStorage) FindOfflineValidationLogsByClient(ctx context.Context, clientID string) ([]*OfflineValidationLog, error) {
	return ps.backend.FindOfflineValidationLogsByClient(ctx, clientID)
}

// Subscription methods - forward to backend
func (ps *PersistentStorage) SaveSubscription(ctx context.Context, sub *Subscription) error {
	return ps.backend.SaveSubscription(ctx, sub)
}

func (ps *PersistentStorage) UpdateSubscription(ctx context.Context, sub *Subscription) error {
	return ps.backend.UpdateSubscription(ctx, sub)
}

func (ps *PersistentStorage) GetSubscription(ctx context.Context, subID string) (*Subscription, error) {
	return ps.backend.GetSubscription(ctx, subID)
}

func (ps *PersistentStorage) ListSubscriptions(ctx context.Context) ([]*Subscription, error) {
	return ps.backend.ListSubscriptions(ctx)
}

func (ps *PersistentStorage) ListSubscriptionsByClient(ctx context.Context, clientID string) ([]*Subscription, error) {
	return ps.backend.ListSubscriptionsByClient(ctx, clientID)
}

func (ps *PersistentStorage) DeleteSubscription(ctx context.Context, subID string) error {
	return ps.backend.DeleteSubscription(ctx, subID)
}

func (ps *PersistentStorage) SaveCouponCode(ctx context.Context, coupon *CouponCode) error {
	if err := ps.backend.SaveCouponCode(ctx, coupon); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateCouponCode(ctx context.Context, coupon *CouponCode) error {
	if err := ps.backend.UpdateCouponCode(ctx, coupon); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetCouponCode(ctx context.Context, couponID string) (*CouponCode, error) {
	return ps.backend.GetCouponCode(ctx, couponID)
}

func (ps *PersistentStorage) GetCouponCodeByCode(ctx context.Context, code string) (*CouponCode, error) {
	return ps.backend.GetCouponCodeByCode(ctx, code)
}

func (ps *PersistentStorage) ListCouponCodes(ctx context.Context) ([]*CouponCode, error) {
	return ps.backend.ListCouponCodes(ctx)
}

func (ps *PersistentStorage) SaveCouponRedemption(ctx context.Context, redemption *CouponRedemption) error {
	if err := ps.backend.SaveCouponRedemption(ctx, redemption); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListCouponRedemptionsByCoupon(ctx context.Context, couponID string) ([]*CouponRedemption, error) {
	return ps.backend.ListCouponRedemptionsByCoupon(ctx, couponID)
}

func (ps *PersistentStorage) ListCouponRedemptionsByLicense(ctx context.Context, licenseID string) ([]*CouponRedemption, error) {
	return ps.backend.ListCouponRedemptionsByLicense(ctx, licenseID)
}

func (ps *PersistentStorage) ListCouponRedemptionsByClient(ctx context.Context, clientID string) ([]*CouponRedemption, error) {
	return ps.backend.ListCouponRedemptionsByClient(ctx, clientID)
}

// Email provider/template/message methods - proxy to backend and persist

func (ps *PersistentStorage) SaveEmailProvider(ctx context.Context, provider *email.EmailProvider) error {
	if err := ps.backend.SaveEmailProvider(ctx, provider); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateEmailProvider(ctx context.Context, provider *email.EmailProvider) error {
	if err := ps.backend.UpdateEmailProvider(ctx, provider); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListEmailProviders(ctx context.Context, includeDisabled bool) ([]*email.EmailProvider, error) {
	return ps.backend.ListEmailProviders(ctx, includeDisabled)
}

func (ps *PersistentStorage) GetEmailProvider(ctx context.Context, providerID string) (*email.EmailProvider, error) {
	return ps.backend.GetEmailProvider(ctx, providerID)
}

func (ps *PersistentStorage) DeleteEmailProvider(ctx context.Context, providerID string) error {
	if err := ps.backend.DeleteEmailProvider(ctx, providerID); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) SaveEmailTemplate(ctx context.Context, tpl *email.EmailTemplate) error {
	if err := ps.backend.SaveEmailTemplate(ctx, tpl); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateEmailTemplate(ctx context.Context, tpl *email.EmailTemplate) error {
	if err := ps.backend.UpdateEmailTemplate(ctx, tpl); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListEmailTemplates(ctx context.Context) ([]*email.EmailTemplate, error) {
	return ps.backend.ListEmailTemplates(ctx)
}

func (ps *PersistentStorage) GetEmailTemplate(ctx context.Context, templateID string) (*email.EmailTemplate, error) {
	return ps.backend.GetEmailTemplate(ctx, templateID)
}

func (ps *PersistentStorage) GetEmailTemplateBySlug(ctx context.Context, slug string) (*email.EmailTemplate, error) {
	return ps.backend.GetEmailTemplateBySlug(ctx, slug)
}

func (ps *PersistentStorage) DeleteEmailTemplate(ctx context.Context, templateID string) error {
	if err := ps.backend.DeleteEmailTemplate(ctx, templateID); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) SaveEmailTemplateRoute(ctx context.Context, route *email.EmailTemplateRoute) error {
	if err := ps.backend.SaveEmailTemplateRoute(ctx, route); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListEmailTemplateRoutes(ctx context.Context, templateID, category string) ([]*email.EmailTemplateRoute, error) {
	return ps.backend.ListEmailTemplateRoutes(ctx, templateID, category)
}

func (ps *PersistentStorage) DeleteEmailTemplateRoute(ctx context.Context, routeID string) error {
	if err := ps.backend.DeleteEmailTemplateRoute(ctx, routeID); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) EnqueueEmail(ctx context.Context, msg *email.EmailMessage) error {
	if err := ps.backend.EnqueueEmail(ctx, msg); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateEmailMessage(ctx context.Context, msg *email.EmailMessage) error {
	if err := ps.backend.UpdateEmailMessage(ctx, msg); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetEmailMessage(ctx context.Context, messageID string) (*email.EmailMessage, error) {
	return ps.backend.GetEmailMessage(ctx, messageID)
}

func (ps *PersistentStorage) LeaseNextEmail(ctx context.Context, dueBefore time.Time) (*email.EmailMessage, error) {
	msg, err := ps.backend.LeaseNextEmail(ctx, dueBefore)
	if err != nil || msg == nil {
		return msg, err
	}
	if err := ps.persist(); err != nil {
		return nil, err
	}
	return msg, nil
}

func (ps *PersistentStorage) AppendEmailEvent(ctx context.Context, event *email.EmailEvent) error {
	if err := ps.backend.AppendEmailEvent(ctx, event); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListEmailEvents(ctx context.Context, messageID string) ([]*email.EmailEvent, error) {
	return ps.backend.ListEmailEvents(ctx, messageID)
}

func (ps *PersistentStorage) persist() error {
	snapshot := ps.backend.snapshot()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ps.path), 0o700); err != nil {
		return err
	}
	tmpPath := ps.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, ps.path)
}

func (ps *PersistentStorage) loadFromDisk() error {
	data, err := os.ReadFile(ps.path)
	if err != nil {
		return err
	}
	var snapshot storageSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	ps.backend.loadSnapshot(&snapshot)
	return nil
}

func BuildStorageFromEnv() (Storage, string, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE")))
	switch mode {
	case "", "sqlite", "sql", "sqlite3":
		path := strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_SQLITE_PATH"))
		if path == "" {
			// Default to ~/.licensing/data/licensing.db
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, "", fmt.Errorf("failed to get home directory: %w", err)
			}
			path = filepath.Join(homeDir, ".licensing", "data", "licensing.db")
		} else {
			path = filepath.Clean(path)
		}
		storage, err := NewSQLiteStorage(path)
		if err != nil {
			return nil, "", err
		}
		return storage, fmt.Sprintf("sqlite:%s", path), nil
	case "memory":
		return NewInMemoryStorage(), "memory", nil
	case "file", "disk", "persistent":
		path := strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_FILE"))
		if path == "" {
			// Default to ~/.licensing/data/licensing-state.json
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, "", fmt.Errorf("failed to get home directory: %w", err)
			}
			path = filepath.Join(homeDir, ".licensing", "data", "licensing-state.json")
		} else {
			path = filepath.Clean(path)
		}
		storage, err := NewPersistentStorage(path)
		if err != nil {
			return nil, "", err
		}
		return storage, fmt.Sprintf("file:%s", path), nil
	default:
		return nil, "", fmt.Errorf("unsupported storage mode %q", mode)
	}
}
