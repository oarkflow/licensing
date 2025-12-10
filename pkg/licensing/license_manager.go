package licensing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crypto/ed25519"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	licenseKeyEntropyBytes  = 21
	licenseKeyChecksumBytes = 4
	licenseKeyGroupSize     = 5
)

var licenseKeyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	defaultCustomCheckInterval = 24 * time.Hour
	minCustomCheckInterval     = 5 * time.Minute
)

func normalizeCheckMode(mode LicenseCheckMode) LicenseCheckMode {
	if mode == "" {
		return LicenseCheckModeYearly
	}
	switch mode {
	case LicenseCheckModeNone,
		LicenseCheckModeEachRun,
		LicenseCheckModeMonthly,
		LicenseCheckModeYearly,
		LicenseCheckModeCustom:
		return mode
	default:
		return LicenseCheckModeYearly
	}
}

func normalizeCheckInterval(mode LicenseCheckMode, interval time.Duration) time.Duration {
	if mode != LicenseCheckModeCustom {
		return 0
	}
	if interval < minCustomCheckInterval {
		return defaultCustomCheckInterval
	}
	return interval
}

func ensureLicenseCheckDefaults(license *License) {
	if license == nil {
		return
	}
	license.CheckMode = normalizeCheckMode(license.CheckMode)
	if license.CheckMode == LicenseCheckModeCustom {
		if license.CheckIntervalSecs <= 0 {
			license.CheckIntervalSecs = int64(defaultCustomCheckInterval.Seconds())
		}
	} else {
		license.CheckIntervalSecs = 0
	}
}

func computeNextCheck(license *License, from time.Time) time.Time {
	if license == nil {
		return time.Time{}
	}
	mode := normalizeCheckMode(license.CheckMode)
	if mode == LicenseCheckModeNone {
		return time.Time{}
	}
	location := from.Location()
	switch mode {
	case LicenseCheckModeEachRun:
		return from
	case LicenseCheckModeMonthly:
		year, month, _ := from.Date()
		return time.Date(year, month+1, 1, 0, 0, 0, 0, location)
	case LicenseCheckModeYearly:
		return from.AddDate(1, 0, 0)
	case LicenseCheckModeCustom:
		interval := time.Duration(license.CheckIntervalSecs) * time.Second
		if interval <= 0 {
			interval = defaultCustomCheckInterval
		}
		return from.Add(interval)
	default:
		return from
	}
}

func (lm *LicenseManager) applyLicenseCheckDefaults(license *License) {
	if license == nil {
		return
	}
	ensureLicenseCheckDefaults(license)
	if license.CheckMode == LicenseCheckModeCustom && license.CheckIntervalSecs <= 0 {
		_, interval := lm.DefaultCheckPolicy()
		license.CheckIntervalSecs = int64(interval.Seconds())
	}
	if license.CheckMode == LicenseCheckModeCustom {
		_, interval := lm.DefaultCheckPolicy()
		desired := int64(interval.Seconds())
		if desired <= 0 {
			desired = int64(defaultCustomCheckInterval.Seconds())
		}
		legacyDefault := int64(defaultCustomCheckInterval.Seconds())
		if license.CheckIntervalSecs == legacyDefault && desired != legacyDefault {
			license.CheckIntervalSecs = desired
		}
	}
	if license.CheckMode == LicenseCheckModeNone {
		license.CheckIntervalSecs = 0
	}
}

func (lm *LicenseManager) markServerCheck(license *License, now time.Time) {
	if license == nil {
		return
	}
	lm.applyLicenseCheckDefaults(license)
	if license.CheckMode == LicenseCheckModeNone {
		license.LastCheckAt = time.Time{}
		license.NextCheckAt = time.Time{}
		return
	}
	license.LastCheckAt = now
	license.NextCheckAt = computeNextCheck(license, now)
}

type LicenseManager struct {
	storage              Storage
	signer               SigningProvider
	signerID             string
	offlineSigner        OfflineSigningProvider
	offlineSignerID      string
	publicKeyPath        string
	mu                   sync.RWMutex
	defaultCheckMode     LicenseCheckMode
	defaultCheckInterval time.Duration
}

func NewLicenseManager(storage Storage) (*LicenseManager, error) {
	if storage == nil {
		return nil, fmt.Errorf("storage implementation is required")
	}

	signer, err := BuildSigningProviderFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to configure signing provider: %w", err)
	}

	lm := &LicenseManager{
		storage:              storage,
		signer:               signer,
		signerID:             signer.ID(),
		offlineSigner:        nil,
		offlineSignerID:      "",
		defaultCheckMode:     LicenseCheckModeYearly,
		defaultCheckInterval: defaultCustomCheckInterval,
	}

	// Configure offline signing provider if available
	if offSigner, err2 := BuildOfflineSigningProviderFromEnv(storage); err2 == nil {
		lm.offlineSigner = offSigner
		if id, err3 := offSigner.ActiveKeyID(); err3 == nil {
			lm.offlineSignerID = id
		}
	}

	path, err := lm.savePublicKey()
	if err != nil {
		_ = signer.Close()
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}
	lm.publicKeyPath = path

	return lm, nil
}

func (lm *LicenseManager) savePublicKey() (string, error) {
	if lm.signer == nil {
		return "", fmt.Errorf("signing provider is not configured")
	}
	pubKey := lm.signer.PublicKey()
	if pubKey == nil {
		return "", fmt.Errorf("signing provider returned nil public key")
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home directory: %w", err)
	}
	secureDir := filepath.Join(homeDir, ".licensing")
	if err := os.MkdirAll(secureDir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create secure directory: %w", err)
	}
	pubKeyPath := filepath.Join(secureDir, "server_public_key.pem")
	tmpPath := pubKeyPath + ".tmp"
	if err := os.WriteFile(tmpPath, pubKeyPEM, 0o600); err != nil {
		return "", fmt.Errorf("failed to write public key: %w", err)
	}
	if err := os.Rename(tmpPath, pubKeyPath); err != nil {
		return "", fmt.Errorf("failed to finalize public key: %w", err)
	}
	return pubKeyPath, nil
}

func (lm *LicenseManager) PublicKeyPath() string {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.publicKeyPath
}

func (lm *LicenseManager) SigningProviderID() string {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.signerID
}

func (lm *LicenseManager) SetDefaultCheckPolicy(mode LicenseCheckMode, interval time.Duration) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	mode = normalizeCheckMode(mode)
	lm.defaultCheckMode = mode
	if mode != LicenseCheckModeCustom {
		interval = 0
	}
	if interval <= 0 && mode == LicenseCheckModeCustom {
		interval = defaultCustomCheckInterval
	}
	lm.defaultCheckInterval = interval
}

func (lm *LicenseManager) DefaultCheckPolicy() (LicenseCheckMode, time.Duration) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	mode := normalizeCheckMode(lm.defaultCheckMode)
	interval := lm.defaultCheckInterval
	if mode == LicenseCheckModeCustom && interval <= 0 {
		interval = defaultCustomCheckInterval
	}
	return mode, interval
}

// Storage returns the underlying storage implementation.
func (lm *LicenseManager) Storage() Storage {
	return lm.storage
}

// ensureLicenseEntitlements computes and attaches entitlements to a license if they're missing.
// It tries to look up the plan by ID first, then by slug if needed.
func (lm *LicenseManager) ensureLicenseEntitlements(ctx context.Context, license *License) error {
	if license == nil {
		return nil
	}

	// If entitlements already exist, nothing to do
	if license.Entitlements != nil {
		return nil
	}

	// Try to get product and plan IDs
	productID := strings.TrimSpace(license.ProductID)
	planID := strings.TrimSpace(license.PlanID)
	planSlug := strings.TrimSpace(license.PlanSlug)

	// If we don't have plan info, we can't compute entitlements
	if planSlug == "" && planID == "" {
		return nil
	}

	// If we have planID and productID, compute entitlements directly
	if productID != "" && planID != "" {
		entitlements, err := lm.storage.ComputeLicenseEntitlements(ctx, productID, planID)
		if err != nil {
			return fmt.Errorf("failed to compute entitlements: %w", err)
		}
		license.Entitlements = entitlements
		return nil
	}

	// Try to find plan by ID first
	var plan *Plan
	var err error
	if planID != "" {
		plan, err = lm.storage.GetPlan(ctx, planID)
	}

	// If not found by ID, try by slug
	if plan == nil && planSlug != "" {
		plan, err = lm.storage.FindPlanBySlug(ctx, planSlug)
	}

	if plan == nil {
		if err != nil {
			return fmt.Errorf("failed to find plan: %w", err)
		}
		return nil // No plan found, can't compute entitlements
	}

	// Update license with plan info if missing
	if license.ProductID == "" {
		license.ProductID = plan.ProductID
	}
	if license.PlanID == "" {
		license.PlanID = plan.ID
	}

	// Compute entitlements
	entitlements, err := lm.storage.ComputeLicenseEntitlements(ctx, plan.ProductID, plan.ID)
	if err != nil {
		return fmt.Errorf("failed to compute entitlements: %w", err)
	}
	license.Entitlements = entitlements
	return nil
}

func (lm *LicenseManager) Close() error {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if lm.signer != nil {
		err := lm.signer.Close()
		lm.signer = nil
		return err
	}
	return nil
}

func (lm *LicenseManager) EnsureDefaultAdmin(ctx context.Context) (*AdminUser, string, string, error) {
	users, err := lm.storage.ListAdminUsers(ctx)
	if err != nil {
		return nil, "", "", err
	}
	if len(users) > 0 {
		return nil, "", "", nil
	}
	password, err := lm.randomSecret(16)
	if err != nil {
		return nil, "", "", err
	}
	user, err := lm.CreateAdminUser(ctx, "admin", password)
	if err != nil {
		return nil, "", "", err
	}
	apiKey, _, err := lm.GenerateAPIKey(ctx, user.ID)
	if err != nil {
		return user, password, "", err
	}
	return user, password, apiKey, nil
}

func (lm *LicenseManager) CreateAdminUser(ctx context.Context, username, password string) (*AdminUser, error) {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username == "" {
		return nil, fmt.Errorf("admin username is required")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	now := time.Now()
	user := &AdminUser{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := lm.storage.CreateAdminUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// AuthenticateAdmin verifies admin credentials and returns the user if valid
func (lm *LicenseManager) AuthenticateAdmin(ctx context.Context, username, password string) (*AdminUser, error) {
	user, err := lm.storage.GetAdminUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return user, nil
}

func (lm *LicenseManager) ListAdminUsers(ctx context.Context) ([]*AdminUser, error) {
	return lm.storage.ListAdminUsers(ctx)
}

// GetAdminUser retrieves an admin user by ID
func (lm *LicenseManager) GetAdminUser(ctx context.Context, userID string) (*AdminUser, error) {
	return lm.storage.GetAdminUser(ctx, userID)
}

// ChangeAdminPassword changes an admin user's password
func (lm *LicenseManager) ChangeAdminPassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	user, err := lm.storage.GetAdminUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(currentPassword)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	if len(newPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = hash
	user.UpdatedAt = time.Now()

	return lm.storage.UpdateAdminUser(ctx, user)
}

// UpdateAdminUser updates the username for an admin user
func (lm *LicenseManager) UpdateAdminUser(ctx context.Context, userID, username string) (*AdminUser, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	user, err := lm.storage.GetAdminUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(user.Username, username) {
		return user, nil
	}
	user.Username = username
	user.UpdatedAt = time.Now()
	if err := lm.storage.UpdateAdminUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// DeleteAdminUser removes an admin user unless it is the last remaining account
func (lm *LicenseManager) DeleteAdminUser(ctx context.Context, userID string) error {
	users, err := lm.storage.ListAdminUsers(ctx)
	if err != nil {
		return err
	}
	if len(users) <= 1 {
		return fmt.Errorf("cannot delete the last admin user")
	}
	return lm.storage.DeleteAdminUser(ctx, userID)
}

func (lm *LicenseManager) GenerateAPIKey(ctx context.Context, userID string) (string, *APIKeyRecord, error) {
	if _, err := lm.storage.GetAdminUser(ctx, userID); err != nil {
		return "", nil, err
	}
	secret, err := lm.randomSecret(24)
	if err != nil {
		return "", nil, err
	}
	hash := hashAPIKey(secret)
	record := &APIKeyRecord{
		ID:        uuid.New().String(),
		UserID:    userID,
		Hash:      hash,
		Prefix:    strings.ToUpper(secret[:8]),
		CreatedAt: time.Now(),
	}
	if err := lm.storage.SaveAPIKey(ctx, record); err != nil {
		return "", nil, err
	}
	return secret, record, nil
}

func (lm *LicenseManager) ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKeyRecord, error) {
	if _, err := lm.storage.GetAdminUser(ctx, userID); err != nil {
		return nil, err
	}
	return lm.storage.ListAPIKeysByUser(ctx, userID)
}

// GenerateClientAPIKey generates a new API key associated with a client (non-admin).
func (lm *LicenseManager) GenerateClientAPIKey(ctx context.Context, clientID string) (string, *APIKeyRecord, error) {
	if _, err := lm.GetClient(ctx, clientID); err != nil {
		return "", nil, err
	}
	secret, err := lm.randomSecret(24)
	if err != nil {
		return "", nil, err
	}
	hash := hashAPIKey(secret)
	record := &APIKeyRecord{
		ID:        uuid.New().String(),
		UserID:    "", // no admin user
		ClientID:  clientID,
		Hash:      hash,
		Prefix:    strings.ToUpper(secret[:8]),
		CreatedAt: time.Now(),
	}
	if err := lm.storage.SaveAPIKey(ctx, record); err != nil {
		return "", nil, err
	}
	return secret, record, nil
}

// ListAPIKeysByClient returns all API keys belonging to a client
func (lm *LicenseManager) ListAPIKeysByClient(ctx context.Context, clientID string) ([]*APIKeyRecord, error) {
	if _, err := lm.GetClient(ctx, clientID); err != nil {
		return nil, err
	}
	return lm.storage.ListAPIKeysByClient(ctx, clientID)
}

// ValidateClientAPIKey validates an API key and returns the associated client if it's a client key
func (lm *LicenseManager) ValidateClientAPIKey(ctx context.Context, token string) (*Client, *APIKeyRecord, error) {
	if token == "" {
		return nil, nil, fmt.Errorf("api key required")
	}
	hash := hashAPIKey(token)
	record, err := lm.storage.GetAPIKeyByHash(ctx, hash)
	if err != nil {
		return nil, nil, err
	}
	if record.ClientID == "" {
		return nil, nil, fmt.Errorf("not a client API key")
	}
	client, err := lm.GetClient(ctx, record.ClientID)
	if err != nil {
		return nil, nil, err
	}
	record.LastUsed = time.Now()
	if err := lm.storage.UpdateAPIKey(ctx, record); err != nil {
		log.Printf("failed to update api key usage: %v", err)
	}
	return client, record, nil
}

// RevokeAPIKey deletes an API key by ID
func (lm *LicenseManager) RevokeAPIKey(ctx context.Context, keyID string) error {
	return lm.storage.DeleteAPIKey(ctx, keyID)
}

// DeleteAPIKey deletes an API key by ID (alias for RevokeAPIKey)
func (lm *LicenseManager) DeleteAPIKey(ctx context.Context, keyID string) error {
	return lm.storage.DeleteAPIKey(ctx, keyID)
}

func (lm *LicenseManager) ValidateAPIKey(ctx context.Context, token string) (*AdminUser, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("api key required")
	}
	hash := hashAPIKey(token)
	record, err := lm.storage.GetAPIKeyByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	user, err := lm.storage.GetAdminUser(ctx, record.UserID)
	if err != nil {
		return nil, err
	}
	record.LastUsed = time.Now()
	if err := lm.storage.UpdateAPIKey(ctx, record); err != nil {
		log.Printf("failed to update api key usage: %v", err)
	}
	return user, nil
}

func (lm *LicenseManager) CreateClient(ctx context.Context, email string) (*Client, error) {
	return lm.CreateClientWithProfile(ctx, email, "", "", "")
}

func (lm *LicenseManager) CreateClientWithProfile(ctx context.Context, email, username, name, company string) (*Client, error) {
	email = strings.TrimSpace(email)
	if !emailRegex.MatchString(email) {
		return nil, fmt.Errorf("invalid email address")
	}

	now := time.Now()
	client := &Client{
		ID:          uuid.New().String(),
		Username:    strings.TrimSpace(username),
		Email:       email,
		Name:        strings.TrimSpace(name),
		CompanyName: strings.TrimSpace(company),
		Status:      ClientStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := lm.storage.SaveClient(ctx, client); err != nil {
		if errors.Is(err, errClientExists) {
			return nil, fmt.Errorf("client with email already exists")
		}
		return nil, fmt.Errorf("failed to save client: %w", err)
	}

	return client, nil
}

// CreateClientWithPassword creates a client with a password (local auth). Password is hashed using bcrypt.
func (lm *LicenseManager) CreateClientWithPassword(ctx context.Context, email, password, username, name, company string) (*Client, error) {
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("password is required")
	}
	client, err := lm.CreateClientWithProfile(ctx, email, username, name, company)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	client.PasswordHash = hash
	if err := lm.storage.UpdateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to save client password: %w", err)
	}
	return client, nil
}

// VerifyClientPassword verifies an email/password combination and returns the client if valid.
func (lm *LicenseManager) VerifyClientPassword(ctx context.Context, email, password string) (*Client, error) {
	client, err := lm.storage.GetClientByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if len(client.PasswordHash) == 0 {
		return nil, fmt.Errorf("password auth not configured for this client")
	}
	if err := bcrypt.CompareHashAndPassword(client.PasswordHash, []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return client, nil
}

// VerifyClientPasswordByUsername verifies an username/password combination and returns the client if valid.
func (lm *LicenseManager) VerifyClientPasswordByUsername(ctx context.Context, username, password string) (*Client, error) {
	client, err := lm.storage.GetClientByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if len(client.PasswordHash) == 0 {
		return nil, fmt.Errorf("password auth not configured for this client")
	}
	if err := bcrypt.CompareHashAndPassword(client.PasswordHash, []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return client, nil
}

func (lm *LicenseManager) UpdateClientProfile(ctx context.Context, client *Client, name, company string) (*Client, error) {
	if client == nil {
		return nil, fmt.Errorf("client is required")
	}
	trimmedName := strings.TrimSpace(name)
	trimmedCompany := strings.TrimSpace(company)
	changed := false
	if trimmedName != "" && trimmedName != client.Name {
		client.Name = trimmedName
		changed = true
	}
	if trimmedCompany != "" && trimmedCompany != client.CompanyName {
		client.CompanyName = trimmedCompany
		changed = true
	}
	if !changed {
		return client, nil
	}
	client.UpdatedAt = time.Now()
	if err := lm.storage.UpdateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}
	return client, nil
}

func (lm *LicenseManager) GetClientByEmail(ctx context.Context, email string) (*Client, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	client, err := lm.storage.GetClientByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (lm *LicenseManager) GetClientByUsername(ctx context.Context, username string) (*Client, error) {
	return lm.storage.GetClientByUsername(ctx, username)
}

// GetClient retrieves a client by ID
func (lm *LicenseManager) GetClient(ctx context.Context, clientID string) (*Client, error) {
	return lm.storage.GetClient(ctx, clientID)
}

func (lm *LicenseManager) ListClients(ctx context.Context) ([]*Client, error) {
	return lm.storage.ListClients(ctx)
}

func (lm *LicenseManager) BanClient(ctx context.Context, clientID, reason string) (*Client, error) {
	client, err := lm.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.Status == ClientStatusBanned {
		return client, nil
	}
	client.Status = ClientStatusBanned
	client.BannedAt = time.Now()
	client.BanReason = strings.TrimSpace(reason)
	client.UpdatedAt = time.Now()
	if err := lm.storage.UpdateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}
	return client, nil
}

func (lm *LicenseManager) UnbanClient(ctx context.Context, clientID string) (*Client, error) {
	client, err := lm.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	client.Status = ClientStatusActive
	client.BannedAt = time.Time{}
	client.BanReason = ""
	client.UpdatedAt = time.Now()
	if err := lm.storage.UpdateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}
	return client, nil
}

// GenerateLicenseOptions contains optional parameters for license generation.
type GenerateLicenseOptions struct {
	ProductID     string
	PlanID        string
	FeatureScopes []FeatureScopeSelection
}

func (lm *LicenseManager) GenerateLicense(ctx context.Context, clientID string, duration time.Duration, maxDevices int, planSlug string, mode LicenseCheckMode, interval time.Duration) (*License, error) {
	return lm.GenerateLicenseWithOptions(ctx, clientID, duration, maxDevices, planSlug, mode, interval, nil)
}

func (lm *LicenseManager) GenerateLicenseWithOptions(ctx context.Context, clientID string, duration time.Duration, maxDevices int, planSlug string, mode LicenseCheckMode, interval time.Duration, opts *GenerateLicenseOptions) (*License, error) {
	if maxDevices <= 0 {
		maxDevices = 1
	}
	planSlug = strings.TrimSpace(planSlug)
	if planSlug == "" {
		return nil, fmt.Errorf("plan slug is required")
	}
	mode = normalizeCheckMode(mode)
	interval = normalizeCheckInterval(mode, interval)
	if mode == LicenseCheckModeCustom && interval <= 0 {
		_, defaultInterval := lm.DefaultCheckPolicy()
		interval = normalizeCheckInterval(mode, defaultInterval)
	}
	client, err := lm.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.Status == ClientStatusBanned {
		return nil, fmt.Errorf("client is banned")
	}

	var productID, planID string
	var featureSelections []FeatureScopeSelection
	var entitlements *LicenseEntitlements
	var isTrial bool
	var trialStartedAt time.Time
	if opts != nil {
		productID = strings.TrimSpace(opts.ProductID)
		planID = strings.TrimSpace(opts.PlanID)
		if len(opts.FeatureScopes) > 0 {
			featureSelections = opts.FeatureScopes
		}

		if productID != "" && planID != "" {
			plan, err := lm.storage.GetPlan(ctx, planID)
			if err != nil {
				return nil, fmt.Errorf("failed to get plan: %w", err)
			}
			if plan.ProductID != productID {
				return nil, fmt.Errorf("plan does not belong to the specified product")
			}
			if !plan.IsActive {
				return nil, fmt.Errorf("plan is not active")
			}
			planSlug = plan.Slug
			if plan.IsTrial {
				isTrial = true
				trialStartedAt = time.Now()
			}
			entitlements, err = lm.storage.ComputeLicenseEntitlements(ctx, productID, planID)
			if err != nil {
				return nil, fmt.Errorf("failed to compute entitlements: %w", err)
			}
		}
	}
	if len(featureSelections) > 0 && (productID == "" || planID == "") {
		return nil, fmt.Errorf("feature scopes require both product_id and plan_id")
	}
	if entitlements != nil && len(featureSelections) > 0 {
		applyFeatureScopeSelections(entitlements, featureSelections)
	}

	licenseKey := lm.generateLicenseKey(client.Email, client.ID)
	now := time.Now()
	license := &License{
		ID:                 uuid.New().String(),
		ClientID:           clientID,
		Email:              client.Email,
		ProductID:          productID,
		PlanID:             planID,
		PlanSlug:           planSlug,
		LicenseKey:         licenseKey,
		IsRevoked:          false,
		IsActivated:        false,
		IssuedAt:           now,
		ExpiresAt:          now.Add(duration),
		MaxDevices:         maxDevices,
		Devices:            make(map[string]*LicenseDevice),
		CurrentActivations: 0,
		CheckMode:          mode,
		CheckIntervalSecs:  int64(interval.Seconds()),
		Entitlements:       entitlements,
		IsTrial:            isTrial,
		TrialStartedAt:     trialStartedAt,
	}
	lm.applyLicenseCheckDefaults(license)
	refreshLicenseDeviceStats(license)

	if err := lm.storage.SaveLicense(ctx, license); err != nil {
		if errors.Is(err, errLicenseExists) {
			return nil, fmt.Errorf("license already exists")
		}
		return nil, fmt.Errorf("failed to save license: %w", err)
	}
	return license, nil
}

// UpdateLicenseEntitlements recomputes a license's entitlements and applies overrides.
func (lm *LicenseManager) UpdateLicenseEntitlements(ctx context.Context, licenseID string, selections []FeatureScopeSelection) (*License, error) {
	if strings.TrimSpace(licenseID) == "" {
		return nil, fmt.Errorf("license_id is required")
	}
	license, err := lm.storage.GetLicense(ctx, licenseID)
	if err != nil {
		return nil, err
	}
	productID := strings.TrimSpace(license.ProductID)
	planID := strings.TrimSpace(license.PlanID)
	if productID == "" || planID == "" {
		return nil, fmt.Errorf("license is missing product or plan information")
	}
	entitlements, err := lm.storage.ComputeLicenseEntitlements(ctx, productID, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to compute entitlements: %w", err)
	}
	if len(selections) > 0 {
		applyFeatureScopeSelections(entitlements, selections)
	}
	license.Entitlements = entitlements
	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to persist license entitlements: %w", err)
	}
	return license, nil
}

func applyFeatureScopeSelections(entitlements *LicenseEntitlements, selections []FeatureScopeSelection) {
	if entitlements == nil || len(selections) == 0 {
		return
	}
	for _, feature := range selections {
		slug := strings.TrimSpace(feature.FeatureSlug)
		if slug == "" {
			continue
		}
		grant, ok := entitlements.Features[slug]
		if !ok {
			continue
		}
		grant.Enabled = feature.Enabled
		if len(feature.Scopes) > 0 && grant.Scopes == nil {
			grant.Scopes = make(map[string]ScopeGrant)
		}
		for _, scope := range feature.Scopes {
			scopeSlug := strings.TrimSpace(scope.ScopeSlug)
			if scopeSlug == "" {
				continue
			}
			scopeGrant, exists := grant.Scopes[scopeSlug]
			if !exists {
				continue
			}
			scopeGrant.Permission = scope.Permission
			scopeGrant.Limit = scope.Limit
			grant.Scopes[scopeSlug] = scopeGrant
		}
		if !feature.Enabled {
			for key, scopeGrant := range grant.Scopes {
				scopeGrant.Permission = ScopePermissionDeny
				grant.Scopes[key] = scopeGrant
			}
		}
		entitlements.Features[slug] = grant
	}
}

// TrialLicenseRequest contains the parameters for generating a trial license.
type TrialLicenseRequest struct {
	Email             string
	DeviceFingerprint string
	ProductID         string
	TrialDurationDays int
	SubscriptionURL   string
}

// TrialLicenseResponse contains the result of a trial license request.
type TrialLicenseResponse struct {
	Success         bool      `json:"success"`
	Message         string    `json:"message"`
	License         *License  `json:"license,omitempty"`
	AlreadyUsed     bool      `json:"already_used"`
	SubscriptionURL string    `json:"subscription_url,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

// DefaultTrialDuration is the default trial period.
const DefaultTrialDuration = 14 * 24 * time.Hour // 14 days

// GenerateTrialLicense creates a trial license for a device.
// It checks if the device has already used a trial and prevents duplicate trials.
// Trial licenses allow unlimited device sharing but only one trial per device fingerprint.
func (lm *LicenseManager) GenerateTrialLicense(ctx context.Context, req *TrialLicenseRequest) (*TrialLicenseResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("trial request is required")
	}
	email := strings.TrimSpace(req.Email)
	if !emailRegex.MatchString(email) {
		return nil, fmt.Errorf("invalid email address")
	}
	fingerprint := strings.TrimSpace(req.DeviceFingerprint)
	if !fingerprintRegex.MatchString(fingerprint) {
		return nil, fmt.Errorf("invalid device fingerprint format")
	}

	// Check if device has already used a trial
	hasUsed, err := lm.storage.HasDeviceUsedTrial(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to check trial status: %w", err)
	}
	if hasUsed {
		existingTrial, _ := lm.storage.GetDeviceTrial(ctx, fingerprint)
		return &TrialLicenseResponse{
			Success:         false,
			Message:         "This device has already used a trial license. Please purchase a subscription.",
			AlreadyUsed:     true,
			SubscriptionURL: req.SubscriptionURL,
			ExpiresAt:       existingTrial.TrialExpiresAt,
		}, nil
	}

	// Get or create client
	client, err := lm.storage.GetClientByEmail(ctx, email)
	if err != nil {
		// Create new client if doesn't exist
		client, err = lm.CreateClient(ctx, email)
		if err != nil {
			return nil, fmt.Errorf("failed to create client: %w", err)
		}
	}
	if client.Status == ClientStatusBanned {
		return &TrialLicenseResponse{
			Success: false,
			Message: "Client is banned",
		}, nil
	}

	// Determine trial duration
	duration := DefaultTrialDuration
	if req.TrialDurationDays > 0 {
		duration = time.Duration(req.TrialDurationDays) * 24 * time.Hour
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	// Generate trial license key
	licenseKey := lm.generateLicenseKey(email, client.ID)

	// Compute full entitlements if product is specified
	var entitlements *LicenseEntitlements
	productID := strings.TrimSpace(req.ProductID)
	if productID != "" {
		// For trial, enable all features of the product
		entitlements, err = lm.computeTrialEntitlements(ctx, productID)
		if err != nil {
			log.Printf("Warning: failed to compute trial entitlements: %v", err)
		}
	}

	// Create trial license with unlimited sharing (MaxDevices = 0 means unlimited)
	license := &License{
		ID:                     uuid.New().String(),
		ClientID:               client.ID,
		Email:                  email,
		ProductID:              productID,
		PlanSlug:               "trial",
		LicenseKey:             licenseKey,
		IsRevoked:              false,
		IsActivated:            false,
		IssuedAt:               now,
		ExpiresAt:              expiresAt,
		MaxDevices:             0, // Unlimited device sharing during trial
		Devices:                make(map[string]*LicenseDevice),
		CurrentActivations:     0,
		CheckMode:              LicenseCheckModeEachRun,
		IsTrial:                true,
		TrialStartedAt:         now,
		TrialDeviceFingerprint: fingerprint,
		Entitlements:           entitlements,
	}
	lm.applyLicenseCheckDefaults(license)

	// Save the license
	if err := lm.storage.SaveLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to save trial license: %w", err)
	}

	// Register this device as having used a trial
	deviceTrial := &DeviceTrial{
		DeviceFingerprint: fingerprint,
		LicenseID:         license.ID,
		ClientID:          client.ID,
		Email:             email,
		ProductID:         productID,
		TrialStartedAt:    now,
		TrialExpiresAt:    expiresAt,
		CreatedAt:         now,
	}
	if err := lm.storage.SaveDeviceTrial(ctx, deviceTrial); err != nil {
		// If we fail to record the trial, we should revoke the license to maintain consistency
		_ = lm.storage.UpdateLicense(ctx, &License{ID: license.ID, IsRevoked: true})
		return nil, fmt.Errorf("failed to register trial: %w", err)
	}

	return &TrialLicenseResponse{
		Success:         true,
		Message:         fmt.Sprintf("Trial license activated. Expires on %s", expiresAt.Format("2006-01-02")),
		License:         license,
		SubscriptionURL: req.SubscriptionURL,
		ExpiresAt:       expiresAt,
	}, nil
}

// computeTrialEntitlements computes full feature entitlements for a trial license.
// Trial licenses get access to all features of the product.
func (lm *LicenseManager) computeTrialEntitlements(ctx context.Context, productID string) (*LicenseEntitlements, error) {
	product, err := lm.storage.GetProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("failed to get product: %w", err)
	}

	features, err := lm.storage.ListFeaturesByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("failed to list features: %w", err)
	}

	entitlements := &LicenseEntitlements{
		ProductID:   productID,
		ProductSlug: product.Slug,
		PlanSlug:    "trial",
		Features:    make(map[string]FeatureGrant),
	}

	for _, feature := range features {
		scopes, err := lm.storage.ListFeatureScopes(ctx, feature.ID)
		if err != nil {
			continue
		}

		scopeGrants := make(map[string]ScopeGrant)
		for _, scope := range scopes {
			scopeGrants[scope.Slug] = ScopeGrant{
				ScopeID:    scope.ID,
				ScopeSlug:  scope.Slug,
				Permission: ScopePermissionAllow, // Allow all for trial
				Metadata:   scope.Metadata,
			}
		}

		entitlements.Features[feature.Slug] = FeatureGrant{
			FeatureID:   feature.ID,
			FeatureSlug: feature.Slug,
			Category:    feature.Category,
			Enabled:     true, // All features enabled for trial
			Scopes:      scopeGrants,
		}
	}

	return entitlements, nil
}

// HasDeviceUsedTrial checks if a device has already used a trial license.
func (lm *LicenseManager) HasDeviceUsedTrial(ctx context.Context, deviceFingerprint string) (bool, error) {
	return lm.storage.HasDeviceUsedTrial(ctx, deviceFingerprint)
}

// GetDeviceTrial retrieves the trial information for a device.
func (lm *LicenseManager) GetDeviceTrial(ctx context.Context, deviceFingerprint string) (*DeviceTrial, error) {
	return lm.storage.GetDeviceTrial(ctx, deviceFingerprint)
}

func (lm *LicenseManager) RevokeLicense(ctx context.Context, licenseID, reason string) (*License, error) {
	license, err := lm.storage.GetLicense(ctx, licenseID)
	if err != nil {
		return nil, err
	}
	license.IsRevoked = true
	license.RevokedAt = time.Now()
	license.RevokeReason = strings.TrimSpace(reason)
	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to revoke license: %w", err)
	}
	return license, nil
}

func (lm *LicenseManager) ReinstateLicense(ctx context.Context, licenseID string) (*License, error) {
	license, err := lm.storage.GetLicense(ctx, licenseID)
	if err != nil {
		return nil, err
	}
	license.IsRevoked = false
	license.RevokedAt = time.Time{}
	license.RevokeReason = ""
	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to reinstate license: %w", err)
	}
	return license, nil
}

func (lm *LicenseManager) BackfillLicenseCheckPolicy(ctx context.Context) error {
	if lm.storage == nil {
		return fmt.Errorf("storage not configured")
	}
	licenses, err := lm.storage.ListLicenses(ctx)
	if err != nil {
		return err
	}
	modeDefault, intervalDefault := lm.DefaultCheckPolicy()
	now := time.Now()
	for _, license := range licenses {
		if license == nil {
			continue
		}
		originalMode := license.CheckMode
		originalInterval := license.CheckIntervalSecs
		originalNext := license.NextCheckAt
		currentMode := normalizeCheckMode(license.CheckMode)
		if (strings.TrimSpace(string(license.CheckMode)) == "" || (currentMode == LicenseCheckModeEachRun && modeDefault != LicenseCheckModeEachRun)) && license.NextCheckAt.IsZero() {
			license.CheckMode = modeDefault
			currentMode = modeDefault
		}
		if currentMode == LicenseCheckModeCustom && license.CheckIntervalSecs <= 0 {
			license.CheckIntervalSecs = int64(intervalDefault.Seconds())
		}
		if currentMode == LicenseCheckModeNone {
			if !license.NextCheckAt.IsZero() || !license.LastCheckAt.IsZero() {
				license.NextCheckAt = time.Time{}
				license.LastCheckAt = time.Time{}
			}
		} else if license.NextCheckAt.IsZero() {
			license.NextCheckAt = computeNextCheck(license, now)
		}
		if license.CheckMode != originalMode || license.CheckIntervalSecs != originalInterval || !license.NextCheckAt.Equal(originalNext) {
			if err := lm.storage.UpdateLicense(ctx, license); err != nil {
				return err
			}
		}
	}
	return nil
}

func (lm *LicenseManager) generateLicenseKey(email, clientID string) string {
	entropy, err := lm.randomBytes(licenseKeyEntropyBytes)
	if err != nil {
		entropy = make([]byte, licenseKeyEntropyBytes)
		if _, fallbackErr := rand.Read(entropy); fallbackErr != nil {
			panic(fmt.Sprintf("failed to obtain random bytes: %v", fallbackErr))
		}
	}

	checksum := lm.licenseKeyChecksum(entropy, email, clientID)
	raw := append(entropy, checksum...)
	encoded := strings.ToUpper(licenseKeyEncoding.EncodeToString(raw))
	return chunkLicenseKey(encoded, licenseKeyGroupSize)
}

func (lm *LicenseManager) licenseKeyChecksum(entropy []byte, email, clientID string) []byte {
	keyMaterial := strings.TrimSpace(clientID)
	if keyMaterial == "" {
		keyMaterial = "default-license-key"
	}
	mac := hmac.New(sha256.New, []byte(keyMaterial))
	mac.Write(entropy)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	sum := mac.Sum(nil)
	checksum := make([]byte, licenseKeyChecksumBytes)
	copy(checksum, sum[:licenseKeyChecksumBytes])
	return checksum
}

func chunkLicenseKey(value string, groupSize int) string {
	if groupSize <= 0 {
		return value
	}
	var parts []string
	for i := 0; i < len(value); i += groupSize {
		end := i + groupSize
		if end > len(value) {
			end = len(value)
		}
		parts = append(parts, value[i:end])
	}
	return strings.Join(parts, "-")
}

func (lm *LicenseManager) randomSecret(numBytes int) (string, error) {
	if numBytes <= 0 {
		numBytes = 16
	}
	raw, err := lm.randomBytes(numBytes)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(raw)), nil
}

func hashAPIKey(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func (lm *LicenseManager) randomBytes(numBytes int) ([]byte, error) {
	if numBytes <= 0 {
		return nil, fmt.Errorf("numBytes must be positive")
	}
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("failed to read secure random bytes: %w", err)
	}
	return buf, nil
}

func (lm *LicenseManager) ActivateLicense(ctx context.Context, req *ActivationRequest) (*ActivationResponse, error) {
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	license, err := lm.storage.GetLicenseByKey(ctx, req.LicenseKey)
	if err != nil {
		return &ActivationResponse{Success: false, Message: "Invalid license key"}, nil
	}

	// Validate product ID if provided in request
	reqProductID := strings.TrimSpace(req.ProductID)
	if reqProductID != "" {
		licenseProductID := strings.TrimSpace(license.ProductID)
		if licenseProductID == "" {
			message := "License is not associated with any product"
			lm.recordActivationAttempt(ctx, license, req, false, message)
			return &ActivationResponse{Success: false, Message: message}, nil
		}
		// Check if reqProductID matches license's product ID or product slug
		productMatch := false
		if licenseProductID == reqProductID {
			productMatch = true
		} else {
			// Try to match by slug
			product, err := lm.storage.GetProduct(ctx, licenseProductID)
			if err == nil && product != nil && strings.EqualFold(product.Slug, reqProductID) {
				productMatch = true
			}
		}
		if !productMatch {
			message := "License is not valid for this product"
			lm.recordActivationAttempt(ctx, license, req, false, message)
			return &ActivationResponse{Success: false, Message: message}, nil
		}
	}

	client, err := lm.storage.GetClient(ctx, license.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to load client: %w", err)
	}

	if client.Status == ClientStatusBanned {
		message := "Client is banned"
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}

	now := time.Now()
	if license.IsRevoked {
		message := "License has been revoked"
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}

	if now.After(license.ExpiresAt) {
		message := fmt.Sprintf("License expired on %s", license.ExpiresAt.Format("2006-01-02"))
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}

	if license.Devices == nil {
		license.Devices = make(map[string]*LicenseDevice)
	}

	identity, needsAttach, err := lm.resolveLicenseIdentity(license, req, true)
	if err != nil {
		message := err.Error()
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}

	device, exists := license.Devices[req.DeviceFingerprint]
	if !exists {
		if license.MaxDevices > 0 && len(license.Devices) >= license.MaxDevices {
			message := fmt.Sprintf("Maximum devices (%d) reached", license.MaxDevices)
			lm.recordActivationAttempt(ctx, license, req, false, message)
			return &ActivationResponse{Success: false, Message: message}, nil
		}
		transportKey, err := lm.randomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate transport key: %w", err)
		}
		device = &LicenseDevice{
			Fingerprint:  req.DeviceFingerprint,
			ActivatedAt:  now,
			LastSeenAt:   now,
			TransportKey: transportKey,
		}
		license.Devices[req.DeviceFingerprint] = device
	} else {
		device.LastSeenAt = now
		if len(device.TransportKey) == 0 {
			transportKey, err := lm.randomBytes(32)
			if err != nil {
				return nil, fmt.Errorf("failed to refresh transport key: %w", err)
			}
			device.TransportKey = transportKey
		}
	}

	license.IsActivated = true
	license.LastActivatedAt = now
	if needsAttach {
		attachAuthorizedIdentity(license, identity)
	}
	refreshLicenseDeviceStats(license)
	lm.markServerCheck(license, now)

	// Ensure entitlements are computed if missing
	if err := lm.ensureLicenseEntitlements(ctx, license); err != nil {
		log.Printf("Warning: failed to compute entitlements for license %s: %v", license.ID, err)
		// Don't fail activation if entitlements can't be computed
	}

	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to persist license state: %w", err)
	}

	resp, err := lm.issueEncryptedLicenseResponse(license, identity, req.DeviceFingerprint, device.TransportKey)
	if err != nil {
		return nil, err
	}
	resp.Message = "License activated successfully"
	log.Printf("Activated license for %s on device %s", identity.Email, truncateFingerprint(req.DeviceFingerprint))
	lm.recordActivationAttempt(ctx, license, req, true, resp.Message)
	return resp, nil
}

func (lm *LicenseManager) issueEncryptedLicenseResponse(license *License, identity *LicenseIdentity, fingerprint string, sessionKey []byte) (*ActivationResponse, error) {
	if license == nil {
		return nil, fmt.Errorf("license missing")
	}
	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("invalid session key length")
	}
	licenseData := lm.buildLicensePayload(license, identity)
	licenseJSON, err := json.Marshal(licenseData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal license: %w", err)
	}
	nonce, err := lm.randomBytes(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	transportKeyMaterial := fingerprint + hex.EncodeToString(nonce)
	transportHash := sha256.Sum256([]byte(transportKeyMaterial))
	transportKey := transportHash[:]
	plaintext := append([]byte{}, sessionKey...)
	plaintext = append(plaintext, licenseJSON...)
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	encryptedData := gcm.Seal(nil, nonce, plaintext, nil)
	dataHash := sha256.Sum256(encryptedData)
	signature, err := lm.signer.Sign(dataHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	pubKey := lm.signer.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("signing provider returned nil public key")
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	return &ActivationResponse{
		Success:          true,
		EncryptedLicense: hex.EncodeToString(encryptedData),
		Nonce:            hex.EncodeToString(nonce),
		Signature:        hex.EncodeToString(signature),
		PublicKey:        string(pubKeyPEM),
		ExpiresAt:        license.ExpiresAt,
	}, nil
}

func (lm *LicenseManager) VerifyLicense(ctx context.Context, req *ActivationRequest) (*ActivationResponse, error) {
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	license, err := lm.storage.GetLicenseByKey(ctx, req.LicenseKey)
	if err != nil {
		return &ActivationResponse{Success: false, Message: "Invalid license key"}, nil
	}

	// Validate product ID if provided in request
	reqProductID := strings.TrimSpace(req.ProductID)
	if reqProductID != "" {
		licenseProductID := strings.TrimSpace(license.ProductID)
		if licenseProductID == "" {
			message := "License is not associated with any product"
			lm.recordActivationAttempt(ctx, license, req, false, message)
			return &ActivationResponse{Success: false, Message: message}, nil
		}
		// Check if reqProductID matches license's product ID or product slug
		productMatch := false
		if licenseProductID == reqProductID {
			productMatch = true
		} else {
			// Try to match by slug
			product, err := lm.storage.GetProduct(ctx, licenseProductID)
			if err == nil && product != nil && strings.EqualFold(product.Slug, reqProductID) {
				productMatch = true
			}
		}
		if !productMatch {
			message := "License is not valid for this product"
			lm.recordActivationAttempt(ctx, license, req, false, message)
			return &ActivationResponse{Success: false, Message: message}, nil
		}
	}

	identity, _, err := lm.resolveLicenseIdentity(license, req, false)
	if err != nil {
		message := err.Error()
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}
	client, err := lm.storage.GetClient(ctx, license.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to load client: %w", err)
	}
	if client.Status == ClientStatusBanned {
		message := "Client is banned"
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}
	now := time.Now()
	if license.IsRevoked {
		message := "License has been revoked"
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}
	if now.After(license.ExpiresAt) {
		message := fmt.Sprintf("License expired on %s", license.ExpiresAt.Format("2006-01-02"))
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}
	if license.Devices == nil {
		message := "Device not previously activated"
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}
	device, exists := license.Devices[req.DeviceFingerprint]
	if !exists {
		message := "Device not previously activated"
		lm.recordActivationAttempt(ctx, license, req, false, message)
		return &ActivationResponse{Success: false, Message: message}, nil
	}
	if len(device.TransportKey) != 32 {
		transportKey, err := lm.randomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh transport key: %w", err)
		}
		device.TransportKey = transportKey
	}
	device.LastSeenAt = now
	license.LastActivatedAt = now
	refreshLicenseDeviceStats(license)
	lm.markServerCheck(license, now)

	// Ensure entitlements are computed if missing
	if err := lm.ensureLicenseEntitlements(ctx, license); err != nil {
		log.Printf("Warning: failed to compute entitlements for license %s: %v", license.ID, err)
		// Don't fail verification if entitlements can't be computed
	}

	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to persist license state: %w", err)
	}
	resp, err := lm.issueEncryptedLicenseResponse(license, identity, req.DeviceFingerprint, device.TransportKey)
	if err != nil {
		return nil, err
	}
	resp.Message = "License verified successfully"
	lm.recordActivationAttempt(ctx, license, req, true, resp.Message)
	return resp, nil
}

func (lm *LicenseManager) getDeviceTransportKey(ctx context.Context, licenseKey, fingerprint string) ([]byte, error) {
	licenseKey = normalizeLicenseKey(licenseKey)
	if licenseKey == "" {
		return nil, fmt.Errorf("license key required")
	}
	if strings.TrimSpace(fingerprint) == "" {
		return nil, fmt.Errorf("device fingerprint required")
	}
	license, err := lm.storage.GetLicenseByKey(ctx, licenseKey)
	if err != nil {
		return nil, fmt.Errorf("license not found")
	}
	if license.Devices == nil {
		return nil, fmt.Errorf("device not registered")
	}
	device, ok := license.Devices[fingerprint]
	if !ok || device == nil {
		return nil, fmt.Errorf("device not registered")
	}
	if len(device.TransportKey) != 32 {
		return nil, fmt.Errorf("device transport key missing")
	}
	return append([]byte(nil), device.TransportKey...), nil
}

func (lm *LicenseManager) buildLicensePayload(license *License, identity *LicenseIdentity) map[string]interface{} {
	devices := make([]*LicenseDevice, 0, len(license.Devices))
	for _, device := range license.Devices {
		if device == nil {
			continue
		}
		copyDev := *device
		devices = append(devices, &copyDev)
	}
	email := license.Email
	relationship := "direct"
	grantedBy := ""
	subjectClientID := ""
	if identity != nil {
		if strings.TrimSpace(identity.Email) != "" {
			email = identity.Email
		}
		if strings.TrimSpace(identity.ClientID) != "" {
			subjectClientID = identity.ClientID
		}
		if provider := strings.TrimSpace(identity.ProviderClientID); provider != "" {
			grantedBy = provider
			relationship = "provider"
		}
	} else {
		subjectClientID = license.ClientID
	}
	payload := map[string]interface{}{
		"id":                  license.ID,
		"client_id":           license.ClientID,
		"plan_slug":           license.PlanSlug,
		"subject_client_id":   subjectClientID,
		"email":               email,
		"relationship":        relationship,
		"license_key":         license.LicenseKey,
		"issued_at":           license.IssuedAt,
		"expires_at":          license.ExpiresAt,
		"last_activated_at":   license.LastActivatedAt,
		"current_activations": license.CurrentActivations,
		"max_devices":         license.MaxDevices,
		"device_count":        license.DeviceCount,
		"devices":             devices,
		"is_revoked":          license.IsRevoked,
		"revoked_at":          license.RevokedAt,
		"revoke_reason":       license.RevokeReason,
	}
	// Add product and plan info if available
	if license.ProductID != "" {
		payload["product_id"] = license.ProductID
	}
	if license.PlanID != "" {
		payload["plan_id"] = license.PlanID
	}
	// Add entitlements if available
	if license.Entitlements != nil {
		payload["entitlements"] = license.Entitlements
	}
	if grantedBy != "" {
		payload["granted_by"] = grantedBy
	}
	payload["check_mode"] = license.CheckMode.String()
	if license.CheckIntervalSecs > 0 {
		payload["check_interval_seconds"] = license.CheckIntervalSecs
	}
	if !license.NextCheckAt.IsZero() {
		payload["next_check_at"] = license.NextCheckAt
	}
	if !license.LastCheckAt.IsZero() {
		payload["last_check_at"] = license.LastCheckAt
	}
	// Add trial information
	payload["is_trial"] = license.IsTrial
	if license.IsTrial {
		if !license.TrialStartedAt.IsZero() {
			payload["trial_started_at"] = license.TrialStartedAt
		}
		// For trial licenses, trial_expires_at equals the license expires_at
		payload["trial_expires_at"] = license.ExpiresAt
		if license.TrialDeviceFingerprint != "" {
			payload["trial_device_fingerprint"] = license.TrialDeviceFingerprint
		}
	}
	return payload
}

func (lm *LicenseManager) resolveLicenseIdentity(license *License, req *ActivationRequest, allowCreate bool) (*LicenseIdentity, bool, error) {
	if license == nil || req == nil {
		return nil, false, fmt.Errorf("license and request are required")
	}
	email := strings.TrimSpace(req.Email)
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		return nil, false, fmt.Errorf("client_id is required")
	}
	ownerID := strings.TrimSpace(license.ClientID)
	if clientID != ownerID {
		return nil, false, fmt.Errorf("client_id does not match license owner")
	}
	if normalizeEmail(email) == normalizeEmail(license.Email) {
		return &LicenseIdentity{Email: license.Email, ClientID: ownerID}, false, nil
	}
	identity := existingLicenseIdentity(license, email)
	if identity != nil {
		return identity, false, nil
	}
	if !allowCreate {
		return nil, false, fmt.Errorf("email is not authorized for this license")
	}
	delegated := &LicenseIdentity{
		Email:            email,
		ClientID:         uuid.New().String(),
		ProviderClientID: ownerID,
		GrantedAt:        time.Now(),
	}
	return delegated, true, nil
}

func existingLicenseIdentity(license *License, email string) *LicenseIdentity {
	if license == nil {
		return nil
	}
	if normalizeEmail(license.Email) == normalizeEmail(email) {
		return &LicenseIdentity{Email: license.Email, ClientID: license.ClientID}
	}
	if license.AuthorizedUsers == nil {
		return nil
	}
	if ident, ok := license.AuthorizedUsers[licenseIdentityKey(email)]; ok && ident != nil {
		copyIdent := *ident
		return &copyIdent
	}
	return nil
}

func attachAuthorizedIdentity(license *License, identity *LicenseIdentity) {
	if license == nil || identity == nil {
		return
	}
	if license.AuthorizedUsers == nil {
		license.AuthorizedUsers = make(map[string]*LicenseIdentity)
	}
	key := licenseIdentityKey(identity.Email)
	copyIdent := *identity
	license.AuthorizedUsers[key] = &copyIdent
}

func truncateFingerprint(fingerprint string) string {
	if len(fingerprint) <= 16 {
		return fingerprint
	}
	return fingerprint[:16]
}

func (lm *LicenseManager) recordActivationAttempt(ctx context.Context, license *License, req *ActivationRequest, success bool, message string) {
	if license == nil || req == nil {
		return
	}
	record := &ActivationRecord{
		ID:                uuid.New().String(),
		LicenseID:         license.ID,
		ClientID:          license.ClientID,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddress:         req.IPAddress,
		UserAgent:         req.UserAgent,
		Success:           success,
		Message:           message,
		Timestamp:         time.Now(),
	}
	if err := lm.storage.RecordActivation(ctx, record); err != nil {
		log.Printf("failed to record activation audit: %v", err)
	}
}

func (lm *LicenseManager) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	return lm.storage.GetLicenseByKey(ctx, normalizeLicenseKey(licenseKey))
}

func (lm *LicenseManager) ListLicenses(ctx context.Context) ([]*License, error) {
	return lm.storage.ListLicenses(ctx)
}

func (lm *LicenseManager) ListActivations(ctx context.Context, licenseID string) ([]*ActivationRecord, error) {
	return lm.storage.ListActivations(ctx, licenseID)
}

// DeactivateDevice removes a device from a license by fingerprint
func (lm *LicenseManager) DeactivateDevice(ctx context.Context, licenseID, fingerprint string) error {
	license, err := lm.storage.GetLicense(ctx, licenseID)
	if err != nil {
		return fmt.Errorf("license not found: %w", err)
	}

	if license.Devices == nil {
		return fmt.Errorf("no devices found on this license")
	}

	if _, exists := license.Devices[fingerprint]; !exists {
		return fmt.Errorf("device not found")
	}

	delete(license.Devices, fingerprint)
	license.DeviceCount = len(license.Devices)
	license.CurrentActivations = license.DeviceCount

	return lm.storage.UpdateLicense(ctx, license)
}

// Offline Validation Token Management

// GenerateOfflineValidationToken creates a new offline validation token for a license
func (lm *LicenseManager) GenerateOfflineValidationToken(ctx context.Context, licenseKey, deviceFingerprint string, maxUses int, validityDays int) (*OfflineValidationToken, string, error) {
	// Get the license
	license, err := lm.storage.GetLicenseByKey(ctx, licenseKey)
	if err != nil {
		return nil, "", fmt.Errorf("license not found: %w", err)
	}

	// Validate the license
	if license.IsRevoked {
		return nil, "", fmt.Errorf("license has been revoked")
	}

	if time.Now().After(license.ExpiresAt) {
		return nil, "", fmt.Errorf("license has expired")
	}

	// Check if the device is authorized for this license
	if len(license.Devices) == 0 {
		return nil, "", fmt.Errorf("license has no activated devices")
	}

	_, exists := license.Devices[deviceFingerprint]
	if !exists {
		return nil, "", fmt.Errorf("device not found in license")
	}

	// Generate a unique token
	tokenBytes, err := lm.randomBytes(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Calculate validity period
	now := time.Now()
	validUntil := now.AddDate(0, 0, validityDays)

	// Create the offline validation token
	offlineToken := &OfflineValidationToken{
		Token:             token,
		LicenseKey:        licenseKey,
		ClientID:          license.ClientID,
		DeviceFingerprint: deviceFingerprint,
		ValidUntil:        validUntil,
		UsageCount:        0,
		MaxUses:           maxUses,
		IsRevoked:         false,
		CreatedAt:         now,
	}

	// Attempt to find an active signing key
	var signedBundle string
	var activeKeyID string
	// Prefer configured offline signer/provider
	if lm.offlineSigner != nil {
		if id, err := lm.offlineSigner.ActiveKeyID(); err == nil {
			activeKeyID = id
			offlineToken.SigningKeyID = id
		}
	} else {
		// fallback to storage for backward compatibility
		if activeKey, keyErr := lm.storage.GetActiveSigningKey(ctx); keyErr == nil && activeKey != nil {
			activeKeyID = activeKey.ID
			offlineToken.SigningKeyID = activeKey.ID
		}
	}

	if err := lm.storage.SaveOfflineValidationToken(ctx, offlineToken); err != nil {
		return nil, "", fmt.Errorf("failed to save offline validation token: %w", err)
	}

	// If we have an active signing key id, attempt to create a signed bundle
	if activeKeyID != "" {
		// Build payload
		payload := map[string]interface{}{
			"token":              offlineToken.Token,
			"license_key":        offlineToken.LicenseKey,
			"client_id":          offlineToken.ClientID,
			"device_fingerprint": offlineToken.DeviceFingerprint,
			"valid_until":        offlineToken.ValidUntil.Format(time.RFC3339),
			"max_uses":           offlineToken.MaxUses,
			"issued_at":          time.Now().UTC().Format(time.RFC3339),
			"signing_key_id":     activeKeyID,
		}
		payloadBytes, _ := json.Marshal(payload)
		// Sign using configured offline signer or fallback to storage private key
		var sig []byte
		var signErr error
		if lm.offlineSigner != nil {
			sig, signErr = lm.offlineSigner.Sign(activeKeyID, payloadBytes)
		} else {
			if ak, err := lm.storage.GetSigningKey(ctx, activeKeyID); err == nil && len(ak.PrivateKey) > 0 {
				sig = ed25519.Sign(ed25519.PrivateKey(ak.PrivateKey), payloadBytes)
			} else {
				signErr = fmt.Errorf("private key not available for active key %s", activeKeyID)
			}
		}
		if signErr == nil && len(sig) > 0 {
			bundle := map[string]interface{}{
				"payload":   payload,
				"signature": base64.StdEncoding.EncodeToString(sig),
			}
			b, _ := json.Marshal(bundle)
			signedBundle = string(b)
			// Update offline token record to include signing key id (already set earlier) — persist the change
			if err := lm.storage.UpdateOfflineValidationToken(ctx, offlineToken); err != nil {
				// Not fatal — token issued; just log
				log.Printf("Warning: failed to persist signing_key_id for offline token: %v", err)
			}
		}
	}

	return offlineToken, signedBundle, nil
}

// GetOfflineValidationToken retrieves an offline validation token
func (lm *LicenseManager) GetOfflineValidationToken(ctx context.Context, token string) (*OfflineValidationToken, error) {
	return lm.storage.GetOfflineValidationToken(ctx, token)
}

// ValidateOfflineToken validates an offline validation token and returns the license if valid
func (lm *LicenseManager) ValidateOfflineToken(ctx context.Context, token string, deviceFingerprint string) (*License, *OfflineValidationToken, error) {
	// Accept either a raw token id, or a signed JSON bundle containing payload+signature.
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, "{") {
		var bundle struct {
			Payload   map[string]interface{} `json:"payload"`
			Signature string                 `json:"signature"`
		}
		if err := json.Unmarshal([]byte(token), &bundle); err != nil {
			return nil, nil, fmt.Errorf("invalid offline token bundle: %w", err)
		}
		// Extract signing key id from payload
		skidVal, ok := bundle.Payload["signing_key_id"]
		if !ok {
			return nil, nil, fmt.Errorf("bundle missing signing_key_id")
		}
		skid, ok := skidVal.(string)
		if !ok || skid == "" {
			return nil, nil, fmt.Errorf("invalid signing_key_id in bundle")
		}
		// Get signing key public part, prefer configured offline signer
		var pub []byte
		var perr error
		if lm.offlineSigner != nil {
			pub, perr = lm.offlineSigner.PublicKey(skid)
			if perr != nil {
				return nil, nil, fmt.Errorf("signing key not available from provider: %w", perr)
			}
		} else {
			key, err := lm.storage.GetSigningKey(ctx, skid)
			if err != nil {
				return nil, nil, fmt.Errorf("signing key not found: %w", err)
			}
			if len(key.PublicKey) == 0 {
				return nil, nil, fmt.Errorf("signing key missing public key")
			}
			pub = key.PublicKey
		}
		// Re-marshal the payload deterministically and verify signature
		payloadBytes, err := json.Marshal(bundle.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to re-marshal bundle payload: %w", err)
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.Signature))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid signature encoding: %w", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), payloadBytes, sig) {
			return nil, nil, fmt.Errorf("invalid bundle signature")
		}
		// Extract token id from payload
		tVal, ok := bundle.Payload["token"]
		if !ok {
			return nil, nil, fmt.Errorf("bundle payload missing token")
		}
		t, ok := tVal.(string)
		if !ok || t == "" {
			return nil, nil, fmt.Errorf("invalid token in bundle payload")
		}
		token = t
	}
	// Get the offline token
	offlineToken, err := lm.storage.GetOfflineValidationToken(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid offline validation token: %w", err)
	}

	// Check if token is revoked
	if offlineToken.IsRevoked {
		return nil, nil, fmt.Errorf("offline validation token has been revoked")
	}

	// Check if token has expired
	if time.Now().After(offlineToken.ValidUntil) {
		return nil, nil, fmt.Errorf("offline validation token has expired")
	}

	// Check if token has exceeded maximum uses
	if offlineToken.UsageCount >= offlineToken.MaxUses {
		return nil, nil, fmt.Errorf("offline validation token has exceeded maximum uses")
	}

	// Check if device fingerprint matches
	if strings.TrimSpace(deviceFingerprint) != "" && deviceFingerprint != offlineToken.DeviceFingerprint {
		return nil, nil, fmt.Errorf("device fingerprint does not match token")
	}

	// Get the license
	license, err := lm.storage.GetLicenseByKey(ctx, offlineToken.LicenseKey)
	if err != nil {
		return nil, nil, fmt.Errorf("license not found: %w", err)
	}

	// Validate the license
	if license.IsRevoked {
		return nil, nil, fmt.Errorf("license has been revoked")
	}

	if time.Now().After(license.ExpiresAt) {
		return nil, nil, fmt.Errorf("license has expired")
	}

	// Increment usage count
	offlineToken.UsageCount++
	if err := lm.storage.UpdateOfflineValidationToken(ctx, offlineToken); err != nil {
		return nil, nil, fmt.Errorf("failed to update token usage: %w", err)
	}

	// Log the validation
	validationLog := &OfflineValidationLog{
		ID:                uuid.New().String(),
		Token:             token,
		LicenseKey:        license.LicenseKey,
		ClientID:          license.ClientID,
		DeviceFingerprint: deviceFingerprint,
		ValidationTime:    time.Now(),
		Success:           true,
	}

	if err := lm.storage.SaveOfflineValidationLog(ctx, validationLog); err != nil {
		// Don't fail the validation if logging fails
		log.Printf("Warning: failed to log offline validation: %v", err)
	}

	return license, offlineToken, nil
}

// RevokeOfflineValidationToken revokes an offline validation token
func (lm *LicenseManager) RevokeOfflineValidationToken(ctx context.Context, token string, revokedBy string, reason string) error {
	// Get the token
	offlineToken, err := lm.storage.GetOfflineValidationToken(ctx, token)
	if err != nil {
		return fmt.Errorf("offline validation token not found: %w", err)
	}

	// Mark as revoked
	offlineToken.IsRevoked = true
	offlineToken.RevokedAt = time.Now()
	offlineToken.RevokedBy = revokedBy
	offlineToken.RevokedReason = reason

	// Update the token
	if err := lm.storage.UpdateOfflineValidationToken(ctx, offlineToken); err != nil {
		return fmt.Errorf("failed to revoke offline validation token: %w", err)
	}

	return nil
}

// ListOfflineValidationTokens lists all offline validation tokens for a license
func (lm *LicenseManager) ListOfflineValidationTokens(ctx context.Context, licenseKey string) ([]*OfflineValidationToken, error) {
	return lm.storage.FindOfflineValidationTokensByLicense(ctx, licenseKey)
}

// ListOfflineValidationTokensByClient lists all offline validation tokens for a client
func (lm *LicenseManager) ListOfflineValidationTokensByClient(ctx context.Context, clientID string) ([]*OfflineValidationToken, error) {
	return lm.storage.FindOfflineValidationTokensByClient(ctx, clientID)
}

// GetOfflineValidationLogs gets validation logs for a token
func (lm *LicenseManager) GetOfflineValidationLogs(ctx context.Context, token string) ([]*OfflineValidationLog, error) {
	return lm.storage.ListOfflineValidationLogs(ctx, token)
}

// GetOfflineValidationLogsByLicense gets validation logs for a license
func (lm *LicenseManager) GetOfflineValidationLogsByLicense(ctx context.Context, licenseKey string) ([]*OfflineValidationLog, error) {
	return lm.storage.FindOfflineValidationLogsByLicense(ctx, licenseKey)
}

// GetOfflineValidationLogsByClient gets validation logs for a client
func (lm *LicenseManager) GetOfflineValidationLogsByClient(ctx context.Context, clientID string) ([]*OfflineValidationLog, error) {
	return lm.storage.FindOfflineValidationLogsByClient(ctx, clientID)
}
