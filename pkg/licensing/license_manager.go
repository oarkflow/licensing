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
		defaultCheckMode:     LicenseCheckModeYearly,
		defaultCheckInterval: defaultCustomCheckInterval,
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

func (lm *LicenseManager) ListAdminUsers(ctx context.Context) ([]*AdminUser, error) {
	return lm.storage.ListAdminUsers(ctx)
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
	email = strings.TrimSpace(email)
	if !emailRegex.MatchString(email) {
		return nil, fmt.Errorf("invalid email address")
	}

	now := time.Now()
	client := &Client{
		ID:        uuid.New().String(),
		Email:     email,
		Status:    ClientStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := lm.storage.SaveClient(ctx, client); err != nil {
		if errors.Is(err, errClientExists) {
			return nil, fmt.Errorf("client with email already exists")
		}
		return nil, fmt.Errorf("failed to save client: %w", err)
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
	ProductID string
	PlanID    string
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
	var entitlements *LicenseEntitlements
	if opts != nil {
		productID = strings.TrimSpace(opts.ProductID)
		planID = strings.TrimSpace(opts.PlanID)

		// If product and plan IDs are provided, validate and compute entitlements
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
			// Use plan slug from the plan record
			planSlug = plan.Slug

			// Compute entitlements
			entitlements, err = lm.storage.ComputeLicenseEntitlements(ctx, productID, planID)
			if err != nil {
				return nil, fmt.Errorf("failed to compute entitlements: %w", err)
			}
		}
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
