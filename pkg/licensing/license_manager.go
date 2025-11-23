package licensing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

type LicenseManager struct {
	storage       Storage
	tpm           *TPM
	signingHandle uint32
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	publicKeyPath string
	mu            sync.RWMutex
}

func NewLicenseManager(storage Storage) (*LicenseManager, error) {
	if storage == nil {
		return nil, fmt.Errorf("storage implementation is required")
	}

	tpm := NewTPM()
	if err := tpm.Startup(); err != nil {
		return nil, fmt.Errorf("failed to start TPM: %w", err)
	}

	signingHandle, pubKey, privKey, err := tpm.CreatePrimary(TPM_RH_OWNER, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing key: %w", err)
	}

	lm := &LicenseManager{
		storage:       storage,
		tpm:           tpm,
		signingHandle: signingHandle,
		privateKey:    privKey,
		publicKey:     pubKey,
	}

	path, err := lm.savePublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}
	lm.publicKeyPath = path

	return lm, nil
}

func (lm *LicenseManager) savePublicKey() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(lm.publicKey)
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

func (lm *LicenseManager) CreateClient(ctx context.Context, email, username string) (*Client, error) {
	email = strings.TrimSpace(email)
	username = strings.TrimSpace(username)
	if !emailRegex.MatchString(email) {
		return nil, fmt.Errorf("invalid email address")
	}
	if username == "" || len(username) > 64 {
		return nil, fmt.Errorf("username is required and must be <= 64 characters")
	}

	now := time.Now()
	client := &Client{
		ID:        uuid.New().String(),
		Email:     email,
		Username:  username,
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

	log.Printf("Created client: %s (%s)", username, email)
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

func (lm *LicenseManager) GenerateLicense(ctx context.Context, clientID string, duration time.Duration, maxActivations int) (*License, error) {
	if maxActivations <= 0 {
		maxActivations = 1
	}
	client, err := lm.storage.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.Status == ClientStatusBanned {
		return nil, fmt.Errorf("client is banned")
	}

	licenseKey := lm.generateLicenseKey(client.Email, client.Username)
	now := time.Now()
	license := &License{
		ID:                 uuid.New().String(),
		ClientID:           clientID,
		Email:              client.Email,
		Username:           client.Username,
		LicenseKey:         licenseKey,
		IsRevoked:          false,
		IsActivated:        false,
		IssuedAt:           now,
		ExpiresAt:          now.Add(duration),
		MaxActivations:     maxActivations,
		Devices:            make(map[string]*LicenseDevice),
		CurrentActivations: 0,
	}

	if err := lm.storage.SaveLicense(ctx, license); err != nil {
		if errors.Is(err, errLicenseExists) {
			return nil, fmt.Errorf("license already exists")
		}
		return nil, fmt.Errorf("failed to save license: %w", err)
	}

	log.Printf("Generated license for client %s: %s", client.Username, licenseKey)
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

func (lm *LicenseManager) generateLicenseKey(email, username string) string {
	// Generate cryptographically secure license key
	randomBytes, err := lm.tpm.GetRandom(16)
	if err != nil {
		randomBytes = make([]byte, 16)
		if _, fallbackErr := rand.Read(randomBytes); fallbackErr != nil {
			panic(fmt.Sprintf("failed to obtain random bytes: %v", fallbackErr))
		}
	}

	data := email + username + hex.EncodeToString(randomBytes) + time.Now().String()
	hash := sha256.Sum256([]byte(data))

	key := hex.EncodeToString(hash[:16])

	// Format as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
	formatted := strings.ToUpper(key)
	parts := []string{}
	for i := 0; i < len(formatted); i += 4 {
		end := i + 4
		if end > len(formatted) {
			end = len(formatted)
		}
		parts = append(parts, formatted[i:end])
	}

	return strings.Join(parts, "-")
}

func (lm *LicenseManager) randomSecret(numBytes int) (string, error) {
	if numBytes <= 0 {
		numBytes = 16
	}
	raw, err := lm.tpm.GetRandom(numBytes)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(raw)), nil
}

func hashAPIKey(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func (lm *LicenseManager) ActivateLicense(ctx context.Context, req *ActivationRequest) (*ActivationResponse, error) {
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	license, err := lm.storage.GetLicenseByKey(ctx, req.LicenseKey)
	if err != nil {
		return &ActivationResponse{Success: false, Message: "Invalid license key"}, nil
	}

	if license.Email != req.Email || license.Username != req.Username {
		return &ActivationResponse{Success: false, Message: "Email or username does not match license"}, nil
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

	device, exists := license.Devices[req.DeviceFingerprint]
	if !exists {
		if license.MaxActivations > 0 && len(license.Devices) >= license.MaxActivations {
			message := fmt.Sprintf("Maximum activations (%d) reached", license.MaxActivations)
			lm.recordActivationAttempt(ctx, license, req, false, message)
			return &ActivationResponse{Success: false, Message: message}, nil
		}
		license.Devices[req.DeviceFingerprint] = &LicenseDevice{
			Fingerprint: req.DeviceFingerprint,
			ActivatedAt: now,
			LastSeenAt:  now,
		}
	} else {
		device.LastSeenAt = now
	}

	license.IsActivated = true
	license.LastActivatedAt = now
	license.CurrentActivations = len(license.Devices)

	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to persist license state: %w", err)
	}

	resp, err := lm.issueEncryptedLicenseResponse(license, req.DeviceFingerprint)
	if err != nil {
		return nil, err
	}
	resp.Message = "License activated successfully"
	log.Printf("Activated license for %s on device %s", license.Email, truncateFingerprint(req.DeviceFingerprint))
	lm.recordActivationAttempt(ctx, license, req, true, resp.Message)
	return resp, nil
}

func (lm *LicenseManager) issueEncryptedLicenseResponse(license *License, fingerprint string) (*ActivationResponse, error) {
	if license == nil {
		return nil, fmt.Errorf("license missing")
	}
	licenseData := lm.buildLicensePayload(license)
	licenseJSON, err := json.Marshal(licenseData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal license: %w", err)
	}
	nonce, err := lm.tpm.GetRandom(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	transportKeyMaterial := fingerprint + hex.EncodeToString(nonce)
	transportHash := sha256.Sum256([]byte(transportKeyMaterial))
	transportKey := transportHash[:]
	aesKey, err := lm.tpm.GetRandom(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	dataToEncrypt := append(aesKey, licenseJSON...)
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	encryptedData := gcm.Seal(nil, nonce, dataToEncrypt, nil)
	dataHash := sha256.Sum256(encryptedData)
	signature, err := lm.tpm.Sign(lm.signingHandle, dataHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(lm.publicKey)
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
	if license.Email != req.Email || license.Username != req.Username {
		message := "Email or username does not match license"
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
	device.LastSeenAt = now
	license.LastActivatedAt = now
	license.CurrentActivations = len(license.Devices)
	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to persist license state: %w", err)
	}
	resp, err := lm.issueEncryptedLicenseResponse(license, req.DeviceFingerprint)
	if err != nil {
		return nil, err
	}
	resp.Message = "License verified successfully"
	lm.recordActivationAttempt(ctx, license, req, true, resp.Message)
	return resp, nil
}

func (lm *LicenseManager) buildLicensePayload(license *License) map[string]interface{} {
	devices := make([]*LicenseDevice, 0, len(license.Devices))
	for _, device := range license.Devices {
		if device == nil {
			continue
		}
		copyDev := *device
		devices = append(devices, &copyDev)
	}
	return map[string]interface{}{
		"id":                  license.ID,
		"client_id":           license.ClientID,
		"email":               license.Email,
		"username":            license.Username,
		"license_key":         license.LicenseKey,
		"issued_at":           license.IssuedAt,
		"expires_at":          license.ExpiresAt,
		"last_activated_at":   license.LastActivatedAt,
		"max_activations":     license.MaxActivations,
		"current_activations": license.CurrentActivations,
		"devices":             devices,
		"is_revoked":          license.IsRevoked,
		"revoked_at":          license.RevokedAt,
		"revoke_reason":       license.RevokeReason,
	}
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
