package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ==================== TPM Implementation ====================

const (
	TPM_RH_OWNER   = 0x40000001
	TPM_ALG_SHA256 = 0x000B
)

type TPMKey struct {
	Handle    uint32
	Public    *rsa.PublicKey
	Private   *rsa.PrivateKey
	Parent    uint32
	CreatedAt time.Time
}

type TPM struct {
	mu           sync.RWMutex
	initialized  bool
	keys         map[uint32]*TPMKey
	nextHandle   uint32
	randomSource io.Reader
}

func NewTPM() *TPM {
	return &TPM{
		keys:         make(map[uint32]*TPMKey),
		nextHandle:   0x80000000,
		randomSource: rand.Reader,
	}
}

func (t *TPM) Startup() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.initialized = true
	return nil
}

func (t *TPM) CreatePrimary(hierarchy uint32, keySize int) (uint32, *rsa.PublicKey, *rsa.PrivateKey, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.initialized {
		return 0, nil, nil, fmt.Errorf("TPM not initialized")
	}

	privateKey, err := rsa.GenerateKey(t.randomSource, keySize)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	handle := t.nextHandle
	t.nextHandle++

	t.keys[handle] = &TPMKey{
		Handle:    handle,
		Public:    &privateKey.PublicKey,
		Private:   privateKey,
		Parent:    hierarchy,
		CreatedAt: time.Now(),
	}

	return handle, &privateKey.PublicKey, privateKey, nil
}

func (t *TPM) Sign(keyHandle uint32, digest []byte) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if !t.initialized {
		return nil, fmt.Errorf("TPM not initialized")
	}

	key, exists := t.keys[keyHandle]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	signature, err := rsa.SignPSS(t.randomSource, key.Private, crypto.SHA256, digest, nil)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

func (t *TPM) GetRandom(numBytes int) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if !t.initialized {
		return nil, fmt.Errorf("TPM not initialized")
	}

	if numBytes > 1024 {
		numBytes = 1024
	}

	randomBytes := make([]byte, numBytes)
	_, err := io.ReadFull(t.randomSource, randomBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random: %w", err)
	}

	return randomBytes, nil
}

// ==================== License Manager ====================

type Client struct {
	ID        string       `json:"id"`
	Email     string       `json:"email"`
	Username  string       `json:"username"`
	Status    ClientStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	BannedAt  time.Time    `json:"banned_at,omitempty"`
	BanReason string       `json:"ban_reason,omitempty"`
}

type License struct {
	ID                 string                    `json:"id"`
	ClientID           string                    `json:"client_id"`
	Email              string                    `json:"email"`
	Username           string                    `json:"username"`
	LicenseKey         string                    `json:"license_key"`
	IsRevoked          bool                      `json:"is_revoked"`
	RevokedAt          time.Time                 `json:"revoked_at,omitempty"`
	RevokeReason       string                    `json:"revoke_reason,omitempty"`
	IsActivated        bool                      `json:"is_activated"`
	IssuedAt           time.Time                 `json:"issued_at"`
	LastActivatedAt    time.Time                 `json:"last_activated_at,omitempty"`
	ExpiresAt          time.Time                 `json:"expires_at"`
	MaxActivations     int                       `json:"max_activations"`
	CurrentActivations int                       `json:"current_activations"`
	Devices            map[string]*LicenseDevice `json:"devices"`
}

type ActivationRequest struct {
	Email             string `json:"email"`
	Username          string `json:"username"`
	LicenseKey        string `json:"license_key"`
	DeviceFingerprint string `json:"device_fingerprint"`
	IPAddress         string `json:"-"`
	UserAgent         string `json:"-"`
}

type ActivationResponse struct {
	Success          bool      `json:"success"`
	Message          string    `json:"message"`
	EncryptedLicense string    `json:"encrypted_license,omitempty"`
	Nonce            string    `json:"nonce,omitempty"`
	Signature        string    `json:"signature,omitempty"`
	PublicKey        string    `json:"public_key,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type ClientStatus string

const (
	ClientStatusActive ClientStatus = "active"
	ClientStatusBanned ClientStatus = "banned"
)

type LicenseDevice struct {
	Fingerprint string    `json:"fingerprint"`
	ActivatedAt time.Time `json:"activated_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type ActivationRecord struct {
	ID                string    `json:"id"`
	LicenseID         string    `json:"license_id"`
	ClientID          string    `json:"client_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	Success           bool      `json:"success"`
	Message           string    `json:"message"`
	Timestamp         time.Time `json:"timestamp"`
}

func cloneClient(client *Client) *Client {
	if client == nil {
		return nil
	}
	clone := *client
	return &clone
}

func cloneLicense(license *License) *License {
	if license == nil {
		return nil
	}
	clone := *license
	if license.Devices != nil {
		clone.Devices = make(map[string]*LicenseDevice, len(license.Devices))
		for fp, dev := range license.Devices {
			if dev == nil {
				continue
			}
			copyDev := *dev
			clone.Devices[fp] = &copyDev
		}
	}
	return &clone
}

func cloneActivationRecord(record *ActivationRecord) *ActivationRecord {
	if record == nil {
		return nil
	}
	clone := *record
	return &clone
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

var (
	emailRegex       = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	licenseKeyRegex  = regexp.MustCompile(`^[A-F0-9]{4}(?:-?[A-F0-9]{4}){7}$`)
	fingerprintRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

const maxActivationPayloadBytes = 1 << 20
const defaultStoragePath = "data/licensing-state.json"

func normalizeLicenseKey(key string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(key))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	return cleaned
}

func validateActivationRequest(req *ActivationRequest) error {
	if !emailRegex.MatchString(req.Email) {
		return errors.New("invalid email address")
	}
	if req.Username == "" || len(req.Username) > 64 {
		return errors.New("username is required and must be <= 64 characters")
	}
	keyCandidate := strings.ToUpper(strings.TrimSpace(req.LicenseKey))
	keyCandidate = strings.ReplaceAll(keyCandidate, " ", "")
	if !licenseKeyRegex.MatchString(keyCandidate) {
		return errors.New("invalid license key format")
	}
	if !fingerprintRegex.MatchString(req.DeviceFingerprint) {
		return errors.New("invalid device fingerprint format")
	}
	return nil
}

// ==================== HTTP Server ====================

const maxAdminPayloadBytes = 256 << 10

type createClientRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

type banClientRequest struct {
	Reason string `json:"reason"`
}

type createLicenseRequest struct {
	ClientID       string `json:"client_id"`
	DurationDays   int    `json:"duration_days"`
	MaxActivations int    `json:"max_activations"`
}

type licenseMutationRequest struct {
	Reason string `json:"reason"`
}

type createAdminUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createAPIKeyRequest struct {
	UserID string `json:"user_id"`
}

type RateLimiter struct {
	mu          sync.Mutex
	requests    map[string]*clientRequestWindow
	maxRequests int
	window      time.Duration
}

type clientRequestWindow struct {
	count   int
	resetAt time.Time
}

func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	if maxRequests <= 0 {
		maxRequests = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{
		requests:    make(map[string]*clientRequestWindow),
		maxRequests: maxRequests,
		window:      window,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window, exists := rl.requests[key]
	if !exists || now.After(window.resetAt) {
		rl.requests[key] = &clientRequestWindow{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	if window.count >= rl.maxRequests {
		return false
	}

	window.count++
	return true
}

// ==================== Main ====================

func main() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager Server                 ║")
	fmt.Println("║    TPM-Based Licensing System             ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	// Initialize storage + License Manager
	ctx := context.Background()
	storage, storageMode, err := buildStorageFromEnv()
	if err != nil {
		log.Fatalf("Failed to configure storage: %v", err)
	}
	lm, err := NewLicenseManager(storage)
	if err != nil {
		log.Fatalf("Failed to initialize License Manager: %v", err)
	}
	log.Printf("📦 Storage backend: %s", storageMode)
	if pubPath := lm.PublicKeyPath(); pubPath != "" {
		log.Printf("🔑 Public key stored at %s", pubPath)
	}
	adminUser, bootstrapPassword, bootstrapKey, err := lm.EnsureDefaultAdmin(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize admin user: %v", err)
	}
	if adminUser != nil {
		log.Printf("🆕 Default admin user created: %s", adminUser.Username)
		log.Printf("   Temporary password: %s", bootstrapPassword)
		log.Printf("   Bootstrap API key: %s", bootstrapKey)
		log.Printf("   Rotate these credentials immediately after logging in.")
	}

	// Create demo clients and licenses
	fmt.Println("📋 Creating demo clients and licenses...")

	client1, _ := lm.CreateClient(ctx, "john@example.com", "john_doe")
	license1, _ := lm.GenerateLicense(ctx, client1.ID, 365*24*time.Hour, 3)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client1.Email, license1.LicenseKey)

	client2, _ := lm.CreateClient(ctx, "jane@example.com", "jane_smith")
	license2, _ := lm.GenerateLicense(ctx, client2.ID, 30*24*time.Hour, 5)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client2.Email, license2.LicenseKey)

	client3, _ := lm.CreateClient(ctx, "bob@example.com", "bob_jones")
	license3, _ := lm.GenerateLicense(ctx, client3.ID, 90*24*time.Hour, 2)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client3.Email, license3.LicenseKey)

	fmt.Println()

	rawAPIKeys := os.Getenv("LICENSE_SERVER_API_KEYS")
	apiKeys := parseAPIKeys(rawAPIKeys)
	if len(apiKeys) == 0 {
		if single := strings.TrimSpace(os.Getenv("LICENSE_SERVER_API_KEY")); single != "" {
			apiKeys = append(apiKeys, single)
		}
	}
	if len(apiKeys) > 0 {
		log.Printf("🔐 Loaded %d legacy admin API key(s) from environment", len(apiKeys))
	} else {
		log.Printf("🔐 No legacy API keys configured - relying on stored user API keys")
	}
	rateLimiter := NewRateLimiter(30, time.Minute)
	tlsCert := os.Getenv("LICENSE_SERVER_TLS_CERT")
	tlsKey := os.Getenv("LICENSE_SERVER_TLS_KEY")
	clientCA := os.Getenv("LICENSE_SERVER_CLIENT_CA")
	if tlsCert == "" || tlsKey == "" {
		log.Printf("⚠️ TLS disabled - set LICENSE_SERVER_TLS_CERT and LICENSE_SERVER_TLS_KEY to enable HTTPS")
	} else if clientCA != "" {
		log.Printf("🔒 mTLS enabled - client CA set to %s", clientCA)
	} else {
		log.Printf("🔒 TLS certificate configured (server-only mode)")
	}
	server, err := NewServer(lm, ":8080", apiKeys, rateLimiter, tlsCert, tlsKey, clientCA)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Start HTTP server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
