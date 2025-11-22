package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

type License struct {
	ID                 string    `json:"id"`
	ClientID           string    `json:"client_id"`
	Email              string    `json:"email"`
	Username           string    `json:"username"`
	LicenseKey         string    `json:"license_key"`
	DeviceFingerprint  string    `json:"device_fingerprint,omitempty"`
	IsActivated        bool      `json:"is_activated"`
	IssuedAt           time.Time `json:"issued_at"`
	ActivatedAt        time.Time `json:"activated_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	MaxActivations     int       `json:"max_activations"`
	CurrentActivations int       `json:"current_activations"`
}

type ActivationRequest struct {
	Email             string `json:"email"`
	Username          string `json:"username"`
	LicenseKey        string `json:"license_key"`
	DeviceFingerprint string `json:"device_fingerprint"`
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

var (
	emailRegex       = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	licenseKeyRegex  = regexp.MustCompile(`^[A-F0-9]{4}(?:-[A-F0-9]{4}){7}$`)
	fingerprintRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

const maxActivationPayloadBytes = 1 << 20

func normalizeLicenseKey(key string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(key))
	return strings.ReplaceAll(cleaned, " ", "")
}

func validateActivationRequest(req *ActivationRequest) error {
	if !emailRegex.MatchString(req.Email) {
		return errors.New("invalid email address")
	}
	if req.Username == "" || len(req.Username) > 64 {
		return errors.New("username is required and must be <= 64 characters")
	}
	if !licenseKeyRegex.MatchString(req.LicenseKey) {
		return errors.New("invalid license key format")
	}
	if !fingerprintRegex.MatchString(req.DeviceFingerprint) {
		return errors.New("invalid device fingerprint format")
	}
	return nil
}

type LicenseManager struct {
	clients       map[string]*Client
	licenses      map[string]*License
	emailToClient map[string]string
	keyToLicense  map[string]string
	tpm           *TPM
	signingHandle uint32
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	mu            sync.RWMutex
}

func NewLicenseManager() (*LicenseManager, error) {
	tpm := NewTPM()
	if err := tpm.Startup(); err != nil {
		return nil, fmt.Errorf("failed to start TPM: %w", err)
	}

	signingHandle, pubKey, privKey, err := tpm.CreatePrimary(TPM_RH_OWNER, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing key: %w", err)
	}

	lm := &LicenseManager{
		clients:       make(map[string]*Client),
		licenses:      make(map[string]*License),
		emailToClient: make(map[string]string),
		keyToLicense:  make(map[string]string),
		tpm:           tpm,
		signingHandle: signingHandle,
		privateKey:    privKey,
		publicKey:     pubKey,
	}

	// Save public key to file
	if err := lm.savePublicKey(); err != nil {
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}

	return lm, nil
}

func (lm *LicenseManager) savePublicKey() error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(lm.publicKey)
	if err != nil {
		return err
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return os.WriteFile("server_public_key.pem", pubKeyPEM, 0644)
}

func (lm *LicenseManager) CreateClient(email, username string) (*Client, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if client exists
	if _, exists := lm.emailToClient[email]; exists {
		return nil, fmt.Errorf("client with email already exists")
	}

	client := &Client{
		ID:        uuid.New().String(),
		Email:     email,
		Username:  username,
		CreatedAt: time.Now(),
	}

	lm.clients[client.ID] = client
	lm.emailToClient[email] = client.ID

	log.Printf("Created client: %s (%s)", username, email)
	return client, nil
}

func (lm *LicenseManager) GenerateLicense(clientID string, duration time.Duration, maxActivations int) (*License, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	client, exists := lm.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found")
	}

	// Generate license key
	licenseKey := lm.generateLicenseKey(client.Email, client.Username)

	license := &License{
		ID:             uuid.New().String(),
		ClientID:       clientID,
		Email:          client.Email,
		Username:       client.Username,
		LicenseKey:     licenseKey,
		IsActivated:    false,
		IssuedAt:       time.Now(),
		ExpiresAt:      time.Now().Add(duration),
		MaxActivations: maxActivations,
	}

	lm.licenses[license.ID] = license
	lm.keyToLicense[licenseKey] = license.ID

	log.Printf("Generated license for client %s: %s", client.Username, licenseKey)
	return license, nil
}

func (lm *LicenseManager) generateLicenseKey(email, username string) string {
	// Generate cryptographically secure license key
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)

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

func (lm *LicenseManager) ActivateLicense(req *ActivationRequest) (*ActivationResponse, error) {
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Find license by key
	licenseID, exists := lm.keyToLicense[req.LicenseKey]
	if !exists {
		return &ActivationResponse{
			Success: false,
			Message: "Invalid license key",
		}, nil
	}

	license := lm.licenses[licenseID]

	// Verify client credentials
	if license.Email != req.Email || license.Username != req.Username {
		return &ActivationResponse{
			Success: false,
			Message: "Email or username does not match license",
		}, nil
	}

	// Check if already activated
	if license.IsActivated {
		// Check if same device
		if license.DeviceFingerprint != req.DeviceFingerprint {
			return &ActivationResponse{
				Success: false,
				Message: "License already activated on another device",
			}, nil
		}
		// Same device - allow reactivation
	}

	// Check expiration
	if time.Now().After(license.ExpiresAt) {
		return &ActivationResponse{
			Success: false,
			Message: fmt.Sprintf("License expired on %s", license.ExpiresAt.Format("2006-01-02")),
		}, nil
	}

	// Check max activations
	if license.CurrentActivations >= license.MaxActivations && license.DeviceFingerprint != req.DeviceFingerprint {
		return &ActivationResponse{
			Success: false,
			Message: fmt.Sprintf("Maximum activations (%d) reached", license.MaxActivations),
		}, nil
	}

	// Activate license
	if !license.IsActivated {
		license.IsActivated = true
		license.ActivatedAt = time.Now()
		license.DeviceFingerprint = req.DeviceFingerprint
		license.CurrentActivations++
	}

	// Create encrypted license package
	licenseData := map[string]interface{}{
		"id":                 license.ID,
		"email":              license.Email,
		"username":           license.Username,
		"license_key":        license.LicenseKey,
		"device_fingerprint": license.DeviceFingerprint,
		"issued_at":          license.IssuedAt,
		"expires_at":         license.ExpiresAt,
	}

	licenseJSON, err := json.Marshal(licenseData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal license: %w", err)
	}

	// Generate random nonce
	nonce, err := lm.tpm.GetRandom(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Derive transport key from device fingerprint + nonce
	transportKeyMaterial := req.DeviceFingerprint + hex.EncodeToString(nonce)
	transportHash := sha256.Sum256([]byte(transportKeyMaterial))
	transportKey := transportHash[:]

	// Get random AES key for actual license encryption
	aesKey, err := lm.tpm.GetRandom(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Prepare package: [aesKey + licenseJSON]
	dataToEncrypt := append(aesKey, licenseJSON...)

	// Encrypt with transport key
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	encryptedData := gcm.Seal(nil, nonce, dataToEncrypt, nil)

	// Sign with TPM
	dataHash := sha256.Sum256(encryptedData)
	signature, err := lm.tpm.Sign(lm.signingHandle, dataHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Export public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(lm.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	log.Printf("Activated license for %s on device %s", license.Email, req.DeviceFingerprint[:16])

	return &ActivationResponse{
		Success:          true,
		Message:          "License activated successfully",
		EncryptedLicense: hex.EncodeToString(encryptedData),
		Nonce:            hex.EncodeToString(nonce),
		Signature:        hex.EncodeToString(signature),
		PublicKey:        string(pubKeyPEM),
		ExpiresAt:        license.ExpiresAt,
	}, nil
}

func (lm *LicenseManager) GetLicense(licenseKey string) (*License, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	licenseID, exists := lm.keyToLicense[licenseKey]
	if !exists {
		return nil, fmt.Errorf("license not found")
	}

	license := lm.licenses[licenseID]
	return license, nil
}

func (lm *LicenseManager) ListLicenses() []*License {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	licenses := make([]*License, 0, len(lm.licenses))
	for _, license := range lm.licenses {
		licenses = append(licenses, license)
	}
	return licenses
}

// ==================== HTTP Server ====================

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

type Server struct {
	lm          *LicenseManager
	port        string
	apiKey      string
	rateLimiter *RateLimiter
}

func NewServer(lm *LicenseManager, port, apiKey string, limiter *RateLimiter) (*Server, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	if limiter == nil {
		limiter = NewRateLimiter(60, time.Minute)
	}
	return &Server{
		lm:          lm,
		port:        port,
		apiKey:      apiKey,
		rateLimiter: limiter,
	}, nil
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) enforceRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if s.rateLimiter == nil {
		return true
	}
	ip := clientIP(r)
	if !s.rateLimiter.Allow(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return false
	}
	return true
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	providedKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(s.apiKey)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}

	limitedBody := http.MaxBytesReader(w, r.Body, maxActivationPayloadBytes)
	defer limitedBody.Close()

	var req ActivationRequest
	if err := json.NewDecoder(limitedBody).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	if err := validateActivationRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := s.lm.ActivateLicense(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLicenses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	licenses := s.lm.ListLicenses()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(licenses)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) Start() error {
	http.HandleFunc("/api/activate", s.handleActivate)
	http.HandleFunc("/api/licenses", s.handleLicenses)
	http.HandleFunc("/health", s.handleHealth)

	log.Printf("🚀 License Manager Server starting on port %s", s.port)
	log.Printf("📝 Endpoints:")
	log.Printf("   POST   http://localhost%s/api/activate", s.port)
	log.Printf("   GET    http://localhost%s/api/licenses", s.port)
	log.Printf("   GET    http://localhost%s/health", s.port)

	return http.ListenAndServe(s.port, nil)
}

// ==================== Main ====================

func main() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager Server                 ║")
	fmt.Println("║    TPM-Based Licensing System             ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	// Initialize License Manager
	lm, err := NewLicenseManager()
	if err != nil {
		log.Fatalf("Failed to initialize License Manager: %v", err)
	}

	// Create demo clients and licenses
	fmt.Println("📋 Creating demo clients and licenses...")

	client1, _ := lm.CreateClient("john@example.com", "john_doe")
	license1, _ := lm.GenerateLicense(client1.ID, 365*24*time.Hour, 1)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client1.Email, license1.LicenseKey)

	client2, _ := lm.CreateClient("jane@example.com", "jane_smith")
	license2, _ := lm.GenerateLicense(client2.ID, 30*24*time.Hour, 2)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client2.Email, license2.LicenseKey)

	client3, _ := lm.CreateClient("bob@example.com", "bob_jones")
	license3, _ := lm.GenerateLicense(client3.ID, 90*24*time.Hour, 1)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client3.Email, license3.LicenseKey)

	fmt.Println()

	apiKey := os.Getenv("LICENSE_SERVER_API_KEY")
	if apiKey == "" {
		log.Fatalf("LICENSE_SERVER_API_KEY environment variable is required")
	}
	rateLimiter := NewRateLimiter(30, time.Minute)
	server, err := NewServer(lm, ":8080", apiKey, rateLimiter)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Start HTTP server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
