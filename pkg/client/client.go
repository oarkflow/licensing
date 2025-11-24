package client

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/oarflow/licensing/pkg/utils"
)

const (
	EnvServerURL       = "LICENSE_CLIENT_SERVER"
	DefaultLicenseFile = ".license.dat"
	DefaultConfigDir   = ".licensing"
	DefaultServerURL   = "https://localhost:8801"
)

const (
	headerSecureFlag  = "X-License-Secure"
	headerFingerprint = "X-Device-Fingerprint"
	headerLicenseKey  = "X-License-Key"
)

const (
	defaultAppName     = "LicensingClient"
	defaultAppVersion  = "0.0.1"
	defaultHTTPTimeout = 15 * time.Second
)

const checksumFileSuffix = ".chk"

// Config controls how the licensing client persists data and contacts the server.
type Config struct {
	ConfigDir         string
	LicenseFile       string
	ServerURL         string
	AppName           string
	AppVersion        string
	HTTPTimeout       time.Duration
	CACertPath        string
	AllowInsecureHTTP bool
}

// Client manages license activation and verification for Go applications.
type Client struct {
	config           Config
	configDir        string
	licensePath      string
	checksumPath     string
	publicKey        *rsa.PublicKey
	httpClient       *http.Client
	sessionKey       []byte
	boundFingerprint string
	boundLicenseKey  string
}

// ActivationRequest is sent to the licensing server.
type ActivationRequest struct {
	Email             string `json:"email"`
	ClientID          string `json:"client_id,omitempty"`
	LicenseKey        string `json:"license_key"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

// ActivationResponse is returned by the licensing server.
type ActivationResponse struct {
	Success          bool      `json:"success"`
	Message          string    `json:"message"`
	EncryptedLicense string    `json:"encrypted_license,omitempty"`
	Nonce            string    `json:"nonce,omitempty"`
	Signature        string    `json:"signature,omitempty"`
	PublicKey        string    `json:"public_key,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

// StoredLicense is the encrypted payload persisted locally.
type StoredLicense struct {
	EncryptedData     []byte    `json:"encrypted_data"`
	Nonce             []byte    `json:"nonce"`
	Signature         []byte    `json:"signature"`
	PublicKey         []byte    `json:"public_key"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// LicenseData is the decrypted license information consumed by applications.
type LicenseData struct {
	ID                 string          `json:"id"`
	ClientID           string          `json:"client_id"`
	SubjectClientID    string          `json:"subject_client_id"`
	Email              string          `json:"email"`
	Relationship       string          `json:"relationship"`
	GrantedBy          string          `json:"granted_by,omitempty"`
	LicenseKey         string          `json:"license_key"`
	IssuedAt           time.Time       `json:"issued_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	LastActivatedAt    time.Time       `json:"last_activated_at"`
	CurrentActivations int             `json:"current_activations"`
	MaxDevices         int             `json:"max_devices"`
	DeviceCount        int             `json:"device_count"`
	IsRevoked          bool            `json:"is_revoked"`
	RevokedAt          time.Time       `json:"revoked_at"`
	RevokeReason       string          `json:"revoke_reason"`
	Devices            []LicenseDevice `json:"devices"`
	DeviceFingerprint  string          `json:"-"`
}

// LicenseDevice represents device metadata tied to a license.
type LicenseDevice struct {
	Fingerprint string    `json:"fingerprint"`
	ActivatedAt time.Time `json:"activated_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// New constructs a licensing client using the provided configuration.
func New(cfg Config) (*Client, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	httpClient, err := buildHTTPClient(normalized)
	if err != nil {
		return nil, err
	}

	client := &Client{
		config:       normalized,
		configDir:    normalized.ConfigDir,
		licensePath:  filepath.Join(normalized.ConfigDir, normalized.LicenseFile),
		checksumPath: filepath.Join(normalized.ConfigDir, normalized.LicenseFile+checksumFileSuffix),
		httpClient:   httpClient,
	}

	return client, nil
}

func normalizeConfig(cfg Config) (Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return Config{}, fmt.Errorf("failed to get home directory: %w", err)
	}

	cfg.ConfigDir = strings.TrimSpace(cfg.ConfigDir)
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = DefaultConfigDir
	}
	if !filepath.IsAbs(cfg.ConfigDir) {
		cfg.ConfigDir = filepath.Join(homeDir, cfg.ConfigDir)
	}
	if err := os.MkdirAll(cfg.ConfigDir, 0o700); err != nil {
		return Config{}, fmt.Errorf("failed to create config directory: %w", err)
	}

	cfg.LicenseFile = strings.TrimSpace(cfg.LicenseFile)
	if cfg.LicenseFile == "" {
		cfg.LicenseFile = DefaultLicenseFile
	}

	serverURL := strings.TrimSpace(cfg.ServerURL)
	if serverURL == "" {
		serverURL = strings.TrimSpace(os.Getenv(EnvServerURL))
	}
	if serverURL == "" {
		serverURL = DefaultServerURL
	}
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return Config{}, fmt.Errorf("invalid server URL: %w", err)
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}
	if parsedURL.Host == "" {
		return Config{}, fmt.Errorf("server URL must include host")
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "https" && scheme != "http" {
		return Config{}, fmt.Errorf("unsupported server URL scheme: %s", scheme)
	}
	if scheme == "http" && !cfg.AllowInsecureHTTP {
		return Config{}, fmt.Errorf("http endpoints are disabled; rerun with --allow-insecure-http for development")
	}
	cfg.ServerURL = strings.TrimRight(parsedURL.String(), "/")

	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}

	if strings.TrimSpace(cfg.AppName) == "" {
		cfg.AppName = defaultAppName
	}
	if strings.TrimSpace(cfg.AppVersion) == "" {
		cfg.AppVersion = defaultAppVersion
	}
	if strings.TrimSpace(cfg.CACertPath) != "" {
		if _, err := os.Stat(cfg.CACertPath); err != nil {
			return Config{}, fmt.Errorf("failed to access CA certificate: %w", err)
		}
	}

	return cfg, nil
}

func buildHTTPClient(cfg Config) (*http.Client, error) {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	var transport *http.Transport
	if ok {
		transport = baseTransport.Clone()
	} else {
		transport = &http.Transport{}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(cfg.CACertPath) != "" {
		caBytes, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.AllowInsecureHTTP {
		tlsConfig.InsecureSkipVerify = true
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Timeout:   cfg.HTTPTimeout,
		Transport: transport,
	}, nil
}

func normalizeLicenseKey(key string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(key))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	return cleaned
}

func (lc *Client) baseURL() string {
	if lc.config.ServerURL != "" {
		return lc.config.ServerURL
	}
	return DefaultServerURL
}

func (lc *Client) apiURL(path string) string {
	base := lc.baseURL()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// ServerURL exposes the configured licensing server endpoint.
func (lc *Client) ServerURL() string {
	return lc.baseURL()
}

func (lc *Client) userAgent() string {
	return fmt.Sprintf("%s/%s", lc.config.AppName, lc.config.AppVersion)
}

// IsActivated reports whether a license file already exists locally.
func (lc *Client) IsActivated() bool {
	_, err := os.Stat(lc.licensePath)
	return err == nil
}

// Activate runs the device enrollment flow with the licensing server.
func (lc *Client) Activate(email, clientID, licenseKey string) error {
	fmt.Println("\n🔐 Starting license activation...")
	email = strings.TrimSpace(email)
	clientID = strings.TrimSpace(clientID)
	licenseKey = strings.TrimSpace(licenseKey)
	if clientID == "" {
		return fmt.Errorf("client ID is required for activation")
	}

	fmt.Println("🔍 Generating device fingerprint...")
	fingerprint, err := lc.generateDeviceFingerprint()
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}
	fmt.Printf("   Device ID: %s...\n", truncateFingerprint(fingerprint))

	activationReq := ActivationRequest{
		Email:             email,
		ClientID:          clientID,
		LicenseKey:        licenseKey,
		DeviceFingerprint: fingerprint,
	}

	reqBody, err := json.Marshal(activationReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	requestBody, encrypted, err := lc.encryptPayload(fingerprint, licenseKey, reqBody)
	if err != nil {
		return fmt.Errorf("failed to encrypt activation payload: %w", err)
	}

	fmt.Println("📡 Contacting license server...")
	req, err := http.NewRequest(http.MethodPost, lc.apiURL("/api/activate"), bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", lc.userAgent())
	req.Header.Set(headerFingerprint, fingerprint)
	req.Header.Set(headerLicenseKey, normalizeLicenseKey(licenseKey))
	if encrypted {
		req.Header.Set(headerSecureFlag, "1")
	}
	resp, err := lc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to contact license server: %w", err)
	}
	defer resp.Body.Close()

	plaintext, err := lc.readSecureResponse(resp)
	if err != nil {
		return err
	}

	var activationResp ActivationResponse
	if err := json.Unmarshal(plaintext, &activationResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !activationResp.Success {
		return fmt.Errorf("activation failed: %s", activationResp.Message)
	}
	if activationResp.EncryptedLicense == "" || activationResp.Nonce == "" || activationResp.Signature == "" || activationResp.PublicKey == "" {
		return fmt.Errorf("activation payload missing cryptographic material")
	}

	fmt.Println("✓ License validated by server")

	fmt.Println("🔑 Parsing server public key...")
	fmt.Println("✍️  Verifying signature...")
	storedLicense, err := lc.buildStoredLicenseFromResponse(&activationResp, fingerprint)
	if err != nil {
		return err
	}
	fmt.Println("✓ Signature verified")

	fmt.Println("💾 Saving license file...")
	if err := lc.writeLicenseFile(storedLicense); err != nil {
		return err
	}
	if _, err := lc.decryptLicense(storedLicense); err != nil {
		return err
	}

	fmt.Printf("✓ License saved to: %s\n", lc.licensePath)
	return nil
}

func (lc *Client) writeLicenseFile(stored *StoredLicense) error {
	if stored == nil {
		return fmt.Errorf("license payload missing")
	}
	licenseJSON, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal stored license: %w", err)
	}
	tmpPath := lc.licensePath + ".tmp"
	if err := os.WriteFile(tmpPath, licenseJSON, 0o600); err != nil {
		return fmt.Errorf("failed to write license: %w", err)
	}
	if err := lc.persistLicenseChecksum(stored.DeviceFingerprint, licenseJSON); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to secure license checksum: %w", err)
	}
	if err := os.Rename(tmpPath, lc.licensePath); err != nil {
		_ = os.Remove(tmpPath)
		_ = os.Remove(lc.checksumPath)
		return fmt.Errorf("failed to finalize license: %w", err)
	}
	return nil
}

func (lc *Client) encryptPayload(fingerprint, licenseKey string, plaintext []byte) ([]byte, bool, error) {
	if lc.canUseSessionKey(fingerprint, licenseKey) {
		envelope, err := utils.EncryptEnvelope(lc.sessionKey, plaintext)
		if err != nil {
			return nil, false, err
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			return nil, false, err
		}
		return payload, true, nil
	}
	return plaintext, false, nil
}

func (lc *Client) decryptPayload(ciphertext []byte) ([]byte, error) {
	if len(lc.sessionKey) != 32 {
		return nil, fmt.Errorf("secure payload received before session key available")
	}
	var envelope utils.SecureEnvelope
	if err := json.Unmarshal(ciphertext, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse secure envelope: %w", err)
	}
	return utils.DecryptEnvelope(lc.sessionKey, &envelope)
}

func (lc *Client) canUseSessionKey(fingerprint, licenseKey string) bool {
	if len(lc.sessionKey) != 32 {
		return false
	}
	if fingerprint == "" || lc.boundFingerprint != fingerprint {
		return false
	}
	return lc.boundLicenseKey != "" && lc.boundLicenseKey == normalizeLicenseKey(licenseKey)
}

func (lc *Client) bindSessionKey(sessionKey []byte, fingerprint, licenseKey string) {
	if len(sessionKey) != 32 {
		return
	}
	lc.sessionKey = append([]byte(nil), sessionKey...)
	lc.boundFingerprint = fingerprint
	lc.boundLicenseKey = normalizeLicenseKey(licenseKey)
}

func (lc *Client) readSecureResponse(resp *http.Response) ([]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("response missing")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read server response: %w", err)
	}
	secure := strings.EqualFold(resp.Header.Get(headerSecureFlag), "1")
	plaintext := body
	if secure {
		var decryptErr error
		plaintext, decryptErr = lc.decryptPayload(body)
		if decryptErr != nil {
			if resp.StatusCode >= http.StatusOK && resp.StatusCode < 300 {
				return nil, fmt.Errorf("failed to decrypt server payload: %w", decryptErr)
			}
			return nil, fmt.Errorf("license server responded %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= 300 {
		var errPayload map[string]string
		if err := json.Unmarshal(plaintext, &errPayload); err == nil {
			if msg := strings.TrimSpace(errPayload["error"]); msg != "" {
				return nil, fmt.Errorf("license server responded %s: %s", resp.Status, msg)
			}
		}
		return nil, fmt.Errorf("license server responded %s: %s", resp.Status, strings.TrimSpace(string(plaintext)))
	}
	return plaintext, nil
}

func (lc *Client) buildStoredLicenseFromResponse(resp *ActivationResponse, fingerprint string) (*StoredLicense, error) {
	if resp == nil {
		return nil, fmt.Errorf("activation response missing")
	}
	if strings.TrimSpace(resp.EncryptedLicense) == "" || strings.TrimSpace(resp.Nonce) == "" || strings.TrimSpace(resp.Signature) == "" || strings.TrimSpace(resp.PublicKey) == "" {
		return nil, fmt.Errorf("activation payload missing cryptographic material")
	}
	encryptedData, err := hex.DecodeString(resp.EncryptedLicense)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted license: %w", err)
	}
	nonce, err := hex.DecodeString(resp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	signature, err := hex.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	publicKeyBlock, _ := pem.Decode([]byte(resp.PublicKey))
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("failed to parse public key PEM")
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	dataHash := sha256.Sum256(encryptedData)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, dataHash[:], signature, nil); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	lc.publicKey = publicKey
	storedLicense := &StoredLicense{
		EncryptedData:     encryptedData,
		Nonce:             nonce,
		Signature:         signature,
		PublicKey:         publicKeyBlock.Bytes,
		DeviceFingerprint: fingerprint,
		ExpiresAt:         resp.ExpiresAt,
	}
	return storedLicense, nil
}

func (lc *Client) loadStoredLicense(raw []byte) (*StoredLicense, error) {
	var stored StoredLicense
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("failed to parse license file: %w", err)
	}
	if err := lc.validateStoredLicenseSignature(&stored); err != nil {
		return nil, err
	}
	return &stored, nil
}

func (lc *Client) validateStoredLicenseSignature(stored *StoredLicense) error {
	if stored == nil {
		return fmt.Errorf("stored license missing")
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(stored.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key type")
	}
	lc.publicKey = publicKey
	dataHash := sha256.Sum256(stored.EncryptedData)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, dataHash[:], stored.Signature, nil); err != nil {
		return fmt.Errorf("signature verification failed - license may be tampered")
	}
	return nil
}

func (lc *Client) recoverLicenseFromServer(stored *StoredLicense) (*StoredLicense, error) {
	if stored == nil {
		return nil, fmt.Errorf("stored license missing")
	}
	licenseData, err := lc.decryptLicense(stored)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt license for server verification: %w", err)
	}
	verificationReq := ActivationRequest{
		Email:             licenseData.Email,
		LicenseKey:        licenseData.LicenseKey,
		DeviceFingerprint: stored.DeviceFingerprint,
	}
	ownerID := strings.TrimSpace(licenseData.ClientID)
	verificationReq.ClientID = ownerID
	body, err := json.Marshal(verificationReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification request: %w", err)
	}
	secureBody, encrypted, err := lc.encryptPayload(stored.DeviceFingerprint, verificationReq.LicenseKey, body)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt verification payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, lc.apiURL("/api/verify"), bytes.NewBuffer(secureBody))
	if err != nil {
		return nil, fmt.Errorf("failed to build verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", lc.userAgent())
	req.Header.Set(headerFingerprint, stored.DeviceFingerprint)
	req.Header.Set(headerLicenseKey, normalizeLicenseKey(verificationReq.LicenseKey))
	if encrypted {
		req.Header.Set(headerSecureFlag, "1")
	}
	resp, err := lc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact license server: %w", err)
	}
	defer resp.Body.Close()
	plaintext, err := lc.readSecureResponse(resp)
	if err != nil {
		return nil, err
	}
	var verificationResp ActivationResponse
	if err := json.Unmarshal(plaintext, &verificationResp); err != nil {
		return nil, fmt.Errorf("failed to decode verification response: %w", err)
	}
	if !verificationResp.Success {
		message := verificationResp.Message
		if message == "" {
			message = "license verification failed"
		}
		return nil, fmt.Errorf("server rejected license verification: %s", message)
	}
	updated, err := lc.buildStoredLicenseFromResponse(&verificationResp, stored.DeviceFingerprint)
	if err != nil {
		return nil, err
	}
	fmt.Println("🔄 License refreshed from server")
	if err := lc.writeLicenseFile(updated); err != nil {
		return nil, err
	}
	if _, err := lc.decryptLicense(updated); err != nil {
		return nil, err
	}
	return updated, nil
}

func (lc *Client) ensureLicenseFileSecure(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("license file %s has insecure permissions (%#o) - run 'chmod 600'", lc.licensePath, info.Mode().Perm())
	}
	return nil
}

// Verify loads, decrypts, and validates the stored license file.
func (lc *Client) Verify() (*LicenseData, error) {
	info, err := os.Stat(lc.licensePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("license not found - please activate first")
		}
		return nil, fmt.Errorf("failed to stat license file: %w", err)
	}
	if err := lc.ensureLicenseFileSecure(info); err != nil {
		return nil, err
	}

	licenseJSON, err := os.ReadFile(lc.licensePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}

	storedLicense, err := lc.loadStoredLicense(licenseJSON)
	if err != nil {
		return nil, err
	}

	currentFingerprint, err := lc.generateDeviceFingerprint()
	if err != nil {
		return nil, fmt.Errorf("failed to generate current fingerprint: %w", err)
	}

	if storedLicense.DeviceFingerprint != currentFingerprint {
		return nil, fmt.Errorf("device fingerprint mismatch - license is tied to different device")
	}

	if err := lc.verifyStoredChecksum(currentFingerprint, licenseJSON); err != nil {
		if errors.Is(err, errChecksumMissing) {
			fmt.Println("⚠️  License checksum missing — revalidating with server...")
			recovered, recErr := lc.recoverLicenseFromServer(storedLicense)
			if recErr != nil {
				return nil, recErr
			}
			storedLicense = recovered
			licenseJSON, err = os.ReadFile(lc.licensePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read refreshed license file: %w", err)
			}
			if err := lc.verifyStoredChecksum(currentFingerprint, licenseJSON); err != nil {
				return nil, err
			}
			storedLicense, err = lc.loadStoredLicense(licenseJSON)
			if err != nil {
				return nil, err
			}
			if storedLicense.DeviceFingerprint != currentFingerprint {
				return nil, fmt.Errorf("device fingerprint mismatch after server verification")
			}
		} else {
			return nil, err
		}
	}

	licenseData, err := lc.decryptLicense(storedLicense)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt license: %w", err)
	}

	if time.Now().After(storedLicense.ExpiresAt) {
		return nil, fmt.Errorf("license expired on %s", storedLicense.ExpiresAt.Format("2006-01-02"))
	}
	if licenseData.IsRevoked {
		reason := licenseData.RevokeReason
		if reason == "" {
			reason = "no reason provided"
		}
		return nil, fmt.Errorf("license revoked: %s", reason)
	}

	return licenseData, nil
}

func (lc *Client) decryptLicense(stored *StoredLicense) (*LicenseData, error) {
	if stored == nil {
		return nil, fmt.Errorf("stored license missing")
	}
	transportKey, err := lc.deriveTransportKey(stored.DeviceFingerprint, stored.Nonce)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	decryptedPackage, err := gcm.Open(nil, stored.Nonce, stored.EncryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	if len(decryptedPackage) < 32 {
		return nil, fmt.Errorf("decrypted payload too small")
	}
	sessionKey := append([]byte(nil), decryptedPackage[:32]...)
	licenseJSON := decryptedPackage[32:]
	var licenseData LicenseData
	if err := json.Unmarshal(licenseJSON, &licenseData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal license: %w", err)
	}
	licenseData.DeviceFingerprint = stored.DeviceFingerprint
	lc.bindSessionKey(sessionKey, stored.DeviceFingerprint, licenseData.LicenseKey)
	return &licenseData, nil
}

func (lc *Client) deriveTransportKey(fingerprint string, nonce []byte) ([]byte, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("device fingerprint missing")
	}
	if len(nonce) == 0 {
		return nil, fmt.Errorf("nonce missing")
	}
	material := fingerprint + hex.EncodeToString(nonce)
	hash := sha256.Sum256([]byte(material))
	return hash[:], nil
}

// Device fingerprinting helpers -------------------------------------------------

func (lc *Client) generateDeviceFingerprint() (string, error) {
	var identifiers []string

	hostname, err := os.Hostname()
	if err == nil {
		identifiers = append(identifiers, "HOST:"+hostname)
	}

	identifiers = append(identifiers, "OS:"+runtime.GOOS)
	identifiers = append(identifiers, "ARCH:"+runtime.GOARCH)

	macAddr, err := lc.getPrimaryMACAddress()
	if err == nil {
		identifiers = append(identifiers, "MAC:"+macAddr)
	}

	cpuInfo, err := lc.getCPUInfo()
	if err == nil {
		identifiers = append(identifiers, "CPU:"+cpuInfo)
	}

	combined := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:]), nil
}

func (lc *Client) getPrimaryMACAddress() (string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		for _, iface := range []string{"eth0", "ens33", "enp0s3", "wlan0"} {
			cmd = exec.Command("cat", "/sys/class/net/"+iface+"/address")
			if output, err := cmd.Output(); err == nil && len(output) > 0 {
				return strings.TrimSpace(string(output)), nil
			}
		}
	case "darwin":
		cmd = exec.Command("ifconfig", "en0")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "ether") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						return fields[1], nil
					}
				}
			}
		}
	case "windows":
		cmd = exec.Command("getmac", "/fo", "csv", "/nh")
		if output, err := cmd.Output(); err == nil && len(output) > 0 {
			parts := strings.Split(string(output), ",")
			if len(parts) > 0 {
				return strings.Trim(parts[0], "\" \r\n"), nil
			}
		}
	}

	return "NO_MAC_ADDR", nil
}

func (lc *Client) getCPUInfo() (string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("cat", "/proc/cpuinfo")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "model name") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						cpuName := strings.TrimSpace(parts[1])
						hash := sha256.Sum256([]byte(cpuName))
						return hex.EncodeToString(hash[:16]), nil
					}
				}
			}
		}
	case "darwin":
		cmd = exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
		if output, err := cmd.Output(); err == nil {
			cpuName := strings.TrimSpace(string(output))
			hash := sha256.Sum256([]byte(cpuName))
			return hex.EncodeToString(hash[:16]), nil
		}
	case "windows":
		cmd = exec.Command("wmic", "cpu", "get", "name")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 1 {
				cpuName := strings.TrimSpace(lines[1])
				hash := sha256.Sum256([]byte(cpuName))
				return hex.EncodeToString(hash[:16]), nil
			}
		}
	}

	return "NO_CPU_INFO", nil
}

func truncateFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}
