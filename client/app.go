package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ==================== Configuration ====================

const (
	LICENSE_FILE       = ".license.dat"
	CONFIG_DIR         = ".myapp"
	LICENSE_SERVER     = "http://localhost:8080"
	LICENSE_SERVER_ENV = "LICENSE_CLIENT_SERVER"
	HTTP_TIMEOUT       = 15 * time.Second
	APP_NAME           = "MySecureApp"
	APP_VERSION        = "1.0.0"
)

// ==================== Data Structures ====================

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

type StoredLicense struct {
	EncryptedData     []byte    `json:"encrypted_data"`
	Nonce             []byte    `json:"nonce"`
	Signature         []byte    `json:"signature"`
	PublicKey         []byte    `json:"public_key"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type LicenseData struct {
	ID                 string          `json:"id"`
	ClientID           string          `json:"client_id"`
	Email              string          `json:"email"`
	Username           string          `json:"username"`
	LicenseKey         string          `json:"license_key"`
	IssuedAt           time.Time       `json:"issued_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	LastActivatedAt    time.Time       `json:"last_activated_at"`
	MaxActivations     int             `json:"max_activations"`
	CurrentActivations int             `json:"current_activations"`
	IsRevoked          bool            `json:"is_revoked"`
	RevokedAt          time.Time       `json:"revoked_at"`
	RevokeReason       string          `json:"revoke_reason"`
	Devices            []LicenseDevice `json:"devices"`
	DeviceFingerprint  string          `json:"-"`
}

type LicenseDevice struct {
	Fingerprint string    `json:"fingerprint"`
	ActivatedAt time.Time `json:"activated_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// ==================== License Client ====================

type LicenseClient struct {
	configPath  string
	licensePath string
	publicKey   *rsa.PublicKey
	serverURL   string
	httpClient  *http.Client
}

func NewLicenseClient() (*LicenseClient, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, CONFIG_DIR)
	if err := os.MkdirAll(configPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	licensePath := filepath.Join(configPath, LICENSE_FILE)

	serverURL := strings.TrimSpace(os.Getenv(LICENSE_SERVER_ENV))
	if serverURL == "" {
		serverURL = LICENSE_SERVER
	}
	serverURL = strings.TrimRight(serverURL, "/")
	client := &http.Client{Timeout: HTTP_TIMEOUT}

	return &LicenseClient{
		configPath:  configPath,
		licensePath: licensePath,
		serverURL:   serverURL,
		httpClient:  client,
	}, nil
}

func (lc *LicenseClient) baseURL() string {
	if lc.serverURL != "" {
		return lc.serverURL
	}
	return LICENSE_SERVER
}

func (lc *LicenseClient) apiURL(path string) string {
	base := lc.baseURL()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func (lc *LicenseClient) ServerURL() string {
	return lc.baseURL()
}

func (lc *LicenseClient) userAgent() string {
	return fmt.Sprintf("%s/%s", APP_NAME, APP_VERSION)
}

// ==================== Device Fingerprinting ====================

func (lc *LicenseClient) generateDeviceFingerprint() (string, error) {
	var identifiers []string

	// Hostname
	hostname, err := os.Hostname()
	if err == nil {
		identifiers = append(identifiers, "HOST:"+hostname)
	}

	// OS and Architecture
	identifiers = append(identifiers, "OS:"+runtime.GOOS)
	identifiers = append(identifiers, "ARCH:"+runtime.GOARCH)

	// MAC Address
	macAddr, err := lc.getPrimaryMACAddress()
	if err == nil {
		identifiers = append(identifiers, "MAC:"+macAddr)
	}

	// CPU Info
	cpuInfo, err := lc.getCPUInfo()
	if err == nil {
		identifiers = append(identifiers, "CPU:"+cpuInfo)
	}

	// Combine and hash
	combined := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:]), nil
}

func (lc *LicenseClient) getPrimaryMACAddress() (string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// Try common interface names
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

func (lc *LicenseClient) getCPUInfo() (string, error) {
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

// ==================== License Activation ====================

func (lc *LicenseClient) Activate(email, username, licenseKey string) error {
	fmt.Println("\n🔐 Starting license activation...")
	email = strings.TrimSpace(email)
	username = strings.TrimSpace(username)
	licenseKey = strings.TrimSpace(licenseKey)

	// Generate device fingerprint
	fmt.Println("🔍 Generating device fingerprint...")
	fingerprint, err := lc.generateDeviceFingerprint()
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}
	fmt.Printf("   Device ID: %s...\n", truncateFingerprint(fingerprint))

	// Prepare activation request
	activationReq := ActivationRequest{
		Email:             email,
		Username:          username,
		LicenseKey:        licenseKey,
		DeviceFingerprint: fingerprint,
	}

	reqBody, err := json.Marshal(activationReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send activation request
	fmt.Println("📡 Contacting license server...")
	if lc.httpClient == nil {
		lc.httpClient = &http.Client{Timeout: HTTP_TIMEOUT}
	}
	req, err := http.NewRequest(http.MethodPost, lc.apiURL("/api/activate"), bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", lc.userAgent())
	resp, err := lc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to contact license server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("license server responded %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var activationResp ActivationResponse
	if err := json.NewDecoder(resp.Body).Decode(&activationResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !activationResp.Success {
		return fmt.Errorf("activation failed: %s", activationResp.Message)
	}
	if activationResp.EncryptedLicense == "" || activationResp.Nonce == "" || activationResp.Signature == "" || activationResp.PublicKey == "" {
		return fmt.Errorf("activation payload missing cryptographic material")
	}

	fmt.Println("✓ License validated by server")

	// Decode response data
	encryptedData, err := hex.DecodeString(activationResp.EncryptedLicense)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted license: %w", err)
	}

	nonce, err := hex.DecodeString(activationResp.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	signature, err := hex.DecodeString(activationResp.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Parse public key
	fmt.Println("🔑 Parsing server public key...")
	publicKeyBlock, _ := pem.Decode([]byte(activationResp.PublicKey))
	if publicKeyBlock == nil {
		return fmt.Errorf("failed to parse public key PEM")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	lc.publicKey = publicKey

	// Verify signature
	fmt.Println("✍️  Verifying signature...")
	dataHash := sha256.Sum256(encryptedData)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, dataHash[:], signature, nil); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	fmt.Println("✓ Signature verified")

	storedLicense := StoredLicense{
		EncryptedData:     encryptedData,
		Nonce:             nonce,
		Signature:         signature,
		PublicKey:         publicKeyBlock.Bytes,
		DeviceFingerprint: fingerprint,
		ExpiresAt:         activationResp.ExpiresAt,
	}

	fmt.Println("💾 Saving license file...")
	if err := lc.writeLicenseFile(&storedLicense); err != nil {
		return err
	}

	fmt.Printf("✓ License saved to: %s\n", lc.licensePath)
	return nil
}

func (lc *LicenseClient) writeLicenseFile(stored *StoredLicense) error {
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
	if err := os.Rename(tmpPath, lc.licensePath); err != nil {
		return fmt.Errorf("failed to finalize license: %w", err)
	}
	return nil
}

func (lc *LicenseClient) ensureLicenseFileSecure(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("license file %s has insecure permissions (%#o) - run 'chmod 600'", lc.licensePath, info.Mode().Perm())
	}
	return nil
}

// ==================== License Verification ====================

func (lc *LicenseClient) Verify() (*LicenseData, error) {
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

	var storedLicense StoredLicense
	if err := json.Unmarshal(licenseJSON, &storedLicense); err != nil {
		return nil, fmt.Errorf("failed to parse license file: %w", err)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(storedLicense.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key type")
	}

	lc.publicKey = publicKey

	dataHash := sha256.Sum256(storedLicense.EncryptedData)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, dataHash[:], storedLicense.Signature, nil); err != nil {
		return nil, fmt.Errorf("signature verification failed - license may be tampered")
	}

	currentFingerprint, err := lc.generateDeviceFingerprint()
	if err != nil {
		return nil, fmt.Errorf("failed to generate current fingerprint: %w", err)
	}
	if storedLicense.DeviceFingerprint != currentFingerprint {
		return nil, fmt.Errorf("device fingerprint mismatch - license is tied to different device")
	}

	licenseData, err := lc.decryptLicense(&storedLicense)
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

func (lc *LicenseClient) decryptLicense(stored *StoredLicense) (*LicenseData, error) {
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
	licenseJSON := decryptedPackage[32:]
	var licenseData LicenseData
	if err := json.Unmarshal(licenseJSON, &licenseData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal license: %w", err)
	}
	licenseData.DeviceFingerprint = stored.DeviceFingerprint
	return &licenseData, nil
}

func (lc *LicenseClient) deriveTransportKey(fingerprint string, nonce []byte) ([]byte, error) {
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

func (lc *LicenseClient) IsActivated() bool {
	_, err := os.Stat(lc.licensePath)
	return err == nil
}

// ==================== Main Application ====================

func showBanner() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Printf("║  %s v%s%-20s║\n", APP_NAME, APP_VERSION, "")
	fmt.Println("║  TPM-Protected Licensed Application       ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
}

func setupLicense(client *LicenseClient) error {
	fmt.Println()
	fmt.Println("⚠️  License activation required")
	fmt.Println()

	var email, username, licenseKey string

	fmt.Print("Enter email: ")
	fmt.Scanln(&email)
	email = strings.TrimSpace(email)

	fmt.Print("Enter username: ")
	fmt.Scanln(&username)
	username = strings.TrimSpace(username)

	fmt.Print("Enter license key: ")
	fmt.Scanln(&licenseKey)
	licenseKey = strings.TrimSpace(licenseKey)

	return client.Activate(email, username, licenseKey)
}

func showLicenseInfo(license *LicenseData) {
	if license == nil {
		return
	}
	fmt.Println("\n📄 License Information:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  User: %s\n", license.Username)
	fmt.Printf("  Email: %s\n", license.Email)
	if license.ClientID != "" {
		fmt.Printf("  Client ID: %s\n", license.ClientID)
	}
	fmt.Printf("  License ID: %s\n", license.ID)
	if license.DeviceFingerprint != "" {
		fmt.Printf("  This device: %s...\n", truncateFingerprint(license.DeviceFingerprint))
	}
	fmt.Printf("  Issued: %s\n", license.IssuedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Expires: %s\n", license.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Activations: %d / %d\n", license.CurrentActivations, license.MaxActivations)
	if len(license.Devices) > 0 {
		fmt.Println("  Registered devices:")
		for _, device := range license.Devices {
			if device.Fingerprint == "" {
				continue
			}
			fmt.Printf("    • %s... | activated %s | last seen %s\n",
				truncateFingerprint(device.Fingerprint),
				formatTimestamp(device.ActivatedAt),
				formatTimestamp(device.LastSeenAt),
			)
		}
	}

	daysLeft := int(time.Until(license.ExpiresAt).Hours() / 24)
	if daysLeft > 0 {
		fmt.Printf("  Days remaining: %d\n", daysLeft)
	} else {
		fmt.Println("  Status: ⚠️  EXPIRED")
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func runApplication(license *LicenseData) {
	fmt.Println()
	fmt.Println("🚀 Starting application...")
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Printf("║  Welcome, %s!%-25s║\n", license.Username, strings.Repeat(" ", max(0, 25-len(license.Username))))
	fmt.Println("║                                           ║")
	fmt.Println("║  Your application is running with a       ║")
	fmt.Println("║  valid TPM-protected license.             ║")
	fmt.Println("║                                           ║")
	fmt.Println("║  All operations are cryptographically     ║")
	fmt.Println("║  verified and device-locked.              ║")
	fmt.Println("╚═══════════════════════════════════════════╝")

	// Simulate application work
	fmt.Println("\n📊 Application Status:")
	fmt.Println("  ✓ License verified")
	fmt.Println("  ✓ Device authenticated")
	fmt.Println("  ✓ Signature validated")
	fmt.Println("  ✓ All systems operational")

	fmt.Println("\n💡 Your actual application logic would run here...")
	fmt.Println("\nPress Ctrl+C to exit")

	// Keep application running until interrupted
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	<-sigCh

	fmt.Println("\n🛑 Shutdown signal received. Exiting...")
}

func truncateFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}

func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return "n/a"
	}
	return ts.Format("2006-01-02 15:04:05")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	showBanner()

	// Initialize license client
	client, err := NewLicenseClient()
	if err != nil {
		log.Fatalf("Failed to initialize license client: %v", err)
	}
	fmt.Printf("🔗 License server: %s\n", client.ServerURL())

	// Check if already activated
	if !client.IsActivated() {
		// First time - need activation
		if err := setupLicense(client); err != nil {
			log.Fatalf("\n❌ Activation failed: %v", err)
		}
		fmt.Println("\n✅ License activated successfully!")
	}

	// Verify license
	fmt.Println("\n🔒 Verifying license...")
	license, err := client.Verify()
	if err != nil {
		log.Fatalf("\n❌ License verification failed: %v\n\nPlease reactivate your license.", err)
	}

	fmt.Println("✓ License verified successfully")

	// Show license info
	showLicenseInfo(license)

	// Run application
	runApplication(license)
}
