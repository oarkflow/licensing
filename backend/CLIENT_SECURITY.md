# Client-Side Security Guide

## Overview

This guide covers implementing security measures on the client side of your licensing system to ensure tamper-proof, secure license verification.

## Client Security Architecture

```
Client Application
├── License Verification
│   ├── Signature Verification
│   ├── Integrity Checks
│   └── Anti-Tampering
├── Secure Communication
│   ├── TLS/mTLS
│   └── Certificate Pinning
└── Runtime Protection
    ├── Debugger Detection
    └── Memory Protection
```

## 1. Secure License Storage

### Best Practices

```go
// Store licenses securely on client side
type SecureLicenseStore struct {
    encryptor crypto.Encryptor
    storage   Storage
}

// Store license with encryption
func (s *SecureLicenseStore) StoreLicense(license *License) error {
    // Encrypt license data
    encrypted, err := s.encryptor.Encrypt(license.Serialize())
    if err != nil {
        return err
    }

    // Store in secure location (not in plain files)
    return s.storage.Save("license.dat", encrypted)
}
```

### Storage Locations

**Windows:**
- Use Windows Credential Manager
- Registry (HKEY_LOCAL_MACHINE\SOFTWARE\YourApp)
- Encrypted files in `%PROGRAMDATA%`

**Linux:**
- `/etc/yourapp/` (requires root)
- `~/.config/yourapp/` with 600 permissions
- System keyring integration

**macOS:**
- Keychain Services
- `/Library/Application Support/YourApp/`

## 2. License Verification

### Multi-Layer Verification

```go
package client

import (
    "github.com/oarkflow/licensing/pkg/crypto"
    "github.com/oarkflow/licensing/pkg/integrity"
)

type LicenseVerifier struct {
    publicKey   []byte
    verifier    *integrity.Verifier
}

func NewLicenseVerifier(publicKey []byte) *LicenseVerifier {
    return &LicenseVerifier{
        publicKey: publicKey,
        verifier:  integrity.NewVerifier(),
    }
}

// VerifyLicense performs comprehensive verification
func (lv *LicenseVerifier) VerifyLicense(license *License) error {
    // 1. Signature verification
    if err := lv.verifySignature(license); err != nil {
        return fmt.Errorf("signature verification failed: %w", err)
    }

    // 2. Expiration check
    if license.ExpiresAt.Before(time.Now()) {
        return fmt.Errorf("license expired")
    }

    // 3. Hardware binding (if applicable)
    if license.HardwareID != "" {
        currentHwID := getHardwareID()
        if license.HardwareID != currentHwID {
            return fmt.Errorf("hardware mismatch")
        }
    }

    // 4. Checksum verification
    if err := lv.verifyIntegrity(license); err != nil {
        return fmt.Errorf("integrity check failed: %w", err)
    }

    return nil
}

func (lv *LicenseVerifier) verifySignature(license *License) error {
    // Reconstruct signed data
    data := license.GetSignableData()

    // Verify signature using Ed25519/RSA
    signer := crypto.NewEd25519Signer("client-verify")
    // Import public key
    if err := signer.ImportPublicKey(lv.publicKey); err != nil {
        return err
    }

    return signer.Verify(data, []byte(license.Signature))
}

func (lv *LicenseVerifier) verifyIntegrity(license *License) error {
    // Use multi-layer verification
    verification := integrity.NewMultiLayerVerification()

    // Add verification layers
    verification.AddLayer("checksum", "Verify data checksum",
        license.Checksum == computeChecksum(license), nil)

    return nil
}
```

## 3. Anti-Tampering Protection

### Runtime Checks

```go
package client

import (
    "github.com/oarkflow/licensing/pkg/integrity"
)

type ClientProtection struct {
    tamperDetector *integrity.TamperDetector
    checkInterval  time.Duration
}

func NewClientProtection() *ClientProtection {
    return &ClientProtection{
        tamperDetector: integrity.NewTamperDetector(),
        checkInterval:  5 * time.Minute,
    }
}

// StartProtection begins continuous monitoring
func (cp *ClientProtection) StartProtection() {
    go cp.continuousCheck()
}

func (cp *ClientProtection) continuousCheck() {
    ticker := time.NewTicker(cp.checkInterval)
    defer ticker.Stop()

    for range ticker.C {
        result, err := cp.tamperDetector.RunChecks()
        if err != nil {
            log.Printf("Tamper check error: %v", err)
            continue
        }

        if result.TamperingDetected {
            cp.handleTampering(result)
        }
    }
}

func (cp *ClientProtection) handleTampering(result *integrity.TamperResult) {
    // Log the incident
    log.Printf("TAMPERING DETECTED: %v", result.FailedChecks)

    // Take action
    // 1. Disable functionality
    // 2. Notify server
    // 3. Exit application
    os.Exit(1)
}
```

### Code Obfuscation

Protect sensitive code from reverse engineering:

```bash
# Use Go obfuscation tools
garble build -o app ./cmd/app

# Or use commercial obfuscators
# - VMProtect
# - Themida
# - Enigma Protector
```

## 4. Secure Communication

### SSH Key Authentication

#### Generating SSH Keys for Client Authentication

Clients can use SSH key pairs for secure authentication with the licensing server. This provides stronger security than passwords and enables automated authentication.

##### Using OpenSSH (Linux/macOS/Windows)

```bash
# Generate Ed25519 key (recommended - most secure and fastest)
ssh-keygen -t ed25519 -C "client@licensing-system" -f ~/.ssh/licensing_client

# Or generate RSA key (widely compatible)
ssh-keygen -t rsa -b 4096 -C "client@licensing-system" -f ~/.ssh/licensing_client_rsa

# Output:
# ~/.ssh/licensing_client      (private key - keep secure!)
# ~/.ssh/licensing_client.pub  (public key - share with server)

# Set secure permissions
chmod 600 ~/.ssh/licensing_client
chmod 644 ~/.ssh/licensing_client.pub
```

##### Using Go crypto Package (Programmatic)

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
)

// GenerateSSHKeyPair generates an Ed25519 SSH key pair
func GenerateSSHKeyPair(outputPath string) error {
    // Generate Ed25519 key pair
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return fmt.Errorf("failed to generate key: %w", err)
    }

    // Marshal private key to PKCS8 format
    privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return fmt.Errorf("failed to marshal private key: %w", err)
    }

    // Create PEM block for private key
    privateKeyPEM := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    // Write private key to file
    privateKeyFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return fmt.Errorf("failed to create private key file: %w", err)
    }
    defer privateKeyFile.Close()

    if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
        return fmt.Errorf("failed to write private key: %w", err)
    }

    // Marshal public key
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return fmt.Errorf("failed to marshal public key: %w", err)
    }

    // Create PEM block for public key
    publicKeyPEM := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    // Write public key to file
    publicKeyFile, err := os.Create(outputPath + ".pub")
    if err != nil {
        return fmt.Errorf("failed to create public key file: %w", err)
    }
    defer publicKeyFile.Close()

    if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
        return fmt.Errorf("failed to write public key: %w", err)
    }

    fmt.Printf("SSH key pair generated:\n")
    fmt.Printf("  Private key: %s (keep secure!)\n", outputPath)
    fmt.Printf("  Public key:  %s.pub\n", outputPath)

    return nil
}

// Usage
func main() {
    if err := GenerateSSHKeyPair("./client_key"); err != nil {
        panic(err)
    }
}
```

#### Using SSH Keys for Authentication

##### Client-Side Implementation

```go
package client

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "net/http"
    "time"
)

type SSHKeyAuthenticator struct {
    privateKey ed25519.PrivateKey
    publicKey  ed25519.PublicKey
    clientID   string
}

// NewSSHKeyAuthenticator creates an authenticator from key file
func NewSSHKeyAuthenticator(privateKeyPath, clientID string) (*SSHKeyAuthenticator, error) {
    // Read private key file
    keyData, err := ioutil.ReadFile(privateKeyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read private key: %w", err)
    }

    // Parse PEM block
    block, _ := pem.Decode(keyData)
    if block == nil {
        return nil, fmt.Errorf("failed to parse PEM block")
    }

    // Parse private key
    key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %w", err)
    }

    privateKey, ok := key.(ed25519.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("key is not Ed25519 private key")
    }

    // Derive public key
    publicKey := privateKey.Public().(ed25519.PublicKey)

    return &SSHKeyAuthenticator{
        privateKey: privateKey,
        publicKey:  publicKey,
        clientID:   clientID,
    }, nil
}

// SignRequest signs an HTTP request for authentication
func (auth *SSHKeyAuthenticator) SignRequest(req *http.Request) error {
    // Create signature payload: METHOD + PATH + TIMESTAMP + BODY
    timestamp := time.Now().Unix()

    payload := fmt.Sprintf("%s\n%s\n%d\n",
        req.Method,
        req.URL.Path,
        timestamp,
    )

    // Add body hash if present
    if req.Body != nil {
        bodyBytes, err := ioutil.ReadAll(req.Body)
        if err != nil {
            return err
        }
        // Restore body for actual request
        req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

        bodyHash := sha256.Sum256(bodyBytes)
        payload += base64.StdEncoding.EncodeToString(bodyHash[:])
    }

    // Sign the payload
    signature := ed25519.Sign(auth.privateKey, []byte(payload))

    // Add authentication headers
    req.Header.Set("X-Client-ID", auth.clientID)
    req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
    req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(signature))
    req.Header.Set("X-Public-Key", base64.StdEncoding.EncodeToString(auth.publicKey))

    return nil
}

// CreateAuthenticatedClient creates HTTP client with SSH key auth
func CreateAuthenticatedClient(privateKeyPath, clientID string) (*http.Client, error) {
    auth, err := NewSSHKeyAuthenticator(privateKeyPath, clientID)
    if err != nil {
        return nil, err
    }

    // Create custom transport with auth
    transport := &authenticatedTransport{
        base: http.DefaultTransport,
        auth: auth,
    }

    return &http.Client{
        Transport: transport,
        Timeout:   30 * time.Second,
    }, nil
}

type authenticatedTransport struct {
    base http.RoundTripper
    auth *SSHKeyAuthenticator
}

func (t *authenticatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    // Clone request to avoid modifying original
    reqCopy := req.Clone(req.Context())

    // Sign the request
    if err := t.auth.SignRequest(reqCopy); err != nil {
        return nil, fmt.Errorf("failed to sign request: %w", err)
    }

    // Execute request
    return t.base.RoundTrip(reqCopy)
}
```

##### Usage Example

```go
package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
)

func main() {
    // Create authenticated client
    client, err := CreateAuthenticatedClient(
        "/home/user/.ssh/licensing_client",
        "client-12345",
    )
    if err != nil {
        panic(err)
    }

    // Make authenticated request
    resp, err := client.Get("https://license-server.com/api/licenses")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    fmt.Printf("Response: %s\n", body)
}
```

#### Server-Side SSH Key Verification

```go
package server

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "net/http"
    "strconv"
    "time"
)

type SSHKeyVerifier struct {
    publicKeys map[string]ed25519.PublicKey // clientID -> publicKey
    maxAge     time.Duration
}

func NewSSHKeyVerifier() *SSHKeyVerifier {
    return &SSHKeyVerifier{
        publicKeys: make(map[string]ed25519.PublicKey),
        maxAge:     5 * time.Minute, // Allow 5 minute clock skew
    }
}

// RegisterClientKey registers a client's public key
func (v *SSHKeyVerifier) RegisterClientKey(clientID string, publicKeyPEM []byte) error {
    // Parse PEM and extract public key
    block, _ := pem.Decode(publicKeyPEM)
    if block == nil {
        return fmt.Errorf("failed to parse PEM")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return err
    }

    publicKey, ok := pub.(ed25519.PublicKey)
    if !ok {
        return fmt.Errorf("not an Ed25519 public key")
    }

    v.publicKeys[clientID] = publicKey
    return nil
}

// VerifyRequest verifies SSH key authentication
func (v *SSHKeyVerifier) VerifyRequest(r *http.Request) (string, error) {
    // Extract headers
    clientID := r.Header.Get("X-Client-ID")
    timestampStr := r.Header.Get("X-Timestamp")
    signatureB64 := r.Header.Get("X-Signature")

    if clientID == "" || timestampStr == "" || signatureB64 == "" {
        return "", fmt.Errorf("missing authentication headers")
    }

    // Verify timestamp (prevent replay attacks)
    timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
    if err != nil {
        return "", fmt.Errorf("invalid timestamp")
    }

    requestTime := time.Unix(timestamp, 0)
    if time.Since(requestTime) > v.maxAge {
        return "", fmt.Errorf("request too old")
    }
    if requestTime.After(time.Now().Add(v.maxAge)) {
        return "", fmt.Errorf("request from future")
    }

    // Get client's public key
    publicKey, exists := v.publicKeys[clientID]
    if !exists {
        return "", fmt.Errorf("unknown client ID")
    }

    // Reconstruct signed payload
    payload := fmt.Sprintf("%s\n%s\n%d\n",
        r.Method,
        r.URL.Path,
        timestamp,
    )

    // Add body hash if present
    if r.Body != nil {
        bodyBytes, err := ioutil.ReadAll(r.Body)
        if err != nil {
            return "", err
        }
        r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

        bodyHash := sha256.Sum256(bodyBytes)
        payload += base64.StdEncoding.EncodeToString(bodyHash[:])
    }

    // Decode signature
    signature, err := base64.StdEncoding.DecodeString(signatureB64)
    if err != nil {
        return "", fmt.Errorf("invalid signature encoding")
    }

    // Verify signature
    if !ed25519.Verify(publicKey, []byte(payload), signature) {
        return "", fmt.Errorf("signature verification failed")
    }

    return clientID, nil
}

// Middleware for SSH key authentication
func (v *SSHKeyVerifier) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientID, err := v.VerifyRequest(r)
        if err != nil {
            http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Add clientID to context
        ctx := context.WithValue(r.Context(), "client_id", clientID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

#### Key Rotation for SSH Keys

```go
// Client key rotation
func RotateSSHKey(oldKeyPath, newKeyPath string, serverURL string) error {
    // Generate new key pair
    if err := GenerateSSHKeyPair(newKeyPath); err != nil {
        return err
    }

    // Read new public key
    newPubKeyData, err := ioutil.ReadFile(newKeyPath + ".pub")
    if err != nil {
        return err
    }

    // Create authenticated client with old key
    client, err := CreateAuthenticatedClient(oldKeyPath, "client-id")
    if err != nil {
        return err
    }

    // Upload new public key to server
    resp, err := client.Post(
        serverURL+"/api/keys/rotate",
        "application/x-pem-file",
        bytes.NewBuffer(newPubKeyData),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("key rotation failed: %s", resp.Status)
    }

    // Backup old key
    os.Rename(oldKeyPath, oldKeyPath+".old")

    fmt.Println("SSH key rotation successful")
    return nil
}
```

#### Best Practices for SSH Key Management

**Client-Side:**
- ✅ Store private keys with 600 permissions (read/write owner only)
- ✅ Never commit private keys to version control
- ✅ Use separate keys for different environments (dev/staging/prod)
- ✅ Rotate keys every 90-180 days
- ✅ Use Ed25519 keys (smaller, faster, more secure than RSA)
- ✅ Encrypt private keys with passphrase for additional security
- ✅ Store keys in secure locations (OS keychain, encrypted storage)

**Server-Side:**
- ✅ Store only public keys (never private keys)
- ✅ Implement timestamp validation to prevent replay attacks
- ✅ Rate limit authentication attempts
- ✅ Log all authentication attempts
- ✅ Support key revocation
- ✅ Allow multiple keys per client (for rotation)
- ✅ Implement key expiration dates

**Security Considerations:**
- ⚠️ SSH keys provide non-repudiation (actions can be tied to key owner)
- ⚠️ Protect private keys like passwords (compromise = full access)
- ⚠️ Use different keys for different clients/services
- ⚠️ Monitor for unusual authentication patterns
- ⚠️ Implement automatic key rotation policies
- ⚠️ Have key recovery procedures in place

### TLS Configuration

```go
package client

import (
    "crypto/tls"
    "crypto/x509"
    "net/http"
)

func createSecureClient(certPEM []byte) *http.Client {
    // Load server certificate for pinning
    certPool := x509.NewCertPool()
    certPool.AppendCertsFromPEM(certPEM)

    // Configure TLS
    tlsConfig := &tls.Config{
        RootCAs:            certPool,
        MinVersion:         tls.VersionTLS13,
        InsecureSkipVerify: false,
    }

    // Create HTTP client
    transport := &http.Transport{
        TLSClientConfig: tlsConfig,
    }

    return &http.Client{
        Transport: transport,
        Timeout:   30 * time.Second,
    }
}
```

### Certificate Pinning

```go
// Pin specific certificate
func createPinnedClient(expectedCertHash []byte) *http.Client {
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS13,
        VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            // Verify certificate hash matches expected
            for _, rawCert := range rawCerts {
                hash := sha256.Sum256(rawCert)
                if bytes.Equal(hash[:], expectedCertHash) {
                    return nil
                }
            }
            return fmt.Errorf("certificate pinning failed")
        },
    }

    return &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsConfig},
    }
}
```

## 5. License Activation

### Secure Activation Flow

```go
func ActivateLicense(licenseKey string) error {
    // 1. Validate format
    if !isValidLicenseFormat(licenseKey) {
        return fmt.Errorf("invalid license format")
    }

    // 2. Contact server securely
    client := createSecureClient(serverCert)

    // 3. Get hardware fingerprint
    hwID := getHardwareID()

    // 4. Send activation request
    resp, err := client.Post(
        "https://license-server.com/activate",
        "application/json",
        bytes.NewBuffer([]byte(fmt.Sprintf(`{
            "license_key": "%s",
            "hardware_id": "%s"
        }`, licenseKey, hwID))),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // 5. Verify response signature
    var activation ActivationResponse
    if err := json.NewDecoder(resp.Body).Decode(&activation); err != nil {
        return err
    }

    // 6. Verify license signature
    if err := verifyActivation(&activation); err != nil {
        return err
    }

    // 7. Store securely
    return storeSecurely(&activation)
}
```

## 6. Hardware Binding

### Hardware Fingerprinting

```go
func getHardwareID() string {
    var components []string

    // CPU ID
    if cpuID := getCPUID(); cpuID != "" {
        components = append(components, cpuID)
    }

    // MAC Address (first non-virtual)
    if mac := getPrimaryMAC(); mac != "" {
        components = append(components, mac)
    }

    // Motherboard Serial (if available)
    if mb := getMotherboardSerial(); mb != "" {
        components = append(components, mb)
    }

    // Disk serial (system disk)
    if disk := getSystemDiskSerial(); disk != "" {
        components = append(components, disk)
    }

    // Create stable hash
    combined := strings.Join(components, "|")
    hash := sha256.Sum256([]byte(combined))
    return hex.EncodeToString(hash[:])
}
```

## 7. Offline Validation

### Periodic Online Check with Grace Period

```go
type OfflineLicenseManager struct {
    lastCheck       time.Time
    gracePeriod     time.Duration
    maxOfflineDays  int
}

func (olm *OfflineLicenseManager) Validate() error {
    license := loadStoredLicense()

    // Always verify signature and expiration
    if err := verifyLicense(license); err != nil {
        return err
    }

    // Check if online validation needed
    daysSinceCheck := time.Since(olm.lastCheck).Hours() / 24

    if daysSinceCheck > float64(olm.maxOfflineDays) {
        // Must connect to server
        if err := olm.validateOnline(license); err != nil {
            if daysSinceCheck > float64(olm.maxOfflineDays+7) {
                // Grace period exceeded
                return fmt.Errorf("license validation required")
            }
            // Still in grace period
            log.Printf("Warning: Unable to validate online, %d days remaining",
                7-int(daysSinceCheck-float64(olm.maxOfflineDays)))
        } else {
            olm.lastCheck = time.Now()
            olm.saveCheckTime()
        }
    }

    return nil
}
```

## 8. Error Handling

### Secure Error Messages

```go
// DON'T: Expose internal details
func badVerify(license *License) error {
    if license.Signature != computeSignature(license) {
        return fmt.Errorf("signature mismatch: expected %s, got %s",
            computeSignature(license), license.Signature)
    }
    return nil
}

// DO: Generic error messages
func goodVerify(license *License) error {
    if license.Signature != computeSignature(license) {
        // Log details internally
        log.Printf("Signature verification failed for license %s", license.ID)

        // Return generic error
        return fmt.Errorf("license verification failed")
    }
    return nil
}
```

## 9. License Caching

### Secure Local Cache

```go
type LicenseCache struct {
    cache     map[string]*CachedLicense
    encryptor crypto.Encryptor
    maxAge    time.Duration
}

type CachedLicense struct {
    License   *License
    CachedAt  time.Time
    Verified  bool
}

func (lc *LicenseCache) Get(key string) (*License, error) {
    cached, exists := lc.cache[key]
    if !exists {
        return nil, fmt.Errorf("license not cached")
    }

    // Check cache age
    if time.Since(cached.CachedAt) > lc.maxAge {
        delete(lc.cache, key)
        return nil, fmt.Errorf("cache expired")
    }

    // Verify integrity
    if !cached.Verified {
        if err := verifyLicense(cached.License); err != nil {
            delete(lc.cache, key)
            return nil, err
        }
        cached.Verified = true
    }

    return cached.License, nil
}
```

## 10. Best Practices

### Security Checklist

- [ ] **Never hardcode keys** - Embed public keys only
- [ ] **Always verify signatures** - Before using any license
- [ ] **Use TLS 1.3** - For all server communication
- [ ] **Implement certificate pinning** - Prevent MITM attacks
- [ ] **Enable tamper detection** - Continuous monitoring
- [ ] **Obfuscate code** - Make reverse engineering harder
- [ ] **Hardware binding** - Prevent license sharing
- [ ] **Secure storage** - Encrypt license files
- [ ] **Rate limiting** - Prevent brute force
- [ ] **Logging** - Record all security events
- [ ] **Grace period** - For offline validation
- [ ] **Update mechanism** - Secure auto-update
- [ ] **Error handling** - Don't leak information
- [ ] **Code signing** - Sign your binaries
- [ ] **Anti-debugging** - Detect debuggers

### Common Pitfalls

❌ **Don't:**
- Store private keys on client
- Trust client timestamps
- Skip signature verification
- Use insecure communication
- Expose internal errors
- Hardcode server URLs (make configurable)
- Allow unlimited offline use

✅ **Do:**
- Verify everything server-side
- Use certificate pinning
- Implement fallback mechanisms
- Log security events
- Regular online checks
- Graceful degradation
- Clear error messages (to users, not attackers)

## 11. Platform-Specific Considerations

### Windows
```go
// Use Windows Credential Manager
import "github.com/danieljoos/wincred"

func storeWindowsLicense(license *License) error {
    cred := wincred.NewGenericCredential("MyApp/License")
    cred.CredentialBlob = license.Serialize()
    return cred.Write()
}
```

### macOS
```go
// Use Keychain
// Consider using: github.com/keybase/go-keychain
```

### Linux
```go
// Use system keyring
// Consider using: github.com/zalando/go-keyring
```

## 12. Testing Client Security

```go
func TestLicenseVerification(t *testing.T) {
    tests := []struct {
        name      string
        license   *License
        wantError bool
    }{
        {"valid license", validLicense(), false},
        {"expired license", expiredLicense(), true},
        {"invalid signature", tamperedLicense(), true},
        {"wrong hardware", wrongHWLicense(), true},
    }

    verifier := NewLicenseVerifier(publicKey)

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := verifier.VerifyLicense(tt.license)
            if (err != nil) != tt.wantError {
                t.Errorf("VerifyLicense() error = %v, wantError %v",
                    err, tt.wantError)
            }
        })
    }
}
```

## Summary

Client-side security is crucial for a tamper-proof licensing system. Key points:

1. **Verify everything** - Never trust stored data
2. **Protect runtime** - Detect tampering attempts
3. **Secure communication** - Use TLS with pinning
4. **Hardware binding** - Prevent license sharing
5. **Graceful degradation** - Handle offline scenarios
6. **Regular updates** - Keep security current

Implement these practices to create a robust, secure client that protects your licensing system from tampering, reverse engineering, and unauthorized use.
