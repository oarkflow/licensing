# Client Security Library

Secure client-side implementation for license verification with tamper protection.

## Features

- License signature verification
- Secure storage using OS keychain
- Anti-tampering detection
- Secure communication
- Memory protection
- Obfuscated license storage

## Installation

```bash
go get github.com/oarkflow/licensing/client
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/oarkflow/licensing/client"
)

func main() {
    // Initialize secure client
    config := &client.SecureClientConfig{
        ServerURL:          "https://license.yourcompany.com",
        PublicKey:          publicKeyPEM, // Server's public key for signature verification
        EnableTamperCheck:  true,
        EnableSecureStorage: true,
        ProductID:          "your-product-id",
    }

    secureClient, err := client.NewSecureClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer secureClient.Close()

    // Activate license
    result, err := secureClient.ActivateLicense(context.Background(), "LICENSE-KEY-HERE")
    if err != nil {
        log.Fatal(err)
    }

    if result.Valid {
        log.Println("License activated successfully!")
        log.Printf("Expires: %s", result.ExpiresAt)

        // Start continuous verification
        secureClient.StartContinuousVerification(15 * time.Minute)

        // Your application logic here
        runApplication()
    } else {
        log.Fatal("Invalid license")
    }
}
```

## API Reference

### SecureClient

```go
type SecureClient struct {
    config     *SecureClientConfig
    httpClient *http.Client
    storage    Storage
    verifier   crypto.Verifier
    tamper     *integrity.TamperDetector
}

// NewSecureClient creates a new secure client
func NewSecureClient(config *SecureClientConfig) (*SecureClient, error)

// ActivateLicense activates a license and stores it securely
func (c *SecureClient) ActivateLicense(ctx context.Context, licenseKey string) (*ActivationResult, error)

// VerifyLicense verifies the stored license
func (c *SecureClient) VerifyLicense(ctx context.Context) (*VerificationResult, error)

// DeactivateLicense deactivates the license
func (c *SecureClient) DeactivateLicense(ctx context.Context) error

// GetLicenseInfo retrieves license information
func (c *SecureClient) GetLicenseInfo() (*LicenseInfo, error)

// StartContinuousVerification starts background verification
func (c *SecureClient) StartContinuousVerification(interval time.Duration)

// StopContinuousVerification stops background verification
func (c *SecureClient) StopContinuousVerification()

// Close cleans up resources
func (c *SecureClient) Close() error
```

### Secure Storage

The client automatically uses the most secure storage available on each platform:

- **macOS**: Keychain
- **Windows**: Credential Manager
- **Linux**: Secret Service API (gnome-keyring/KWallet)

```go
// Custom storage implementation (optional)
type CustomStorage struct {
    // Your implementation
}

func (s *CustomStorage) Store(key string, data []byte) error {
    // Store securely
}

func (s *CustomStorage) Retrieve(key string) ([]byte, error) {
    // Retrieve securely
}

func (s *CustomStorage) Delete(key string) error {
    // Delete securely
}
```

### Tamper Detection

```go
// Run integrity checks
result, err := secureClient.CheckIntegrity()
if err != nil {
    log.Printf("Integrity check failed: %v", err)
}

if result.TamperingDetected {
    log.Printf("Tampering detected! Failed checks: %d", result.FailedChecks)
    // Handle tampering
}
```

## Security Features

### 1. Signature Verification

All licenses are cryptographically signed by the server. The client verifies signatures before accepting any license data.

```go
// Automatic signature verification
result, err := client.ActivateLicense(ctx, licenseKey)
// Signature is automatically verified
```

### 2. Secure Storage

Licenses are encrypted before storage and stored in the OS-specific secure storage.

```go
config := &SecureClientConfig{
    EnableSecureStorage: true, // Use OS keychain
    ObfuscateLicense:    true, // Additional obfuscation
}
```

### 3. Tamper Detection

Continuous monitoring for tampering attempts:

```go
// Enable tamper detection
config.EnableTamperCheck = true

// Automatic checks every 5 minutes
client.StartContinuousVerification(5 * time.Minute)
```

### 4. Anti-Debug Protection

Detect debugging attempts (can be disabled for development):

```go
config.EnableAntiDebug = true // Production only

// Or check manually
if client.IsBeingDebugged() {
    // Handle debugging attempt
}
```

### 5. Memory Protection

Sensitive data is cleared from memory after use:

```go
// Automatic memory cleanup
defer secureClient.Close() // Clears sensitive data
```

### 6. Device Fingerprinting

Bind licenses to specific devices:

```go
// Automatic fingerprint generation
fingerprint := client.GetDeviceFingerprint()
```

## Configuration

```go
type SecureClientConfig struct {
    // Server Configuration
    ServerURL      string
    PublicKey      []byte  // Server's public key (PEM format)
    TLSConfig      *tls.Config

    // Product Information
    ProductID      string
    ProductVersion string

    // Security Options
    EnableTamperCheck   bool // Enable tamper detection
    EnableAntiDebug     bool // Enable anti-debugging (disable for development)
    EnableSecureStorage bool // Use OS keychain
    ObfuscateLicense    bool // Obfuscate stored license

    // Verification Options
    VerifyInterval      time.Duration // Auto-verification interval
    RequireOnlineCheck  bool          // Require periodic online checks
    GracePeriod         time.Duration // Offline grace period

    // Timeouts
    RequestTimeout      time.Duration

    // Certificate Pinning
    PinnedCertificates  [][]byte // Pin specific certificates
}
```

## Error Handling

```go
import "github.com/oarkflow/licensing/client"

result, err := client.ActivateLicense(ctx, licenseKey)
if err != nil {
    switch {
    case errors.Is(err, client.ErrInvalidLicense):
        // License is invalid
    case errors.Is(err, client.ErrExpiredLicense):
        // License has expired
    case errors.Is(err, client.ErrTamperingDetected):
        // Tampering detected
    case errors.Is(err, client.ErrNetworkError):
        // Network error
    case errors.Is(err, client.ErrServerError):
        // Server error
    default:
        // Other error
    }
}
```

## Best Practices

### 1. Initialize Early

Initialize the secure client as early as possible in your application:

```go
func main() {
    client, err := client.NewSecureClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Rest of application
}
```

### 2. Handle Expiration Gracefully

```go
result, err := client.VerifyLicense(ctx)
if err != nil {
    if errors.Is(err, client.ErrExpiredLicense) {
        showExpirationNotice()
        // Give user option to renew
    }
}
```

### 3. Continuous Verification

Enable background verification for long-running applications:

```go
// Check every 15 minutes
client.StartContinuousVerification(15 * time.Minute)

// Listen for verification events
go func() {
    for event := range client.VerificationEvents() {
        if !event.Valid {
            log.Printf("License verification failed: %s", event.Reason)
            // Handle invalid license
        }
    }
}()
```

### 4. Offline Support

Configure grace period for offline usage:

```go
config := &SecureClientConfig{
    RequireOnlineCheck: true,
    GracePeriod:        7 * 24 * time.Hour, // 7 days offline
}
```

### 5. Security in Production

```go
// Development
config.EnableAntiDebug = false
config.EnableTamperCheck = false

// Production
config.EnableAntiDebug = true
config.EnableTamperCheck = true
config.EnableSecureStorage = true
```

## Testing

```go
// Use mock server for testing
mockServer := client.NewMockServer()
defer mockServer.Close()

config := &SecureClientConfig{
    ServerURL: mockServer.URL,
    // ... other config
}

// Run tests
```

## Platform-Specific Notes

### macOS

- Uses Keychain Services for secure storage
- Requires codesigning for keychain access

### Windows

- Uses Windows Credential Manager
- Requires appropriate permissions

### Linux

- Uses Secret Service API
- Requires gnome-keyring or KWallet

### Mobile Platforms

#### iOS
```go
// Uses iOS Keychain
config.EnableSecureStorage = true
```

#### Android
```go
// Uses Android Keystore
config.EnableSecureStorage = true
```

## Troubleshooting

### License Verification Fails

1. Check server connectivity
2. Verify public key is correct
3. Check system clock (time sync issues)
4. Review tamper detection logs

### Secure Storage Issues

1. Ensure platform keychain is available
2. Check application permissions
3. Try fallback storage if needed

### Performance Issues

1. Adjust verification interval
2. Disable unnecessary security features in development
3. Use caching for license data

## Security Considerations

1. **Never hardcode licenses** - Always validate with server
2. **Protect public keys** - Embed securely in binary
3. **Use HTTPS** - Always use TLS for server communication
4. **Certificate pinning** - Pin certificates for critical applications
5. **Regular updates** - Keep security library updated
6. **Audit logs** - Monitor for suspicious activity
7. **Fail securely** - Default to denying access on errors

## Support

For security issues, please email: security@yourcompany.com

For general support: support@yourcompany.com

## License

Copyright © 2024 Your Company. All rights reserved.
