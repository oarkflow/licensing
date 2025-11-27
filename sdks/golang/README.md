# Go Licensing SDK

A Go SDK for integrating hardware-bound software licensing into Go applications. This SDK provides the full licensing client with activation, verification, background scheduling, and encrypted license storage.

## Features

- 🔐 **AES-256-GCM encryption** for secure license transport and storage
- ✅ **RSA-PSS signature verification** to ensure license authenticity
- 🖥️ **Hardware fingerprinting** for device-bound licenses
- ⏰ **Background verification** with configurable check modes
- 🔄 **Automatic retry** with exponential backoff for network failures
- 📦 **Zero external dependencies** for crypto operations

## Requirements

- Go 1.21 or later

## Installation

```bash
go get github.com/oarkflow/licensing/sdks/golang
```

## Quick Start

### 1. Basic Usage

```go
package main

import (
    "log"
    "os"

    licensing "github.com/oarkflow/licensing/sdks/golang"
)

func main() {
    // Create client with configuration
    client, err := licensing.New(licensing.Config{
        ServerURL:   "https://licensing.example.com",
        ConfigDir:   os.Getenv("HOME") + "/.myapp",
        LicenseFile: ".license.dat",
        AppName:     "MyApp",
        AppVersion:  "1.0.0",
    })
    if err != nil {
        log.Fatalf("failed to create client: %v", err)
    }

    // Check if already activated
    if !client.HasLicense() {
        // Activate with credentials
        err := client.ActivateWithCredentials(licensing.ActivationRequest{
            Email:      "user@example.com",
            ClientID:   "client-123",
            LicenseKey: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
        })
        if err != nil {
            log.Fatalf("activation failed: %v", err)
        }
    }

    // Verify license is valid
    if err := client.Verify(); err != nil {
        log.Fatalf("verification failed: %v", err)
    }

    // Get license data
    license, err := client.License()
    if err != nil {
        log.Fatalf("failed to get license: %v", err)
    }

    log.Printf("License: %s (plan: %s)", license.ID, license.PlanSlug)
    log.Printf("Expires: %s", license.ExpiresAt)
}
```

### 2. Feature Gating

```go
func isFeatureEnabled(license *licensing.LicenseData, feature string) bool {
    planFeatures := map[string][]string{
        "starter":      {"basic"},
        "professional": {"basic", "advanced"},
        "enterprise":   {"basic", "advanced", "premium", "api"},
    }

    for _, f := range planFeatures[license.PlanSlug] {
        if f == feature {
            return true
        }
    }
    return false
}

// Usage
if isFeatureEnabled(license, "api") {
    enableAPIAccess()
}
```

### 3. Background Verification

```go
import (
    "context"
    "os"
    "os/signal"
    "syscall"
)

func main() {
    client, _ := licensing.New(cfg)

    // Start background verification
    ctx, cancel := context.WithCancel(context.Background())
    go client.StartBackgroundVerification(ctx)

    // Handle graceful shutdown
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    cancel() // Stop background verification
}
```

## Configuration

### Config Struct

```go
type Config struct {
    ConfigDir         string        // Directory for license storage (default: ~/.licensing)
    LicenseFile       string        // License filename (default: .license.dat)
    ServerURL         string        // License server URL (default: https://localhost:8801)
    AppName           string        // Application name for User-Agent
    AppVersion        string        // Application version for User-Agent
    HTTPTimeout       time.Duration // HTTP request timeout (default: 15s)
    CACertPath        string        // Custom CA certificate path
    AllowInsecureHTTP bool          // Allow non-TLS connections (dev only!)
}
```

### Environment Variables

The SDK respects these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `LICENSE_CLIENT_SERVER` | License server URL | `https://localhost:8801` |
| `LICENSE_CLIENT_CONFIG_DIR` | License storage directory | `~/.licensing` |
| `LICENSE_CLIENT_LICENSE_FILE` | License filename | `.license.dat` |
| `LICENSE_CLIENT_EMAIL` | Activation email | — |
| `LICENSE_CLIENT_ID` | Client identifier | — |
| `LICENSE_CLIENT_LICENSE_KEY` | License key | — |
| `LICENSE_CLIENT_ALLOW_INSECURE_HTTP` | Allow non-TLS | `false` |

## API Reference

### Types

#### `LicenseData`

```go
type LicenseData struct {
    ID                 string          // Unique license identifier
    ClientID           string          // Owner client ID
    SubjectClientID    string          // Runtime client ID
    Email              string          // License owner email
    PlanSlug           string          // Plan for feature gating
    Relationship       string          // "direct" or "delegated"
    GrantedBy          string          // Granting client (delegated)
    LicenseKey         string          // The license key
    IssuedAt           time.Time       // Issue timestamp
    ExpiresAt          time.Time       // Expiration timestamp
    LastActivatedAt    time.Time       // Last activation time
    CurrentActivations int             // Current activation count
    MaxDevices         int             // Maximum allowed devices
    DeviceCount        int             // Current device count
    IsRevoked          bool            // Revocation status
    RevokedAt          time.Time       // Revocation timestamp
    RevokeReason       string          // Revocation reason
    Devices            []LicenseDevice // Registered devices
    DeviceFingerprint  string          // Current device fingerprint
    CheckMode          string          // Verification schedule
    CheckIntervalSecs  int64           // Custom interval (seconds)
    NextCheckAt        time.Time       // Next scheduled check
    LastCheckAt        time.Time       // Last check timestamp
}
```

#### `StoredLicense`

```go
type StoredLicense struct {
    EncryptedData     []byte    // AES-GCM encrypted license + session key
    Nonce             []byte    // 12-byte GCM nonce
    Signature         []byte    // RSA-PSS signature
    PublicKey         []byte    // DER-encoded public key
    DeviceFingerprint string    // Device fingerprint (hex)
    ExpiresAt         time.Time // License expiration
}
```

### Client Methods

```go
// New creates a new licensing client
func New(cfg Config) (*Client, error)

// Activate activates using environment variables
func (c *Client) Activate() error

// ActivateWithCredentials activates with explicit credentials
func (c *Client) ActivateWithCredentials(req ActivationRequest) error

// Verify checks license validity (online if due, offline otherwise)
func (c *Client) Verify() error

// License returns the decrypted license data
func (c *Client) License() (*LicenseData, error)

// HasLicense returns true if a local license exists
func (c *Client) HasLicense() bool

// IsValid returns true if the license is currently valid
func (c *Client) IsValid() bool

// StartBackgroundVerification starts the verification scheduler
func (c *Client) StartBackgroundVerification(ctx context.Context)
```

### Standalone Crypto Functions

For SDK testing and fixture verification:

```go
// DecryptStoredLicense decrypts a stored license
func DecryptStoredLicense(stored *StoredLicense) (*LicenseData, []byte, error)

// VerifyStoredLicenseSignature verifies the RSA-PSS signature
func VerifyStoredLicenseSignature(stored *StoredLicense) error

// BuildStoredLicenseFromResponse constructs a StoredLicense from API response
func BuildStoredLicenseFromResponse(resp *ActivationResponse, fingerprint string) (*StoredLicense, error)
```

## Error Handling

```go
import "errors"

err := client.Verify()
if err != nil {
    switch {
    case errors.Is(err, licensing.ErrLicenseNotFound):
        log.Println("No license found - please activate")
    case errors.Is(err, licensing.ErrLicenseExpired):
        log.Fatal("License has expired - please renew")
    case errors.Is(err, licensing.ErrLicenseRevoked):
        log.Fatal("License has been revoked")
    case errors.Is(err, licensing.ErrSignatureInvalid):
        log.Fatal("License file tampered - please re-activate")
    case errors.Is(err, licensing.ErrServerUnavailable):
        log.Println("Server unavailable - using cached license")
    default:
        log.Fatalf("Verification failed: %v", err)
    }
}
```

## Check Modes

The SDK supports various verification schedules:

| Mode | Behavior |
|------|----------|
| `none` | No automatic verification after initial activation |
| `each_execution` | Verify with server on every startup |
| `monthly` | Verify at the start of each month |
| `yearly` | Verify at the start of each year |
| `custom` | Use `check_interval_seconds` for custom scheduling |

```go
license, _ := client.License()
switch license.CheckMode {
case "each_execution":
    // Always verify on startup
case "monthly":
    // Check if we're past next_check_at
case "custom":
    interval := time.Duration(license.CheckIntervalSecs) * time.Second
    // Schedule next check
}
```

## HTTP Handler Integration

```go
import (
    "net/http"
    "encoding/json"
)

type LicenseMiddleware struct {
    client *licensing.Client
}

func (m *LicenseMiddleware) Handler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if err := m.client.Verify(); err != nil {
            w.WriteHeader(http.StatusForbidden)
            json.NewEncoder(w).Encode(map[string]string{
                "error": "License validation failed",
            })
            return
        }

        license, _ := m.client.License()
        ctx := context.WithValue(r.Context(), "license", license)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Usage
mux := http.NewServeMux()
middleware := &LicenseMiddleware{client: client}
http.ListenAndServe(":8080", middleware.Handler(mux))
```

## gRPC Integration

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

func LicenseInterceptor(client *licensing.Client) grpc.UnaryServerInterceptor {
    return func(
        ctx context.Context,
        req interface{},
        info *grpc.UnaryServerInfo,
        handler grpc.UnaryHandler,
    ) (interface{}, error) {
        if err := client.Verify(); err != nil {
            return nil, status.Error(codes.PermissionDenied, "license validation failed")
        }
        return handler(ctx, req)
    }
}

// Usage
server := grpc.NewServer(
    grpc.UnaryInterceptor(LicenseInterceptor(client)),
)
```

## Testing

### Run Fixture Tests

```bash
cd sdks/golang
go test -v ./...
```

### Using Fixtures in Your Tests

```go
func TestLicenseValidation(t *testing.T) {
    // Load fixture
    data, _ := os.ReadFile("../../docs/fixtures/v1/license.dat")
    var stored licensing.StoredLicense
    json.Unmarshal(data, &stored)

    // Verify signature
    err := licensing.VerifyStoredLicenseSignature(&stored)
    require.NoError(t, err)

    // Decrypt
    license, _, err := licensing.DecryptStoredLicense(&stored)
    require.NoError(t, err)

    assert.Equal(t, "lic_fixture_v1", license.ID)
    assert.Equal(t, "enterprise", license.PlanSlug)
}
```

## Security Best Practices

1. **Always use TLS in production**
   ```go
   // NEVER do this in production:
   // AllowInsecureHTTP: true  ❌
   ```

2. **Protect license files** - The SDK sets `0600` permissions automatically

3. **Handle expiration proactively**
   ```go
   if time.Until(license.ExpiresAt) < 7*24*time.Hour {
       log.Warn("License expires in less than 7 days!")
   }
   ```

4. **Don't embed license keys in code**
   ```go
   // ❌ Don't do this
   licenseKey := "ABCD-..."

   // ✅ Use environment variables
   licenseKey := os.Getenv("LICENSE_KEY")
   ```

## Protocol Details

### Key Algorithms

- **Transport Key**: `SHA-256(fingerprint + hex(nonce))` → 32-byte AES key
- **Encryption**: AES-256-GCM with 12-byte nonce
- **Signature**: RSA-PSS with SHA-256 (max salt length = 222 bytes for 2048-bit keys)
- **Checksum Key**: `SHA-256("github.com/oarkflow/licensing/client-checksum/v1" + fingerprint)`

### Device Fingerprint

```go
fingerprint = SHA256("HOST:<hostname>|OS:<os>|ARCH:<arch>|MAC:<mac>|CPU:<cpu_hash>")
```

## Related Documentation

- [SDK Developer Guide](../../docs/SDK_GUIDE.md)
- [SDK Protocol Specification](../../docs/sdk_protocol.md)
- [OpenAPI Specification](../../docs/api/licensing_openapi.yaml)

## License

MIT License - see LICENSE file for details.
