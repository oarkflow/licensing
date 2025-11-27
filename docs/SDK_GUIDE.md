# Multi-Language SDK Developer Guide

This guide provides comprehensive documentation for integrating the Licensing system into your applications using our official SDKs. Whether you're building a Go service, Node.js application, or PHP backend, this guide covers everything from initial setup to production deployment.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [SDK Installation](#sdk-installation)
4. [Configuration](#configuration)
5. [Core Concepts](#core-concepts)
   - [Products, Plans, and Features](#products-plans-and-features)
6. [License Lifecycle](#license-lifecycle)
7. [API Reference](#api-reference)
8. [Error Handling](#error-handling)
9. [Security Best Practices](#security-best-practices)
10. [Testing & Fixtures](#testing--fixtures)
11. [Troubleshooting](#troubleshooting)
12. [Migration Guide](#migration-guide)

---

## Overview

The Licensing SDK provides a secure, cross-platform solution for software license management. Key features include:

- **Hardware-bound licenses**: Licenses are cryptographically tied to specific devices using hardware fingerprinting
- **Encrypted transport**: All license data is encrypted with AES-256-GCM during transit and at rest
- **RSA-PSS signatures**: License authenticity is verified using RSA-PSS with SHA-256
- **Offline capability**: Once activated, licenses work offline until the next verification checkpoint
- **Multi-language support**: Native SDKs for Go, TypeScript/Node.js, and PHP

### Architecture Overview

```
┌─────────────────┐     HTTPS/TLS      ┌─────────────────┐
│  Your App       │◄──────────────────►│  License Server │
│  + SDK          │                    │  (Go backend)   │
└────────┬────────┘                    └─────────────────┘
         │
         ▼
┌─────────────────┐
│  Local Storage  │
│  license.dat    │
│  license.dat.chk│
└─────────────────┘
```

---

## Quick Start

### 1. Server Setup

Before using any SDK, ensure your license server is running:

```bash
# Clone and build
git clone https://github.com/oarkflow/licensing.git
cd licensing
go mod tidy

# Set required environment variables
export LICENSE_SERVER_API_KEY="your-admin-key"
export LICENSE_SERVER_TLS_CERT="/path/to/cert.pem"
export LICENSE_SERVER_TLS_KEY="/path/to/key.pem"

# Start the server
go run cmd/server/main.go
```

For development/testing, you can disable TLS:

```bash
export LICENSE_SERVER_ALLOW_INSECURE_HTTP=1
go run cmd/server/main.go
```

### 2. Create a License

Use the admin API to create a client and issue a license:

```bash
# Create a client
curl -X POST https://localhost:8801/api/clients \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-admin-key" \
  -d '{
    "id": "client-123",
    "name": "Example Corp",
    "email": "admin@example.com"
  }'

# Create a license
curl -X POST https://localhost:8801/api/licenses \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-admin-key" \
  -d '{
    "client_id": "client-123",
    "plan_slug": "professional",
    "max_devices": 5,
    "expires_at": "2026-01-01T00:00:00Z"
  }'
```

### 3. Integrate the SDK

Choose your language and follow the installation instructions below.

---

## SDK Installation

### Go SDK

```bash
go get github.com/oarkflow/licensing/sdks/golang
```

```go
import licensing "github.com/oarkflow/licensing/sdks/golang"
```

### TypeScript/Node.js SDK

```bash
npm install @oarkflow/licensing-client
# or
yarn add @oarkflow/licensing-client
```

```typescript
import { LicensingClient, loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';
```

### PHP SDK

```bash
composer require oarkflow/licensing-client
```

```php
<?php
use Oarkflow\Licensing\License;
use Oarkflow\Licensing\Crypto;
```

---

## Configuration

### Environment Variables

All SDKs support consistent environment variable configuration:

| Variable | Description | Default |
|----------|-------------|---------|
| `LICENSE_CLIENT_SERVER` | License server URL | `https://localhost:8801` |
| `LICENSE_CLIENT_CONFIG_DIR` | Directory for license storage | `~/.licensing` |
| `LICENSE_CLIENT_LICENSE_FILE` | License filename | `.license.dat` |
| `LICENSE_CLIENT_EMAIL` | Activation email | — |
| `LICENSE_CLIENT_ID` | Client identifier | — |
| `LICENSE_CLIENT_LICENSE_KEY` | License key for activation | — |
| `LICENSE_CLIENT_ALLOW_INSECURE_HTTP` | Allow non-TLS connections | `false` |

### Go Configuration

```go
client, err := licensing.New(licensing.Config{
    ServerURL:         "https://licensing.example.com",
    ConfigDir:         "/var/lib/myapp",
    LicenseFile:       ".license.dat",
    AppName:           "MyApp",
    AppVersion:        "1.0.0",
    HTTPTimeout:       15 * time.Second,
    CACertPath:        "/path/to/ca.pem",      // Optional: custom CA
    AllowInsecureHTTP: false,                   // Never in production!
})
```

### TypeScript Configuration

```typescript
const client = new LicensingClient({
    serverUrl: 'https://licensing.example.com',
    allowInsecureHttp: false,
    httpTimeoutMs: 15000,
});
```

### PHP Configuration

```php
// Configuration is typically passed directly to methods
$serverUrl = getenv('LICENSE_CLIENT_SERVER') ?: 'https://localhost:8801';
$configDir = getenv('LICENSE_CLIENT_CONFIG_DIR') ?: $_SERVER['HOME'] . '/.licensing';
```

---

## Core Concepts

### Device Fingerprinting

Every SDK generates a deterministic hardware fingerprint that uniquely identifies the device. The fingerprint is computed as:

```
fingerprint = SHA256("HOST:<hostname>|OS:<os>|ARCH:<arch>|MAC:<mac>|CPU:<cpu_hash>")
```

This ensures:
- Licenses cannot be copied between machines
- The same machine always generates the same fingerprint
- Cross-platform consistency (Go, Node.js, PHP all produce identical fingerprints)

### Transport Encryption

All license data is encrypted using AES-256-GCM:

1. **Transport Key Derivation**: `SHA256(fingerprint + hex(nonce))`
2. **Payload Structure**: `[session_key (32 bytes) || license_json]`
3. **Encryption**: AES-256-GCM with 12-byte nonce

### Signature Verification

License authenticity is verified using RSA-PSS signatures:

- **Algorithm**: RSA-PSS with SHA-256
- **Salt Length**: Maximum (222 bytes for 2048-bit keys)
- **Signed Data**: The encrypted license ciphertext

### License Storage

Licenses are stored locally in JSON format:

```json
{
  "encrypted_data": "<base64>",
  "nonce": "<base64>",
  "signature": "<base64>",
  "public_key": "<base64 DER>",
  "device_fingerprint": "<hex>",
  "expires_at": "2026-01-01T00:00:00Z"
}
```

A companion checksum file (`.license.dat.chk`) prevents tampering:

```json
{
  "version": 1,
  "nonce": "<hex>",
  "payload": "<encrypted SHA256 hash as hex>",
  "created_at": "2025-01-01T00:00:00Z"
}
```

### Products, Plans, and Features

The licensing system supports configurable products with hierarchical plans and features:

```
Product (e.g., "SecretR")
├── Plan: Basic
│   ├── Feature: GUI
│   │   ├── Scope: view (allow)
│   │   └── Scope: list (allow)
│   └── Feature: CLI
│       └── Scope: list (allow)
├── Plan: Professional
│   ├── Feature: GUI
│   │   ├── Scope: view (allow)
│   │   ├── Scope: list (allow)
│   │   ├── Scope: create (allow)
│   │   └── Scope: update (allow)
│   └── Feature: CLI (all scopes)
└── Plan: Enterprise
    ├── Feature: GUI (all scopes)
    ├── Feature: CLI (all scopes)
    └── Feature: API (all scopes)
```

#### Key Concepts

- **Product**: A software application or service (e.g., "SecretR")
- **Plan**: A pricing tier within a product (e.g., "Basic", "Professional", "Enterprise")
- **Feature**: A capability or module within a product (e.g., "GUI", "CLI", "API")
- **Scope**: A specific operation within a feature (e.g., "list", "create", "update", "delete")
- **Permission**: Controls access to a scope:
  - `allow`: Full access to the scope
  - `deny`: No access to the scope
  - `limit`: Access with restrictions (uses the `limit` field)

#### License Entitlements

When a license is activated, it includes entitlements based on the associated plan:

```json
{
  "entitlements": {
    "product_id": "prod_123",
    "product_slug": "secretr",
    "plan_id": "plan_456",
    "plan_slug": "professional",
    "features": {
      "gui": {
        "feature_id": "feat_001",
        "feature_slug": "gui",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "view": { "scope_id": "s1", "scope_slug": "view", "permission": "allow" },
          "list": { "scope_id": "s2", "scope_slug": "list", "permission": "allow" },
          "create": { "scope_id": "s3", "scope_slug": "create", "permission": "allow" },
          "update": { "scope_id": "s4", "scope_slug": "update", "permission": "allow" }
        }
      },
      "cli": {
        "feature_id": "feat_002",
        "feature_slug": "cli",
        "enabled": true,
        "scopes": {
          "list": { "scope_id": "s5", "scope_slug": "list", "permission": "allow" },
          "create": { "scope_id": "s6", "scope_slug": "create", "permission": "allow" }
        }
      }
    }
  }
}
```

---

## License Lifecycle

### 1. Activation

Activation registers a device with the license server and retrieves an encrypted license.

#### Go

```go
client, _ := licensing.New(licensing.Config{
    ServerURL: "https://licensing.example.com",
})

// Activate with credentials
err := client.ActivateWithCredentials(licensing.ActivationRequest{
    Email:      "user@example.com",
    ClientID:   "client-123",
    LicenseKey: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
})
if err != nil {
    log.Fatalf("Activation failed: %v", err)
}
```

#### TypeScript

```typescript
// Full HTTP activation flow (coming soon)
// For now, use the Go CLI to activate, then load the license:

import { loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';

const stored = await loadLicenseFile('~/.licensing/.license.dat');
const { license, sessionKey } = decryptStoredLicense(stored);
console.log(`Licensed plan: ${license.plan_slug}`);
```

#### PHP

```php
use Oarkflow\Licensing\License;

// Load and decrypt an existing license
$stored = json_decode(file_get_contents($HOME . '/.licensing/.license.dat'), true);
$result = License::decrypt($stored);

$license = $result['license'];
echo "Plan: " . $license['plan_slug'] . "\n";
```

### 2. Verification

Verification checks license validity with the server (when online) or locally (when offline).

#### Go

```go
// Verify license is valid
if err := client.Verify(); err != nil {
    switch {
    case errors.Is(err, licensing.ErrLicenseExpired):
        log.Fatal("License has expired")
    case errors.Is(err, licensing.ErrLicenseRevoked):
        log.Fatal("License has been revoked")
    case errors.Is(err, licensing.ErrServerUnavailable):
        log.Println("Server unavailable, using cached license")
    default:
        log.Fatalf("Verification failed: %v", err)
    }
}
```

### 3. Reading License Data

After verification, access the decrypted license information:

#### Go

```go
license, err := client.License()
if err != nil {
    log.Fatalf("Failed to get license: %v", err)
}

fmt.Printf("License ID: %s\n", license.ID)
fmt.Printf("Plan: %s\n", license.PlanSlug)
fmt.Printf("Expires: %s\n", license.ExpiresAt)
fmt.Printf("Max Devices: %d\n", license.MaxDevices)
fmt.Printf("Check Mode: %s\n", license.CheckMode)

// Feature gating based on plan
if license.PlanSlug == "enterprise" {
    enableEnterpriseFeatures()
}
```

#### TypeScript

```typescript
const { license } = decryptStoredLicense(stored);

console.log(`License ID: ${license.id}`);
console.log(`Plan: ${license.plan_slug}`);
console.log(`Expires: ${license.expires_at}`);
console.log(`Max Devices: ${license.max_devices}`);

// Feature gating
if (license.plan_slug === 'enterprise') {
    enableEnterpriseFeatures();
}
```

#### PHP

```php
$result = License::decrypt($stored);
$license = $result['license'];

echo "License ID: " . $license['id'] . "\n";
echo "Plan: " . $license['plan_slug'] . "\n";
echo "Expires: " . $license['expires_at'] . "\n";

// Feature gating
if ($license['plan_slug'] === 'enterprise') {
    enableEnterpriseFeatures();
}
```

### 4. Background Verification

For long-running applications, implement background verification based on `check_mode`:

| Mode | Behavior |
|------|----------|
| `none` | No automatic verification |
| `each_execution` | Verify on every startup |
| `monthly` | Verify at the start of each month |
| `yearly` | Verify at the start of each year |
| `custom` | Use `check_interval_seconds` |

#### Go (Built-in)

```go
// Start background verification (automatically handles check_mode)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go client.StartBackgroundVerification(ctx)
```

#### TypeScript (Manual Implementation)

```typescript
function scheduleNextCheck(license: LicenseData) {
    const nextCheck = new Date(license.next_check_at);
    const delay = nextCheck.getTime() - Date.now();

    if (delay > 0) {
        setTimeout(async () => {
            await verifyWithServer();
            // Reload and schedule next
        }, delay);
    }
}
```

### 5. Feature & Scope Checking

When a license is associated with a product and plan, you can use the entitlements to perform fine-grained feature access checks.

#### Go

```go
license, err := client.License()
if err != nil {
    log.Fatal(err)
}

// Check if a feature is enabled
if license.HasFeature("gui") {
    fmt.Println("GUI access is enabled")
}

// Check a specific scope within a feature
if license.HasScope("gui", "create") {
    fmt.Println("Can create via GUI")
}

// Check with limit information
allowed, limit := license.CanPerform("api", "requests")
if allowed {
    if limit > 0 {
        fmt.Printf("API requests allowed (max %d per month)\n", limit)
    } else {
        fmt.Println("Unlimited API requests")
    }
}

// Get full feature details
if feature, ok := license.GetFeature("cli"); ok {
    fmt.Printf("CLI feature: %s (category: %s)\n", feature.FeatureSlug, feature.Category)
    for scopeSlug, scope := range feature.Scopes {
        fmt.Printf("  - %s: %s\n", scopeSlug, scope.Permission)
    }
}
```

#### TypeScript

```typescript
import {
    decryptStoredLicense,
    hasFeature,
    hasScope,
    canPerform,
    getFeature
} from '@oarkflow/licensing-client';

const { license } = decryptStoredLicense(stored);

// Check if a feature is enabled
if (hasFeature(license, 'gui')) {
    console.log('GUI access is enabled');
}

// Check a specific scope within a feature
if (hasScope(license, 'gui', 'create')) {
    console.log('Can create via GUI');
}

// Check with limit information
const { allowed, limit } = canPerform(license, 'api', 'requests');
if (allowed) {
    if (limit > 0) {
        console.log(`API requests allowed (max ${limit} per month)`);
    } else {
        console.log('Unlimited API requests');
    }
}

// Get full feature details
const feature = getFeature(license, 'cli');
if (feature) {
    console.log(`CLI feature: ${feature.feature_slug}`);
    if (feature.scopes) {
        for (const [scopeSlug, scope] of Object.entries(feature.scopes)) {
            console.log(`  - ${scopeSlug}: ${scope.permission}`);
        }
    }
}
```

#### PHP

```php
use Oarkflow\Licensing\License;

$result = License::decrypt($stored);
$license = $result['license'];

// Check if a feature is enabled
if (License::hasFeature($license, 'gui')) {
    echo "GUI access is enabled\n";
}

// Check a specific scope within a feature
if (License::hasScope($license, 'gui', 'create')) {
    echo "Can create via GUI\n";
}

// Check with limit information
$check = License::canPerform($license, 'api', 'requests');
if ($check['allowed']) {
    if ($check['limit'] > 0) {
        echo "API requests allowed (max {$check['limit']} per month)\n";
    } else {
        echo "Unlimited API requests\n";
    }
}

// Get full feature details
$feature = License::getFeature($license, 'cli');
if ($feature !== null) {
    echo "CLI feature: {$feature['feature_slug']}\n";
    foreach ($feature['scopes'] ?? [] as $scopeSlug => $scope) {
        echo "  - {$scopeSlug}: {$scope['permission']}\n";
    }
}
```

---

## API Reference

### Go SDK

#### Types

```go
// Config controls client behavior
type Config struct {
    ConfigDir         string        // Directory for license storage
    LicenseFile       string        // License filename
    ServerURL         string        // License server URL
    AppName           string        // Application name for User-Agent
    AppVersion        string        // Application version
    HTTPTimeout       time.Duration // HTTP request timeout
    CACertPath        string        // Custom CA certificate path
    AllowInsecureHTTP bool          // Allow non-TLS (development only)
}

// LicenseData contains decrypted license information
type LicenseData struct {
    ID                 string              // Unique license identifier
    ClientID           string              // Owner client ID
    SubjectClientID    string              // Runtime client ID
    Email              string              // License owner email
    ProductID          string              // Product ID (if assigned)
    PlanID             string              // Plan ID (if assigned)
    PlanSlug           string              // Plan identifier for feature gating
    Relationship       string              // "direct" or "delegated"
    GrantedBy          string              // Granting client (for delegated)
    LicenseKey         string              // The license key
    IssuedAt           time.Time           // Issue timestamp
    ExpiresAt          time.Time           // Expiration timestamp
    LastActivatedAt    time.Time           // Last activation time
    CurrentActivations int                 // Current activation count
    MaxDevices         int                 // Maximum allowed devices
    DeviceCount        int                 // Current device count
    IsRevoked          bool                // Revocation status
    RevokedAt          time.Time           // Revocation timestamp
    RevokeReason       string              // Revocation reason
    Devices            []LicenseDevice     // Registered devices
    DeviceFingerprint  string              // Current device fingerprint
    CheckMode          string              // Verification schedule
    CheckIntervalSecs  int64               // Custom interval (seconds)
    NextCheckAt        time.Time           // Next scheduled check
    LastCheckAt        time.Time           // Last check timestamp
    Entitlements       *LicenseEntitlements // Feature entitlements (if product/plan assigned)
}

// LicenseEntitlements contains feature grants from the plan
type LicenseEntitlements struct {
    ProductID   string                     // Product identifier
    ProductSlug string                     // Product slug
    PlanID      string                     // Plan identifier
    PlanSlug    string                     // Plan slug
    Features    map[string]FeatureGrant    // Feature grants by slug
}

// FeatureGrant represents a feature enabled for a license
type FeatureGrant struct {
    FeatureID   string                  // Feature identifier
    FeatureSlug string                  // Feature slug
    Category    string                  // Feature category
    Enabled     bool                    // Is feature enabled
    Scopes      map[string]ScopeGrant   // Scope grants by slug
}

// ScopeGrant represents a scope permission
type ScopeGrant struct {
    ScopeID    string                  // Scope identifier
    ScopeSlug  string                  // Scope slug
    Permission ScopePermission         // "allow", "deny", or "limit"
    Limit      int                     // Limit value (when Permission is "limit")
    Metadata   map[string]interface{}  // Additional scope metadata
}
```

#### Methods

```go
// New creates a new licensing client
func New(cfg Config) (*Client, error)

// Activate activates the license using environment variables
func (c *Client) Activate() error

// ActivateWithCredentials activates with explicit credentials
func (c *Client) ActivateWithCredentials(req ActivationRequest) error

// Verify checks license validity
func (c *Client) Verify() error

// License returns the decrypted license data
func (c *Client) License() (*LicenseData, error)

// StartBackgroundVerification starts the verification scheduler
func (c *Client) StartBackgroundVerification(ctx context.Context)

// IsValid returns true if the license is currently valid
func (c *Client) IsValid() bool

// Feature/Scope checking methods on LicenseData:

// HasFeature checks if the license has access to a feature
func (ld *LicenseData) HasFeature(featureSlug string) bool

// GetFeature returns the feature grant for a feature slug
func (ld *LicenseData) GetFeature(featureSlug string) (FeatureGrant, bool)

// HasScope checks if the license has access to a scope within a feature
func (ld *LicenseData) HasScope(featureSlug, scopeSlug string) bool

// GetScope returns the scope grant for a feature and scope slug
func (ld *LicenseData) GetScope(featureSlug, scopeSlug string) (ScopeGrant, bool)

// CanPerform checks if an operation is allowed and returns any limit
func (ld *LicenseData) CanPerform(featureSlug, scopeSlug string) (allowed bool, limit int)
```

### TypeScript SDK

#### Types

```typescript
interface LicensingClientOptions {
    serverUrl: string;
    allowInsecureHttp?: boolean;
    httpTimeoutMs?: number;
}

interface LicenseData {
    id: string;
    client_id: string;
    subject_client_id: string;
    email: string;
    product_id?: string;
    plan_id?: string;
    plan_slug: string;
    relationship: string;
    granted_by?: string;
    license_key: string;
    issued_at: string;
    expires_at: string;
    last_activated_at: string;
    current_activations: number;
    max_devices: number;
    device_count: number;
    is_revoked: boolean;
    revoked_at?: string;
    revoke_reason?: string;
    devices: LicenseDevice[];
    device_fingerprint?: string;
    check_mode: string;
    check_interval_seconds: number;
    next_check_at: string;
    last_check_at: string;
    entitlements?: LicenseEntitlements;
}

type ScopePermission = 'allow' | 'deny' | 'limit';

interface ScopeGrant {
    scope_id: string;
    scope_slug: string;
    permission: ScopePermission;
    limit?: number;
    metadata?: Record<string, unknown>;
}

interface FeatureGrant {
    feature_id: string;
    feature_slug: string;
    category?: string;
    enabled: boolean;
    scopes?: Record<string, ScopeGrant>;
}

interface LicenseEntitlements {
    product_id: string;
    product_slug: string;
    plan_id: string;
    plan_slug: string;
    features: Record<string, FeatureGrant>;
}

interface StoredLicenseFile {
    encrypted_data: string;
    nonce: string;
    signature: string;
    public_key: string;
    device_fingerprint: string;
    expires_at: string;
}

interface DecryptedLicense {
    sessionKey: Buffer;
    license: LicenseData;
}
```

#### Functions

```typescript
// Load a stored license file from disk
async function loadLicenseFile(path: string): Promise<StoredLicenseFile>

// Decrypt a stored license and verify its signature
function decryptStoredLicense(stored: StoredLicenseFile): DecryptedLicense

// Feature/Scope checking functions
function hasFeature(license: LicenseData, featureSlug: string): boolean
function getFeature(license: LicenseData, featureSlug: string): FeatureGrant | undefined
function hasScope(license: LicenseData, featureSlug: string, scopeSlug: string): boolean
function getScope(license: LicenseData, featureSlug: string, scopeSlug: string): ScopeGrant | undefined
function canPerform(license: LicenseData, featureSlug: string, scopeSlug: string): { allowed: boolean; limit: number }

// Low-level crypto functions
function deriveTransportKey(fingerprint: string, nonce: Buffer): Buffer
function decryptAesGcm(ciphertext: Buffer, nonce: Buffer, key: Buffer): Buffer
function verifySignature(data: Buffer, signature: Buffer, publicKey: KeyObject): boolean
```

### PHP SDK

#### Classes

```php
final class License
{
    /**
     * Decrypt a stored license and verify its signature.
     *
     * @param array{
     *   encrypted_data: string,
     *   nonce: string,
     *   signature: string,
     *   public_key: string,
     *   device_fingerprint: string,
     *   expires_at: string
     * } $stored The stored license from disk
     *
     * @return array{sessionKey: string, license: array<string, mixed>}
     * @throws RuntimeException If decryption or verification fails
     */
    public static function decrypt(array $stored): array

    /**
     * Check if the license has access to a specific feature.
     */
    public static function hasFeature(array $license, string $featureSlug): bool

    /**
     * Get a feature grant from the license.
     */
    public static function getFeature(array $license, string $featureSlug): ?array

    /**
     * Check if the license has access to a specific scope within a feature.
     */
    public static function hasScope(array $license, string $featureSlug, string $scopeSlug): bool

    /**
     * Get a scope grant from the license.
     */
    public static function getScope(array $license, string $featureSlug, string $scopeSlug): ?array

    /**
     * Check if an operation is allowed and return any limit.
     * @return array{allowed: bool, limit: int}
     */
    public static function canPerform(array $license, string $featureSlug, string $scopeSlug): array
}

final class Crypto
{
    /**
     * Derive the transport key from fingerprint and nonce.
     */
    public static function deriveTransportKey(string $fingerprint, string $nonceHex): string

    /**
     * Decrypt AES-256-GCM ciphertext.
     */
    public static function decryptAesGcm(string $ciphertext, string $nonce, string $key): string

    /**
     * Verify an RSA-PSS signature.
     */
    public static function verifySignature(string $payload, string $signature, string $publicKeyPem): bool
}
```

---

## Error Handling

### Common Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `ErrLicenseNotFound` | No local license file | Run activation |
| `ErrLicenseExpired` | License past expiration date | Renew license |
| `ErrLicenseRevoked` | License has been revoked | Contact support |
| `ErrSignatureInvalid` | Tampered license file | Re-activate |
| `ErrDeviceMismatch` | Fingerprint changed | Re-activate on new device |
| `ErrActivationLimit` | Max devices exceeded | Deactivate a device or upgrade |
| `ErrServerUnavailable` | Cannot reach server | Use cached license if valid |

### Go Error Handling

```go
err := client.Verify()
if err != nil {
    var licenseErr *licensing.LicenseError
    if errors.As(err, &licenseErr) {
        switch licenseErr.Code {
        case licensing.ErrCodeExpired:
            // Handle expiration
        case licensing.ErrCodeRevoked:
            // Handle revocation
        case licensing.ErrCodeDeviceMismatch:
            // Handle device change
        }
    }
}
```

### TypeScript Error Handling

```typescript
try {
    const { license } = decryptStoredLicense(stored);
} catch (error) {
    if (error instanceof Error) {
        if (error.message.includes('signature invalid')) {
            // License file has been tampered with
        } else if (error.message.includes('decryption failed')) {
            // Wrong device or corrupted file
        }
    }
}
```

### PHP Error Handling

```php
try {
    $result = License::decrypt($stored);
} catch (RuntimeException $e) {
    if (str_contains($e->getMessage(), 'signature invalid')) {
        // License file has been tampered with
    } elseif (str_contains($e->getMessage(), 'decryption failed')) {
        // Wrong device or corrupted file
    }
}
```

---

## Security Best Practices

### 1. Always Use TLS in Production

```go
// NEVER do this in production:
// AllowInsecureHTTP: true  ❌

// Always use proper TLS:
client, _ := licensing.New(licensing.Config{
    ServerURL:  "https://licensing.example.com",
    CACertPath: "/path/to/ca.pem",
})
```

### 2. Protect License Files

License files contain sensitive cryptographic material. Ensure proper permissions:

```bash
# The SDK automatically sets these, but verify:
chmod 600 ~/.licensing/.license.dat
chmod 600 ~/.licensing/.license.dat.chk
chmod 700 ~/.licensing
```

### 3. Validate Expiration Early

Don't wait for operations to fail—check expiration proactively:

```go
license, _ := client.License()
if time.Until(license.ExpiresAt) < 7*24*time.Hour {
    log.Warn("License expires in less than 7 days!")
}
```

### 4. Handle Revocation Gracefully

```go
if license.IsRevoked {
    log.Errorf("License revoked: %s", license.RevokeReason)
    // Gracefully shutdown or enter limited mode
    enterGracefulDegradation()
}
```

### 5. Don't Embed License Keys in Code

```go
// ❌ Don't do this:
licenseKey := "ABCD-EFGH-..."

// ✅ Use environment variables or secure config:
licenseKey := os.Getenv("LICENSE_KEY")
```

### 6. Implement Checksum Verification

The SDK handles this automatically, but understand what's protected:

```go
// The checksum prevents:
// - Manual editing of license.dat
// - Copying licenses between devices
// - Replay attacks with old licenses
```

---

## Testing & Fixtures

### Using Fixtures

The repository includes fixtures for testing SDK implementations without a running server:

```
docs/fixtures/v1/
├── activation_request.json   # Sample activation request
├── activation_response.json  # Sample server response
├── stored_license.json       # Pretty-printed stored license
├── license.dat              # Raw stored license
├── license.dat.chk          # Checksum file
├── license_data.json        # Decrypted license data
└── checksum_pretty.json     # Pretty-printed checksum
```

### Go Fixture Tests

```go
func TestWithFixtures(t *testing.T) {
    stored, _ := os.ReadFile("../../docs/fixtures/v1/license.dat")
    var storedLicense licensing.StoredLicense
    json.Unmarshal(stored, &storedLicense)

    // Verify signature
    err := licensing.VerifyStoredLicenseSignature(&storedLicense)
    assert.NoError(t, err)

    // Decrypt
    license, _, err := licensing.DecryptStoredLicense(&storedLicense)
    assert.NoError(t, err)
    assert.Equal(t, "lic_fixture_v1", license.ID)
}
```

### TypeScript Fixture Tests

```typescript
import { loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';

describe('License SDK', () => {
    it('should decrypt fixture license', async () => {
        const stored = await loadLicenseFile('../../docs/fixtures/v1/license.dat');
        const { license } = decryptStoredLicense(stored);
        expect(license.id).toBe('lic_fixture_v1');
        expect(license.plan_slug).toBe('enterprise');
    });
});
```

### PHP Fixture Tests

```php
public function testDecryptFixture(): void
{
    $stored = json_decode(
        file_get_contents(__DIR__ . '/../../docs/fixtures/v1/stored_license.json'),
        true
    );
    $result = License::decrypt($stored);

    $this->assertEquals('lic_fixture_v1', $result['license']['id']);
    $this->assertEquals('enterprise', $result['license']['plan_slug']);
}
```

### Regenerating Fixtures

If you modify the protocol, regenerate fixtures:

```bash
cd /path/to/licensing
go test -v ./pkg/client -run TestUpdateFixtures -update-fixtures
```

---

## Troubleshooting

### "Signature verification failed"

**Causes:**
- License file was manually edited
- License was copied from another device
- Public key mismatch

**Solutions:**
1. Delete the license file and re-activate
2. Ensure you're using the correct server URL
3. Check that server keys haven't rotated

### "Decryption failed"

**Causes:**
- Device fingerprint changed (hardware change, VM migration)
- Corrupted license file

**Solutions:**
1. Re-activate on the new device
2. If fingerprint shouldn't have changed, check for:
   - VM UUID changes
   - MAC address changes
   - Hostname changes

### "Server unavailable"

**Causes:**
- Network connectivity issues
- Server down
- TLS certificate problems

**Solutions:**
1. Check network connectivity
2. Verify server status
3. For TLS issues:
   ```bash
   curl -v https://licensing.example.com/health
   ```
4. Use cached license if `next_check_at` is in the future

### "Activation limit exceeded"

**Causes:**
- Reached `max_devices` for the license

**Solutions:**
1. Deactivate unused devices via admin API
2. Upgrade to a plan with more device slots
3. Contact support for manual cleanup

### "License expired"

**Causes:**
- License `expires_at` has passed

**Solutions:**
1. Renew the license
2. Check for clock skew on the device:
   ```bash
   date -u  # Compare with actual UTC time
   ```

---

## Migration Guide

### From v0.x to v1.x

If you're upgrading from an earlier version:

1. **License file format changed**: Delete old `.license.dat` and re-activate
2. **Checksum file added**: The SDK now creates `.license.dat.chk`
3. **API changes**:
   - `Client.Activate()` now returns `error` instead of `(*License, error)`
   - Use `Client.License()` to get license data after activation

### Cross-Language Migration

Licenses activated with the Go CLI work with TypeScript and PHP SDKs:

```bash
# Activate with Go CLI
./license-cli activate --email user@example.com --key ABCD-...

# Use the same license.dat with TypeScript
import { loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';
const stored = await loadLicenseFile('~/.licensing/.license.dat');
const { license } = decryptStoredLicense(stored);
```

---

## Support

- **Documentation**: See `docs/sdk_protocol.md` for protocol details
- **Issues**: https://github.com/oarkflow/licensing/issues
- **Security**: Report vulnerabilities via security@oarkflow.com

---

## License

MIT License - see LICENSE file for details.
