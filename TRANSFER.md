# Secretr Secure Transfer System

## Overview

The Secretr Secure Transfer System provides **military-grade security** for transferring secrets, files, and sensitive data between devices, cloud services, and air-gapped environments. It implements end-to-end encryption, device authentication, and comprehensive audit logging to ensure compliance with security standards like NIST SP 800-53 and SOC 2.

## Who Is This For?

### Security-Conscious Organizations
- **Financial institutions** requiring secure credential transfers between data centers
- **Healthcare providers** transferring PHI-compliant data between systems
- **Government agencies** needing classified data transfer capabilities
- **Defense contractors** requiring air-gapped transfer solutions

### DevOps & Platform Teams
- Teams managing secrets across **multi-cloud environments** (AWS, GCP, Azure)
- Organizations implementing **disaster recovery** with secure secret replication
- Teams needing **automated secret rotation** with secure distribution

### Compliance Officers
- Organizations subject to **SOC 2**, **HIPAA**, **PCI-DSS**, or **FedRAMP** requirements
- Teams needing **audit trails** for all secret movements
- Organizations requiring **chain of custody** documentation

---

## Features

### 🔐 Device-to-Device Transfer
- **Mutual TLS (mTLS)** authentication between devices
- **ECDH key exchange** for perfect forward secrecy
- **Device fingerprinting** for identity verification
- **Bandwidth throttling** for controlled transfers

### ☁️ Cloud Storage Transfer
- **Multi-cloud support**: AWS S3, GCP Cloud Storage, Azure Blob Storage
- **Client-side encryption** before upload
- **IP/Device authentication** for access control
- **Rate limiting** to prevent abuse

### 📦 Air-Gapped Transfer
- **QR code bundles** for offline transfer
- **Password-protected archives** with AES-256 encryption
- **Self-expiring transfers** with automatic cleanup
- **Tamper-evident manifests** with HMAC chains

### 🔄 Automated Transfers
- **Scheduled transfers** with cron-like expressions
- **Event-driven triggers** for real-time sync
- **Retry policies** with exponential backoff
- **Workflow orchestration** for complex transfer patterns

### 📋 Audit & Compliance
- **Complete audit trail** for all transfers
- **Chain of custody** with cryptographic verification
- **Compliance reporting** for regulatory requirements
- **Transfer manifests** with checksums and signatures

---

## Quick Start

### 1. Device-to-Device Transfer

#### Initialize Transfer Manager
```go
package main

import (
    "github.com/oarkflow/secretr"
)

func main() {
    // Create vault instance
    vault := secretr.New()
    vault.InitCipher([]byte("your-master-key"), nil)

    // Create transfer manager
    mgr, err := secretr.NewSecureTransferManager(vault, nil)
    if err != nil {
        panic(err)
    }
    defer mgr.Stop()

    // Get local device info
    localDevice := mgr.LocalDevice()
    fmt.Printf("Device ID: %s\n", localDevice.DeviceID)
    fmt.Printf("Fingerprint: %s\n", localDevice.DeviceFingerprint)
}
```

#### Add Trusted Device
```go
// Add a trusted destination device
destDevice := &secretr.TransferDeviceInfo{
    DeviceID:          "server-prod-01",
    DeviceFingerprint: "sha256:abc123...",
    Hostname:          "prod-server.example.com",
    IPAddress:         "192.168.1.100",
    Username:          "deploy",
}

if err := mgr.AddTrustedDevice(destDevice); err != nil {
    log.Fatalf("Failed to add trusted device: %v", err)
}
```

#### Create and Send Transfer
```go
// Store a secret to transfer
vault.Set("api/production/key", "sk-prod-12345")

// Create transfer manifest
manifest, err := mgr.CreateTransferManifest(
    "secret",           // Content type
    "api/production/key", // Key
    []byte("sk-prod-12345"), // Value
    destDevice,         // Destination
    nil,                // Options
)
if err != nil {
    log.Fatalf("Failed to create manifest: %v", err)
}

fmt.Printf("Transfer ID: %s\n", manifest.ManifestID)
fmt.Printf("Expires: %s\n", manifest.ExpiresAt)
```

### 2. Cloud Storage Transfer

#### Configure AWS S3 Transfer
```go
config := &secretr.CloudTransferConfig{
    Provider:        secretr.CloudProviderAWS,
    Region:          "us-east-1",
    Bucket:          "my-secrets-backup",
    AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",

    Encryption: secretr.CloudEncryptionConfig{
        Enabled:   true,
        Algorithm: "AES-256-GCM",
    },

    AccessControl: secretr.CloudAccessControl{
        AllowedDeviceIDs: []string{"server-prod-01", "server-prod-02"},
        AllowedCIDRs:     []string{"10.0.0.0/8", "192.168.0.0/16"},
        RequireMFA:       true,
        MaxUploadsPerHour: 100,
    },
}

cloudMgr, err := secretr.NewCloudTransferManager(vault, config, mgr)
if err != nil {
    log.Fatalf("Failed to create cloud manager: %v", err)
}
defer cloudMgr.Stop()
```

#### Upload Secret to S3
```go
// Create authentication context
authCtx, err := cloudMgr.CreateAuthContext(
    mgr.LocalDevice(),  // Device info
    "192.168.1.50",     // Source IP
    "admin@example.com", // Principal
)
if err != nil {
    log.Fatalf("Failed to create auth context: %v", err)
}

// Upload secret
result, err := cloudMgr.UploadSecret("api/production/key", authCtx, nil)
if err != nil {
    log.Fatalf("Upload failed: %v", err)
}

fmt.Printf("Uploaded to: %s\n", result.ObjectKey)
fmt.Printf("ETag: %s\n", result.ETag)
fmt.Printf("Size: %d bytes\n", result.Size)
```

#### Download Secret from S3
```go
value, result, err := cloudMgr.DownloadSecret("secrets/2024/12/04/api_production_key", authCtx)
if err != nil {
    log.Fatalf("Download failed: %v", err)
}

fmt.Printf("Retrieved value: %s\n", value)
fmt.Printf("Verified: %v\n", result.Verified)
```

### 3. Air-Gapped Transfer

#### Create Air-Gapped Bundle
```go
// Create password-protected bundle for air-gapped transfer
bundle, err := mgr.CreateAirGappedBundle(
    "secret",                    // Content type
    "classified/mission-data",   // Key
    []byte("top-secret-value"),  // Value
    "S3cur3P@ssw0rd!",          // Bundle password
    time.Hour,                   // Expiry duration
)
if err != nil {
    log.Fatalf("Failed to create bundle: %v", err)
}

// Save bundle to USB drive or generate QR codes
err = os.WriteFile("/mnt/usb/transfer-bundle.enc", bundle, 0600)
if err != nil {
    log.Fatalf("Failed to save bundle: %v", err)
}

fmt.Println("Bundle saved! Transfer via secure USB to destination.")
```

#### Import Air-Gapped Bundle
```go
// On destination device
bundle, err := os.ReadFile("/mnt/usb/transfer-bundle.enc")
if err != nil {
    log.Fatalf("Failed to read bundle: %v", err)
}

// Decrypt and import
result, err := mgr.ImportAirGappedBundle(bundle, "S3cur3P@ssw0rd!")
if err != nil {
    log.Fatalf("Import failed: %v", err)
}

fmt.Printf("Imported: %s\n", result.Key)
fmt.Printf("Verified: %v\n", result.Verified)
```

### 4. Automated Scheduled Transfers

#### Create Transfer Scheduler
```go
scheduler, err := secretr.NewTransferScheduler(mgr, "/var/secretr/schedules")
if err != nil {
    log.Fatalf("Failed to create scheduler: %v", err)
}
defer scheduler.Stop()

// Start the scheduler
scheduler.Start()
```

#### Add Scheduled Transfer
```go
// Backup secrets to cloud every hour
schedule := &secretr.TransferSchedule{
    Name:         "Hourly Secret Backup",
    Enabled:      true,
    ScheduleType: secretr.ScheduleTypeInterval,
    Interval:     time.Hour,
    ContentType:  "secret",
    ContentKey:   "production/*",  // Pattern matching
    Destination:  "cloud:s3://backup-bucket",
    Priority:     secretr.PriorityNormal,
    RetryPolicy: &secretr.RetryPolicy{
        MaxRetries:   3,
        Strategy:     secretr.RetryStrategyExponential,
        InitialDelay: time.Minute,
        MaxDelay:     time.Hour,
        Multiplier:   2.0,
    },
}

if err := scheduler.AddSchedule(schedule); err != nil {
    log.Fatalf("Failed to add schedule: %v", err)
}
```

#### Add Cron-Based Schedule
```go
// Daily backup at 2 AM
cronSchedule := &secretr.TransferSchedule{
    Name:           "Daily Full Backup",
    Enabled:        true,
    ScheduleType:   secretr.ScheduleTypeCron,
    CronExpression: "0 2 * * *",  // 2:00 AM daily
    ContentType:    "bundle",
    ContentKey:     "*",  // All secrets
    Destination:    "cloud:s3://backup-bucket/daily",
    Priority:       secretr.PriorityHigh,
}

scheduler.AddSchedule(cronSchedule)
```

---

## CLI Commands

### Device Management
```bash
# List trusted devices
secretr transfer devices list

# Add trusted device
secretr transfer devices add \
    --device-id "server-prod-01" \
    --fingerprint "sha256:abc123..." \
    --hostname "prod.example.com" \
    --ip "192.168.1.100"

# Remove trusted device
secretr transfer devices remove --device-id "server-prod-01"

# Verify device
secretr transfer devices verify --device-id "server-prod-01"
```

### Transfer Operations
```bash
# Transfer secret to device
secretr transfer send \
    --type secret \
    --key "api/production/key" \
    --destination "server-prod-01" \
    --priority high

# Transfer file to cloud
secretr transfer upload \
    --type file \
    --file "/path/to/sensitive.pdf" \
    --provider aws \
    --bucket "my-backup-bucket" \
    --encrypt

# Download from cloud
secretr transfer download \
    --provider aws \
    --bucket "my-backup-bucket" \
    --key "files/2024/12/04/sensitive.pdf" \
    --output "/path/to/output.pdf"
```

### Air-Gapped Operations
```bash
# Create air-gapped bundle
secretr transfer bundle create \
    --type secret \
    --key "classified/*" \
    --password "S3cur3P@ss!" \
    --expiry 24h \
    --output "/mnt/usb/bundle.enc"

# Import air-gapped bundle
secretr transfer bundle import \
    --file "/mnt/usb/bundle.enc" \
    --password "S3cur3P@ss!"

# Generate QR codes for small secrets
secretr transfer bundle qr \
    --type secret \
    --key "api/key" \
    --output "/tmp/qr-codes/"
```

### Schedule Management
```bash
# List schedules
secretr transfer schedule list

# Add interval schedule
secretr transfer schedule add \
    --name "Hourly Backup" \
    --interval 1h \
    --content-type secret \
    --content-key "production/*" \
    --destination "cloud:s3://backup"

# Add cron schedule
secretr transfer schedule add \
    --name "Daily Backup" \
    --cron "0 2 * * *" \
    --content-type bundle \
    --destination "cloud:s3://daily-backup"

# Pause schedule
secretr transfer schedule pause --id "sched-abc123"

# Resume schedule
secretr transfer schedule resume --id "sched-abc123"

# Run immediately
secretr transfer schedule run --id "sched-abc123"
```

---

## Security Architecture

### Encryption Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Secret/File Content                      │   │
│  │         (AES-256-GCM Encrypted at Rest)              │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Transfer Layer                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Transfer Manifest + Content                 │   │
│  │    (ECDH Key Exchange + AES-256-GCM Session Key)     │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              TLS 1.3 with mTLS                        │   │
│  │      (ECDSA Certificates, Perfect Forward Secrecy)   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
┌──────────────┐                              ┌──────────────┐
│   Source     │                              │ Destination  │
│   Device     │                              │   Device     │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  1. Initiate Connection (mTLS)             │
       │─────────────────────────────────────────────>
       │                                             │
       │  2. Exchange Device Fingerprints           │
       │<─────────────────────────────────────────────
       │                                             │
       │  3. Verify Trusted Device List             │
       │─────────────────────────────────────────────>
       │                                             │
       │  4. ECDH Key Exchange                      │
       │<─────────────────────────────────────────────
       │                                             │
       │  5. Derive Session Key (HKDF)              │
       │─────────────────────────────────────────────>
       │                                             │
       │  6. Encrypted Transfer (AES-256-GCM)       │
       │─────────────────────────────────────────────>
       │                                             │
       │  7. Verify Checksums (SHA-256, SHA-512)    │
       │<─────────────────────────────────────────────
       │                                             │
       │  8. Confirm Receipt + Audit Log            │
       │<─────────────────────────────────────────────
       │                                             │
```

### Access Control Model

```go
// Cloud transfer access control configuration
CloudAccessControl{
    // Device restrictions
    AllowedDeviceIDs:    []string{"prod-*", "staging-*"},
    AllowedFingerprints: []string{"sha256:..."},

    // Network restrictions
    AllowedIPs:   []string{"10.0.1.5", "10.0.1.6"},
    AllowedCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"},

    // Time restrictions
    ValidFrom:  time.Now(),
    ValidUntil: time.Now().Add(24 * time.Hour),

    // Identity restrictions
    AllowedPrincipals: []string{"admin@example.com", "deploy@example.com"},
    RequireMFA:        true,

    // Rate limiting
    MaxUploadsPerHour:   100,
    MaxDownloadsPerHour: 1000,
}
```

---

## Transfer Manifest Structure

Every transfer includes a cryptographically signed manifest:

```json
{
  "manifest_id": "mfst-abc123def456",
  "version": "1.0",
  "created_at": "2024-12-04T10:30:00Z",
  "expires_at": "2024-12-04T11:30:00Z",

  "source": {
    "device_id": "server-source-01",
    "device_fingerprint": "sha256:abc123...",
    "hostname": "source.example.com",
    "ip_address": "10.0.1.5",
    "username": "admin"
  },

  "destination": {
    "device_id": "server-dest-01",
    "device_fingerprint": "sha256:def456...",
    "hostname": "dest.example.com"
  },

  "content": {
    "type": "secret",
    "key": "api/production/key",
    "size": 256,
    "encrypted": true,
    "compression": "gzip",
    "checksums": {
      "sha256": "abc123...",
      "sha512": "def456...",
      "blake3": "789xyz..."
    }
  },

  "security": {
    "encryption_algorithm": "AES-256-GCM",
    "key_derivation": "HKDF-SHA256",
    "classification": "CONFIDENTIAL",
    "require_mfa": true
  },

  "chain_of_custody": [
    {
      "action": "created",
      "device_id": "server-source-01",
      "timestamp": "2024-12-04T10:30:00Z",
      "hmac": "signature..."
    }
  ],

  "signature": {
    "algorithm": "ECDSA-P256",
    "value": "base64-signature..."
  }
}
```

---

## Cloud Provider Configuration

### AWS S3
```go
config := &secretr.CloudTransferConfig{
    Provider:        secretr.CloudProviderAWS,
    Region:          "us-east-1",
    Bucket:          "my-secrets-bucket",
    Prefix:          "secretr-backups",
    AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
    SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
    SessionToken:    os.Getenv("AWS_SESSION_TOKEN"), // For STS

    // For S3-compatible storage (MinIO, etc.)
    Endpoint:       "https://minio.example.com",
    ForcePathStyle: true,
}
```

### Google Cloud Storage
```go
config := &secretr.CloudTransferConfig{
    Provider:          secretr.CloudProviderGCP,
    Bucket:            "my-secrets-bucket",
    ServiceAccountKey: os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
}
```

### Azure Blob Storage
```go
config := &secretr.CloudTransferConfig{
    Provider:        secretr.CloudProviderAzure,
    Bucket:          "secrets-container",  // Container name
    AccessKeyID:     "mystorageaccount",   // Storage account name
    SecretAccessKey: os.Getenv("AZURE_STORAGE_KEY"),
}
```

---

## Compliance & Audit

### Audit Log Format
```json
{
  "timestamp": "2024-12-04T10:30:00Z",
  "operation": "cloud_upload_success",
  "transfer_id": "mfst-abc123",
  "details": "object=secrets/2024/12/04/api_key size=256 etag=\"abc123\" duration=1.5s",
  "source_device": "server-source-01",
  "source_ip": "10.0.1.5",
  "principal": "admin@example.com",
  "mfa_verified": true
}
```

### Compliance Features
- **SOC 2 Type II**: Complete audit trail with tamper-evident logging
- **HIPAA**: PHI transfer controls with access logging
- **PCI-DSS**: Encryption at rest and in transit for cardholder data
- **FedRAMP**: FIPS 140-2 compliant encryption options
- **GDPR**: Data transfer controls with right-to-erasure support

---

## Error Handling

### Common Errors
```go
// Device not trusted
err = secretr.ErrDeviceNotTrusted
// Solution: Add device to trusted list before transfer

// Transfer expired
err = secretr.ErrTransferExpired
// Solution: Create new transfer with valid expiry

// Authentication failed
err = secretr.ErrAuthenticationFailed
// Solution: Verify device fingerprint and credentials

// Rate limit exceeded
err = secretr.ErrRateLimitExceeded
// Solution: Wait before retrying or increase limits

// Checksum mismatch
err = secretr.ErrChecksumMismatch
// Solution: Retry transfer, data may have been corrupted
```

### Retry Strategies
```go
// Exponential backoff (recommended)
RetryPolicy{
    Strategy:     RetryStrategyExponential,
    MaxRetries:   5,
    InitialDelay: time.Second,
    MaxDelay:     5 * time.Minute,
    Multiplier:   2.0,
}

// Linear backoff
RetryPolicy{
    Strategy:     RetryStrategyLinear,
    MaxRetries:   3,
    InitialDelay: 30 * time.Second,
}

// Fixed delay
RetryPolicy{
    Strategy:     RetryStrategyFixed,
    MaxRetries:   3,
    InitialDelay: time.Minute,
}
```

---

## Best Practices

### 1. Device Management
- Rotate device fingerprints periodically
- Remove devices immediately when decommissioned
- Use meaningful device IDs for audit clarity

### 2. Transfer Security
- Always enable encryption for cloud transfers
- Use short expiry times for sensitive transfers
- Require MFA for high-classification data

### 3. Scheduling
- Stagger scheduled transfers to avoid congestion
- Use appropriate retry policies for network conditions
- Monitor failed transfers and alert on anomalies

### 4. Cloud Storage
- Use separate buckets for different classification levels
- Enable versioning for recovery capabilities
- Implement lifecycle policies for automatic cleanup

---

## Comparison with MOVEit

| Feature | Secretr Transfer | MOVEit |
|---------|-----------------|--------|
| **Encryption** | AES-256-GCM, ChaCha20-Poly1305 | AES-256 |
| **Key Exchange** | ECDH with PFS | RSA/DH |
| **Device Auth** | mTLS + Fingerprinting | Certificate-based |
| **Cloud Support** | AWS, GCP, Azure, S3-compatible | Limited |
| **Air-Gapped** | QR codes, encrypted bundles | USB only |
| **Automation** | Cron, interval, event-driven | Cron only |
| **Open Source** | Yes | No |
| **Self-Hosted** | Yes | Yes |
| **Audit Logging** | Built-in with HMAC chains | Separate module |
| **Rate Limiting** | Built-in | Add-on |

---

## Support

For issues, questions, or feature requests:
- GitHub Issues: [github.com/oarkflow/secretr/issues](https://github.com/oarkflow/secretr/issues)
- Documentation: [github.com/oarkflow/secretr/wiki](https://github.com/oarkflow/secretr/wiki)

---

## License

Secretr is released under the MIT License. See [LICENSE](LICENSE) for details.
