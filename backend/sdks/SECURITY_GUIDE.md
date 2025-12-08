# SDK Security Guide

This document provides comprehensive security guidance for all licensing SDK implementations (Go, PHP, TypeScript).

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Encryption](#encryption)
- [Integrity Verification](#integrity-verification)
- [Network Security](#network-security)
- [Key Management](#key-management)
- [Best Practices by Language](#best-practices-by-language)
- [Security Checklist](#security-checklist)

## Overview

All SDKs implement the same security architecture with language-specific adaptations:

- **Ed25519 SSH Key Authentication**: Client authentication using elliptic curve cryptography
- **AES-256-GCM Encryption**: Authenticated encryption for license data
- **RSA-PSS Signatures**: License authenticity verification
- **SHA-256 Hashing**: Integrity checks and fingerprinting
- **TLS 1.3**: Secure transport with optional certificate pinning
- **Multi-Layer Verification**: Defense-in-depth approach

## Authentication

### SSH Key Authentication (Recommended)

All SDKs support Ed25519 SSH key authentication for enhanced security.

#### Generate Keys

**Go:**
```bash
go run examples/secure/main.go --generate-key
```

**PHP:**
```php
use Oarkflow\Licensing\Crypto;

$keys = Crypto::generateEd25519KeyPair();
file_put_contents('private_key.pem', $keys['private'], 0600);
file_put_contents('public_key.pem', $keys['public']);
```

**TypeScript:**
```typescript
import { generateEd25519KeyPair } from '@oarkflow/licensing-client';
import { writeFileSync } from 'fs';

const { privateKey, publicKey } = generateEd25519KeyPair();
writeFileSync('private_key.pem', privateKey, { mode: 0o600 });
writeFileSync('public_key.pem', publicKey);
```

#### Key Registration

1. Generate Ed25519 key pair on client
2. Register public key with licensing server via admin API
3. Configure client with private key path
4. Client signs requests with private key
5. Server verifies signatures with registered public key

#### Sign Requests

**Go:**
```go
privateKey, _ := licensing.LoadEd25519PrivateKey("/path/to/key")
signature, _ := licensing.SignRequest(privateKey, data)
```

**PHP:**
```php
$privateKey = file_get_contents('/path/to/key');
$signature = Crypto::signEd25519($privateKey, $data);
```

**TypeScript:**
```typescript
import { signEd25519 } from '@oarkflow/licensing-client';

const privateKey = readFileSync('/path/to/key', 'utf8');
const signature = signEd25519(privateKey, data);
```

### Traditional Authentication

If SSH keys are not configured, SDKs fall back to client ID + license key authentication.

⚠️ **Not recommended for production** - SSH keys provide stronger security guarantees.

## Encryption

### AES-256-GCM

All SDKs use AES-256-GCM for authenticated encryption of license data.

**Key Properties:**
- 256-bit keys (32 bytes)
- 96-bit nonces (12 bytes) - **must be unique per encryption**
- 128-bit authentication tags (16 bytes)
- Provides confidentiality and authenticity

#### Encryption

**Go:**
```go
key := licensing.SecureRandomBytes(32)
nonce := licensing.SecureRandomBytes(12)
ciphertext, _ := licensing.EncryptAESGCM(key, plaintext)
```

**PHP:**
```php
$key = Crypto::secureRandomBytes(32);
$nonce = Crypto::secureRandomBytes(12);
$ciphertext = Crypto::encryptAesGcm($plaintext, $nonce, $key);
```

**TypeScript:**
```typescript
import { encryptAesGcm, secureRandomBytes } from '@oarkflow/licensing-client';

const key = secureRandomBytes(32);
const nonce = secureRandomBytes(12);
const ciphertext = encryptAesGcm(plaintext, nonce, key);
```

#### Key Derivation

Transport keys are derived using:
```
transport_key = SHA-256(fingerprint + hex(nonce))
```

This ensures each activation produces a unique encryption key based on device fingerprint.

### Secure Random Generation

**Never use weak random sources for cryptographic operations.**

**Go:**
```go
randomBytes, _ := licensing.SecureRandomBytes(32)
```

**PHP:**
```php
$randomBytes = Crypto::secureRandomBytes(32);  // Uses random_bytes()
```

**TypeScript:**
```typescript
const randomBytes = secureRandomBytes(32);  // Uses crypto.randomBytes()
```

## Integrity Verification

### Multi-Layer Verification (Go SDK)

The Go SDK provides comprehensive multi-layer verification:

```go
license, integrity, err := client.VerifyWithIntegrity()
if err != nil || !integrity.IsValid {
    // Handle verification failure
}

// Check individual layers
for _, layer := range integrity.Layers {
    fmt.Printf("%s: %s\n", layer.Name, layer.Description)
}
```

**Verification Layers:**
1. **Signature Layer**: RSA-PSS signature verification
2. **Integrity Layer**: File tampering detection
3. **Hardware Layer**: Device fingerprint validation
4. **Time Layer**: Expiration and grace period checks
5. **Network Layer**: Revocation status (if online)

### SHA-256 Hashing

Compute file hashes to detect unauthorized modifications:

**Go:**
```go
hash, _ := licensing.ComputeFileSHA256("/path/to/license.dat")
```

**PHP:**
```php
$hash = Crypto::computeFileSHA256('/path/to/license.dat');
```

**TypeScript:**
```typescript
const hash = computeFileSHA256('/path/to/license.dat');
```

### Tamper Detection (Go SDK)

Enable runtime tamper detection:

```go
client, _ := licensing.NewClient(licensing.Config{
    TamperDetection: true,
})

result := client.RunIntegrityChecks()
if result.TamperingDetected {
    log.Fatalf("Tampering detected: %v", result.FailedChecks)
}
```

## Network Security

### TLS 1.3

**Always use HTTPS in production.**

**Go:**
```go
client, _ := licensing.NewClient(licensing.Config{
    ServerURL: "https://licensing.example.com",  // Use HTTPS
    AllowInsecureHTTP: false,  // Enforce TLS
})
```

**PHP:**
```php
$context = stream_context_create([
    'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
    ],
]);
```

**TypeScript:**
```typescript
const agent = new https.Agent({
    rejectUnauthorized: true,
});
```

### Certificate Pinning (Go SDK)

Pin TLS certificates for added security:

```go
client, _ := licensing.NewClient(licensing.Config{
    ServerURL:   "https://licensing.example.com",
    CertPinning: true,
    CACertPath:  "/path/to/ca-cert.pem",
})
```

This prevents man-in-the-middle attacks even if a CA is compromised.

### Offline Operation

Configure offline grace periods to allow temporary operation without network access:

```go
client, _ := licensing.NewClient(licensing.Config{
    OfflineGracePeriod: 7 * 24 * time.Hour,  // 7 days
    MaxOfflineDays:     30,                   // 30 days max
})
```

## Key Management

### Storage Security

**Private Keys:**
- Store in secure locations (e.g., `~/.ssh/`)
- Set permissions to `0600` (owner read/write only)
- Never commit to version control
- Consider using OS keychain/keyring services

**License Files:**
- Store in user-specific directories (e.g., `~/.myapp/`)
- Set directory permissions to `0700`
- Set file permissions to `0600`
- Encrypt if stored in shared locations

### Key Rotation

Support key rotation for long-lived deployments:

1. Generate new Ed25519 key pair
2. Register new public key with server (keep old key active)
3. Update client configuration with new private key
4. Deactivate old key after transition period

### Secure Deletion

When deleting sensitive files, use secure deletion:

**Go:**
```go
licensing.SecureDelete("/path/to/sensitive/file")
```

**PHP:**
```php
Crypto::secureDelete('/path/to/sensitive/file');
```

**TypeScript:**
```typescript
await secureDelete('/path/to/sensitive/file');
```

This overwrites the file with random data 3 times before deletion.

## Best Practices by Language

### Go

1. **Use multi-layer verification** for security-critical applications
2. **Enable tamper detection** for runtime integrity monitoring
3. **Configure offline grace periods** appropriately
4. **Use background verification** for long-running processes
5. **Monitor security metrics** regularly

```go
metrics := client.GetSecurityMetrics()
if metrics.TamperingAttempts > 0 {
    // Alert and take action
}
```

### PHP

1. **Set strict file permissions** using `chmod()`
2. **Use stream contexts** for TLS configuration
3. **Implement rate limiting** to prevent brute force
4. **Cache encrypted data** using AES-GCM
5. **Validate server-side** don't trust client-only checks

```php
chmod($licensePath, 0600);
chmod(dirname($licensePath), 0700);
```

### TypeScript

1. **Use environment variables** for configuration
2. **Implement graceful error handling**
3. **Set file permissions** with `fs.chmodSync()`
4. **Use HTTPS agents** with certificate verification
5. **Consider using worker threads** for background verification

```typescript
chmodSync(licensePath, 0o600);
```

## Security Checklist

### Deployment

- [ ] SSH keys generated and registered
- [ ] TLS enabled with valid certificates
- [ ] Certificate pinning configured (Go)
- [ ] File permissions set correctly (0600 for files, 0700 for directories)
- [ ] Environment variables used for secrets (not hardcoded)
- [ ] Logging doesn't expose sensitive data
- [ ] Error messages are user-friendly (no technical details to end users)

### Runtime

- [ ] License verified on startup
- [ ] Background verification enabled for long-running processes
- [ ] Tamper detection enabled (Go)
- [ ] Security metrics monitored (Go)
- [ ] Expiration warnings shown to users
- [ ] Revocation checked periodically
- [ ] Rate limiting implemented
- [ ] Offline grace period enforced

### Code Review

- [ ] No hardcoded secrets (keys, passwords, tokens)
- [ ] Secure random used for cryptographic operations
- [ ] File operations use proper error handling
- [ ] Network operations use TLS
- [ ] Sensitive data not logged
- [ ] Input validation on all external data
- [ ] Dependencies up to date
- [ ] Security vulnerabilities scanned

### Testing

- [ ] Expired license handling tested
- [ ] Revoked license handling tested
- [ ] Network failure scenarios tested
- [ ] Tamper detection triggered correctly (Go)
- [ ] Offline operation within grace period works
- [ ] Signature verification rejects invalid signatures
- [ ] Encryption/decryption round-trips successfully

## Threat Model

### Threats Mitigated

1. **License Tampering**: RSA-PSS signatures + AES-GCM authentication
2. **Unauthorized Copying**: Hardware fingerprinting + device limits
3. **Man-in-the-Middle**: TLS 1.3 + optional certificate pinning
4. **Credential Theft**: SSH key authentication (not passwords)
5. **Offline Exploitation**: Grace period + expiration enforcement
6. **Binary Patching**: Integrity checks + tamper detection
7. **Replay Attacks**: Nonce-based encryption + timestamps

### Residual Risks

1. **Determined Attackers**: No licensing system is 100% secure against sophisticated attackers with unlimited resources
2. **Root/Admin Access**: If attacker has root/admin access, they can potentially bypass protections
3. **Memory Inspection**: License data in memory may be readable by privileged processes
4. **Time Manipulation**: System clock manipulation can affect expiration checks (mitigated by server verification)

### Defense in Depth

Use multiple security layers:
- Strong authentication (SSH keys)
- Encrypted storage (AES-256-GCM)
- Signature verification (RSA-PSS)
- Hardware binding (fingerprints)
- Network security (TLS 1.3)
- Runtime monitoring (tamper detection)
- Periodic verification (background checks)
- Audit logging (server-side)

## Incident Response

### License Compromise

1. **Revoke compromised licenses** via admin API
2. **Regenerate SSH keys** for affected clients
3. **Update client configurations** with new keys
4. **Monitor for suspicious activity** in audit logs
5. **Notify affected users** if required

### Tampering Detected

1. **Log the incident** with full context
2. **Alert administrators** via monitoring system
3. **Disable affected license** (optional)
4. **Investigate root cause** (binary patching, memory manipulation, etc.)
5. **Update security controls** based on findings

## Compliance

This SDK architecture supports compliance with:

- **SOC 2**: Audit logging, access controls, encryption
- **ISO 27001**: Information security management
- **GDPR**: Data protection, user privacy
- **HIPAA**: Healthcare data security (if applicable)
- **PCI DSS**: Payment card industry standards (if handling payments)

Consult with your compliance team for specific requirements.

## Additional Resources

- [Client Security Guide](../CLIENT_SECURITY.md)
- [SDK Developer Guide](../docs/SDK_GUIDE.md)
- [SDK Protocol Specification](../docs/sdk_protocol.md)
- [Go SDK README](go/README.md)
- [PHP SDK README](php/README.md)
- [TypeScript SDK README](typescript/README.md)

## Support

For security issues, please report privately to: security@example.com

For general questions, see documentation or open an issue on GitHub.
