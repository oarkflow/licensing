# TypeScript/Node.js Licensing SDK

A TypeScript SDK for integrating hardware-bound software licensing into Node.js applications with enterprise-grade security features. This SDK provides secure license validation, signature verification, encrypted license storage, and comprehensive cryptographic utilities.

## Features

### Core Licensing
- 🔐 **AES-256-GCM encryption** for secure license transport and storage
- ✅ **RSA-PSS signature verification** to ensure license authenticity
- 🖥️ **Hardware fingerprinting** for device-bound licenses
- 📦 **Zero external crypto dependencies** - uses Node.js built-in crypto
- 🧪 **Fixture-based testing** for cross-language compatibility

### Security Features (New in v2.0)
- 🔑 **Ed25519 key generation and signing** for SSH authentication
- 🛡️ **SHA-256 hashing** for integrity verification
- 🔒 **Secure random byte generation**
- 🗝️ **Secure file deletion** with overwriting
- 📊 **Additional AES-GCM encryption** helpers

## Requirements

- Node.js 18.0.0 or later
- TypeScript 5.0+ (for TypeScript projects)

## Installation

```bash
npm install @oarkflow/licensing-client
# or
yarn add @oarkflow/licensing-client
# or
pnpm add @oarkflow/licensing-client
```

## Quick Start

### 1. Generate SSH Keys (Recommended)

For enhanced security, generate SSH keys for client authentication:

```bash
# Using ssh-keygen
ssh-keygen -t ed25519 -f ~/.ssh/licensing_client -N ""

# Or using TypeScript
import { generateEd25519KeyPair } from '@oarkflow/licensing-client';
import { writeFileSync } from 'fs';

const { privateKey, publicKey } = generateEd25519KeyPair();
writeFileSync('private_key.pem', privateKey, { mode: 0o600 });
writeFileSync('public_key.pem', publicKey);
```

Register your public key with the licensing server before activation.

### 2. Activate a License (using Go CLI)

Currently, activation requires the Go CLI. The TypeScript SDK can then load and decrypt the activated license:

```bash
# Install the Go CLI
go install github.com/oarkflow/licensing/cmd/license-cli@latest

# Activate with SSH authentication
license-cli activate \
  --server https://licensing.example.com \
  --email user@example.com \
  --client-id client-123 \
  --license-key ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456 \
  --ssh-key ~/.ssh/licensing_client
```

### 3. Load and Verify the License

```typescript
import { loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';
import { homedir } from 'os';
import { join } from 'path';

async function validateLicense() {
    // Load the stored license
    const licensePath = join(homedir(), '.licensing', '.license.dat');
    const stored = await loadLicenseFile(licensePath);

    // Decrypt and verify signature
    // Optionally provide the current device fingerprint as a second argument to
    // ensure the license file can only be decrypted on the device it was bound to.
    const { license, sessionKey } = decryptStoredLicense(stored /*, currentFingerprint */);

    // Check expiration
    const expiresAt = new Date(license.expires_at);
    if (expiresAt < new Date()) {
        throw new Error('License has expired');
    }

    // Check revocation
    if (license.is_revoked) {
        throw new Error(`License revoked: ${license.revoke_reason}`);
    }

    console.log(`Licensed for: ${license.plan_slug}`);
    console.log(`Expires: ${license.expires_at}`);

    return license;
}
```

### 3. Feature Gating

```typescript
import { LicenseData } from '@oarkflow/licensing-client';

function isFeatureEnabled(license: LicenseData, feature: string): boolean {
    const planFeatures: Record<string, string[]> = {
        'starter': ['basic'],
        'professional': ['basic', 'advanced'],
        'enterprise': ['basic', 'advanced', 'premium', 'api'],
    };

    const allowed = planFeatures[license.plan_slug] || [];
    return allowed.includes(feature);
}

// Usage
const license = await validateLicense();
if (isFeatureEnabled(license, 'api')) {
    enableAPIAccess();
}
```

## Examples

See the [examples](examples/) directory for complete working examples:

- **[basic](examples/basic/)** - Load and verify license files, check features and scopes

To run an example:

```bash
cd examples/basic
npx tsx index.ts --license-file ~/.licensing-example/.license.dat
```

## API Reference

### Types

#### `LicensingClientOptions`

```typescript
interface LicensingClientOptions {
    serverUrl: string;           // License server URL
    allowInsecureHttp?: boolean; // Allow non-TLS (dev only)
    httpTimeoutMs?: number;      // HTTP timeout in milliseconds
}
```

#### `LicenseData`

```typescript
interface LicenseData {
    id: string;                    // Unique license identifier
    client_id: string;             // Owner client ID
    subject_client_id: string;     // Runtime client ID
    email: string;                 // License owner email
    plan_slug: string;             // Plan for feature gating
    relationship: string;          // "direct" or "delegated"
    granted_by?: string;           // Granting client (delegated)
    license_key: string;           // The license key
    issued_at: string;             // ISO 8601 issue timestamp
    expires_at: string;            // ISO 8601 expiration
    last_activated_at: string;     // Last activation time
    current_activations: number;   // Current activation count
    max_devices: number;           // Maximum allowed devices
    device_count: number;          // Current device count
    is_revoked: boolean;           // Revocation status
    revoked_at?: string;           // Revocation timestamp
    revoke_reason?: string;        // Revocation reason
    devices: LicenseDevice[];      // Registered devices
    device_fingerprint?: string;   // Current device fingerprint
    check_mode: string;            // Verification schedule
    check_interval_seconds: number;// Custom interval (seconds)
    next_check_at: string;         // Next scheduled check
    last_check_at: string;         // Last check timestamp
}
```

#### `StoredLicenseFile`

```typescript
interface StoredLicenseFile {
    encrypted_data: string;    // Base64 AES-GCM ciphertext
    nonce: string;             // Base64 12-byte nonce
    signature: string;         // Base64 RSA-PSS signature
    public_key: string;        // Base64 DER public key
    device_fingerprint: string;// Hex device fingerprint
    expires_at: string;        // ISO 8601 expiration
}
```

### Functions

#### `loadLicenseFile(path: string): Promise<StoredLicenseFile>`

Loads a stored license file from disk.

```typescript
const stored = await loadLicenseFile('/path/to/license.dat');
```

#### `decryptStoredLicense(stored: StoredLicenseFile): DecryptedLicense`

Decrypts a stored license, verifying its signature.

```typescript
const { license, sessionKey } = decryptStoredLicense(stored);
```

**Throws:**
- `Error` if signature verification fails
- `Error` if decryption fails

### Low-Level Crypto Functions

For advanced use cases or custom implementations:

```typescript
import { deriveTransportKey, decryptAesGcm, verifySignature } from '@oarkflow/licensing-client';

// Derive transport key from fingerprint and nonce
const transportKey = deriveTransportKey(fingerprint, nonce);

// Decrypt AES-256-GCM ciphertext
const plaintext = decryptAesGcm(ciphertext, nonce, key);

// Verify RSA-PSS signature
const isValid = verifySignature(data, signature, publicKey);
```

## Environment Variables

The SDK respects these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `LICENSE_CLIENT_SERVER` | License server URL | `https://localhost:6601` |
| `LICENSE_CLIENT_CONFIG_DIR` | License storage directory | `~/.licensing` |
| `LICENSE_CLIENT_LICENSE_FILE` | License filename | `.license.dat` |

## Error Handling

```typescript
import { loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';

async function safeLicenseCheck() {
    try {
        const stored = await loadLicenseFile(licensePath);
        const { license } = decryptStoredLicense(stored);
        return { valid: true, license };
    } catch (error) {
        if (error instanceof Error) {
            if (error.message.includes('signature invalid')) {
                return { valid: false, error: 'LICENSE_TAMPERED' };
            }
            if (error.message.includes('ENOENT')) {
                return { valid: false, error: 'LICENSE_NOT_FOUND' };
            }
            if (error.message.includes('decryption failed')) {
                return { valid: false, error: 'DEVICE_MISMATCH' };
            }
        }
        return { valid: false, error: 'UNKNOWN' };
    }
}
```

## Express.js Integration Example

```typescript
import express from 'express';
import { loadLicenseFile, decryptStoredLicense, LicenseData } from '@oarkflow/licensing-client';

declare global {
    namespace Express {
        interface Request {
            license?: LicenseData;
        }
    }
}

async function licenseMiddleware(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) {
    try {
        const stored = await loadLicenseFile(process.env.LICENSE_PATH!);
        const { license } = decryptStoredLicense(stored);

        if (new Date(license.expires_at) < new Date()) {
            return res.status(403).json({ error: 'License expired' });
        }

        if (license.is_revoked) {
            return res.status(403).json({ error: 'License revoked' });
        }

        req.license = license;
        next();
    } catch (error) {
        return res.status(500).json({ error: 'License validation failed' });
    }
}

const app = express();
app.use(licenseMiddleware);

app.get('/api/data', (req, res) => {
    console.log(`Request from: ${req.license?.plan_slug} plan`);
    res.json({ data: 'protected content' });
});
```

## Testing

### Run Fixture Tests

```bash
npm test
```

This validates:
- Signature verification against known fixtures
- AES-GCM decryption
- Transport key derivation
- License data parsing

### Using Fixtures in Your Tests

```typescript
import { readFileSync } from 'fs';
import { decryptStoredLicense, StoredLicenseFile } from '@oarkflow/licensing-client';

describe('License validation', () => {
    it('should decrypt valid license', () => {
        const stored: StoredLicenseFile = JSON.parse(
            readFileSync('docs/fixtures/v1/stored_license.json', 'utf-8')
        );
        const { license } = decryptStoredLicense(stored);
        expect(license.id).toBe('lic_fixture_v1');
    });
});
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Security Best Practices

### 1. Use SSH Key Authentication

Always use SSH keys for enhanced security:

```typescript
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from '@oarkflow/licensing-client';
import { readFileSync, writeFileSync } from 'fs';

// Generate Ed25519 key pair
const { privateKey, publicKey } = generateEd25519KeyPair();
writeFileSync('/secure/path/private_key.pem', privateKey, { mode: 0o600 });
writeFileSync('/secure/path/public_key.pem', publicKey);

// Sign requests with private key
const privateKeyPem = readFileSync('/secure/path/private_key.pem', 'utf8');
const data = Buffer.from('sensitive data');
const signature = signEd25519(privateKeyPem, data);

// Verify signature with public key
const publicKeyPem = readFileSync('/secure/path/public_key.pem', 'utf8');
const valid = verifyEd25519(publicKeyPem, data, signature);
```

### 2. Implement Integrity Verification

Compute and verify file hashes to detect tampering:

```typescript
import { computeFileSHA256, computeSHA256 } from '@oarkflow/licensing-client';

// Compute hash of license file
const hash = computeFileSHA256(licensePath);

// Verify against expected hash
if (hash !== expectedHash) {
    throw new Error('License file has been tampered with');
}

// For sensitive data
const dataHash = computeSHA256(Buffer.from(sensitiveData));
```

### 3. Secure Sensitive Files

Use secure deletion for sensitive data:

```typescript
import { secureDelete } from '@oarkflow/licensing-client';

// Securely delete temporary files
await secureDelete('/tmp/sensitive_data.tmp');

// Overwrites file 3 times with random data before deletion
```

### 4. Use Cryptographically Secure Random

Always use secure random generation:

```typescript
import { secureRandomBytes } from '@oarkflow/licensing-client';

// Generate secure random bytes
const nonce = secureRandomBytes(12);  // For AES-GCM
const sessionId = secureRandomBytes(32).toString('hex');
```

### 5. Encrypt Cached Data

If caching license data, encrypt it:

```typescript
import { encryptAesGcm, decryptAesGcm, secureRandomBytes } from '@oarkflow/licensing-client';
import { writeFileSync, readFileSync } from 'fs';

// Encrypt before caching
const key = secureRandomBytes(32);
const nonce = secureRandomBytes(12);
const plaintext = Buffer.from(JSON.stringify(license));
const encrypted = encryptAesGcm(plaintext, nonce, key);

// Store encrypted data
writeFileSync(cachePath, JSON.stringify({
    data: encrypted.toString('base64'),
    nonce: nonce.toString('base64'),
}), { mode: 0o600 });

// Decrypt when loading
const cached = JSON.parse(readFileSync(cachePath, 'utf8'));
const decrypted = decryptAesGcm(
    Buffer.from(cached.data, 'base64'),
    Buffer.from(cached.nonce, 'base64'),
    key
);
```

### 6. Protect License Files

Set strict file permissions:

```typescript
import { chmodSync } from 'fs';

// After writing license file
chmodSync(licensePath, 0o600);  // Owner read/write only
```

### 7. Use TLS in Production

```typescript
import https from 'https';

// ❌ NEVER do this in production:
const agent = new https.Agent({
    rejectUnauthorized: false  // DANGEROUS
});

// ✅ Always verify certificates in production
const agent = new https.Agent({
    rejectUnauthorized: true,
    ca: readFileSync('/path/to/ca-bundle.crt'),
});
```

### 8. Never Log Sensitive Data

```typescript
// ❌ Don't do this
console.log('License data:', license);
console.log('Session key:', sessionKey);

// ✅ Log only non-sensitive information
console.log('License ID:', license.id);
console.log('Expires:', license.expires_at);
```

### 9. Validate Expiration

Always check expiration:

```typescript
const expiresAt = new Date(license.expires_at);
const now = new Date();

if (expiresAt < now) {
    throw new Error('License expired');
}

// Warn before expiration
const daysUntilExpiry = Math.floor((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
if (daysUntilExpiry < 7) {
    console.warn(`License expires in ${daysUntilExpiry} days`);
}
```

### 10. Implement Rate Limiting

Protect against brute force attacks:

```typescript
import { RateLimiter } from 'limiter';

const limiter = new RateLimiter({ tokensPerInterval: 10, interval: 'minute' });

async function verifyLicense() {
    const hasToken = await limiter.removeTokens(1);
    if (!hasToken) {
        throw new Error('Too many verification attempts');
    }
    // ... verification logic
}
```

## Cryptographic Operations

The SDK provides comprehensive cryptographic utilities:

```typescript
import {
    generateEd25519KeyPair,
    signEd25519,
    verifyEd25519,
    encryptAesGcm,
    decryptAesGcm,
    computeSHA256,
    computeFileSHA256,
    secureRandomBytes,
    secureDelete,
} from '@oarkflow/licensing-client';

// Ed25519 Key Generation
const { privateKey, publicKey } = generateEd25519KeyPair();
// Returns: { privateKey: '...PEM...', publicKey: '...PEM...' }

// Ed25519 Signing
const signature = signEd25519(privateKeyPem, data);
// Returns: Base64-encoded signature string

// Ed25519 Verification
const valid = verifyEd25519(publicKeyPem, data, signature);
// Returns: boolean

// AES-256-GCM Encryption
const encrypted = encryptAesGcm(plaintext, nonce, key);
// Returns: Buffer with ciphertext and authentication tag

// AES-256-GCM Decryption
const plaintext = decryptAesGcm(ciphertext, nonce, key);
// Returns: Buffer with plaintext

// SHA-256 Hashing
const hash = computeSHA256(data);  // Hex string
const binaryHash = computeSHA256(data, 'binary' as BufferEncoding);  // Binary
const fileHash = computeFileSHA256(filepath);

// Secure Random
const randomBytes = secureRandomBytes(32);  // Returns Buffer

// Secure File Deletion
await secureDelete(filepath);  // Overwrites then deletes
```

## Roadmap

- [ ] HTTP activation flow (currently requires Go CLI)
- [ ] Device fingerprint generation for Node.js
- [ ] Background verification scheduler
- [x] Ed25519 key generation and signing
- [x] SHA-256 hashing utilities
- [x] Secure random byte generation
- [x] Secure file deletion
- [ ] Checksum file validation
- [ ] Offline grace period handling
- [ ] Multi-layer integrity verification

## Related Documentation

- [Client Security Guide](../../backend/CLIENT_SECURITY.md)
- [SDK Developer Guide](../../docs/SDK_GUIDE.md)
- [SDK Protocol Specification](../../docs/sdk_protocol.md)
- [OpenAPI Specification](../../docs/api/licensing_openapi.yaml)

## License

MIT License - see LICENSE file for details.
