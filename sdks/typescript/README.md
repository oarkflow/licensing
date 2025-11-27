# TypeScript/Node.js Licensing SDK

A TypeScript SDK for integrating hardware-bound software licensing into Node.js applications. This SDK provides secure license validation, signature verification, and encrypted license storage.

## Features

- 🔐 **AES-256-GCM encryption** for secure license transport and storage
- ✅ **RSA-PSS signature verification** to ensure license authenticity
- 🖥️ **Hardware fingerprinting** for device-bound licenses
- 📦 **Zero external crypto dependencies** - uses Node.js built-in crypto
- 🧪 **Fixture-based testing** for cross-language compatibility

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

### 1. Activate a License (using Go CLI)

Currently, activation requires the Go CLI. The TypeScript SDK can then load and decrypt the activated license:

```bash
# Install the Go CLI
go install github.com/oarkflow/licensing/cmd/license-cli@latest

# Activate
license-cli activate \
  --server https://licensing.example.com \
  --email user@example.com \
  --client-id client-123 \
  --license-key ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456
```

### 2. Load and Verify the License

```typescript
import { loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';
import { homedir } from 'os';
import { join } from 'path';

async function validateLicense() {
    // Load the stored license
    const licensePath = join(homedir(), '.licensing', '.license.dat');
    const stored = await loadLicenseFile(licensePath);

    // Decrypt and verify signature
    const { license, sessionKey } = decryptStoredLicense(stored);

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
| `LICENSE_CLIENT_SERVER` | License server URL | `https://localhost:8801` |
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

## Security Notes

1. **Never log license data** - It contains sensitive cryptographic material
2. **Protect license files** - They should have `600` permissions
3. **Use TLS in production** - Never set `allowInsecureHttp: true` in production
4. **Validate expiration client-side** - Don't rely solely on server checks

## Roadmap

- [ ] HTTP activation flow (currently requires Go CLI)
- [ ] Device fingerprint generation for Node.js
- [ ] Background verification scheduler
- [ ] Checksum file validation
- [ ] Offline grace period handling

## Related Documentation

- [SDK Developer Guide](../../docs/SDK_GUIDE.md)
- [SDK Protocol Specification](../../docs/sdk_protocol.md)
- [OpenAPI Specification](../../docs/api/licensing_openapi.yaml)

## License

MIT License - see LICENSE file for details.
