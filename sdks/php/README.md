# PHP Licensing SDK

A PHP SDK for integrating hardware-bound software licensing into PHP applications. This SDK provides secure license validation, signature verification, and encrypted license storage.

## Features

- 🔐 **AES-256-GCM encryption** for secure license transport and storage
- ✅ **RSA-PSS signature verification** to ensure license authenticity
- 🖥️ **Hardware fingerprinting** for device-bound licenses
- 📦 **Minimal dependencies** - only requires phpseclib3 for RSA-PSS
- 🧪 **Fixture-based testing** for cross-language compatibility

## Requirements

- PHP 8.2 or later
- OpenSSL extension (for AES-GCM)
- Composer

## Installation

### Via Composer

```bash
composer require oarkflow/licensing-client
```

### Manual Installation

```bash
cd sdks/php
composer install
```

## Quick Start

### 1. Activate a License (using Go CLI)

Currently, activation requires the Go CLI. The PHP SDK can then load and decrypt the activated license:

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

```php
<?php

require_once 'vendor/autoload.php';

use Oarkflow\Licensing\License;

// Load the stored license
$licensePath = $_SERVER['HOME'] . '/.licensing/.license.dat';
$stored = json_decode(file_get_contents($licensePath), true);

// Decrypt and verify signature
$result = License::decrypt($stored);
$license = $result['license'];
$sessionKey = $result['sessionKey'];

// Check expiration
$expiresAt = new DateTimeImmutable($license['expires_at']);
if ($expiresAt < new DateTimeImmutable()) {
    throw new RuntimeException('License has expired');
}

// Check revocation
if ($license['is_revoked']) {
    throw new RuntimeException('License revoked: ' . $license['revoke_reason']);
}

echo "Licensed for: " . $license['plan_slug'] . PHP_EOL;
echo "Expires: " . $license['expires_at'] . PHP_EOL;
```

### 3. Feature Gating

```php
<?php

function isFeatureEnabled(array $license, string $feature): bool
{
    $planFeatures = [
        'starter' => ['basic'],
        'professional' => ['basic', 'advanced'],
        'enterprise' => ['basic', 'advanced', 'premium', 'api'],
    ];

    $allowed = $planFeatures[$license['plan_slug']] ?? [];
    return in_array($feature, $allowed, true);
}

// Usage
if (isFeatureEnabled($license, 'api')) {
    enableAPIAccess();
}
```

## Examples

See the [examples](examples/) directory for complete working examples:

- **[basic](examples/basic/)** - Load and verify license files, check features and scopes

To run an example:

```bash
cd examples/basic
php index.php --license-file ~/.licensing-example/.license.dat
```

## API Reference

### Classes

#### `Oarkflow\Licensing\License`

Static class for license operations.

```php
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
 * } $stored The stored license from disk (base64 encoded fields)
 *
 * @return array{sessionKey: string, license: array<string, mixed>}
 * @throws RuntimeException If decryption or signature verification fails
 */
public static function decrypt(array $stored): array
```

#### `Oarkflow\Licensing\Crypto`

Low-level cryptographic operations.

```php
/**
 * Derive the transport key from fingerprint and nonce.
 *
 * @param string $fingerprint Device fingerprint (hex)
 * @param string $nonceHex Nonce as hex string
 * @return string 32-byte binary key
 */
public static function deriveTransportKey(string $fingerprint, string $nonceHex): string

/**
 * Decrypt AES-256-GCM ciphertext.
 *
 * @param string $ciphertext Binary ciphertext with GCM tag appended
 * @param string $nonce 12-byte binary nonce
 * @param string $key 32-byte binary key
 * @return string Decrypted plaintext
 * @throws RuntimeException If decryption fails
 */
public static function decryptAesGcm(string $ciphertext, string $nonce, string $key): string

/**
 * Verify an RSA-PSS signature.
 *
 * @param string $payload Binary data that was signed
 * @param string $signature Binary signature
 * @param string $publicKeyPem PEM-encoded public key
 * @return bool True if signature is valid
 * @throws RuntimeException If key parsing fails
 */
public static function verifySignature(string $payload, string $signature, string $publicKeyPem): bool
```

### License Data Structure

The decrypted license contains:

```php
[
    'id' => 'lic_123',                    // Unique license identifier
    'client_id' => 'client-owner',        // Owner client ID
    'subject_client_id' => 'client-user', // Runtime client ID
    'email' => 'user@example.com',        // License owner email
    'plan_slug' => 'professional',        // Plan for feature gating
    'relationship' => 'direct',           // "direct" or "delegated"
    'granted_by' => null,                 // Granting client (delegated)
    'license_key' => 'ABCD-...',          // The license key
    'issued_at' => '2025-01-01T00:00:00Z',
    'expires_at' => '2026-01-01T00:00:00Z',
    'last_activated_at' => '2025-01-01T00:00:00Z',
    'current_activations' => 2,
    'max_devices' => 5,
    'device_count' => 2,
    'is_revoked' => false,
    'revoked_at' => null,
    'revoke_reason' => null,
    'devices' => [
        [
            'fingerprint' => 'abc123...',
            'activated_at' => '2025-01-01T00:00:00Z',
            'last_seen_at' => '2025-01-02T00:00:00Z',
        ],
    ],
    'device_fingerprint' => 'abc123...',  // Current device
    'check_mode' => 'monthly',            // Verification schedule
    'check_interval_seconds' => 0,        // Custom interval
    'next_check_at' => '2025-02-01T00:00:00Z',
    'last_check_at' => '2025-01-01T00:00:00Z',
]
```

## Environment Variables

The SDK respects these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `LICENSE_CLIENT_SERVER` | License server URL | `https://localhost:8801` |
| `LICENSE_CLIENT_CONFIG_DIR` | License storage directory | `~/.licensing` |
| `LICENSE_CLIENT_LICENSE_FILE` | License filename | `.license.dat` |

## Error Handling

```php
<?php

use Oarkflow\Licensing\License;
use RuntimeException;

function safeLicenseCheck(): array
{
    $licensePath = $_SERVER['HOME'] . '/.licensing/.license.dat';

    try {
        if (!file_exists($licensePath)) {
            return ['valid' => false, 'error' => 'LICENSE_NOT_FOUND'];
        }

        $stored = json_decode(file_get_contents($licensePath), true);
        if ($stored === null) {
            return ['valid' => false, 'error' => 'LICENSE_CORRUPTED'];
        }

        $result = License::decrypt($stored);
        return ['valid' => true, 'license' => $result['license']];

    } catch (RuntimeException $e) {
        if (str_contains($e->getMessage(), 'signature invalid')) {
            return ['valid' => false, 'error' => 'LICENSE_TAMPERED'];
        }
        if (str_contains($e->getMessage(), 'decryption failed')) {
            return ['valid' => false, 'error' => 'DEVICE_MISMATCH'];
        }
        return ['valid' => false, 'error' => 'UNKNOWN'];
    }
}
```

## Laravel Integration Example

### Service Provider

```php
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Oarkflow\Licensing\License;
use RuntimeException;

class LicenseServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton('license', function () {
            $path = config('licensing.path', storage_path('license.dat'));

            if (!file_exists($path)) {
                throw new RuntimeException('License file not found');
            }

            $stored = json_decode(file_get_contents($path), true);
            $result = License::decrypt($stored);

            return $result['license'];
        });
    }
}
```

### Middleware

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ValidateLicense
{
    public function handle(Request $request, Closure $next)
    {
        try {
            $license = app('license');

            if (new \DateTimeImmutable($license['expires_at']) < new \DateTimeImmutable()) {
                return response()->json(['error' => 'License expired'], 403);
            }

            if ($license['is_revoked']) {
                return response()->json(['error' => 'License revoked'], 403);
            }

            $request->merge(['license' => $license]);

        } catch (\Exception $e) {
            return response()->json(['error' => 'License validation failed'], 500);
        }

        return $next($request);
    }
}
```

### Feature Check

```php
<?php

namespace App\Services;

class LicenseService
{
    public function __construct(private array $license)
    {
    }

    public function canUse(string $feature): bool
    {
        $planFeatures = [
            'starter' => ['basic'],
            'professional' => ['basic', 'advanced'],
            'enterprise' => ['basic', 'advanced', 'premium', 'api'],
        ];

        return in_array($feature, $planFeatures[$this->license['plan_slug']] ?? [], true);
    }

    public function daysUntilExpiration(): int
    {
        $expires = new \DateTimeImmutable($this->license['expires_at']);
        $now = new \DateTimeImmutable();
        return max(0, (int) $now->diff($expires)->days);
    }
}
```

## Symfony Integration Example

### Service Definition

```yaml
# config/services.yaml
services:
    App\License\LicenseLoader:
        arguments:
            $licensePath: '%kernel.project_dir%/var/license.dat'

    App\License\LicenseData:
        factory: ['@App\License\LicenseLoader', 'load']
```

### License Loader

```php
<?php

namespace App\License;

use Oarkflow\Licensing\License;
use RuntimeException;

class LicenseLoader
{
    public function __construct(private string $licensePath)
    {
    }

    public function load(): LicenseData
    {
        if (!file_exists($this->licensePath)) {
            throw new RuntimeException('License not found');
        }

        $stored = json_decode(file_get_contents($this->licensePath), true);
        $result = License::decrypt($stored);

        return new LicenseData($result['license']);
    }
}
```

## Testing

### Run Fixture Tests

```bash
php scripts/verify-fixtures.php
```

This validates:
- Signature verification against known fixtures
- AES-GCM decryption
- Transport key derivation
- License data parsing

### Using Fixtures in Your Tests

```php
<?php

use PHPUnit\Framework\TestCase;
use Oarkflow\Licensing\License;

class LicenseTest extends TestCase
{
    public function testDecryptValidLicense(): void
    {
        $stored = json_decode(
            file_get_contents(__DIR__ . '/../../docs/fixtures/v1/stored_license.json'),
            true
        );

        $result = License::decrypt($stored);

        $this->assertEquals('lic_fixture_v1', $result['license']['id']);
        $this->assertEquals('enterprise', $result['license']['plan_slug']);
    }

    public function testInvalidSignatureThrows(): void
    {
        $stored = json_decode(
            file_get_contents(__DIR__ . '/../../docs/fixtures/v1/stored_license.json'),
            true
        );

        // Tamper with the encrypted data
        $stored['encrypted_data'] = base64_encode('tampered');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('signature invalid');

        License::decrypt($stored);
    }
}
```

## Security Notes

1. **Never log license data** - It contains sensitive cryptographic material
2. **Protect license files** - They should have `600` permissions
3. **Use TLS in production** - Never disable certificate verification
4. **Validate expiration server-side** - Don't trust client-only checks
5. **Store session keys securely** - If caching, use encrypted storage

## RSA-PSS Salt Length

This SDK correctly handles Go's RSA-PSS implementation which uses `PSSSaltLengthAuto` (maximum salt length). For 2048-bit RSA keys with SHA-256:

```
max_salt = (key_bits / 8) - hash_len - 2
         = 256 - 32 - 2
         = 222 bytes
```

The salt length is calculated dynamically from the key size.

## Roadmap

- [ ] HTTP activation flow (currently requires Go CLI)
- [ ] Device fingerprint generation for PHP
- [ ] Background verification scheduler (for long-running processes)
- [ ] Checksum file validation
- [ ] Offline grace period handling

## Related Documentation

- [SDK Developer Guide](../../docs/SDK_GUIDE.md)
- [SDK Protocol Specification](../../docs/sdk_protocol.md)
- [OpenAPI Specification](../../docs/api/licensing_openapi.yaml)

## License

MIT License - see LICENSE file for details.

## Testing

```bash
php scripts/verify-fixtures.php
```

This validates the SDK against the shared fixture bundle in `docs/fixtures/v1/`.

## Implementation Notes

- Uses `phpseclib3` for RSA-PSS signature verification with SHA-256.
- Go's `rsa.SignPSS` with default options uses maximum salt length (`keyBits/8 - hashLen - 2`), which for 2048-bit RSA with SHA-256 equals 222 bytes.
- Transport key derivation matches the Go/TypeScript implementations: `SHA256(fingerprint + hex(nonce))`.
- AES-256-GCM decryption uses OpenSSL with the 16-byte auth tag appended to the ciphertext.
