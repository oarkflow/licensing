# Licensing SDKs

This directory contains official SDK implementations for integrating the Licensing system into applications written in various programming languages.

## Available SDKs

| SDK | Language | Status | Features |
|-----|----------|--------|----------|
| [golang](./golang/) | Go | ✅ Complete | Full client, activation, verification, background checks |
| [typescript](./typescript/) | TypeScript/Node.js | ✅ Decrypt/Verify | License loading, signature verification, decryption |
| [php](./php/) | PHP 8.2+ | ✅ Decrypt/Verify | License loading, signature verification, decryption |

## Quick Comparison

### Feature Matrix

| Feature | Go | TypeScript | PHP |
|---------|:--:|:----------:|:---:|
| License Decryption | ✅ | ✅ | ✅ |
| Signature Verification | ✅ | ✅ | ✅ |
| HTTP Activation | ✅ | 🚧 | 🚧 |
| Device Fingerprinting | ✅ | 🚧 | 🚧 |
| Background Verification | ✅ | 🚧 | 🚧 |
| Checksum Validation | ✅ | 🚧 | 🚧 |
| Local License Storage | ✅ | ✅ | ✅ |

**Legend:** ✅ Complete | 🚧 In Progress | ❌ Not Available

## Getting Started

### 1. Run the License Server

```bash
# Start the server (development mode)
export LICENSE_SERVER_ALLOW_INSECURE_HTTP=1
export LICENSE_SERVER_API_KEY="your-admin-key"
go run cmd/server/main.go
```

### 2. Create a License

```bash
# Create a client
curl -X POST http://localhost:8801/api/clients \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-admin-key" \
  -d '{"id":"client-123","name":"Test Client","email":"test@example.com"}'

# Issue a license
curl -X POST http://localhost:8801/api/licenses \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-admin-key" \
  -d '{"client_id":"client-123","plan_slug":"professional","max_devices":5}'
```

### 3. Activate (using Go CLI)

```bash
# Build the CLI
go build -o license-cli ./client

# Activate
./license-cli activate \
  --server http://localhost:8801 \
  --email test@example.com \
  --client-id client-123 \
  --license-key <key-from-step-2>
```

### 4. Use the License in Your App

#### Go

```go
import licensing "github.com/oarkflow/licensing/sdks/golang"

client, _ := licensing.New(licensing.Config{
    ServerURL: "http://localhost:8801",
})
client.Verify()
license, _ := client.License()
fmt.Println("Plan:", license.PlanSlug)
```

#### TypeScript

```typescript
import { loadLicenseFile, decryptStoredLicense } from '@oarkflow/licensing-client';

const stored = await loadLicenseFile('~/.licensing/.license.dat');
const { license } = decryptStoredLicense(stored);
console.log('Plan:', license.plan_slug);
```

#### PHP

```php
use Oarkflow\Licensing\License;

$stored = json_decode(file_get_contents('~/.licensing/.license.dat'), true);
$result = License::decrypt($stored);
echo "Plan: " . $result['license']['plan_slug'];
```

## Cross-Language Compatibility

All SDKs are tested against the same fixture bundle to ensure they produce identical results:

```
docs/fixtures/v1/
├── activation_request.json   # Sample activation request
├── activation_response.json  # Sample server response
├── stored_license.json       # Pretty-printed stored license
├── license.dat              # Raw stored license (compact JSON)
├── license.dat.chk          # Checksum file
├── license_data.json        # Decrypted license data
└── checksum_pretty.json     # Pretty-printed checksum
```

### Running Fixture Tests

```bash
# Go SDK
cd sdks/golang && go test -v ./...

# TypeScript SDK
cd sdks/typescript && npm test

# PHP SDK
cd sdks/php && php scripts/verify-fixtures.php
```

## Documentation

- **[SDK Developer Guide](../docs/SDK_GUIDE.md)** - Comprehensive guide for SDK users
- **[SDK Protocol Specification](../docs/sdk_protocol.md)** - Low-level protocol details
- **[OpenAPI Specification](../docs/api/licensing_openapi.yaml)** - API documentation

## Security Notes

1. **Always use TLS in production** - The `AllowInsecureHTTP` flag is for development only
2. **Protect license files** - They should have `0600` permissions
3. **Never log license data** - It contains cryptographic material
4. **Validate server certificates** - Use proper CA chains in production

## Contributing

### Adding a New SDK

1. Create a directory under `sdks/` (e.g., `sdks/python/`)
2. Implement the core crypto operations:
   - Transport key derivation: `SHA256(fingerprint + hex(nonce))`
   - AES-256-GCM decryption
   - RSA-PSS signature verification (SHA-256, max salt length)
3. Add fixture validation tests
4. Document the API in a README

### Testing Requirements

All SDKs must pass fixture validation:
- Correctly derive transport keys
- Successfully decrypt the fixture license
- Verify RSA-PSS signatures with correct salt length
- Parse license data matching `license_data.json`

## Roadmap

### Planned SDKs

- [ ] Python SDK
- [ ] Ruby SDK
- [ ] Java/Kotlin SDK
- [ ] Rust SDK
- [ ] C# SDK

### Feature Roadmap

- [ ] HTTP activation for TypeScript/PHP
- [ ] Device fingerprinting for all platforms
- [ ] Background verification scheduler
- [ ] Offline grace period handling
- [ ] License caching strategies

## Support

- **Issues**: https://github.com/oarkflow/licensing/issues
- **Discussions**: https://github.com/oarkflow/licensing/discussions
