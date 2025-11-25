# TypeScript Licensing SDK

This package houses the cross-language SDK implementation for Node.js/TypeScript environments.

## Local development

```bash
cd sdks/typescript
npm install
npm test        # decrypts docs/fixtures/v1 and validates signatures
npm run build   # emits dist/
```

## Current status

- Crypto helpers (`src/crypto.ts`) reproduce the Go client's transport key derivation, AES-256-GCM decryption, and RSA signature validation.
- The license loader (`src/license.ts`) parses `.license.dat`, verifies signatures, and returns the decrypted `LicenseData` + session key for higher-level flows.
- `scripts/verifyFixtures.ts` loads the shared fixture bundle and proves the implementation can:
  - Verify signatures for both activation responses and stored licenses.
  - Derive the transport key from the fingerprint + nonce.
  - Decrypt the payload and match it byte-for-byte with `license_data.json`.

Next steps include wrapping HTTP calls, local license storage, and background verification—mirroring the behaviors documented in `docs/sdk_protocol.md`.
