# Licensing SDK Protocol Overview

This document captures the bare-metal contract between any licensing client SDK and the server exposed in `cmd/server`. Treat it as the authoritative reference when porting the Go client to other languages.

## 1. Activation & Verification API

### 1.1 Endpoints

| Purpose | Method | Path |
| --- | --- | --- |
| Device activation | `POST` | `/api/activate` |
| License verification | `POST` | `/api/verify` |

Both endpoints accept and return JSON. Requests must include the following headers:

- `Content-Type: application/json`
- `User-Agent: <product>/<version>` (free-form but required for logging)
- `X-Device-Fingerprint`: deterministic fingerprint described in Section 2
- `X-License-Key`: normalized key (uppercase, hyphens removed)
- `X-License-Secure: 1` (optional) when the payload is wrapped in the transport envelope

### 1.2 Request body

```jsonc
{
  "email": "owner@example.com",           // required, validated via regex
  "client_id": "client-123",             // required for direct + delegated flows
  "license_key": "ABCD-...-1234",        // 40 characters after normalization
  "device_fingerprint": "<sha256-hex>"   // 32-64 chars, see Section 2
}
```

### 1.3 Response body

Successful responses always set `success=true` and include a cryptographic payload:

```jsonc
{
  "success": true,
  "message": "Activated",
  "encrypted_license": "<base64>AES-GCM ciphertext</base64>",
  "nonce": "<base64>12-byte nonce</base64>",
  "signature": "<base64>RSA PKCS#1 v1.5 SHA-256 signature</base64>",
  "public_key": "<PEM block>",
  "expires_at": "2025-12-01T00:00:00Z"
}
```

Failure responses set `success=false` (or omit the field) and describe the error via `message` or a top-level `{ "error": "..." }` envelope when the server injects HTTP errors. Clients must handle:

- `400` malformed inputs
- `401` unauthorized/banned/revoked
- `404` unknown licenses
- `409` activation limit exceeded
- `429` rate limiting
- `5xx` transient server failures

## 2. Device Fingerprint Contract

Every SDK must derive the authorization fingerprint from the device proof public key:

```text
fingerprint = "fp:v2:" + public_key_algorithm + ":" + lowercase_hex( SHA256(device_proof_public_key_bytes) )
```

This key-based fingerprint is the canonical device identity used in `X-Device-Fingerprint`, activation, verification, encrypted transport, offline tokens, and device replacement. The client must keep the private key stable across restarts using the best provider available: TPM/hardware key first, OS keystore second, software key file only as fallback.

Hardware identifiers such as DMI UUID, serial numbers, machine IDs, persistent volume IDs, and configured container IDs may still be collected as diagnostic or risk metadata. They are not the authorization root and must not be required to reproduce the canonical fingerprint. Hardware diagnostic fingerprints are versioned separately:

```text
hardware_fingerprint = "hw:v1:" + lowercase_hex( SHA256(stable_hardware_components) )
```

Unstable identifiers such as hostname, MAC address, IP address, CPU brand, container ID, Kubernetes pod UID, Kubernetes pod name, and environment-provided device IDs must not be part of the canonical authorization fingerprint. Container deployments should prefer a mounted persistent device key first, then mounted persistent volume IDs or Kubernetes PVC marker files for diagnostics. TPM-backed keys should only be used in containers when the TPM is intentionally exposed.

Device proof attestations may include diagnostic fields such as `hardware_fingerprint`, `hardware_confidence`, `label`, `platform`, and `is_container`. Servers may store these for audit, support, and suspicious-drift analysis, but authorization must continue to be based on proof-key possession. Confidence values are recorded per component as `high`, `medium`, or `low`.

## 3. Secure Transport Envelope

To prevent plaintext license data from crossing the wire, the client may encrypt request payloads after the first successful activation, and the server will mirror that behavior in responses.

1. The client derives a 32-byte transport key: `SHA256( device_fingerprint + hex(nonce) )`.
2. Activation responses pack `[session_key (32 bytes) || license_json]` and seal it with AES-256-GCM using the derived transport key + nonce.
3. The client verifies the RSA signature (SHA-256 hash of `encrypted_license || device_fingerprint`) with the provided public key before storing the payload. For backward compatibility the client will fall back to verifying SHA-256(encrypted_license) if the server is not yet signing the fingerprint.
4. Subsequent API calls can be wrapped using the same transport key by sending JSON inside `utils.SecureEnvelope` and setting `X-License-Secure: 1`.

### Stored license format

```jsonc
{
  "encrypted_data": "<bytes>",
  "nonce": "<bytes>",
  "signature": "<bytes>",
  "public_key": "<bytes>",
  "device_fingerprint": "<hex>",
  "expires_at": "RFC3339 timestamp"
}
```

This blob lives at `$CONFIG_DIR/$LICENSE_FILE` (default `~/.licensing/.license.dat`) with `0600` permissions. A checksum sidecar (`.license.dat.chk`) stores an encrypted SHA-256 digest to detect tampering.

### Checksum File Format

The checksum file is JSON with AES-256-GCM encrypted payload:

```json
{
  "version": 1,
  "nonce": "<12-byte nonce as hex>",
  "payload": "<encrypted hash + GCM tag as hex>",
  "created_at": "2025-01-02T08:30:00Z"
}
```

The checksum key is derived as:
```
checksum_key = SHA-256("github.com/oarkflow/licensing/client-checksum/v1" + fingerprint)
```

To verify:
1. Compute `expected_hash = SHA-256(license.dat raw bytes)`
2. Decrypt payload using `checksum_key` and `nonce`
3. Compare decrypted bytes to `expected_hash`

## 4. License Payload Schema

Decrypted payloads (after stripping the 32-byte session key) match `pkg/client.LicenseData`:

```jsonc
{
  "id": "lic_123",
  "client_id": "provider-id",
  "subject_client_id": "runtime-id",
  "email": "owner@example.com",
  "plan_slug": "enterprise",
  "relationship": "direct|delegated",
  "granted_by": "provider-id",
  "license_key": "ABCD...",
  "issued_at": "...",
  "expires_at": "...",
  "last_activated_at": "...",
  "current_activations": 2,
  "max_devices": 5,
  "device_count": 2,
  "is_revoked": false,
  "revoked_at": "",
  "revoke_reason": "",
  "devices": [
    { "fingerprint": "...", "activated_at": "...", "last_seen_at": "..." }
  ],
  "check_mode": "monthly|each_execution|custom|none|yearly",
  "check_interval_seconds": 0,
  "next_check_at": "...",
  "last_check_at": "..."
}
```

SDKs must expose these fields to applications and surface revocation/expiry errors immediately.

## 5. Verification & Scheduling Rules

- Treat cached licenses as authoritative until `expires_at` or an explicit revocation occurs.
- Honor `check_mode`:
  - `none`: no periodic verification.
  - `each_execution`: call `/api/verify` on every startup.
  - `monthly`/`yearly`: schedule next check at the start of the next period.
  - `custom`: use `check_interval_seconds`; long-running processes should run background verification loops.
- When `next_check_at` is in the past, verification should begin immediately but allow retries/backoff if the server is unreachable. Revocation errors must halt the host application.

## 6. Configuration Layering

The reference Go CLI resolves security-sensitive configuration in this order: command-line flags → SDK configuration → defaults. Environment variables are intentionally not used for verification endpoints, local license paths, device proof key selection, or diagnostic hardware identity.

| Purpose | Configuration | Default |
| --- | --- | --- |
| Server URL | `--server-url` / `Config.ServerURL` | `https://localhost:6601` |
| Config dir | `--config-dir` / `Config.ConfigDir` | `~/.licensing` |
| License filename | `--license-store` / `Config.LicenseFile` | `.license.dat` |
| Device proof key file | `--device-key-file` / `Config.DeviceKeyFile` | `$CONFIG_DIR/device_ed25519.pem` |
| Allow insecure HTTP | `--allow-insecure-http` / `Config.AllowInsecureHTTP` | `false` |

Containerized clients must place the device proof key file on a persistent mount by passing explicit SDK configuration or the CLI `--device-key-file` flag. Environment variables are intentionally ignored for device proof key selection and diagnostic hardware identifiers, so ambient process env cannot redirect identity material. If no key path is configured, the Go SDK tries common mounted directories such as `/var/lib/licensing`, `/data/licensing`, and `/persistent/licensing` before falling back to the config directory.

## 7. Compliance Checklist

Before publishing a new SDK:

1. Use the golden fixtures (TBD) to prove AES-GCM encryption/decryption matches the Go implementation.
2. Exercise activation + verification against a local server (`go run cmd/server/main.go`) with TLS disabled via `LICENSE_SERVER_ALLOW_INSECURE_HTTP=1`.
3. Verify tamper detection by editing `.license.dat` and ensuring the SDK refuses to run until re-activated.
4. Validate background verification for each `check_mode`, particularly `custom` with long-running timers.
5. Document how host applications receive license data (e.g., exported environment variables or callback hooks).

This document will grow as we formalize the OpenAPI specification and publish ready-to-use fixtures for other languages.

## 8. Golden Fixture Plan

To keep every SDK aligned with the Go reference implementation, we will publish deterministic fixtures under `docs/fixtures/` and mirror them in automated tests. Each fixture bundle will contain:

- `activation_request.json`: canonical payload that produced the encrypted blob (email, client_id, fingerprint, license key).
- `activation_response.json`: fully expanded server response, including `encrypted_license`, `nonce`, `signature`, and `public_key`.
- `stored_license.json`: byte-for-byte contents of `.license.dat` after successful activation.
- `license_data.json`: decrypted payload (excluding the 32-byte session key) for assertions.
- `checksum.bin`: binary checksum vault contents for tamper testing.

Generation flow:

1. Run `go test ./pkg/client -run TestGenerateFixtures` (new helper to be added) to emit the artifacts into `docs/fixtures/<version>/`.
2. Commit the fixtures along with a README that records the Go commit hash, timestamp, and signing key fingerprint.
3. Each non-Go SDK must import the fixtures as test data and confirm it can:
  - Validate the RSA signature using `public_key`.
  - Derive the transport key from the fingerprint + nonce and decrypt `encrypted_license`.
  - Parse `stored_license.json` directly from disk and detect deliberate mutations of `encrypted_data`, `nonce`, or permissions.

Versioning:

- Use semantic directories (`v1`, `v1.1`, etc.) to track protocol revisions.
- When crypto or storage formats change, ship a new fixture set while retaining older ones for backward-compatibility testing.

Open tasks for this plan:

1. Add the `docs/fixtures/README.md` scaffold describing how to regenerate data.
2. Implement the Go helper in `pkg/client` tests to emit fixtures deterministically (fixed RNG seed, canned license payloads).
3. Wire SDK CI pipelines (self-hosted or local-only) to download the fixtures and run compatibility checks before merging.

## 9. CI Integration Blueprint

Every SDK repo (including this Go module) should add a "fixture parity" workflow that runs on pull requests and nightly builds:

1. **Fetch fixtures:** pull the latest bundle from `docs/fixtures/<version>` (or download a released archive once we publish them separately). Treat the directory as read-only test data.
2. **Replay activation:** decrypt `activation_response.json` using the SDK's implementation and compare the decrypted payload to `license_data.json` byte-for-byte.
3. **License file validation:** load `license.dat`, confirm checksums/signatures, and assert that mutating any field causes verification to fail.
4. **Checksum enforcement:** decrypt `license.dat.chk` using the SDK's checksum key derivation and compare the recovered digest to `sha256(license.dat)`.
5. **Regression gating:** fail the CI job if any fixture mismatch occurs. This ensures protocol changes cannot merge without updating the fixtures and consumers simultaneously.

For the Go repository specifically, add a local CI/test target that runs `go test ./pkg/client -run TestGenerateFixtures` (without `-update-fixtures`) to guarantee the generator stays healthy and that the checked-in bundle is up to date.
