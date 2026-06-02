# Production Device Management Tasks

## Protocol and Documentation
- [x] Document canonical device fingerprint as `fp:v2:<alg>:SHA256(device_proof_public_key)`.
- [x] Add versioned hardware fingerprint format `hw:v1:<hash>`.
- [x] Clarify that hardware fingerprinting is diagnostic/risk metadata, not the authorization root.
- [x] Document diagnostic hardware metadata in device proof attestation.
- [ ] Regenerate SDK fixtures after the replacement-token activation flow is finalized.

## Device Schema and Storage
- [x] Add device lifecycle fields to `LicenseDevice`.
- [x] Persist lifecycle fields in SQLite and in-memory storage.
- [x] Add admin-issued device replacement token storage.
- [x] Treat existing devices as `trusted` by default.

## Device Management API
- [x] Add per-device revoke endpoint.
- [x] Add per-device reinstate endpoint.
- [x] Add replacement token issue endpoint.
- [x] Add replacement token list endpoint.
- [x] Keep hard delete endpoint for administrative cleanup.

## Activation and Verification
- [x] Require trusted device state for verification.
- [x] Reject revoked, replaced, and suspicious devices.
- [x] Allow one-time replacement token to bind a new proof-key fingerprint.
- [x] Mark old device as `replaced` and new device as `trusted` after successful replacement.
- [x] Carry diagnostic hardware fingerprint, label, and app version into device records.

## Client SDK
- [x] Add replacement-token activation helper.
- [x] Include diagnostic hardware fingerprint metadata in device proof attestation.
- [x] Include per-component hardware confidence metadata in device proof attestation.
- [x] Send app version as an explicit request header.

## Fingerprint Robustness
- [x] Enforce two-layer identity: proof-key fingerprint for authorization, hardware fingerprint for drift/risk.
- [x] Accept legacy raw SHA-256 fingerprints while emitting versioned `fp:v2` fingerprints from new clients.
- [x] Exclude hostname, MAC, IP address, CPU brand, container ID, pod UID, and pod name from canonical identity.
- [x] Prefer mounted persistent device keys and mounted volume/PVC marker files for container diagnostics.
- [x] Persist container proof keys through explicit application config or `--device-key-file`, not environment variables.
- [x] Ignore environment variables for device proof key selection and diagnostic hardware identifiers.
- [x] Add deterministic tests for proof-key identity, hardware diagnostics, confidence ordering, and container fallback behavior.

## Admin UI
- [x] Show device status and proof metadata in license detail.
- [x] Add revoke and reinstate device actions.
- [x] Add issue replacement token action.
- [x] Show replacement token history.

## Tests and Acceptance
- [x] Add unit tests for replacement token success/failure cases.
- [x] Add SQLite tests for lifecycle columns and replacement-token table creation.
- [x] Add handler tests for admin device lifecycle endpoints.
- [x] Run focused Go and frontend checks.
