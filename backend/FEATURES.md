# Licensing Server Features

This feature catalog highlights the capabilities provided by the licensing stack so you can understand exactly what is available when running the service.

## Security & Trust

- **Hardware-backed signatures:** Supports software, file-based HSM, and TPM signing providers, exporting a public key for customer verification.
- **Encrypted transport payloads:** License blobs are encrypted with AES-GCM using device-derived keys before being stored or transmitted to clients.
- **Integrity sealing:** Each client maintains a checksum vault to detect tampering before a license is parsed or executed.
- **Per-device binding:** Licenses cannot be copied across machines because the cipher key depends on the local fingerprint.
- **Strict file permissions:** Both server keys and client licenses are written with locked-down permissions and validation checks at startup.

## License Lifecycle Management

- **Plan-aware entitlements:** Every license stores a plan slug so downstream services can unlock tiers without extra lookups.
- **Per-device activation limits:** Issue licenses with configurable `max_devices` and track live activations in real time.
- **Delegate support:** Captures both the purchasing identity and the subject client that actually activates, including `granted_by` metadata.
- **Revocation and reinstatement:** Admin endpoints revoke, reinstate, ban, or unban clients with full audit trails.
- **Rate-limited admin API:** Safeguards management endpoints from brute-force attempts.

## Scheduling & Compliance

- **Configurable check modes:** Choose none, every execution, monthly, yearly, or custom intervals per license.
- **Background verification:** Long-running clients automatically re-validate licenses in the background when using custom intervals.
- **Default policy backfill:** Environment-configured check policies apply to new licenses and retroactively upgrade older records.

## Storage & Deployment

- **Pluggable storage backends:** Swap between in-memory, SQLite, or JSON snapshots via environment configuration.
- **Bootstrap automation:** Optional demo seeding creates example clients and licenses for testing new deployments.
- **Health endpoints:** Lightweight probes report readiness for load balancers and orchestration systems.

## Client Experience

- **Flexible activation strategies:** `auto`, `env`, `prompt`, and `verify` modes cover interactive laptops through headless appliances.
- **Command wrapping:** Integrates with any application by running it only after successful activation and exposing license metadata via environment variables.
- **Custom CA and TLS settings:** Clients trust additional certificate bundles or opt into insecure HTTP for local development.
- **JSON activation presets:** Pre-fill required fields via activation files to streamline onboarding scripts.

## Observability & Auditing

- **Activation records:** Every activation captures timestamps, fingerprints, IP addresses, and user agents.
- **Structured logging:** Server logs highlight storage backend, signing provider, bootstrap credentials, and policy changes during startup.
- **Client HTTP surface:** The sample runtime exposes the decrypted license via a local endpoint for rapid debugging.
