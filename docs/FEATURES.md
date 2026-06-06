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
- **Explicit catalog setup:** Product, plan, feature, and scope data is managed through the Admin UI/API or explicitly run SQL seed files.
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

------------------
I want to enhance the licensing server as complete CRM and Product Management. The product can be served as standalone or web based. For verification and authentication, client might require to login each time to access the product or just require offline license validation using client or both

I need you to design the best approach and solution to handle the clients and product where

1) Client could login to product using CRM API endpoints. So there has to be login credentials
2) Offline license validation for product
3) Both
4) any other usage

The system has to be scalable and extensible

Planning conceptual design response
Architecture

API gateway fronts CRM, licensing, auth, product services; enforces mTLS, rate limits, request signing.
Identity & Auth runs as OIDC provider; supports username/password, SSO, device certificates, WebAuthn; issues short-lived JWTs + refresh tokens scoped to CRM vs product.
CRM Service manages orgs, contacts, product entitlements, credentials, provisioning state; expose REST + async webhooks; store in multi-tenant Postgres with row-level security.
Licensing Service issues/rotates cryptographically signed license bundles, tracks activation, enforces seat/device limits, and exposes validation APIs (online) plus offline generators; uses event sourcing so entitlements are replayable.
Product Management Service catalogs product metadata, release channels, feature flags; ties directly to CRM entitlements; publishes updates to products via message bus (NATS/Kafka).
Sync Agent embedded in on-prem/standalone products handles offline license cache, secure storage, periodic sync with licensing API, and telemetry upload when online.
Observability stack (OpenTelemetry) pipelines metrics/logs/traces into monitoring; anomaly detection triggers license revocation workflows.
Usage Scenarios

Login via CRM API: product requests login endpoint, receives JWT + refresh, then calls product APIs; CRM enforces password policies, MFA, session management; gateway forwards identity context downstream.
Offline validation: CRM issues signed license bundle (JWT + CBOR payload) containing features, expiry, hardware binding; Sync Agent validates signature locally, enforces quotas, logs use; revocation list distributed via delta CRL when online.
Hybrid: product first attempts online auth; falls back to cached offline token if gateway unreachable and token still valid; Sync Agent reconciles usage counters and revocations on reconnect; conflict policies (e.g., exceeded seats) resolved server-side.
Other usage (automation, partners): service accounts use client credentials grant scoped to entitlements; hardware appliances use mutual TLS with device certificates; marketplace integrations use webhook + signed callbacks to activate/deactivate licenses.
Scalability & Extensibility

Stateless services with horizontal autoscaling; shared-nothing persistence with read replicas.
Event-driven choreography (user created, entitlement revoked, license synced) so new services subscribe without touching core flows.
Policy engine (OPA/Cedar) externalizes authorization rules for quick changes.
Versioned APIs + migration tooling allow gradual feature rollout; SDKs wrap CRM/licensing flows for client apps.
Strong secret management (KMS/HSM for signing keys), per-tenant encryption, audit trails for every license action.

CRM & Licensing Expansion

CRM logins: introduce a dedicated CRM/identity service (extend auth), storing bcrypt/Argon2 hashed secrets plus MFA data; expose /crm/login, /crm/session, /crm/password behind the API gateway with OIDC-compatible JWT + refresh tokens scoped per tenant/product; support optional IdP/SSO by brokering OAuth/SAML assertions into the same token minting flow; persist org/contact/product relationships in Postgres (row-level security) so CRM calls can enforce tenant isolation before hitting the legacy admin APIs.
Offline + online validation: keep issuing signed license bundles (JWT + CBOR payload) but version them and include device claims, plan, feature flags, usage quotas, and revocation epoch; embed a Sync Agent in products to store bundles securely, validate signatures with the exported public key (~/.licensing/server_public_key.pem), enforce device/seat counters locally, and reconcile against /api/verify when connectivity exists; distribute revocation deltas via pub/sub so agents can refresh CRLs quickly; rotate signing keys via the existing provider abstraction in key_provider.go.
Combined mode: product attempts CRM login first to fetch short-lived tokens and fresh policy; if gateway unreachable it falls back to cached offline bundle provided it hasn’t expired/been revoked; once reconnected, the agent uploads cached audits to audit storage and resolves any seat conflicts (e.g., overuse) according to policy.
Other usages: service accounts and automation tools receive client-credential tokens bound to products; partner portals get delegated admin scopes surfaced through CRM webhooks; hardware appliances authenticate with mutual TLS certs issued per device; marketplace or provisioning scripts trigger license lifecycle events through the event bus so they never need direct DB access.
Implementation Roadmap

Phase 1: document current data contracts (clients, licenses, activations) in api and model CRM entities (Tenant, User, Contact, Product, Entitlement) plus migrations; add OpenAPI paths for CRM login/session and extend RBAC policies.
Phase 2: build the identity service (Go service under auth + new cmd/crm_api) with password/MFA flows, refresh-token store, and OIDC-compliant JWT signing keys managed alongside existing license keys.
Phase 3: extend licensing service to emit versioned license bundles, CRL feeds, and revocation events; implement Sync Agent library (e.g., pkg/client/sync) that product binaries can embed for online/offline reconciliation.
Phase 4: deliver ancillary usage modes—service-account provisioning endpoints, partner webhook subscriptions, mTLS device enrollment—and integrate telemetry/auditing via audit to monitor license abuse.
Phase 5: harden and scale—add message bus, cache layers, and observability; write load/regression tests plus end-to-end scenarios covering CRM login, offline validation, hybrid fallback, and automation flows.
Next steps

Flesh out detailed API contracts for the CRM login/session endpoints and add them to licensing_openapi.yaml.
Prototype the Sync Agent storage + verification logic and validate it against a mocked license bundle/signature.
Plan migrations and data seeding for the new CRM entities before touching production data.
