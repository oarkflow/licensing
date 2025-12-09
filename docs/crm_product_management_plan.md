# CRM & Product Management Phase 1 Plan

## Objectives
- Elevate the licensing server into a CRM + product management hub that covers online CRM logins, offline license validation, and hybrid usage.
- Preserve existing licensing guarantees (per-device bindings, TPM/HSM signing, activation audit trails) while layering multi-tenant CRM capabilities.
- Deliver a scalable and extensible foundation so future services (billing, analytics, partner portals) can subscribe to the same events without tight coupling.

## Target Architecture Overview
1. **API Gateway** (existing edge) front-loads requests, enforces mTLS, rate limits, request signing, and injects identity context headers before routing to downstream services.
2. **Identity & CRM Service** (new `cmd/crm_api`, leveraging `pkg/auth`) issues OIDC-compliant JWTs + refresh tokens for CRM logins, SSO brokering, device certificates, and service accounts. Stores hashed credentials (Argon2/Bcrypt) plus MFA artifacts.
3. **CRM Domain Service** (new `pkg/crm` package) models Tenants → Contacts/Users → Products/Entitlements, exposes REST + webhook interfaces, and persists in Postgres with row-level security per tenant.
4. **Licensing Service** (existing `pkg/licensing`) continues issuing signed bundles, but now emits versioned entitlements, revocation epochs, and CRL feeds so offline agents stay updated.
5. **Product Management Service** extends the product/plan structs in `pkg/licensing/product.go` with release channels, feature flags, and metadata sync to downstream products via message bus (NATS/Kafka).
6. **Sync/Agent Library** (new `pkg/client/sync`) embeds into standalone/web products to cache licenses, reconcile usage when online, and mediate between CRM tokens and offline bundles.
7. **Observability Stack** (OpenTelemetry exporters) unifies metrics/logs/traces, feeds anomaly detection that can trigger automated revocations or provisioning workflows.

## Data Model Additions (Phase 1)
| Entity | Purpose | Storage/Package |
| --- | --- | --- |
| `Tenant` | Logical organization/customer grouping with billing + compliance metadata. | `pkg/crm/models.go`, persisted via new Postgres schema/migrations under `scripts/migrations/*.sql`. |
| `CRMUser` | Human identity with username/password, MFA status, roles, and tenant linkage. | `pkg/crm/models.go`; auth helpers reuse `pkg/auth`. |
| `Contact` | Business contact/persona tied to a tenant and optionally a `Client`. | `pkg/crm/models.go`; link to existing `pkg/licensing.Client`. |
| `CredentialSecret` | Versioned secrets (password hashes, API keys, device cert fingerprints). | `pkg/crm/credentials.go`; encrypted at rest via KMS/HSM abstractions. |
| `SessionToken` | JWT/refresh token metadata with scopes, expiry, device info. | `pkg/crm/session_store.go`; stored in Redis/Postgres depending on deployment. |
| `EntitlementBinding` | Links Tenants/Contacts to `pkg/licensing.Plan` and feature overrides. | `pkg/crm/entitlements.go`; ensures parity with `LicenseEntitlements`. |
| `ProductRelease` | Product metadata (channels, versions, change logs) surfaced to CRM/UI. | Extends `pkg/licensing/product.go` with release structs; stored via new tables. |
| `DeviceLedger` | Tracks device fingerprints, last sync, and pending revocations for hybrid mode. | `pkg/crm/devices.go`; feeds both CRM dashboards and license audits. |

## API Surface (OpenAPI Extensions)
- `POST /crm/login`: username/password (or MFA challenge) → short-lived JWT + refresh token; tokens carry tenant + entitlement claims.
- `POST /crm/token/refresh`: rotates access tokens; enforces session revocation + device binding.
- `GET /crm/session`: introspection endpoint for products to validate CRM sessions without hitting auth DB.
- `POST /crm/tenants`: create tenants with admin contact + default product assignments.
- `GET /crm/tenants/{tenantId}/products`: list products + plans accessible to tenant, including feature scopes derived from `PlanFeature` data.
- `POST /crm/entitlements`: assign plan to contact/user; emits `entitlement.assigned` event for licensing service to mint/rotate bundles.
- `GET /crm/devices/{fingerprint}`: expose device ledger state, pending revocations, and sync deadlines.
- `POST /crm/service-accounts`: provision automation/service accounts using client-credentials grant with scoped entitlements.
- `GET /licensing/offline/bundles/{licenseId}` (new): serve versioned CBOR/JWT bundle with revocation epoch + delta CRL pointer so Sync Agent can validate offline.
- All endpoints will be drafted into `docs/api/licensing_openapi.yaml` with version bump (e.g., `v2alpha`) and tagged `crm`/`product` for SDK generation.

## Storage & Eventing Strategy
- Use Postgres (or CockroachDB) schemas for CRM tables with row-level security keyed by tenant; migrations authored via goose/sqlc under `scripts/migrations`.
- Introduce an event bus abstraction (Kafka/NATS) under `pkg/events` for publishing `tenant.created`, `entitlement.updated`, `license.revoked`, `device.synced` topics.
- Cache hot lookups (sessions, tenant entitlements) in Redis/Memcached with signed cache entries to avoid tampering.

## Work Breakdown (Phase 1 Execution)
1. **Schema & Models**
   - Author ERD + migrations covering Tenants, CRMUsers, Contacts, EntitlementBindings, CredentialSecrets, Sessions, ProductReleases, DeviceLedger.
   - Implement Go structs + validation helpers in `pkg/crm` plus repository interfaces bridging to storage drivers.
2. **API Contract**
   - Extend `docs/api/licensing_openapi.yaml` with CRM/login/session endpoints, request/response schemas, and security schemes for access vs refresh tokens.
   - Update SDK guide (`docs/SDK_GUIDE.md`) to describe CRM flows for Go/TypeScript clients.
3. **Identity Service**
   - Create `cmd/crm_api` entrypoint that wires HTTP handlers, session storage, password hashing, MFA, and token issuance using existing signing providers.
   - Define middleware to translate CRM JWT claims into headers consumed by licensing/product services.
4. **Licensing Integration**
   - Update `pkg/licensing.LicenseManager` to emit versioned bundles with revocation epochs + CRL URIs; ensure compatibility with `pkg/client` structs.
   - Introduce Sync Agent scaffolding (`pkg/client/sync`) that loads offline bundles, validates signatures, manages retry logic, and reconciles device counts.
5. **Observability & Testing**
   - Instrument new services with OpenTelemetry; emit audit logs for every login, entitlement grant, and offline bundle download.
   - Write integration tests covering CRM login → entitlement assignment → license issuance, plus offline validation fallback scenarios.

## Deliverables for Step 1
- This plan document checked into `docs/crm_product_management_plan.md`.
- Follow-up PRs will:
  1. Commit migrations + Go models.
  2. Publish API spec updates.
  3. Scaffold CRM service and Sync Agent packages.

## Current Progress
- Added `pkg/crm/models.go` with tenant, user, contact, entitlement, release, device, and service-account structs plus supporting enums.
- Added `pkg/crm/repository.go` describing the persistence interface and option/filter types the new CRM service will require.
- Next steps: author database migrations + storage implementations before exposing the CRM HTTP endpoints.

By landing this plan we unlock iterative implementation while ensuring every feature (CRM login, offline/online hybrid, ancillary usages) maps cleanly onto the existing licensing architecture and remains scalable/extensible.
