# Production Readiness Gap Analysis

## Current Snapshot
- `cmd/main.go` wires the HTTP server, builds storage from env, and unconditionally seeds demo clients/licenses every start.
- `pkg/licensing/server.go` exposes activation, verification, basic admin CRUD, and rate-limited health endpoints protected only by `X-API-Key`.
- `pkg/licensing/storage.go` provides an in-memory map or JSON snapshot file; there is no transactional database, migrations, or multi-node coordination.
- The CLI (`client/app.go`, `pkg/client`) handles activation/verification and wraps an example HTTP server but lacks packaging, background renewal, or secure OS-specific storage.

## Priority 0 (Blockers)

| Gap | Impact | Enhancement | Reference |
| --- | --- | --- | --- |
| Storage is limited to in-memory maps or a single JSON file; no transactions, schema migrations, backup, or multi-process access. | Any crash or concurrent writer corrupts/loses all licenses and audit records; cannot scale past one node. | Introduce a production datastore (PostgreSQL/MySQL/SQLite with WAL), schema migrations, encrypted backups, and a storage interface with optimistic locking. | `pkg/licensing/storage.go` (`BuildStorageFromEnv`, `PersistentStorage`) |
| The TPM implementation is an in-process RSA helper with keys materialized in Go memory; there is no hardware root-of-trust, key rotation, or attestation. | Attackers with server access can extract signing keys, forge licenses, and impersonate TPM responses. | Integrate a real TPM/HSM (via `go-tpm`, PKCS#11, or cloud KMS), enforce sealed storage, implement signing key rotation/expiry, and persist public-key history. | `pkg/licensing/licensing.go` (`NewTPM`, `CreatePrimary`, `Sign`) |
| TLS is optional and defaults to HTTP; admin/API secrets are taken directly from env vars with no rotation or vault integration. | Plaintext traffic and leaked env vars expose licenses and admin privileges. | Require TLS by default, support ACME/Let's Encrypt, hot-reload certs, integrate with secret managers (HashiCorp Vault, AWS/GCP secrets), and add automatic rotation policies. | `cmd/main.go` (TLS env handling) |
| Admin access relies solely on a shared `X-API-Key`; `AdminUser` passwords are never used and there is no RBAC, MFA, or session management. | No per-user accountability, impossible to grant least privilege, keys cannot be scoped or revoked individually. | Implement real login/token issuance, scoped API keys tied to roles, MFA support, and per-endpoint authorization policies; expose CRUD for admin users via secure flows. | `pkg/licensing/server.go` (`authorizeAdmin`, admin handlers) |
| There is no tamper-proof audit log for admin mutations, license changes, or authentication attempts; only activation attempts are recorded in storage. | Breach investigations, compliance reviews, and anomaly detection are impossible. | Persist append-only audit events (e.g., to Postgres, Cloud Logging, or immutability service) for every admin/API action with request metadata and signatures. | `pkg/licensing/license_manager.go` (`recordActivationAttempt` only covers activations) |
| The server unconditionally seeds demo clients/licenses on startup. | Production data can be overwritten or polluted; operators cannot distinguish seed/test records. | Move seeding into a separate command or gate it behind an explicit `LICENSE_SERVER_BOOTSTRAP_DEMO=true` flag. | `cmd/main.go` ("Creating demo clients and licenses") |

## Priority 1 (High Value)

| Gap | Impact | Enhancement | Reference |
| --- | --- | --- | --- |
| Deployment model is single-process; rate limiting is an in-memory map, so horizontal scaling or restart wipes counters. | Cannot run multiple instances, and DoS protection resets on restart. | Externalize rate limiting and state (Redis/Redis Cluster), add per-license and per-endpoint quotas, and design stateless HTTP handlers for multi-node deployments. | `cmd/main.go`, `pkg/licensing/limiter.go` |
| Admin/activation APIs return entire collections with no pagination, filtering, or richer license metadata (SKUs, feature flags, seat pools). | Integrations with CRMs or billing systems cannot fetch large datasets or express product tiers. | Add pagination/filter query params, introduce license templates/SKUs, feature entitlements, seat pools, and PATCH endpoints for lifecycle operations. | `pkg/licensing/server.go` (list handlers) |
| Logging is ad-hoc `log.Printf`; there are no structured logs, metrics, tracing, or alerting hooks. | Operators lack visibility into failures, performance, or suspicious activity. | Adopt structured logging (zap/zerolog), emit OpenTelemetry traces/metrics, expose Prometheus metrics, and integrate with alerting (Grafana/Loki, CloudWatch, etc.). | `cmd/main.go`, `pkg/licensing/server.go` |
| Client CLI provides activation but no offline grace periods, scheduled re-verification, secure keystore integration, or update channel isolation. | End users cannot run offline, updates require manual intervention, and secrets rest only in plain files. | Implement renewable offline tokens with expiry, background revalidation daemon, platform keychain integration (Keychain, DPAPI, libsecret), and signed client auto-update support. | `client/app.go`, `pkg/client` |
| Automated testing covers only a subset of client recovery; there are no end-to-end, load, fuzz, or regression tests for the server/licensing flows. | Regressions in crypto, storage, and APIs will ship undetected; compliance reviews cannot rely on evidence. | Add Go test suites for server handlers, storage backends, CLI flows, fuzz activation payload parsing, and run integration tests in the internal CI system. | `pkg/client/client_recovery_test.go`, `pkg/client/integrity_test.go` |
| There is no deployment packaging (Docker images, Helm charts, Terraform examples) or runtime configuration validation. | Hard to ship to staging/prod consistently; misconfigurations surface only at runtime. | Provide container images, Helm chart/Compose files, config validation on boot, and sample Terraform for managed secrets/storage. | (Absence in repo; `cmd/main.go` takes env vars directly) |

## Priority 2 (Quality of Life)

| Gap | Impact | Enhancement | Reference |
| --- | --- | --- | --- |
| No operator/admin UI or self-service portal for clients; all management requires raw API calls. | Support teams must script every action; customers cannot self-serve licenses. | Build a web dashboard (React/Next.js) backed by the existing APIs with proper auth/RBAC. | (No UI components present) |
| No webhook/event system to notify downstream systems of activations, revocations, or bans. | External billing/support tools cannot react to license changes in real time. | Publish signed webhooks or stream events (Kafka/NATS) with retry/backoff and signing secrets. | `pkg/licensing/license_manager.go` (mutations are internal only) |
| No analytics or reporting for activations, seats in use, or geographic distribution. | Product and finance teams lack insight into usage and compliance. | Add reporting endpoints, scheduled exports, and dashboards fed by aggregated activation data. | `pkg/licensing/storage.go` (activation data stored but never aggregated) |
| Single-tenant assumptions: licenses tie directly to email/username with no organization hierarchy or delegated admins. | Cannot serve enterprise customers needing org-level policies. | Introduce organizations/tenants, delegated admins, and policy inheritance on licenses/clients. | `pkg/licensing/license_manager.go` (License struct lacks tenant fields) |

## Suggested Next Steps
- Decide on target architecture (single-tenant SaaS vs. on-prem) and prioritize P0 items into an implementation roadmap.
- Stand up a production datastore and migrate existing JSON data before adding new crypto or auth features.
- Define an auth model (admins, service accounts, client apps) and document threat models for TPM/keys.
- Establish CI/CD (lint, tests, security scans) and add observability plumbing early so later features inherit it.
