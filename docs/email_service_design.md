# Email Service Architecture

## Goals & Capabilities
- Manage multiple email providers (SMTP, SendGrid, SES, etc.) with explicit priority and failover rules.
- Create and version reusable email templates (subject + HTML/text bodies + metadata) and bind them to specific providers or provider chains.
- Send transactional emails from server flows (trial creation, subscription, password reset) choosing provider per template/request.
- Automatically retry failed deliveries with bounded exponential backoff plus jitter, then fall back to the next provider when thresholds are exceeded.
- Provide auditability: every attempted/queued/successful email is persisted along with provider, template, personalization variables, and delivery events.

## Domain Model

### Entities
| Entity | Purpose | Key Fields |
| --- | --- | --- |
| `EmailProvider` | Connection profile for an upstream service. | `id`, `name`, `slug`, `type` (smtp, sendgrid, custom), `config` (JSON blob per type), `priority`, `max_retries`, `retry_policy` (base delay, max delay, jitter pct), `is_default`, `enabled`, timestamps, rolling stats |
| `EmailTemplate` | Reusable subject/body pair plus metadata. | `id`, `name`, `slug`, `category`, `subject`, `html_body`, `text_body`, `description`, `metadata` (JSON), `default_provider_id`, `max_retries_override`, `created_at`, `updated_at` |
| `EmailTemplateRoute` | Ordered mapping of templates (or categories) to providers for fallback. | `id`, `template_id` (nullable for category-level routes), `category`, `provider_id`, `priority`, `retry_limit_override`, `enabled` |
| `EmailMessage` | Persisted outbound email (queue item + audit). | `id`, `template_id`, `provider_id`, `to`, `cc`, `bcc`, `subject`, `rendered_html`, `rendered_text`, `variables` (JSON), `status` (queued, sending, retrying, sent, failed, bounced), `retry_count`, `next_attempt_at`, `error_reason`, timestamps |
| `EmailEvent` | Provider callbacks / lifecycle events. | `id`, `message_id`, `provider_id`, `event_type` (delivered, opened, bounced, complaint), `payload`, `created_at` |

### Example SQLite DDL Snippets
```sql
CREATE TABLE email_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    config JSONB NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    max_retries INTEGER NOT NULL DEFAULT 3,
    retry_base_ms INTEGER NOT NULL DEFAULT 1000,
    retry_max_ms INTEGER NOT NULL DEFAULT 60000,
    retry_jitter_pct REAL NOT NULL DEFAULT 0.25,
    is_default BOOLEAN NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE email_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    subject TEXT NOT NULL,
    html_body TEXT,
    text_body TEXT,
    description TEXT,
    metadata JSONB,
    default_provider_id TEXT REFERENCES email_providers(id),
    max_retries_override INTEGER,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE email_template_routes (
    id TEXT PRIMARY KEY,
    template_id TEXT REFERENCES email_templates(id) ON DELETE CASCADE,
    category TEXT,
    provider_id TEXT NOT NULL REFERENCES email_providers(id),
    priority INTEGER NOT NULL,
    retry_limit_override INTEGER,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    CHECK (template_id IS NOT NULL OR category IS NOT NULL)
);

CREATE TABLE email_messages (
    id TEXT PRIMARY KEY,
    template_id TEXT REFERENCES email_templates(id),
    provider_id TEXT REFERENCES email_providers(id),
    to_address TEXT NOT NULL,
    cc TEXT,
    bcc TEXT,
    subject TEXT NOT NULL,
    rendered_html TEXT,
    rendered_text TEXT,
    variables JSONB,
    status TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL,
    next_attempt_at TIMESTAMP,
    error_reason TEXT,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE email_events (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL REFERENCES email_providers(id),
    event_type TEXT NOT NULL,
    payload JSONB,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_email_messages_status_next_attempt ON email_messages(status, next_attempt_at);
```

## Storage Interface Changes
Add email-specific CRUD and queue operations to `pkg/licensing/storage.go` so both SQLite and in-memory backends can manage the new data:
```go
type Storage interface {
    // existing methods ...
    SaveEmailProvider(ctx context.Context, provider *EmailProvider) error
    UpdateEmailProvider(ctx context.Context, provider *EmailProvider) error
    ListEmailProviders(ctx context.Context, includeDisabled bool) ([]*EmailProvider, error)
    GetEmailProvider(ctx context.Context, id string) (*EmailProvider, error)
    DeleteEmailProvider(ctx context.Context, id string) error

    SaveEmailTemplate(ctx context.Context, tpl *EmailTemplate) error
    UpdateEmailTemplate(ctx context.Context, tpl *EmailTemplate) error
    ListEmailTemplates(ctx context.Context) ([]*EmailTemplate, error)
    GetEmailTemplate(ctx context.Context, id string) (*EmailTemplate, error)
    DeleteEmailTemplate(ctx context.Context, id string) error

    SaveEmailTemplateRoute(ctx context.Context, route *EmailTemplateRoute) error
    ListEmailTemplateRoutes(ctx context.Context, templateID string) ([]*EmailTemplateRoute, error)
    DeleteEmailTemplateRoute(ctx context.Context, id string) error

    EnqueueEmail(ctx context.Context, msg *EmailMessage) error
    UpdateEmailMessage(ctx context.Context, msg *EmailMessage) error
    GetEmailMessage(ctx context.Context, id string) (*EmailMessage, error)
    LeaseNextEmail(ctx context.Context, dueBefore time.Time) (*EmailMessage, error)
    AppendEmailEvent(ctx context.Context, event *EmailEvent) error
}
```
Each concrete storage implementation mirrors existing patterns (maps for in-memory, SQL statements for SQLite) and ensures JSON columns are marshaled consistently.

## Provider Abstraction
```go
type EmailProviderDriver interface {
    Type() string // e.g. "smtp", "sendgrid"
    Send(ctx context.Context, msg *RenderedEmail, cfg ProviderConfig) (*ProviderReceipt, error)
}
```
- Drivers live under `pkg/email/providers/<type>` and register themselves via a central registry.
- `ProviderConfig` wraps the decrypted `EmailProvider.Config` payload plus helper getters (API key, region, sender domain, rate limits).
- The licensing server loads enabled providers at startup, decrypts secrets (via env or KMS), and hands the config to the proper driver.

## Template Rendering & Personalization
- Store templates as Go text/template (or mjml-like) strings that accept a map of variables.
- `TemplateRenderer` compiles templates on save, caches them, and renders per message request (subject, HTML, text). Validation happens during creation/update so runtime failures become rare.
- Attach metadata (like `category=license_notifications`, `purpose=password_reset`) to drive routing and auditing.

## Routing, Retry, and Failover
1. **Routing order**:
   - Explicit provider override passed to `EmailService.Send()`.
   - Template-specific routes ordered by `priority`.
   - Category-level routes.
   - Global default provider (`is_default=1`).
   - If none remain, reject send.
2. **Retry policy**:
   - Each message tracks `retry_count`, `max_retries`, and `next_attempt_at`.
   - On failure, compute delay using `next = min(maxDelay, baseDelay * 2^attempt)` and add jitter (`randFloat(-jitter, jitter)` multiplier).
   - If `retry_count` exceeds route/template/provider limit, mark provider exhausted and attempt next provider in chain (reset attempt counter for that provider, but retain per-message `failover_count`).
   - After all providers fail, message status becomes `failed`, but remains queryable.
3. **Backoff worker**:
   - Background goroutine polls `LeaseNextEmail` (ordered by `next_attempt_at`) and hands messages to dispatcher.
   - Worker uses advisory locking (e.g., update row to `status='sending'` with compare-and-swap) so multiple server instances can share the queue.

## API Surface (Admin)
| Method | Path | Description |
| --- | --- | --- |
| `GET /api/email/providers` | List providers with status and stats. |
| `POST /api/email/providers` | Create provider (name, type, config, priority, retry policy). |
| `PUT /api/email/providers/{id}` | Update provider info / enable/disable / set default. |
| `DELETE /api/email/providers/{id}` | Soft-delete or disable provider. |
| `GET /api/email/templates` | List templates with linked providers. |
| `POST /api/email/templates` | Create template plus default routing + validation. |
| `PUT /api/email/templates/{id}` | Update template content and metadata. |
| `POST /api/email/templates/{id}/routes` | Manage provider priority chains per template. |
| `POST /api/email/send` | Queue a message (template slug, recipient, variables, optional provider override). |
| `GET /api/email/messages` | Filterable log/queue (status, template, recipient). |
| `POST /api/email/messages/{id}/retry` | Force retry/failover manually. |

Auth + rate limiting reuse existing admin controls.

## Web UI
- Add new sidebar section "Messaging" with pages for Providers, Templates, and Activity (message log).
- Providers page: cards showing type, priority, default status, uptime stats, enable/disable toggles.
- Template editor: split-pane for subject/body with preview, route builder UI (drag to order providers, set retry count/jitter overrides).
- Activity page: filterable table with status badges, provider used, failure reasons, manual retry button.

## Operational Considerations
- Secrets: provider configs referencing API keys should support env-var placeholders or integration with OS keychain; never echo back via API.
- Metrics: expose counters per provider (success/failure, latency) via existing health endpoints or Prometheus metrics.
- Background worker enable/disable via env (`LICENSE_EMAIL_ENABLED=1`). Worker should gracefully stop on shutdown.
- Webhook ingestion: optional endpoints (`/api/email/providers/{slug}/events`) to record bounces/complaints into `email_events`.
- Testing: create fake provider driver for local dev to capture messages to disk.

## Rollout Plan
1. **Schema + storage**: add tables/migrations and extend storage interface/implementations.
2. **Domain types + service**: define `EmailProvider`, `EmailTemplate`, `EmailTemplateRoute`, `EmailMessage`, drivers, renderer, router, dispatcher.
3. **API handlers**: CRUD for providers/templates/routes, enqueue endpoint, message log, webhook ingestion.
4. **Background worker & retry logic**: implement dispatcher loop, jitter backoff, provider failover.
5. **Integrations**: wire `handleSubscribe`/trial flows to enqueue relevant templates; add CLI/test hooks.
6. **Frontend**: build React pages + hooks to manage providers/templates/messages with the new design language.
7. **Observability**: log structured events, add metrics, document env configs, and update docs/USAGE/README.

## Implementation Work Breakdown
1. **Storage & migrations**
    - Update `pkg/licensing/storage.go`, `storage_sqlite.go`, and `storage_sqlite_product.go` (if reused) with the new interfaces and SQL queries.
    - Create forward/backfill migrations (SQL + documentation in `docs/sqlite_migration.md`).
    - Extend in-memory storage for parity and to unblock unit testing.
2. **Email domain package**
    - Add `pkg/email` with structs (`EmailProvider`, `EmailTemplate`, etc.), renderer, router, retry calculator, provider registry.
    - Implement first-class drivers: `smtp` (net/smtp with STARTTLS) and a `noop` test driver. Stub interfaces for SendGrid/SES for future contributions.
3. **Server wiring**
    - Instantiate the email service inside `pkg/licensing/server.go` (guarded by env flag) and expose admin routes using the existing auth middleware.
    - Provide configuration plumbing via `pkg/licensing/config.go` (or env parsing near `BuildStorageFromEnv`) for worker cadence, queue batch size, default sender, etc.
4. **Background dispatcher**
    - New package `pkg/email/dispatcher` containing the polling loop, jittered retry scheduling, failover decisioning, and graceful shutdown hooks (context cancellation).
    - Integrate with server start/shutdown or reuse existing runner infrastructure if present.
5. **Business hooks**
    - Touch `handleSubscribe`, trial issuance, password reset, and any future workflow to enqueue a template slug + variables instead of TODO comments.
    - Ensure LicenseManager exposes helper methods (`SendLicenseEmail(ctx, templateSlug, payload)`).
6. **Web UI additions**
    - Create React routes (`/email/providers`, `/email/templates`, `/email/messages`) with TanStack Query hooks hitting the new API.
    - Reuse the glassmorphism design system (cards, tables, detail drawers) and add JSON editors for provider config.
7. **Testing & observability**
    - Unit-test routing, retry math, and driver failover with the in-memory storage + noop driver.
    - Add integration tests around the SQLite implementation using temporary DBs.
    - Emit structured logs/metrics for message status transitions and provider health.
