# SQLite Schema Migration Guide

Recent releases removed the legacy `username` fields from licenses and clients and replaced them with explicit `client_id` / `provider_client_id` tracking for delegated activations. The server now infers the provider automatically based on the license owner, but the `license_authorized_users` table stores `(license_id, email, subject_client_id, provider_client_id)` for auditing. Follow the steps below to migrate an existing SQLite deployment.

## 1. Back Up the Current Database

Always copy the original database before running schema changes.

```bash
cp /var/lib/licensing/licensing.db /var/lib/licensing/licensing-$(date +%s).bak
# or, to create a compact backup
sqlite3 /var/lib/licensing/licensing.db \
  "VACUUM INTO '/var/lib/licensing/licensing-backup.db'"
```

## 2. Choose a Migration Strategy

### Option A: Recreate the Database (Recommended)

If you can tolerate reissuing licenses, remove the old file and allow the server to rebuild the schema automatically:

```bash
rm /var/lib/licensing/licensing.db
# restart the server; it will create the new schema on boot
```

Next, create catalog/client data through the Admin UI/API or run explicit SQL seed files.

### Option B: In-Place Migration

For environments that must keep existing licenses, apply the following SQL statements. They drop the obsolete columns and rebuild the authorized-user mapping.

```sql
BEGIN TRANSACTION;

-- Rebuild clients table without username
ALTER TABLE clients RENAME TO clients_old;
CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    email_lower TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    banned_at TIMESTAMP,
    ban_reason TEXT
);
INSERT INTO clients (id, email, email_lower, status, created_at, updated_at, banned_at, ban_reason)
SELECT id, email, email_lower, status, created_at, updated_at, banned_at, ban_reason
FROM clients_old;
DROP TABLE clients_old;

-- Rebuild licenses table without username
ALTER TABLE licenses RENAME TO licenses_old;
CREATE TABLE licenses (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    email TEXT NOT NULL,
    license_key TEXT NOT NULL,
    license_key_norm TEXT NOT NULL UNIQUE,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TIMESTAMP,
    revoke_reason TEXT,
    is_activated INTEGER NOT NULL DEFAULT 0,
    issued_at TIMESTAMP NOT NULL,
    last_activated_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    current_activations INTEGER NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
);
INSERT INTO licenses (
    id,
    client_id,
    email,
    license_key,
    license_key_norm,
    is_revoked,
    revoked_at,
    revoke_reason,
    is_activated,
    issued_at,
    last_activated_at,
    expires_at,
    current_activations,
    max_devices
)
SELECT
    id,
    client_id,
    email,
    license_key,
    license_key_norm,
    is_revoked,
    revoked_at,
    revoke_reason,
    is_activated,
    issued_at,
    last_activated_at,
    expires_at,
    current_activations,
    max_activations AS max_devices
FROM licenses_old;
DROP TABLE licenses_old;

-- Replace authorized users with explicit subject/provider IDs
DROP TABLE license_authorized_users;
CREATE TABLE license_authorized_users (
    license_id TEXT NOT NULL,
    email TEXT NOT NULL,
    email_lower TEXT NOT NULL,
    subject_client_id TEXT NOT NULL,
    provider_client_id TEXT NOT NULL,
    granted_at TIMESTAMP NOT NULL,
    PRIMARY KEY(license_id, email_lower),
    FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
);

COMMIT;
```

> The insert statement copies the legacy `max_activations` values into the new `max_devices` column so existing license quotas remain unchanged.

> **Important:** Because the legacy schema stored delegated activations by username, you cannot automatically infer the new `subject_client_id` / `provider_client_id` pair. The script above clears `license_authorized_users`. After migration, recreate delegated identities by reactivating those devices or calling the admin API to attach them explicitly.

Finally, run `VACUUM;` to compact the database.

```sql
VACUUM;
```

## 3. Validate the Migration

1. Start the license server and watch for schema errors.
2. Run `sqlite3 licensing.db '.schema licenses'` to confirm the new tables match the definitions above.
3. Execute `go test ./...` or `go run ./client --activation-mode verify` to ensure activations still succeed.

## 4. Rollback Plan

If anything fails, stop the server, restore the backup created in step 1, and investigate before retrying.

## 5. Email Delivery Schema (2025.11+)

The email dispatch service introduced in the November 2025 builds stores its own providers, templates, routes, message queue, and delivery events. Fresh databases pick these up automatically because the server runs the new schema bootstrap on startup. Locked-down environments that require an explicit change window can apply the statements below to create the tables and supporting indexes ahead of time.

```sql
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS email_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    slug_lower TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    config TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    max_retries INTEGER NOT NULL DEFAULT 3,
    retry_base_ms INTEGER NOT NULL DEFAULT 1000,
    retry_max_ms INTEGER NOT NULL DEFAULT 60000,
    retry_jitter_pct REAL NOT NULL DEFAULT 0.25,
    is_default INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    metadata TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_providers_slug ON email_providers(slug_lower);

CREATE TABLE IF NOT EXISTS email_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    slug_lower TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    subject TEXT NOT NULL,
    html_body TEXT,
    text_body TEXT,
    description TEXT,
    metadata TEXT,
    default_provider_id TEXT REFERENCES email_providers(id),
    max_retries_override INTEGER,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_templates_category ON email_templates(category);

CREATE TABLE IF NOT EXISTS email_template_routes (
    id TEXT PRIMARY KEY,
    template_id TEXT REFERENCES email_templates(id) ON DELETE CASCADE,
    category TEXT,
    provider_id TEXT NOT NULL REFERENCES email_providers(id),
    priority INTEGER NOT NULL,
    retry_limit_override INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    CHECK (template_id IS NOT NULL OR category IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_email_template_routes_template ON email_template_routes(template_id);
CREATE INDEX IF NOT EXISTS idx_email_template_routes_category ON email_template_routes(category);

CREATE TABLE IF NOT EXISTS email_messages (
    id TEXT PRIMARY KEY,
    template_id TEXT REFERENCES email_templates(id),
    provider_id TEXT REFERENCES email_providers(id),
    to_address TEXT NOT NULL,
    cc TEXT,
    bcc TEXT,
    subject TEXT NOT NULL,
    rendered_html TEXT,
    rendered_text TEXT,
    variables TEXT,
    metadata TEXT,
    status TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    failover_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_attempt_at TIMESTAMP,
    last_attempt_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_messages_status_next_attempt ON email_messages(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_email_messages_template ON email_messages(template_id);

CREATE TABLE IF NOT EXISTS email_events (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL REFERENCES email_providers(id),
    event_type TEXT NOT NULL,
    payload TEXT,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_events_message_id ON email_events(message_id);

COMMIT;
```

Backfill guidance:

- Seed at least one provider row after the migration (for example, a SendGrid API key or a debug console adapter) and mark it `is_default = 1` so new templates can inherit it automatically.
- Define templates and optional routes through the admin API or by inserting directly into `email_templates` / `email_template_routes` so your worker has content to render.
- Restart the licensing server to ensure the email queue worker can pick up pending messages once the schema exists.
