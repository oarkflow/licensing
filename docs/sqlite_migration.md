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

Next, recreate demo data or import clients through the admin APIs.

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
    max_activations INTEGER NOT NULL,
    current_activations INTEGER NOT NULL,
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
    max_activations,
    current_activations
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
    max_activations,
    current_activations
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
