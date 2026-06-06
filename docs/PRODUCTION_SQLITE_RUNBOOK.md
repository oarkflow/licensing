# Production SQLite Runbook

This server supports a hardened single-node SQLite production baseline. SQLite is not an active-active multi-writer HA backend. Run one writer process, use durable mounted storage, and rely on restart, backups, restore drills, and audit verification for operational resilience.

## Startup Checks

Before deployment, validate configuration without binding HTTP:

```bash
APP_ENV=production licensing-server check-config
```

Production requires either local TLS or explicit TLS termination by NPM/reverse proxy:

- `LICENSE_SERVER_STORAGE=sqlite`
- absolute `LICENSE_SERVER_STORAGE_SQLITE_PATH`
- local TLS cert/key paths, or `LICENSE_SERVER_TLS_TERMINATED_BY_PROXY=true` with `LICENSE_SERVER_ALLOW_INSECURE_HTTP=true`
- audit enabled
- non-software signing keys unless explicitly allowed for break-glass testing
- stored scoped API keys for automation; legacy env API keys require `LICENSE_SERVER_ALLOW_LEGACY_ENV_KEYS_IN_PROD=true`

When running behind Nginx Proxy Manager, terminate HTTPS at NPM and forward to the server over a private/local network. Configure NPM to send `X-Forwarded-Proto: https`; the server uses that header to mark cookies secure on proxied HTTPS requests.

Recommended NPM target for the local single-node profile:

```text
Forward scheme: http
Forward hostname/IP: 127.0.0.1
Forward port: 6601
Websockets support: off unless separately needed
Block common exploits: on
Force SSL: on at the NPM host
```

## Local Single-Node Runtime

For a local single-node production-like runtime behind NPM, prepare generated local signing material, SQLite paths, backup paths, and `.env.single-node`:

```bash
make single-node-prepare
```

This creates:

- `.env.single-node`
- `runtime/single-node/data/licensing.db`
- `runtime/single-node/data/audit.db`
- `runtime/single-node/backups`
- `runtime/single-node/keys/signing.pem`

Run the server locally:

```bash
make single-node-run
```

Validate configuration:

```bash
make single-node-check
```

Create a local online backup:

```bash
make single-node-backup
```

Run the local rehearsal checklist:

```bash
make single-node-rehearse
```

The generated signing key is a local operator fixture. Replace it with managed production secrets before sending a customer deployment. TLS should terminate at NPM for this local single-node profile.

## Container Device Identity

Distribution builds use the same device-proof licensing model as client SDKs.
For Docker, keep the cached distribution license and device proof key on a
persistent mounted volume:

```text
LICENSE_SERVER_DISTRIBUTION_CONFIG_DIR=/data/.licensing
LICENSE_SERVER_DISTRIBUTION_DEVICE_KEY_FILE=/data/.licensing/device_ed25519.pem
```

The production compose file mounts `/data`, so stopping, removing, and recreating
the container keeps the same fingerprint and does not consume another device
activation. If you intentionally run multiple independent containers for the
same customer, give each container its own persistent licensing volume and size
`max_devices` accordingly.

## Migrations And Seeds

Use the migrator as the operator path:

```bash
make migrate
make migrate-status
```

Optional catalog fixtures live under `migrations/seeds/*.sql` and are never run by server startup:

```bash
make seed-catalog
```

Keep runtime schema auto-ensure only for compatibility. Production deployments should run migrations before starting the service.

## Backups

Default target:

- daily backups
- 7 daily and 4 weekly retained by operator policy
- monthly restore drill
- RPO: 24 hours
- RTO: 2 hours for single-node restore

Create an online SQLite backup:

```bash
make backup-sqlite SQLITE_DB=/data/licensing.db BACKUP_DIR=/backups
```

The script uses SQLite `.backup`, verifies `PRAGMA integrity_check`, writes a SHA-256 checksum, and updates `LICENSE_SERVER_BACKUP_MARKER_FILE` when configured.

For systemd hosts, adapt and install:

- `deploy/systemd/licensing-backup.service`
- `deploy/systemd/licensing-backup.timer`

Enable with:

```bash
systemctl enable --now licensing-backup.timer
```

## Restore Verification

Stop the service before replacing the live database, then verify:

```bash
make restore-sqlite-verify BACKUP_FILE=/backups/licensing.db.20260606T000000Z.bak SQLITE_DB=/data/licensing.db
```

After restarting the service, verify health:

```bash
make restore-sqlite-verify BACKUP_FILE=/backups/licensing.db.20260606T000000Z.bak SQLITE_DB=/data/licensing.db RESTORE_HEALTH_URL=http://127.0.0.1:6601/health
```

## Audit And Compliance

Audit logging should remain enabled in production. Operators can verify the hash chain through the secured endpoint:

```bash
curl -k -H "X-API-Key: <stored-scoped-admin-key>" https://127.0.0.1:6601/api/admin/audit/verify
```

For the local NPM profile, use the public HTTPS hostname managed by NPM for this
endpoint, or call the loopback HTTP address directly from the host:

```bash
curl -H "X-API-Key: <stored-scoped-admin-key>" http://127.0.0.1:6601/api/admin/audit/verify
```

Or locally, without binding HTTP:

```bash
licensing-server audit-verify --audit-db=/data/audit.db
```

Compliance reports remain available at `/api/admin/audit/compliance`.

## Email Queue

Subscription and provision flows attempt immediate SMTP delivery when requested. If SMTP delivery fails, the rendered email is stored in the email queue with attachments, including `license.json` for license credential emails.

The server runs an email queue worker by default. Configure it with:

- `LICENSE_SERVER_EMAIL_QUEUE_ENABLED`
- `LICENSE_SERVER_EMAIL_QUEUE_POLL_INTERVAL`
- `LICENSE_SERVER_EMAIL_QUEUE_MAX_PER_TICK`
- `LICENSE_SERVER_EMAIL_QUEUE_MAX_RETRY_DELAY`

Configure an SMTP provider before relying on automatic delivery, and monitor queued/failed email rows as part of operational checks.

## Rate Limits And Metrics

Rate limits are per process for the SQLite baseline:

- `LICENSE_SERVER_RATE_LIMIT_DEFAULT`
- `LICENSE_SERVER_RATE_LIMIT_ADMIN`
- `LICENSE_SERVER_RATE_LIMIT_ACTIVATION`
- `LICENSE_SERVER_RATE_LIMIT_VERIFICATION`
- `LICENSE_SERVER_RATE_LIMIT_CLIENT_AUTH`
- `LICENSE_SERVER_RATE_LIMIT_WINDOW`

Metrics include HTTP totals, rate-limit hits, audit write failures, activation/verification counts, SQLite health, and backup marker timestamp when available.

Use `deploy/prometheus/licensing-server.yml` as a starting scrape config. Wire alerts for:

- `licensing_audit_write_failures_total > 0`
- `licensing_sqlite_health_ok == 0`
- stale `licensing_sqlite_backup_last_success_timestamp_seconds`
- sustained rate-limit hits above expected baseline
- queued email failures above zero

## Production Rehearsal

Before customer deployment, run the rehearsal checklist against the target host:

```bash
APP_ENV=production \
SQLITE_DB=/data/licensing.db \
BACKUP_DIR=/backups \
AUDIT_DB=/data/audit.db \
HEALTH_URL=http://127.0.0.1:6601/health \
LICENSING_SERVER_BIN=/usr/local/bin/licensing-server \
scripts/production_rehearsal.sh
```

Record the operator, timestamp, target host, backup file, restore verification result, audit verification result, and any deviations.
