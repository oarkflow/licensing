# Compliance Operations Runbook (Single-Tenant)

This runbook defines minimum operational controls for compliance-heavy production deployments of the licensing server.

## 1. Required Runtime Settings

Set the following in production:

```bash
export APP_ENV=production
export LICENSE_SERVER_ALLOW_INSECURE_HTTP=false
export LICENSE_SERVER_AUDIT_ENABLED=true
export LICENSE_SERVER_STORAGE=sqlite
export LICENSE_SERVER_STORAGE_SQLITE_PATH=/data/licensing.db
export LICENSE_SERVER_TLS_CERT=/certs/tls.crt
export LICENSE_SERVER_TLS_KEY=/certs/tls.key
export LICENSE_SERVER_KEY_PROVIDER=file
export LICENSE_SERVER_KEY_FILE=/certs/signing.key
```

Notes:
- In production, the server now rejects insecure HTTP and requires TLS cert/key.
- In production, memory storage and software signing keys are blocked unless explicitly overridden.
- In production, audit logging cannot be disabled.

## 2. Audit Evidence

Audit endpoints (admin-authenticated):
- `GET /api/admin/audit`
- `GET /api/admin/audit/compliance?framework=SOC2&days=30`

Recommended monthly evidence exports:
1. Raw events from `/api/admin/audit?limit=5000`.
2. Compliance report from `/api/admin/audit/compliance?framework=SOC2&days=30`.
3. Store exports in immutable object storage with restricted access.

## 3. Backup and Restore Controls

Daily backup (example cron):

```bash
scripts/backup_sqlite.sh /data/licensing.db /backups/licensing
```

Quarterly restore drill:

```bash
scripts/restore_sqlite_verify.sh /backups/licensing/licensing.db.<timestamp>.bak /tmp/restore/licensing.db
```

After restore, run smoke checks:
1. `/health`
2. Admin login/setup path
3. One read-only API (`GET /api/clients`)

## 4. Rotation Policy

- API keys: rotate every 90 days.
- Signing keys: rotate every 90 days (or policy-mandated interval).
- TLS certificates: renew before expiry and test reload/restart in staging.

## 5. Monitoring and Alerts

If metrics are enabled (`LICENSE_SERVER_METRICS_ENABLED=true`), scrape:
- `/metrics`

Alerting minimum:
1. sustained 5xx responses
2. repeated unauthorized requests (4xx surge)
3. service unavailability (`/health` failures)

## 6. Change and Access Control

- Require pull-request approval for all production code changes.
- Keep CI security checks required (`go test`, `go vet`, `govulncheck`, `gosec`).
- Restrict production shell/database access to approved operators only.

## 7. Incident Retention

- Retain audit logs and backups per your compliance window (commonly 1-7 years depending on policy).
- Preserve incident timelines with audit report export IDs and timestamps.
