# Licensing Server & Client Usage Guide

This document walks through everything you need to operate the licensing server, integrate the client runner, and test full activation flows. Each section contains runnable commands plus explanations of why the step matters.

## Prerequisites

- Go 1.21 or newer
- macOS, Linux, or Windows host (server can run headless, client fingerprinting works on all three)
- TLS certificates for production deployments (self-signed is acceptable for local testing)
- `curl` or HTTP client of your choice for calling the admin API

---

## 10-Minute Local Quickstart

1. **Install dependencies**
   ```bash
   go mod tidy
   ```
2. **Start the server (development mode allows HTTP):**
   ```bash
   export LICENSE_SERVER_API_KEY="dev-admin-key"
   export LICENSE_SERVER_ALLOW_INSECURE_HTTP=1
   go run ./cmd/server --http-addr :8801 --allow-insecure-http
   ```
   On first boot the server prints a bootstrap admin user, API key, and where it stored the signing public key (`~/.licensing/server_public_key.pem`).
3. **Create a client record:**
   ```bash
   curl -sSL -X POST http://localhost:8801/api/clients \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: dev-admin-key' \
     -d '{"email":"owner@example.com"}'
   ```
   Note the returned `id`; you will reference it when creating a license.
4. **Issue a license with a plan + check policy:**
   ```bash
   curl -sSL -X POST http://localhost:8801/api/licenses \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: dev-admin-key' \
     -d '{
       "client_id": "<CLIENT_ID>",
       "duration_days": 365,
       "max_devices": 3,
       "plan_slug": "enterprise",
       "check_mode": "custom",
       "check_interval_seconds": 21600
     }'
   ```
   Copy the `license_key` from the response.
5. **Seed activation data for the CLI:**
   ```bash
   cat > activation.json <<'JSON'
   {
     "email": "owner@example.com",
     "client_id": "client-owner",
     "license_key": "PASTE-LICENSE-KEY"
   }
   JSON
   ```
6. **Run the client and wrap demo app:**
   ```bash
   go run ./client \
     --activation-mode auto \
     --server-url http://localhost:8801 \
     --license-file ./activation.json
   ```
   After activation the helper HTTP server (`client/app.go`) listens on `http://localhost:8081` and returns the decrypted license payload (including `plan_slug`, check metadata, and `subject_client_id`).

---

## Server Operations

### Configuration Overview

| Setting | Description | Default |
| --- | --- | --- |
| `LICENSE_SERVER_API_KEY` / `LICENSE_SERVER_API_KEYS` | Comma-separated legacy admin API keys accepted via `X-API-Key`. | None |
| `LICENSE_SERVER_STORAGE` | `sqlite` (default), `memory`, or `file`. | `sqlite` |
| `LICENSE_SERVER_STORAGE_SQLITE_PATH` | Path to SQLite DB when `sqlite` backend is used. | `./data/licensing.db` |
| `LICENSE_SERVER_STORAGE_FILE` | JSON snapshot path when using `file` backend. | `./data/licensing-state.json` |
| `LICENSE_SERVER_TLS_CERT` / `LICENSE_SERVER_TLS_KEY` | Enables HTTPS when both are present. | Disabled |
| `LICENSE_SERVER_CLIENT_CA` | PEM bundle required for mutual TLS clients. | Disabled |
| `LICENSE_SERVER_ALLOW_INSECURE_HTTP` | Set to `1` only for local HTTP testing. | `false` |
| `LICENSE_SERVER_KEY_PROVIDER` | `software`, `file`, or `tpm`. | `software` |
| `LICENSE_SERVER_KEY_FILE` / `LICENSE_SERVER_KEY_PASSPHRASE` | Location + password for file-based signing keys. | — |
| `LICENSE_SERVER_TPM_DEVICE` | Device path for TPM provider. | `/dev/tpmrm0` |
| `LICENSE_SERVER_DEFAULT_CHECK_MODE` | Applied when new licenses omit `check_mode`. | `yearly` |
| `LICENSE_SERVER_DEFAULT_CHECK_INTERVAL` | Go duration string used when default mode is `custom`. | — |
| `LICENSE_SERVER_BOOTSTRAP_DEMO` | `true` seeds demo clients/licenses on startup. | `false` |

### Default Check Policy & Backfill

`cmd/server` reads the default check policy from the environment and immediately applies it to every new license. On startup it also runs `BackfillLicenseCheckPolicy`, which upgrades existing records that were missing the new cadence fields. Use this to roll out global policy changes:

```bash
export LICENSE_SERVER_DEFAULT_CHECK_MODE="monthly"
export LICENSE_SERVER_DEFAULT_CHECK_INTERVAL="720h"   # only used when mode=custom
```

### Demo Data

Set `LICENSE_SERVER_BOOTSTRAP_DEMO=true` before launching the server to automatically create three sample clients (`starter`, `standard`, `enterprise`). Each license uses the current default check policy so you can test various plans immediately.

### Admin Authentication

- **Legacy API key header:** supply `X-API-Key: <token>` on every HTTP request. Keys come from `LICENSE_SERVER_API_KEY` or `LICENSE_SERVER_API_KEYS`.
- **Bootstrap admin user:** the server prints credentials the first time it runs so you can log in via any future UI. Rotate the password and API key immediately in production.

### Signing Providers

The License Manager signs every activation payload. Choose one of:

1. `software` (default): in-memory RSA key generated on boot.
2. `file`: reference your own PEM private key via `LICENSE_SERVER_KEY_FILE`.
3. `tpm`: sign inside a TPM 2.0 device; point `LICENSE_SERVER_TPM_DEVICE` at the TPM resource manager.

Regardless of provider, the server exports the public key to `~/.licensing/server_public_key.pem`. Clients verify signatures using the embedded copy inside each activation response.

### Storage Backends

Switch backends without code changes:

```bash
# In-memory (ephemeral)
export LICENSE_SERVER_STORAGE=memory

# JSON-on-disk snapshot
export LICENSE_SERVER_STORAGE=file
export LICENSE_SERVER_STORAGE_FILE=/var/lib/licensing/state.json

# SQLite (default)
export LICENSE_SERVER_STORAGE=sqlite
export LICENSE_SERVER_STORAGE_SQLITE_PATH=/var/lib/licensing/licensing.db
```

Consult `docs/sqlite_migration.md` before upgrading schemas in production.

---

## Admin API Cookbook

All endpoints live under `http(s)://<host>:<port>/api`. Supply `X-API-Key` unless you switch to authenticated admin users.

### Create a Client
```bash
curl -X POST "$BASE/api/clients" \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $ADMIN_KEY" \
  -d '{"email":"owner@example.com"}'
```

### List Clients
```bash
curl -X GET "$BASE/api/clients" -H "X-API-Key: $ADMIN_KEY"
```

### Issue a License
```bash
curl -X POST "$BASE/api/licenses" \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $ADMIN_KEY" \
  -d '{
    "client_id": "client-123",
    "duration_days": 90,
    "max_devices": 5,
    "plan_slug": "pro",
    "check_mode": "yearly"
  }'
```
`plan_slug` is mandatory. The request optionally includes `check_interval_seconds` when `check_mode` equals `custom`.

### Revoke or Reinstate
```bash
curl -X POST "$BASE/api/licenses/<LICENSE_ID>/revoke" \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $ADMIN_KEY" \
  -d '{"reason":"chargeback"}'

curl -X POST "$BASE/api/licenses/<LICENSE_ID>/reinstate" \
  -H 'X-API-Key: $ADMIN_KEY'
```

### Ban / Unban a Client
```bash
curl -X POST "$BASE/api/clients/<CLIENT_ID>/ban" \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $ADMIN_KEY" \
  -d '{"reason":"abuse"}'

curl -X POST "$BASE/api/clients/<CLIENT_ID>/unban" \
  -H "X-API-Key: $ADMIN_KEY"
```

### Health Check
```bash
curl -k "$BASE/health"
```
Responds with `200 OK` when the server is ready to accept requests.

---

## Client Operations

Run the CLI directly (`go run ./client`) or build a static binary. Configuration flows from **flags → environment variables → built-ins**.

### Flag & Environment Reference

| Flag | Environment | Purpose |
| --- | --- | --- |
| `--activation-mode` | — | `auto`, `env`, `prompt`, or `verify`. |
| `--config-dir` | `LICENSE_CLIENT_CONFIG_DIR` | Directory that holds the encrypted license (`~/.licensing` default). |
| `--license-store` | `LICENSE_CLIENT_LICENSE_FILE` | File name under the config dir (`.license.dat` default). |
| `--license-file` | — | JSON file containing `email`, `client_id`, `license_key`. |
| `--server-url` | `LICENSE_CLIENT_SERVER` | Server base URL. HTTPS is required unless `--allow-insecure-http`. |
| `--http-timeout` | `LICENSE_CLIENT_HTTP_TIMEOUT` | Go duration string (e.g. `30s`). |
| `--ca-cert` | `LICENSE_CLIENT_CA_CERT` | Additional CA bundle path. |
| `--allow-insecure-http` | `LICENSE_CLIENT_ALLOW_INSECURE_HTTP` | Accept HTTP + skip TLS verification (local testing). |
| `--exec` / `--` | `LICENSE_CLIENT_EXEC` | Command to run after successful verification. |

Additional activation env vars:

- `LICENSE_CLIENT_EMAIL`
- `LICENSE_CLIENT_LICENSE_KEY`
- `LICENSE_CLIENT_ID` (always required for env-based activation)

### Activation Strategies

| Mode | Description | Example |
| --- | --- | --- |
| `auto` | Verify existing licenses, attempt env-based activation, finally prompt interactively. | `go run ./client --activation-mode auto` |
| `env` | Uses environment variables exclusively. Fails if any field missing. | `LICENSE_CLIENT_EMAIL=john@example.com LICENSE_CLIENT_ID=client-john LICENSE_CLIENT_LICENSE_KEY=KEY go run ./client --activation-mode env` |
| `prompt` | Forces prompts even if env/JSON data exists. | `go run ./client --activation-mode prompt --server-url https://licensing.example.com` |
| `verify` | Only verifies existing license files; never activates or runs wrapped commands. | `go run ./client --activation-mode verify --config-dir /var/lib/myapp-licenses` |

### Wrapping Your Application

Supply a command after `--` or via `--exec` so your app only runs when licensing succeeds:

```bash
# Using --exec
LICENSE_CLIENT_SERVER=https://licensing.example.com \
  go run ./client --exec "./bin/my-app --serve"

# Using -- to forward arbitrary args
go run ./client -- -- ./bin/my-app --serve --port 9000
```

During execution the CLI exposes these environment variables for your process:

- `LICENSED_USER`, `LICENSED_EMAIL`, `LICENSE_ID`
- `LICENSE_CLIENT_ID`, `LICENSE_DEVICE_FINGERPRINT`
- `LICENSE_PLAN_SLUG`
- `LICENSE_EXPIRES_AT`
- `LICENSE_DATA_JSON` (entire decrypted payload)

### Background Verification (Custom Mode)

When a license uses `check_mode"custom"`, the helper client (`client/app.go`) automatically starts `RunBackgroundVerification`. It refreshes the cached license based on `check_interval_seconds` and updates the embedded HTTP server so you can watch changes live.

---

## Scenario Playbooks

### 1. SaaS Production rollout
1. Issue TLS certificates and store them in `/etc/ssl/licensing`.
2. Configure environment:
   ```bash
   export LICENSE_SERVER_TLS_CERT=/etc/ssl/licensing/server.crt
   export LICENSE_SERVER_TLS_KEY=/etc/ssl/licensing/server.key
   export LICENSE_SERVER_CLIENT_CA=/etc/ssl/licensing/custom-clients.pem
   export LICENSE_SERVER_DEFAULT_CHECK_MODE=monthly
   export LICENSE_SERVER_API_KEYS="admin-prod-key"
   ```
3. Deploy `go run ./cmd/server --http-addr :443`.
4. Use CI to call `/api/licenses` with `plan_slug` per tier.
5. Distribute the client binary with `LICENSE_CLIENT_SERVER=https://licensing.example.com` baked in.

### 2. Offline-first appliance
1. Activate once while connected using `--activation-mode env`.
2. Persist the encrypted license to a secure volume.
3. On each boot run `go run ./client --activation-mode verify --config-dir /mnt/license`.
4. If the server becomes reachable, switch back to `auto` so scheduled checks resume.

### 3. Reseller / Delegated activations
1. Provider issues the license normally and shares the key with downstream customer.
2. Customer sets `LICENSE_CLIENT_EMAIL=<customer>` and `LICENSE_CLIENT_ID=<their-id>`.
3. Server records `subject_client_id` separately from the original purchaser.
4. Your wrapped app inspects `LICENSE_DATA_JSON` to see `client_id`, `subject_client_id`, and `plan_slug` for entitlement decisions.

### 4. Custom interval with background checks
1. Create licenses with `"check_mode":"custom"` and `"check_interval_seconds":7200`.
2. Clients run `go run ./client --activation-mode auto --server-url https://...`.
3. `client/app.go` spawns the background verifier so long-running daemons stay up-to-date without restarting.
4. Inspect logs or hit `http://localhost:8081` to confirm `next_check_at` moves forward after each contact.

---

## Troubleshooting Cheatsheet

| Symptom | Fix |
| --- | --- |
| `license not found - please activate first` | Run the client once with `auto`, `env`, or `prompt` to generate the encrypted license file. |
| `license file ... has insecure permissions` | Restrict permissions: `chmod 600 ~/.licensing/.license.dat`. |
| `license revoked` / `client banned` | Reinstate via the admin API (`/api/licenses/{id}/reinstate` or `/api/clients/{id}/unban`). |
| TLS failures during development | Either trust the server certificate via `--ca-cert` or set `--allow-insecure-http` (test only). |
| Invalid custom check interval | Ensure `LICENSE_SERVER_DEFAULT_CHECK_INTERVAL` and request payloads use valid Go duration strings or positive integers for seconds. |

---

## Next Steps

- See `README.md` for architectural details and feature lists.
- Review `docs/sqlite_migration.md` before upgrading production SQLite databases.
- Run `go test ./...` whenever you modify the licensing logic.
