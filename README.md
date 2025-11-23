# TPM License Manager

A hardened license server and client that leverage TPM-backed signing, per-device activation, and encrypted transport to keep software licenses tamper resistant.

## Features

- **TPM-backed signing:** every activation payload is signed by a TPM-generated RSA key whose public half is exported once to `~/.licensing/server_public_key.pem` with `0600` permissions.
- **Per-device locking:** activations require a deterministic device fingerprint and are bounded by `max_activations` per license.
- **Encrypted license transport:** licenses are encrypted with AES-GCM using a key derived from the device fingerprint and nonce before being stored client-side.
- **Integrity-bound checksum:** the client seals a SHA-256 checksum of the on-disk license blob using the device fingerprint so tampering attempts are detected before parsing, and it re-validates with the server before recreating a lost checksum.
- **Session-keyed channel:** once activated, each device receives a unique transport key embedded inside the license payload, and subsequent HTTP traffic is re-encrypted with that key so no pre-shared secrets are required beyond TLS.
- **Audit + admin APIs:** rate-limited HTTP endpoints for managing clients, issuing licenses, banning/unbanning, and revoking/reinstating licenses.
- **Pluggable storage:** choose in-memory or JSON-on-disk storage via environment variables; disk snapshots are written atomically with `0600` permissions.
- **Secure client storage:** the CLI enforces `chmod 600` on `~/.myapp/.license.dat`, verifies TPM signatures, and refuses to run if the payload or fingerprint diverge.

## Requirements

- Go 1.21+
- macOS, Linux, or Windows (server can run headless; client fingerprint helpers cover all three platforms)

## Server Setup

1. **Install dependencies:**
   ```bash
   go mod tidy
   ```
2. **Configure environment:**
   ```bash
   export LICENSE_SERVER_API_KEY="super-secret-admin-key"
   # Optional comma-separated list alternative:
   # export LICENSE_SERVER_API_KEYS="key-one,key-two"

   # Storage backend: "memory" (default) or "file"
   export LICENSE_SERVER_STORAGE="file"
   # When using file storage the server persists to this path (default: ./data/licensing-state.json)
   export LICENSE_SERVER_STORAGE_FILE="/var/lib/licensing/state.json"

   # TLS (optional but recommended)
   export LICENSE_SERVER_TLS_CERT="/path/to/server.crt"
   export LICENSE_SERVER_TLS_KEY="/path/to/server.key"
   # Enable mutual TLS by providing a client CA bundle
   export LICENSE_SERVER_CLIENT_CA="/path/to/clients.pem"
   ```
3. **Run the server:**
   ```bash
   go run .
   ```
   On startup the server logs the active storage backend, TLS mode, and the location of the exported public key (`~/.licensing/server_public_key.pem`).
4. **Use the admin APIs:** include `X-API-Key: <key>` when calling `/api/clients`, `/api/licenses`, `/api/licenses/{id}/revoke`, etc.

## Client Setup

1. **(Optional) Point to a remote server:**
   ```bash
   export LICENSE_CLIENT_SERVER="https://licensing.example.com"
   ```
   Defaults to `http://localhost:8080`.
2. **Run the client:**
   ```bash
   go run ./client
   ```
   The CLI will display the server it will contact, prompt for the license credentials, and persist the encrypted payload to `~/.myapp/.license.dat` with `0600` permissions.
3. **Verification:** subsequent runs skip activation, verify the TPM signature, confirm the encrypted payload matches the current device fingerprint, and refuse to continue if the license is revoked or expired.

### Client Configuration Options

The CLI layers configuration in the following order: command-line flags → environment variables → baked-in defaults. This lets you keep sane defaults for local development while still overriding any field in CI/CD pipelines or packaged binaries.

| Flag | Env Var | Description | Default |
| --- | --- | --- | --- |
| `--activation-mode` | — | Chooses the activation strategy (`auto`, `env`, `prompt`, `verify`). | `auto` |
| `--config-dir` | `LICENSE_CLIENT_CONFIG_DIR` | Directory that stores the encrypted license payload. | `$HOME/.myapp` |
| `--license-file` | `LICENSE_CLIENT_LICENSE_FILE` | File name (placed under `config-dir`) for the encrypted license blob. | `.license.dat` |
| `--server-url` | `LICENSE_CLIENT_SERVER` | Licensing server base URL. | `http://localhost:8080` |
| `--http-timeout` | `LICENSE_CLIENT_HTTP_TIMEOUT` | HTTP client timeout (Go duration, e.g. `20s`, `1m`). | `15s` |
| `--exec` or args after `--` | `LICENSE_CLIENT_EXEC` | Command to run once the license is verified (quote the flag value or place the command after `--`). | — |

Example:

```bash
LICENSE_CLIENT_CONFIG_DIR=/var/lib/myapp-licenses \
LICENSE_CLIENT_LICENSE_FILE=myapp.lic \
go run ./client --server-url https://licensing.example.com --http-timeout 20s
```

### Wrapping Your Application

The CLI is intentionally minimal so it can wrap any binary or script once licensing succeeds. Supply the command either with the `--exec` flag or by appending it after `--`:

```bash
go run ./client --activation-mode auto -- ./bin/my-app --serve --port 9000
# or
go run ./client --exec "./bin/my-app --serve --port 9000"
```

When a command is provided the client performs activation/verification and then launches it with stdin/stdout/stderr attached. The child process receives these environment variables so it can inspect license metadata without re-reading disk:

- `LICENSED_USER`, `LICENSED_EMAIL`, `LICENSE_ID`
- `LICENSE_CLIENT_ID`, `LICENSE_DEVICE_FINGERPRINT`
- `LICENSE_EXPIRES_AT` (RFC3339 timestamp)
- `LICENSE_DATA_JSON` (entire license payload)

If you omit the wrapped command the client simply verifies the license and exits successfully. `verify` mode always skips the wrapped command even if one is provided, which is useful for boot checks or CI probes.

### Activation Strategies

| Mode | Flow | When to use |
| --- | --- | --- |
| `auto` | Runs verification if a license already exists. Otherwise attempts environment activation, falling back to the interactive prompt. | Production defaults where you want non-interactive first, but still allow manual entry. |
| `env` | Requires `LICENSE_CLIENT_EMAIL`, `LICENSE_CLIENT_USERNAME`, and `LICENSE_CLIENT_LICENSE_KEY`. Fails fast if any field is missing. | Headless containers/CI that receive license secrets via env/secret stores. |
| `prompt` | Always prompt for email/username/license key in the terminal. | Local development, demos, or manual activation scripts. |
| `verify` | Only verifies an already-activated license; never prompts, uses env credentials, or runs the wrapped command. | Hardened production startups where activations happen during image build time. |

### Exercising Each Mode

Use the new flags to test every path without touching code:

1. **Auto (default layering demo):**
   ```bash
   go run ./client \
     --activation-mode auto \
     --config-dir /tmp/myapp-licenses \
     --license-file demo.lic \
     --server-url http://localhost:8080
   ```
   Verifies existing licenses, tries environment activation, then prompts as a last resort.

2. **Environment activation:**
   ```bash
   export LICENSE_CLIENT_EMAIL=john@example.com
   export LICENSE_CLIENT_USERNAME=john
   export LICENSE_CLIENT_LICENSE_KEY=ABCDE-12345-FGHIJ-67890
   go run ./client --activation-mode env --http-timeout 25s
   ```
   Confirms that non-interactive activation succeeds (or fails with a descriptive error if credentials are wrong).

3. **Interactive prompt:**
   ```bash
   go run ./client --activation-mode prompt --server-url https://licensing.example.com
   ```
   Forces the CLI to ask for credentials even if env vars are present, useful for support/debugging.

4. **Verification-only:**
   ```bash
   go run ./client --activation-mode verify --config-dir /tmp/myapp-licenses
   ```
   Ensures the runner aborts if the license file is missing or tampered with, mimicking production boot checks.

Each command honors the layered config above, so you can mix flags and env vars to mimic the environments where your application will ship.

## How Server & Client Communicate

1. The client derives a stable device fingerprint (hostname, OS, CPU brand, and MAC hash) and posts it with the license key to `/api/activate`.
2. The server validates the request (API rate limit, client ban status, license quotas) before encrypting `[random 32-byte transport key || license JSON]` with AES-GCM using a key derived from the device fingerprint + nonce.
3. The ciphertext is signed by the TPM key and returned together with the PEM-encoded public key and expiration metadata.
4. The client verifies the signature, derives the same transport key, decrypts the payload, persists it, and caches the transport key for future HTTPS payload encryption.
5. Subsequent client requests and server responses are re-encrypted with that cached transport key (and identify themselves via headers) so plaintext never crosses process boundaries even if TLS terminates upstream.
6. Every launch replays those checks, enforces file permissions, and prints detailed device + activation telemetry.

## Tamper-Resistance Guidelines

- **Public key hygiene:** the server writes `server_public_key.pem` only inside `~/.licensing/` with permissions `0700/0600`. Delete the file if you rotate TPM keys; it will be re-created on next start.
- **Client license file:** if the CLI detects that `~/.myapp/.license.dat` is world-readable it aborts with instructions to `chmod 600`.
- **Detached checksum vault:** every activation records an encrypted checksum next to the license file; if it goes missing the client recontacts the server to reissue the license before recreating the checksum, and it still aborts if the checksum diverges.
- **Signatures first:** both activation time and runtime verification fail fast if the TPM signature or ciphertext hash mismatches.
- **Device binding:** moving the license file to a different machine fails because the fingerprint becomes invalid and the transport key cannot be recreated.
- **Admin controls:** revoke or ban clients to immediately block further activations; reinstating can be done via the admin endpoints without server restarts.

## Testing

- Run the full build:
  ```bash
  go build ./...
  ```
- Exercise the client end-to-end:
  ```bash
  go run ./client
  ```
- Hit the health probe:
  ```bash
  curl -k https://localhost:8080/health
  ```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `license not found - please activate first` | Run the client and complete activation; ensure `~/.myapp/` exists. |
| `license file ... has insecure permissions` | Run `chmod 600 ~/.myapp/.license.dat` (Unix hosts). |
| `license server responded 401` | Set `LICENSE_SERVER_API_KEY` on the server or provide the correct admin key in your request. |
| `license revoked` / `client banned` | Use the admin API to reinstate the license or client once the issue is resolved. |
| TLS errors when running locally | Either disable TLS env vars during local testing or trust the self-signed certificate from the server. |

## Directory Layout

```
go.mod              # module definition
licensing.go        # entry point + wiring
license_manager.go  # core business logic + TPM integration
server.go           # HTTP handlers, security middleware
storage.go          # in-memory + persistent storage backends
client/app.go       # CLI activation + runtime verification
README.md           # this file
```
