#!/usr/bin/env bash
set -euo pipefail

# Prepares a local single-node production-like SQLite runtime.
# It creates local-only signing material, writes .env.single-node, creates the
# SQLite files, runs migrations, and validates startup config without binding HTTP.
# TLS is expected to terminate at NPM/Nginx Proxy Manager or another reverse proxy.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${LOCAL_SINGLE_NODE_DIR:-$ROOT_DIR/runtime/single-node}"
ENV_FILE="${LOCAL_SINGLE_NODE_ENV:-$ROOT_DIR/.env.single-node}"
FORCE="${FORCE:-false}"

for bin in openssl sqlite3 migrator go; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "error: required command not found: $bin"
    exit 1
  fi
done

mkdir -p "$RUNTIME_DIR"/{data,backups,keys,logs}
mkdir -p "$RUNTIME_DIR/go-build-cache"
chmod 700 "$RUNTIME_DIR" "$RUNTIME_DIR/data" "$RUNTIME_DIR/backups" "$RUNTIME_DIR/keys" "$RUNTIME_DIR/logs" "$RUNTIME_DIR/go-build-cache"

signing_key="$RUNTIME_DIR/keys/signing.pem"

if [[ "$FORCE" == "true" || ! -f "$signing_key" ]]; then
  openssl genrsa -out "$signing_key" 3072
  chmod 600 "$signing_key"
fi

cat > "$ENV_FILE" <<EOF
APP_ENV=production
LICENSE_SERVER_HTTP_ADDR=127.0.0.1:6601
LICENSE_SERVER_ALLOW_INSECURE_HTTP=true
LICENSE_SERVER_TLS_TERMINATED_BY_PROXY=true
LICENSE_SERVER_STORAGE=sqlite
LICENSE_SERVER_STORAGE_SQLITE_PATH=$RUNTIME_DIR/data/licensing.db
LICENSE_SERVER_AUDIT_ENABLED=true
LICENSE_SERVER_AUDIT_DB_PATH=$RUNTIME_DIR/data/audit.db
LICENSE_SERVER_BACKUP_MARKER_FILE=$RUNTIME_DIR/backups/latest.json
LICENSE_SERVER_KEY_PROVIDER=file
LICENSE_SERVER_KEY_FILE=$signing_key
LICENSE_SERVER_METRICS_ENABLED=true
LICENSE_SERVER_EMAIL_QUEUE_ENABLED=true
LICENSE_SERVER_EMAIL_QUEUE_POLL_INTERVAL=15s
LICENSE_SERVER_EMAIL_QUEUE_MAX_PER_TICK=10
LICENSE_SERVER_EMAIL_QUEUE_MAX_RETRY_DELAY=30m
LICENSE_SERVER_RATE_LIMIT_DEFAULT=30
LICENSE_SERVER_RATE_LIMIT_ADMIN=300
LICENSE_SERVER_RATE_LIMIT_ACTIVATION=30
LICENSE_SERVER_RATE_LIMIT_VERIFICATION=60
LICENSE_SERVER_RATE_LIMIT_CLIENT_AUTH=30
LICENSE_SERVER_RATE_LIMIT_WINDOW=1m
EOF
chmod 600 "$ENV_FILE"

cat > "$RUNTIME_DIR/migrate.json" <<EOF
{
  "database": {
    "charset": "utf8",
    "database": "$RUNTIME_DIR/data/licensing.db",
    "driver": "sqlite",
    "host": "",
    "password": "",
    "port": 0,
    "ssl_mode": "disable",
    "timeout": 30,
    "username": ""
  },
  "logging": {
    "format": "text",
    "level": "info",
    "log_file": "$RUNTIME_DIR/logs/migrate.log",
    "output": "console",
    "verbose": false
  },
  "migration": {
    "auto_rollback": false,
    "batch_size": 100,
    "directory": "$ROOT_DIR/migrations",
    "dry_run": false,
    "lock_timeout": 300,
    "skip_validation": false,
    "table_name": "migrations"
  },
  "seed": {
    "batch_size": 1000,
    "default_rows": 10,
    "directory": "$ROOT_DIR/migrations/seeds",
    "truncate_first": false
  },
  "validation": {
    "enabled": true,
    "forbidden_names": ["temp", "tmp", "test"],
    "max_identifier_length": 64,
    "require_description": true,
    "strict_mode": false
  }
}
EOF
chmod 600 "$RUNTIME_DIR/migrate.json"

cat > "$RUNTIME_DIR/licensing-server" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$ROOT_DIR"
export GOCACHE="$RUNTIME_DIR/go-build-cache"
export LICENSE_SERVER_ENV_FILE="\${LICENSE_SERVER_ENV_FILE:-$ENV_FILE}"
exec go run ./cmd "\$@"
EOF
chmod 700 "$RUNTIME_DIR/licensing-server"

(
  cd "$RUNTIME_DIR"
  sqlite3 "$RUNTIME_DIR/data/licensing.db" "PRAGMA user_version;" >/dev/null
  sqlite3 "$RUNTIME_DIR/data/audit.db" "PRAGMA user_version;" >/dev/null
  LICENSE_SERVER_ENV_FILE="$ENV_FILE" migrator cli migrate --verbose=true
)

(
  cd "$ROOT_DIR"
  GOCACHE="$RUNTIME_DIR/go-build-cache" LICENSE_SERVER_ENV_FILE="$ENV_FILE" go run ./cmd check-config
)

echo "local single-node runtime prepared"
echo "env file: $ENV_FILE"
echo "runtime:  $RUNTIME_DIR"
