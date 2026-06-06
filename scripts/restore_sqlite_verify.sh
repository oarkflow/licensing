#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/restore_sqlite_verify.sh /path/to/backup.bak /path/to/licensing.db [health_url]

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <backup_file> <target_db_path> [health_url]"
  exit 1
fi

BACKUP_FILE="$1"
TARGET_DB="$2"
HEALTH_URL="${3:-}"
SHA_FILE="${BACKUP_FILE}.sha256"

if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "error: backup file not found: $BACKUP_FILE"
  exit 1
fi
if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "error: sqlite3 CLI is required for restore verification"
  exit 1
fi

if [[ -f "$SHA_FILE" ]]; then
  if command -v shasum >/dev/null 2>&1; then
    (cd "$(dirname "$BACKUP_FILE")" && shasum -a 256 -c "$(basename "$SHA_FILE")")
  elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$BACKUP_FILE")" && sha256sum -c "$(basename "$SHA_FILE")")
  else
    echo "warning: checksum file exists but no sha256 utility is available"
  fi
else
  echo "error: checksum file not found: $SHA_FILE"
  exit 1
fi

integrity="$(sqlite3 "file:$BACKUP_FILE?mode=ro" "PRAGMA integrity_check;")"
if [[ "$integrity" != "ok" ]]; then
  echo "error: backup integrity check failed: $integrity"
  exit 1
fi

if ! sqlite3 "file:$BACKUP_FILE?mode=ro" "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('schema_migrations','migrations') LIMIT 1;" | grep -Eq 'schema_migrations|migrations'; then
  echo "warning: no migrator history table found in backup; verify this database was migrated intentionally"
fi

mkdir -p "$(dirname "$TARGET_DB")"
cp "$BACKUP_FILE" "$TARGET_DB"
chmod 600 "$TARGET_DB"

restored_integrity="$(sqlite3 "file:$TARGET_DB?mode=ro" "PRAGMA integrity_check;")"
if [[ "$restored_integrity" != "ok" ]]; then
  echo "error: restored database integrity check failed: $restored_integrity"
  exit 1
fi

echo "restore completed: $TARGET_DB"
echo "integrity check: ok"

if [[ -n "$HEALTH_URL" ]]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "$HEALTH_URL" >/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$HEALTH_URL" >/dev/null
  else
    echo "warning: no curl/wget found; skipping health check"
    exit 0
  fi
  echo "health check: ok ($HEALTH_URL)"
else
  echo "restart the service, then rerun with a health URL to verify /health"
fi
