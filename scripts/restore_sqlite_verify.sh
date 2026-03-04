#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/restore_sqlite_verify.sh /path/to/backup.bak /path/to/licensing.db

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <backup_file> <target_db_path>"
  exit 1
fi

BACKUP_FILE="$1"
TARGET_DB="$2"
SHA_FILE="${BACKUP_FILE}.sha256"

if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "error: backup file not found: $BACKUP_FILE"
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
  echo "warning: checksum file not found: $SHA_FILE"
fi

mkdir -p "$(dirname "$TARGET_DB")"
cp "$BACKUP_FILE" "$TARGET_DB"
chmod 600 "$TARGET_DB"

echo "restore completed: $TARGET_DB"
echo "recommended: run a service smoke test against /health and key API endpoints"
