#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/backup_sqlite.sh /path/to/licensing.db /path/to/backup-dir

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <sqlite_db_path> <backup_dir>"
  exit 1
fi

DB_PATH="$1"
BACKUP_DIR="$2"

if [[ ! -f "$DB_PATH" ]]; then
  echo "error: sqlite database not found: $DB_PATH"
  exit 1
fi

mkdir -p "$BACKUP_DIR"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
base="$(basename "$DB_PATH")"
backup_file="$BACKUP_DIR/${base}.${ts}.bak"
sha_file="${backup_file}.sha256"

cp "$DB_PATH" "$backup_file"
chmod 600 "$backup_file"

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$backup_file" > "$sha_file"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$backup_file" > "$sha_file"
else
  echo "warning: no sha256 utility found; checksum file not written"
  exit 0
fi

chmod 600 "$sha_file"
echo "backup created: $backup_file"
echo "checksum file: $sha_file"
