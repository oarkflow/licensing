#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/backup_sqlite.sh /path/to/licensing.db /path/to/backup-dir [retention_days]

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <sqlite_db_path> <backup_dir>"
  exit 1
fi

DB_PATH="$1"
BACKUP_DIR="$2"
RETENTION_DAYS="${3:-${RETENTION_DAYS:-30}}"
MARKER_FILE="${LICENSE_SERVER_BACKUP_MARKER_FILE:-$BACKUP_DIR/latest.json}"

if [[ ! -f "$DB_PATH" ]]; then
  echo "error: sqlite database not found: $DB_PATH"
  exit 1
fi
if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "error: sqlite3 CLI is required for online SQLite backups"
  exit 1
fi

mkdir -p "$BACKUP_DIR"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
base="$(basename "$DB_PATH")"
backup_file="$BACKUP_DIR/${base}.${ts}.bak"
sha_file="${backup_file}.sha256"

sqlite3 "$DB_PATH" ".backup '$backup_file'"
chmod 600 "$backup_file"

integrity="$(sqlite3 "$backup_file" "PRAGMA integrity_check;")"
if [[ "$integrity" != "ok" ]]; then
  echo "error: backup integrity check failed: $integrity"
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$backup_file" > "$sha_file"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$backup_file" > "$sha_file"
else
  echo "warning: no sha256 utility found; checksum file not written"
  sha_file=""
fi

if [[ -n "$sha_file" ]]; then
  chmod 600 "$sha_file"
fi
mkdir -p "$(dirname "$MARKER_FILE")"
cat > "$MARKER_FILE" <<EOF
{"backup_file":"$backup_file","checksum_file":"$sha_file","created_at":"$ts","integrity":"ok"}
EOF
chmod 600 "$MARKER_FILE"

if [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] && [[ "$RETENTION_DAYS" -gt 0 ]]; then
  find "$BACKUP_DIR" -type f \( -name "${base}.*.bak" -o -name "${base}.*.bak.sha256" \) -mtime +"$RETENTION_DAYS" -delete
fi

echo "backup created: $backup_file"
if [[ -n "$sha_file" ]]; then
  echo "checksum file: $sha_file"
fi
echo "marker file: $MARKER_FILE"
