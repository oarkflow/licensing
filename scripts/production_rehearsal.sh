#!/usr/bin/env bash
set -euo pipefail

# Production rehearsal checklist runner.
# Required environment:
#   LICENSING_SERVER_BIN=/path/to/licensing-server
#   SQLITE_DB=/absolute/path/licensing.db
#   BACKUP_DIR=/absolute/path/backups
# Optional:
#   HEALTH_URL=http://127.0.0.1:6601/health
#   AUDIT_DB=/absolute/path/audit.db
#   MIGRATOR_DIR=/directory/containing/migrate.json

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${LICENSING_SERVER_BIN:-licensing-server}"
SQLITE_DB="${SQLITE_DB:-}"
BACKUP_DIR="${BACKUP_DIR:-}"
HEALTH_URL="${HEALTH_URL:-}"
AUDIT_DB="${AUDIT_DB:-${LICENSE_SERVER_AUDIT_DB_PATH:-}}"
MIGRATOR_DIR="${MIGRATOR_DIR:-.}"

if [[ -z "$SQLITE_DB" || -z "$BACKUP_DIR" ]]; then
  echo "usage: SQLITE_DB=/path/licensing.db BACKUP_DIR=/path/backups LICENSING_SERVER_BIN=/path/licensing-server $0"
  exit 1
fi

echo "== check-config =="
"$BIN" check-config

echo "== migrate idempotency =="
(cd "$MIGRATOR_DIR" && migrator cli migrate --verbose=true)

echo "== backup =="
backup_output="$("$ROOT_DIR/scripts/backup_sqlite.sh" "$SQLITE_DB" "$BACKUP_DIR" 30)"
echo "$backup_output"
backup_file="$(printf '%s\n' "$backup_output" | awk -F': ' '/backup created:/ {print $2}')"
if [[ -z "$backup_file" ]]; then
  echo "error: backup script did not report a backup file"
  exit 1
fi

echo "== restore verification =="
restore_target="$(mktemp -d)/licensing-restore.db"
"$ROOT_DIR/scripts/restore_sqlite_verify.sh" "$backup_file" "$restore_target"

if [[ -n "$AUDIT_DB" && -f "$AUDIT_DB" ]]; then
  echo "== audit verification =="
  "$BIN" audit-verify --audit-db="$AUDIT_DB"
else
  echo "warning: AUDIT_DB not set or file missing; skipped audit verification"
fi

if [[ -n "$HEALTH_URL" ]]; then
  echo "== health check =="
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "$HEALTH_URL" >/dev/null
  else
    wget -qO- "$HEALTH_URL" >/dev/null
  fi
  echo "health check: ok"
fi

echo "production rehearsal completed"
