-- Migration: add signing_keys table and signing_key_id column to offline_validation_tokens
BEGIN TRANSACTION;

ALTER TABLE offline_validation_tokens ADD COLUMN signing_key_id TEXT;

CREATE TABLE IF NOT EXISTS signing_keys (
    id TEXT PRIMARY KEY,
    name TEXT,
    public_key BLOB NOT NULL,
    private_key BLOB,
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_active ON signing_keys(is_active);

COMMIT;
