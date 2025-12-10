-- Migration: add signing_keys table and signing_key_id column to offline_validation_tokens (Postgres)
BEGIN;

ALTER TABLE offline_validation_tokens ADD COLUMN IF NOT EXISTS signing_key_id TEXT;

CREATE TABLE IF NOT EXISTS signing_keys (
    id TEXT PRIMARY KEY,
    name TEXT,
    public_key BYTEA NOT NULL,
    private_key BYTEA,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_active ON signing_keys(is_active);

COMMIT;
