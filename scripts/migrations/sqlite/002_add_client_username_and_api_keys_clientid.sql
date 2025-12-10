-- Add optional username and password hash to clients and client_id to api_keys
-- intended for upgrading older databases

PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;

-- Add columns if they don't exist
ALTER TABLE clients ADD COLUMN username TEXT;
ALTER TABLE clients ADD COLUMN password_hash BLOB;

ALTER TABLE api_keys ADD COLUMN client_id TEXT;

COMMIT;
PRAGMA foreign_keys = ON;

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_client_id ON api_keys(client_id);
