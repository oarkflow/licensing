-- Add optional username and password hash on clients and client_id on api_keys
BEGIN;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS username_lower TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS password_hash BYTEA;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS client_id TEXT REFERENCES clients(id) ON DELETE CASCADE;
-- Create indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_username_lower ON clients(username_lower);
CREATE INDEX IF NOT EXISTS idx_api_keys_client_id ON api_keys(client_id);
COMMIT;
