-- migration-up
CREATE TABLE IF NOT EXISTS email_attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    data BLOB NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_attachments_message ON email_attachments(message_id);

-- migration-down
DROP INDEX IF EXISTS idx_email_attachments_message;
DROP TABLE IF EXISTS email_attachments;
