-- CRM + Product Management base schema
-- Applies to PostgreSQL-compatible databases.

BEGIN;

CREATE TABLE IF NOT EXISTS tenants (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'active',
    industry        TEXT,
    region          TEXT,
    billing_email   TEXT,
    support_email   TEXT,
    metadata        JSONB DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    deleted_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id       TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    login_modes     JSONB NOT NULL DEFAULT '[]'::JSONB,
    allowed_origins JSONB NOT NULL DEFAULT '[]'::JSONB,
    policy_version  TEXT,
    metadata        JSONB DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS crm_users (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email               TEXT NOT NULL,
    email_lower         TEXT NOT NULL,
    username            TEXT NOT NULL,
    username_lower      TEXT NOT NULL,
    role                TEXT NOT NULL,
    status              TEXT NOT NULL,
    password_hash       BYTEA,
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_methods         JSONB NOT NULL DEFAULT '[]'::JSONB,
    attributes          JSONB DEFAULT '{}'::JSONB,
    last_login_at       TIMESTAMPTZ,
    password_rotated_at TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, email_lower),
    UNIQUE (tenant_id, username_lower)
);

CREATE TABLE IF NOT EXISTS contacts (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id    TEXT,
    first_name   TEXT NOT NULL,
    last_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    email_lower  TEXT NOT NULL,
    phone        TEXT,
    title        TEXT,
    tags         JSONB NOT NULL DEFAULT '[]'::JSONB,
    attributes   JSONB DEFAULT '{}'::JSONB,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, email_lower)
);

CREATE TABLE IF NOT EXISTS credential_secrets (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         TEXT REFERENCES crm_users(id) ON DELETE CASCADE,
    contact_id      TEXT REFERENCES contacts(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,
    version         INTEGER NOT NULL,
    hash            BYTEA,
    encrypted_value BYTEA,
    metadata        JSONB DEFAULT '{}'::JSONB,
    expires_at      TIMESTAMPTZ,
    rotated_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS session_tokens (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id         TEXT NOT NULL,
    subject_type       TEXT NOT NULL,
    audience           JSONB NOT NULL DEFAULT '[]'::JSONB,
    scopes             JSONB NOT NULL DEFAULT '[]'::JSONB,
    issued_at          TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    not_before         TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    revoked_by         TEXT,
    device_fingerprint TEXT,
    client_ip          TEXT,
    metadata           JSONB DEFAULT '{}'::JSONB
);
CREATE INDEX IF NOT EXISTS idx_session_tokens_subject ON session_tokens(tenant_id, subject_id, subject_type);
CREATE INDEX IF NOT EXISTS idx_session_tokens_expires ON session_tokens(expires_at);

CREATE TABLE IF NOT EXISTS entitlement_bindings (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id        TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    client_id         TEXT,
    product_id        TEXT NOT NULL,
    product_slug      TEXT,
    plan_id           TEXT NOT NULL,
    plan_slug         TEXT,
    status            TEXT NOT NULL,
    feature_overrides JSONB DEFAULT '{}'::JSONB,
    effective_at      TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    revocation_reason TEXT,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entitlements_tenant ON entitlement_bindings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entitlements_contact ON entitlement_bindings(contact_id);
CREATE INDEX IF NOT EXISTS idx_entitlements_product ON entitlement_bindings(product_id);

CREATE TABLE IF NOT EXISTS product_releases (
    id           TEXT PRIMARY KEY,
    product_id   TEXT NOT NULL,
    channel      TEXT NOT NULL,
    version      TEXT NOT NULL,
    summary      TEXT,
    metadata     JSONB DEFAULT '{}'::JSONB,
    published_at TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_product_releases_product ON product_releases(product_id, channel);

CREATE TABLE IF NOT EXISTS device_ledgers (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id          TEXT,
    license_id         TEXT,
    device_fingerprint TEXT NOT NULL,
    last_seen_at       TIMESTAMPTZ NOT NULL,
    last_sync_at       TIMESTAMPTZ,
    pending_revocation BOOLEAN NOT NULL DEFAULT FALSE,
    revocation_epoch   BIGINT NOT NULL DEFAULT 0,
    metadata           JSONB DEFAULT '{}'::JSONB,
    created_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, device_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_device_ledgers_pending ON device_ledgers(tenant_id, pending_revocation);

CREATE TABLE IF NOT EXISTS service_accounts (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    scopes      JSONB NOT NULL DEFAULT '[]'::JSONB,
    created_by  TEXT NOT NULL,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_service_accounts_tenant ON service_accounts(tenant_id);

COMMIT;
