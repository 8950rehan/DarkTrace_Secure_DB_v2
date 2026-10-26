-- DarkTrace secure PostgreSQL schema (v2)
-- Apply with a database-owner/migration account, not the application account.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    usr_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE CHECK (username ~ '^[A-Za-z0-9_.-]{3,50}$'),
    email VARCHAR(254) NOT NULL UNIQUE CHECK (email = lower(email) AND position('@' in email) > 1),
    password_hash TEXT NOT NULL CHECK (length(password_hash) >= 20),
    role VARCHAR(20) NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin','analyst','supervisor','auditor','readonly')),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(12) NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_status_role ON users(status, role);

-- Legal authorization is normalized into its own table rather than storing an
-- arbitrary auth_ref string on every source. Keep secrets/document contents elsewhere.
CREATE TABLE IF NOT EXISTS authorizations (
    authorization_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_code VARCHAR(100) NOT NULL UNIQUE,
    approved_by UUID NOT NULL REFERENCES users(usr_id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL CHECK (length(trim(purpose)) BETWEEN 10 AND 2000),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    status VARCHAR(12) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_until > valid_from)
);
CREATE INDEX IF NOT EXISTS idx_authorizations_status_dates ON authorizations(status, valid_from, valid_until);

CREATE TABLE IF NOT EXISTS source (
    source_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(160) NOT NULL CHECK (length(trim(name)) BETWEEN 2 AND 160),
    source_type VARCHAR(20) NOT NULL CHECK (source_type IN ('onion_site','forum','marketplace','paste','blog','i2p_site')),
    address TEXT NOT NULL UNIQUE CHECK (length(trim(address)) BETWEEN 3 AND 2048),
    authorization_id UUID NOT NULL REFERENCES authorizations(authorization_id) ON DELETE RESTRICT,
    crawl_policy JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(crawl_policy) = 'object'),
    health JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(health) = 'object'),
    status VARCHAR(12) NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','dead')),
    created_by UUID NOT NULL REFERENCES users(usr_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_source_status_type ON source(status, source_type);
CREATE INDEX IF NOT EXISTS idx_source_authorization ON source(authorization_id);

CREATE TABLE IF NOT EXISTS crawl_job (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    intent_id UUID NOT NULL,
    source_id UUID NOT NULL REFERENCES source(source_id) ON DELETE RESTRICT,
    requested_by UUID NOT NULL REFERENCES users(usr_id) ON DELETE RESTRICT,
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('scheduled','incremental','manual')),
    state VARCHAR(12) NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed','dead','cancelled')),
    attempt SMALLINT NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 20),
    stats JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(stats) = 'object'),
    error_summary VARCHAR(1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);
CREATE INDEX IF NOT EXISTS idx_crawl_job_source_created ON crawl_job(source_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_crawl_job_state_created ON crawl_job(state, created_at);
CREATE INDEX IF NOT EXISTS idx_crawl_job_intent ON crawl_job(intent_id);

-- Append-only application audit events. Never store passwords, tokens, or raw secrets here.
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id UUID REFERENCES users(usr_id) ON DELETE SET NULL,
    action VARCHAR(80) NOT NULL CHECK (length(trim(action)) BETWEEN 2 AND 80),
    entity_type VARCHAR(50) NOT NULL,
    entity_id TEXT,
    outcome VARCHAR(12) NOT NULL CHECK (outcome IN ('success','denied','failure')),
    request_id UUID,
    details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_actor_created ON audit_log(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);

-- Example least-privilege application role. Run as DB admin and set a strong secret
-- out-of-band; don't put production credentials in source control.
-- CREATE ROLE darktrace_app LOGIN PASSWORD 'REPLACE_WITH_SECRET_FROM_SECRET_MANAGER';
-- GRANT CONNECT ON DATABASE darktrace TO darktrace_app;
-- GRANT USAGE ON SCHEMA public TO darktrace_app;
-- GRANT SELECT, INSERT, UPDATE ON users, authorizations, source, crawl_job TO darktrace_app;
-- GRANT SELECT, INSERT ON audit_log TO darktrace_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO darktrace_app;
-- Revoke dangerous privileges from PUBLIC and avoid granting schema/table ownership to the app role.
