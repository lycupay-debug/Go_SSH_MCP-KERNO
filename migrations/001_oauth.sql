BEGIN;

CREATE SCHEMA IF NOT EXISTS oauth;

CREATE TABLE IF NOT EXISTS oauth.users (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    is_enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE TABLE IF NOT EXISTS oauth.sessions (
    id uuid PRIMARY KEY,
    session_hash text NOT NULL UNIQUE,
    csrf_hash text NOT NULL,
    user_id uuid NOT NULL REFERENCES oauth.users(id),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth.clients (
    client_id text PRIMARY KEY,
    metadata jsonb NOT NULL,
    is_enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth.authorization_codes (
    id uuid PRIMARY KEY,
    code_hash text NOT NULL UNIQUE,
    client_id text NOT NULL REFERENCES oauth.clients(client_id),
    user_id uuid NOT NULL REFERENCES oauth.users(id),
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    scopes text[] NOT NULL,
    resource text NOT NULL,
    expires_at timestamptz NOT NULL,
    exchanged_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth.access_tokens (
    id uuid PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    client_id text NOT NULL REFERENCES oauth.clients(client_id),
    user_id uuid NOT NULL REFERENCES oauth.users(id),
    scopes text[] NOT NULL,
    resource text NOT NULL,
    family_id uuid,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth.refresh_token_families (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES oauth.clients(client_id),
    user_id uuid NOT NULL REFERENCES oauth.users(id),
    revoked_at timestamptz,
    reuse_detected_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth.refresh_tokens (
    id uuid PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    family_id uuid NOT NULL REFERENCES oauth.refresh_token_families(id),
    parent_token_id uuid REFERENCES oauth.refresh_tokens(id),
    client_id text NOT NULL REFERENCES oauth.clients(client_id),
    user_id uuid NOT NULL REFERENCES oauth.users(id),
    scopes text[] NOT NULL,
    resource text NOT NULL,
    expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth.consents (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES oauth.users(id),
    client_id text NOT NULL REFERENCES oauth.clients(client_id),
    scopes text[] NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, client_id)
);
CREATE TABLE IF NOT EXISTS oauth.audit_log (
    id bigserial PRIMARY KEY,
    event_type text NOT NULL,
    outcome text NOT NULL,
    user_id uuid,
    client_id text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oauth_access_lookup_idx ON oauth.access_tokens (token_hash, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS oauth_refresh_lookup_idx ON oauth.refresh_tokens (token_hash, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS oauth_codes_lookup_idx ON oauth.authorization_codes (code_hash, expires_at) WHERE exchanged_at IS NULL;

COMMIT;
