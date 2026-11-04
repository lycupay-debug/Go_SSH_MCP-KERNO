BEGIN;

CREATE SCHEMA IF NOT EXISTS remote;

CREATE TABLE IF NOT EXISTS remote.targets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id uuid NOT NULL REFERENCES oauth.users(id) ON DELETE CASCADE,
    name text NOT NULL,
    host text NOT NULL,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username text NOT NULL,
    host_key_type text NOT NULL,
    host_key_data text NOT NULL,
    host_key_fingerprint text NOT NULL,
    is_enabled boolean NOT NULL DEFAULT true,
    created_by_client_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(owner_user_id, name)
);

CREATE TABLE IF NOT EXISTS remote.credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id uuid NOT NULL REFERENCES remote.targets(id) ON DELETE CASCADE,
    owner_user_id uuid NOT NULL REFERENCES oauth.users(id) ON DELETE CASCADE,
    name text NOT NULL,
    private_key text NOT NULL,
    passphrase text NOT NULL DEFAULT '',
    public_key text NOT NULL DEFAULT '',
    fingerprint text NOT NULL DEFAULT '',
    is_enabled boolean NOT NULL DEFAULT true,
    created_by_client_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(target_id, name)
);

CREATE TABLE IF NOT EXISTS remote.audit_log (
    id bigserial PRIMARY KEY,
    owner_user_id uuid NOT NULL REFERENCES oauth.users(id) ON DELETE CASCADE,
    client_id text,
    target_id uuid REFERENCES remote.targets(id) ON DELETE SET NULL,
    credential_id uuid REFERENCES remote.credentials(id) ON DELETE SET NULL,
    operation text NOT NULL,
    outcome text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN remote.credentials.private_key IS 'PLAINTEXT SSH private key by explicit product requirement; restrict database, backup, and log access.';
COMMENT ON COLUMN remote.credentials.passphrase IS 'PLAINTEXT SSH key passphrase when supplied; same access restrictions as private_key.';

CREATE INDEX IF NOT EXISTS remote_targets_owner_idx ON remote.targets(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS remote_credentials_target_idx ON remote.credentials(target_id, owner_user_id);
CREATE INDEX IF NOT EXISTS remote_audit_owner_idx ON remote.audit_log(owner_user_id, created_at DESC);

COMMIT;
