BEGIN;

ALTER TABLE oidc_authorizations ADD COLUMN IF NOT EXISTS amr oidc_amr_type[];

CREATE SEQUENCE IF NOT EXISTS oidc_password_credential_version_seq AS BIGINT;
CREATE TABLE IF NOT EXISTS oidc_password_credentials (
    user_id UUID PRIMARY KEY REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT nextval('oidc_password_credential_version_seq') CHECK (version > 0),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidc_login_attempts (
    attempt_id UUID PRIMARY KEY,
    user_id UUID REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    flow TEXT NOT NULL,
    binding_hash BYTEA NOT NULL,
    methods oidc_amr_type[],
    credential_version BIGINT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    challenge_id UUID,
    code_digest BYTEA,
    code_expires_at TIMESTAMPTZ,
    failed_attempts INT NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    last_sent_at TIMESTAMPTZ,
    continuation TEXT NOT NULL DEFAULT '/',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_oidc_login_attempts_user ON oidc_login_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_login_attempts_expires ON oidc_login_attempts(expires_at);

COMMIT;