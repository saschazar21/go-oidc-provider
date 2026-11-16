-- Migration for release 0.1.13
-- Adds stored authentication time to authorizations and aligns the PKCE
-- challenge-method default with RFC 7636 (plain when omitted).

BEGIN;

ALTER TABLE oidc_authorizations
    ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ;

ALTER TABLE oidc_authorizations
    ALTER COLUMN code_challenge_method SET DEFAULT 'plain';

COMMIT;
