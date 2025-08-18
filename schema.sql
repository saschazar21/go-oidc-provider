CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enums

CREATE TYPE oidc_acr_type AS ENUM (
    'urn:mace:incommon:iap:bronze',  -- Bronze, single-factor authentication
    'urn:mace:incommon:iap:silver',  -- Silver, multi-factor authentication
    'urn:mace:incommon:iap:gold'    -- Gold, multi-factor authentication with additional security measures (hardware tokens, etc.)
);

CREATE TYPE oidc_amr_type AS ENUM (
    'pwd',                -- Password
    'otp',                -- One-Time Password
    'mfa',                -- Multi-Factor Authentication
    'sms',                -- SMS-based authentication
    'email',              -- Email-based authentication
    'push',               -- Push notification
    'fido',               -- FIDO2/WebAuthn
    'biometric'         -- Biometric authentication
);

CREATE TYPE oidc_grant_type AS ENUM (
    'authorization_code',
    'implicit',
    'client_credentials',
    'refresh_token',
    'urn:ietf:params:oauth:grant-type:device_code',  -- For device flow
    'urn:ietf:params:oauth:grant-type:jwt-bearer',   -- JWT bearer flow
    'urn:openid:params:grant-type:ciba'              -- CIBA flow
);

CREATE TYPE oidc_response_type AS ENUM (
    'code',               -- Authorization Code Flow
    'token',              -- Implicit Flow (not recommended)
    'id_token',           -- OpenID Connect specific
    'code token',         -- Hybrid Flow
    'code id_token',      -- Hybrid Flow
    'id_token token',     -- Hybrid Flow
    'code id_token token' -- Hybrid Flow
    'form_post'           -- OAuth 2.0 Form Post Response Mode
);

CREATE TYPE oidc_auth_method AS ENUM (
    'client_secret_basic',     -- Client credentials in Authorization header
    'client_secret_post',      -- Client credentials in request body
    'client_secret_jwt',       -- Client assertion as JWT
    'private_key_jwt',         -- Private key JWT
    'tls_client_auth',         -- Mutual TLS
    'self_signed_tls_client_auth',
    'none'                     -- Public clients (PKCE required)
);

CREATE TYPE oidc_standard_scope AS ENUM (
    -- OpenID Connect Core Scopes
    'openid',
    'profile',
    'email',
    'address',
    'phone',
    
    -- OAuth 2.0 Standard Scopes
    'read',
    'write',
    'update',
    'delete',
    'offline_access'
);

-- Tables

CREATE TABLE oidc_users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email BYTEA UNIQUE NOT NULL,
    email_hash BYTEA UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    phone_number BYTEA UNIQUE,
    phone_number_verified BOOLEAN DEFAULT FALSE,
    given_name BYTEA,
    family_name BYTEA,
    middle_name BYTEA,
    nickname VARCHAR(100),
    preferred_username VARCHAR(100),
    profile BYTEA,
    picture BYTEA,
    website BYTEA,
    gender BYTEA,
    birthdate BYTEA,
    zoneinfo VARCHAR(50),
    locale VARCHAR(10),
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP WITH TIME ZONE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_locked BOOLEAN DEFAULT FALSE,
    
    -- Custom claims if needed
    custom_claims JSONB
);

CREATE INDEX idx_oidc_users_email_hash ON oidc_users(email_hash);

CREATE TABLE oidc_addresses (
    address_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    street_address BYTEA,
    locality BYTEA,
    region BYTEA,
    postal_code BYTEA,
    country VARCHAR(100),
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE oidc_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret BYTEA, -- Hashed if confidential client
    client_name VARCHAR(255) NOT NULL,
    client_description TEXT,
    client_uri VARCHAR(512),
    logo_uri VARCHAR(512),
    owner_id UUID NOT NULL REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    
    -- Auth types
    grant_types oidc_grant_type[] DEFAULT ARRAY['authorization_code'::oidc_grant_type, 'refresh_token'::oidc_grant_type],
    response_types oidc_response_type[] DEFAULT ARRAY['code'::oidc_response_type],
    token_endpoint_auth_method oidc_auth_method DEFAULT 'client_secret_basic'::oidc_auth_method,
    
    -- Redirect URIs
    redirect_uris VARCHAR(512)[] NOT NULL,
    post_logout_redirect_uris VARCHAR(512)[],
    
    -- Security
    require_auth_time BOOLEAN DEFAULT FALSE,
    require_pkce BOOLEAN DEFAULT TRUE,
    
    -- Token configuration
    access_token_lifetime INT DEFAULT 3600, -- 1 hour
    refresh_token_lifetime INT DEFAULT 86400, -- 24 hours
    id_token_lifetime INT DEFAULT 300, -- 5 minutes
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_confidential BOOLEAN DEFAULT FALSE,

    -- Constriant: Client secret must be set for confidential clients
    CONSTRAINT chk_client_secret CHECK (
        (is_confidential = TRUE AND client_secret IS NOT NULL)
        OR
        (is_confidential = FALSE AND client_secret IS NULL AND require_pkce = TRUE)
    )
);

CREATE INDEX idx_oidc_clients_active ON oidc_clients(is_active);

CREATE TABLE oidc_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    ip_address BYTEA,
    user_agent TEXT,
    device_info TEXT,
    
    -- Session metadata
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    last_accessed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    
    -- Session state
    is_active BOOLEAN DEFAULT TRUE,
    logout_reason VARCHAR(100),
    
    -- OIDC specific
    client_id VARCHAR(255) REFERENCES oidc_clients(client_id) ON DELETE SET NULL,
    scope oidc_standard_scope[],
    auth_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    acr_values oidc_acr_type[], -- Authentication Context Class Reference
    amr oidc_amr_type[] -- Array of authentication methods
);

CREATE INDEX idx_oidc_sessions_user ON oidc_sessions(user_id);
CREATE INDEX idx_oidc_sessions_expires ON oidc_sessions(expires_at);

CREATE TABLE oidc_authorizations (
    authorization_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id UUID REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    response_type oidc_response_type NOT NULL,
    
    -- Authorization metadata
    scope oidc_standard_scope[] NOT NULL,
    acr_values oidc_acr_type[], -- Authentication Context Class Reference values
    claims_requested JSONB,
    claims_granted JSONB,
    
    -- PKCE (Proof Key for Code Exchange)
    code_challenge TEXT,
    code_challenge_method VARCHAR(10) DEFAULT 'S256' CHECK (
        code_challenge_method IN ('plain', 'S256')
    ),
    
    -- State/nonce
    state VARCHAR(255),
    nonce VARCHAR(255),
    
    -- Status
    is_active BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'pending' CHECK (
        status IN ('pending', 'approved', 'denied', 'revoked')
    ),
    replaced_id UUID REFERENCES oidc_authorizations(authorization_id),
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    -- Empty user_id constraint
    CONSTRAINT chk_empty_user_id CHECK (
        (user_id IS NULL AND status = 'pending' AND is_active = FALSE)
        OR
        (user_id IS NOT NULL AND status IN ('approved', 'denied', 'revoked'))
    )
);

-- Indexes for the authorizations table
CREATE INDEX idx_oidc_auth_client_user ON oidc_authorizations(client_id, user_id);
CREATE INDEX idx_oidc_auth_status ON oidc_authorizations(status);
CREATE INDEX idx_oidc_auth_expires ON oidc_authorizations(expires_at);

CREATE TABLE oidc_tokens (
    token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorization_id UUID REFERENCES oidc_authorizations(authorization_id) ON DELETE CASCADE, -- will be checked using chk_custom_token constraint below
    token_value BYTEA NOT NULL,
    token_type VARCHAR(50) NOT NULL CHECK (
        token_type IN ('authorization_code', 'access_token', 'refresh_token', 'client_credentials') -- 'id_token'
    ),
    
    -- Token-specific metadata
    redirect_uri VARCHAR(512),  -- for authorization_code
    
    -- JWT fields if using JWT tokens
    -- jwt_id VARCHAR(255),
    -- jwt_claims JSONB,
    
    -- Timestamps
    issued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    revocation_reason VARCHAR(255),

    -- Token rotation tracking
    previous_token_id UUID REFERENCES oidc_tokens(token_id) ON DELETE SET NULL,
    rotation_count INT DEFAULT 0,

    -- Client credentials
    client_id VARCHAR(255) REFERENCES oidc_clients(client_id) ON DELETE CASCADE,

    -- Custom created tokens
    is_custom BOOLEAN DEFAULT FALSE,
    description TEXT,
    user_id UUID REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    scope oidc_standard_scope[],

    -- Constraint: Either is_custom + user_id + scope + token_type = 'access_token' OR authorization_id must be set
    CONSTRAINT chk_token_structure CHECK (
      (is_custom = TRUE AND authorization_id IS NULL AND token_type = 'access_token' AND client_id IS NULL AND user_id IS NOT NULL AND cardinality(scope) > 0)
      OR
      (is_custom = FALSE AND token_type = 'client_credentials' AND authorization_id IS NULL AND client_id IS NOT NULL AND user_id IS NULL)
      OR
      (is_custom = FALSE AND authorization_id IS NOT NULL AND client_id IS NULL AND user_id IS NULL AND cardinality(scope) = 0)
    )
);

-- Indexes for the tokens table
CREATE INDEX idx_oidc_tokens_value ON oidc_tokens(token_value);
CREATE INDEX idx_oidc_tokens_auth ON oidc_tokens(authorization_id);
CREATE INDEX idx_oidc_tokens_type_expires ON oidc_tokens(token_type, expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_oidc_tokens_previous ON oidc_tokens(previous_token_id);
CREATE INDEX idx_oidc_tokens_custom ON oidc_tokens(is_custom) WHERE is_custom = TRUE;

CREATE TABLE oidc_magic_link_whitelist (
    whitelist_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email BYTEA UNIQUE NOT NULL,
    
    -- Metadata
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    added_by UUID REFERENCES oidc_users(user_id) ON DELETE SET NULL,
    
    -- Expiration if needed
    expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Optional metadata
    reason TEXT,
    notes TEXT
);

CREATE INDEX idx_oidc_magic_whitelist_email ON oidc_magic_link_whitelist(email);

CREATE TABLE oidc_magic_link_tokens (
    token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token BYTEA UNIQUE NOT NULL,
    email BYTEA NOT NULL,
    user_id UUID REFERENCES oidc_users(user_id) ON DELETE CASCADE,
    
    -- Token metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',
    consumed_at TIMESTAMP WITH TIME ZONE,
    
    -- Usage data
    ip_address BYTEA,
    user_agent TEXT,
    
    -- State
    is_active BOOLEAN DEFAULT TRUE,
    result VARCHAR(50) CHECK (
      result in ('success', 'failed', 'expired')
    ) -- "success", "failed", "expired", etc.
);

CREATE INDEX idx_oidc_magic_tokens_token ON oidc_magic_link_tokens(token);
CREATE INDEX idx_oidc_magic_tokens_email ON oidc_magic_link_tokens(email);
CREATE INDEX idx_oidc_magic_tokens_user ON oidc_magic_link_tokens(user_id);

-- Functions

-- Deletes all entries of a given table, which has expired for longer than the given retention period
CREATE OR REPLACE FUNCTION clean_expired_records()
RETURNS TRIGGER AS $$
DECLARE
    query TEXT;
    rows_deleted INT;
    column_exists BOOLEAN;
BEGIN
    -- Check if the table has an expires_at column
    SELECT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = TG_TABLE_NAME 
        AND column_name = 'expires_at'
    ) INTO column_exists;
    
    IF NOT column_exists THEN
        RAISE EXCEPTION 'Table % does not have an expires_at column', TG_TABLE_NAME;
    END IF;
    
    -- Build and execute the dynamic query
    query := format(
        'DELETE FROM %I 
         WHERE expires_at < (NOW() - $1) 
         RETURNING *', 
        TG_TABLE_NAME
    );
    
    EXECUTE query USING TG_ARGV[0]::INTERVAL;
    
    -- Get the number of rows deleted
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    
    RAISE NOTICE 'Deleted % expired records from % (older than %)', 
        rows_deleted, TG_TABLE_NAME, TG_ARGV[0];

    RETURN OLD;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Updates the updated_at field with the current timestamp
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers

CREATE OR REPLACE TRIGGER update_oidc_users_modtime
BEFORE UPDATE ON oidc_users
FOR EACH ROW EXECUTE FUNCTION update_modified_column();

CREATE OR REPLACE TRIGGER update_oidc_addresses_modtime
BEFORE UPDATE ON oidc_addresses
FOR EACH ROW EXECUTE FUNCTION update_modified_column();

CREATE OR REPLACE TRIGGER update_oidc_clients_modtime
BEFORE UPDATE ON oidc_clients
FOR EACH ROW EXECUTE FUNCTION update_modified_column();

CREATE OR REPLACE TRIGGER delete_expired_authorizations
AFTER INSERT OR UPDATE ON oidc_authorizations
FOR EACH STATEMENT EXECUTE FUNCTION clean_expired_records('7 days');

CREATE OR REPLACE TRIGGER delete_expired_sessions
AFTER INSERT OR UPDATE ON oidc_sessions
FOR EACH STATEMENT EXECUTE FUNCTION clean_expired_records('1 day');

CREATE OR REPLACE TRIGGER delete_expired_tokens
AFTER INSERT OR UPDATE ON oidc_tokens
FOR EACH STATEMENT EXECUTE FUNCTION clean_expired_records('3 days');

CREATE OR REPLACE TRIGGER delete_expired_magic_link_tokens
AFTER INSERT OR UPDATE ON oidc_magic_link_tokens
FOR EACH STATEMENT EXECUTE FUNCTION clean_expired_records('1 hour');

CREATE OR REPLACE TRIGGER delete_expired_magic_link_whitelist
AFTER INSERT OR UPDATE ON oidc_magic_link_whitelist
FOR EACH STATEMENT EXECUTE FUNCTION clean_expired_records('1 day');