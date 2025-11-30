-- Enable pgcrypto for UUID generation if not already enabled
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Users Table
CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       full_name VARCHAR(255) NOT NULL,
                       email VARCHAR(255) NOT NULL UNIQUE,
                       password VARCHAR(255) NOT NULL,
                       role VARCHAR(50) NOT NULL,

    -- Email Verification Fields
                       is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                       verification_token VARCHAR(255),
                       verification_token_expiry TIMESTAMP,

    -- Auditing
                       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP
);

-- Index for faster login lookups
CREATE INDEX idx_users_email ON users(email);


-- 2. Refresh Tokens Table
-- We store the HASH of the token, not the token itself.
CREATE TABLE refresh_tokens (
                                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                user_id UUID NOT NULL,
                                token_hash VARCHAR(255) NOT NULL, -- SHA-256 Hash
                                expires_at TIMESTAMP NOT NULL,
                                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

                                CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for looking up tokens quickly during refresh
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);