-- Enable pgcrypto for UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Email Verifications Table
CREATE TABLE email_verifications (
                                     email VARCHAR(255) PRIMARY KEY,
                                     otp_code VARCHAR(10) NOT NULL,
                                     expiry_date TIMESTAMP NOT NULL
);

-- 2. Users Table
CREATE TABLE users (
                       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                       first_name VARCHAR(100) NOT NULL,
                       last_name VARCHAR(100) NOT NULL,
                       email VARCHAR(255) NOT NULL UNIQUE,

    -- Password is NULLABLE (For Social Login users)
                       password VARCHAR(255),

                       role VARCHAR(50) NOT NULL,

    -- OAuth2 / Social Auth Fields
                       oauth_provider VARCHAR(50),
                       oauth_id VARCHAR(255),

    -- Status
                       is_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    -- Password Reset
                       password_reset_token VARCHAR(255),
                       password_reset_token_expiry TIMESTAMP,

    -- Auditing
                       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_pwd_reset ON users(password_reset_token);

-- Composite Index for fast OIDC lookups (Provider + Sub)
CREATE INDEX idx_users_oauth ON users(oauth_provider, oauth_id);

-- 3. Refresh Tokens Table
CREATE TABLE refresh_tokens (
                                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                user_id UUID NOT NULL,
                                token_hash VARCHAR(255) NOT NULL,
                                expires_at TIMESTAMP NOT NULL,
                                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

                                CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);