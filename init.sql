-- init.sql
-- This runs automatically when the database container starts for the first time

-- Enable UUID extension (optional, for better IDs)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table to store issued API tokens
CREATE TABLE api_tokens (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    active BOOLEAN DEFAULT true,
    issued_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    created_by VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_api_tokens_client_id ON api_tokens(client_id);
CREATE INDEX idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX idx_api_tokens_active ON api_tokens(active);
CREATE INDEX idx_api_tokens_expires_at ON api_tokens(expires_at);

-- Table for token usage audit log
CREATE TABLE token_usage_log (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255),
    method VARCHAR(10),
    status_code INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes for audit log
CREATE INDEX idx_token_usage_client_id ON token_usage_log(client_id);
CREATE INDEX idx_token_usage_timestamp ON token_usage_log(timestamp);
CREATE INDEX idx_token_usage_endpoint ON token_usage_log(endpoint);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at
CREATE TRIGGER update_api_tokens_updated_at
    BEFORE UPDATE ON api_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert sample admin token (optional - for testing)
-- Password for admin: admin123 (change immediately in production!)
INSERT INTO api_tokens (
    client_id,
    client_name,
    token_hash,
    expires_at,
    created_by,
    notes
) VALUES (
    'admin_console',
    'Admin Console',
    'placeholder_will_be_replaced_on_first_use',
    NOW() + INTERVAL '10 years',
    'system',
    'Initial admin token - replace immediately'
);

-- Create view for active tokens
CREATE VIEW active_tokens AS
SELECT
    client_id,
    client_name,
    active,
    issued_at,
    expires_at,
    last_used_at,
    CASE
        WHEN expires_at < NOW() THEN 'expired'
        WHEN last_used_at IS NULL THEN 'never_used'
        WHEN last_used_at < NOW() - INTERVAL '7 days' THEN 'inactive'
        ELSE 'active'
    END as status
FROM api_tokens
WHERE active = true;

-- Create view for usage statistics
CREATE VIEW token_usage_stats AS
SELECT
    l.client_id,
    t.client_name,
    COUNT(*) as total_requests,
    COUNT(DISTINCT l.endpoint) as unique_endpoints,
    MAX(l.timestamp) as last_request,
    MIN(l.timestamp) as first_request,
    DATE_TRUNC('day', l.timestamp) as date
FROM token_usage_log l
JOIN api_tokens t ON l.client_id = t.client_id
GROUP BY l.client_id, t.client_name, DATE_TRUNC('day', l.timestamp);

-- Grant permissions (if using different user for API)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO api_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO api_user;