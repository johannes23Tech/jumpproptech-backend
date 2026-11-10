-- Security hardening — 2026-11-09
-- Safe to run more than once. The application also creates rate_limits on
-- first use, but running this migration avoids relying on DDL privileges at
-- request time.

CREATE TABLE IF NOT EXISTS rate_limits (
    bucket VARCHAR(50) NOT NULL,
    identifier CHAR(64) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    window_start DATETIME NOT NULL,
    locked_until DATETIME NULL,
    PRIMARY KEY (bucket, identifier)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Optional: speed up password-reset lookups on large tables.
-- Run once; ignore "duplicate key name" if the index already exists.
-- ALTER TABLE password_resets ADD INDEX idx_password_resets_token (token);
-- ALTER TABLE password_resets ADD INDEX idx_password_resets_email (email);
