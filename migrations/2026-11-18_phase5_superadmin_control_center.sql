-- Phase 5 (foundations) - Super Admin Control Center - 2026-11-18
--
-- Adds session issuance tracking for active-session/device visibility and
-- revocation (recommended). Also ensures revoked_tokens exists if missing.
-- Additive and safe to re-run.

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti CHAR(32) NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (jti),
    KEY idx_revoked_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    jti_hash CHAR(64) NOT NULL,
    ip VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    last_seen_at DATETIME NULL,
    revoked_at DATETIME NULL,
    revoke_reason VARCHAR(100) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_sessions_jti_hash (jti_hash),
    KEY idx_user_sessions_user (user_id, revoked_at, expires_at),
    KEY idx_user_sessions_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;