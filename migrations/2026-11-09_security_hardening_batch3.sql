-- Security hardening batch 3 - 2026-11-09
-- Adds token revocation, an append-only audit trail and the indexes needed
-- for password-reset lookups. Safe to re-run: the column add is guarded by
-- information_schema and every table uses CREATE TABLE IF NOT EXISTS.

-- 1. Token version: every JWT carries `ver`. Bumping it invalidates every
--    token issued before the bump (password change/reset, "logout everywhere").
SET @col_exists = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'users'
      AND COLUMN_NAME = 'token_version'
);
SET @sql = IF(
    @col_exists = 0,
    'ALTER TABLE users ADD COLUMN token_version INT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2. Per-token denylist for single-device logout. Rows expire with the JWT.
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti CHAR(32) NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (jti),
    KEY idx_revoked_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Append-only audit trail. Never store secrets or full request bodies.
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id INT NULL,
    actor_email VARCHAR(150) NULL,
    action VARCHAR(60) NOT NULL,
    entity_type VARCHAR(40) NULL,
    entity_id INT NULL,
    outcome ENUM('success', 'failure', 'denied') NOT NULL DEFAULT 'success',
    ip VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    meta LONGTEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_logs_action (action, created_at),
    KEY idx_audit_logs_actor (actor_user_id, created_at),
    KEY idx_audit_logs_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Enforce append-only at the database layer. Drop first so the migration
--    can be re-run. Remove these triggers only during a documented archival
--    procedure.
DROP TRIGGER IF EXISTS audit_logs_no_update;
CREATE TRIGGER audit_logs_no_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only';

DROP TRIGGER IF EXISTS audit_logs_no_delete;
CREATE TRIGGER audit_logs_no_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only';

-- 5. Password-reset lookups are by token hash or email. Add the indexes if
--    they are missing.
SET @idx_token = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'password_resets'
      AND INDEX_NAME = 'idx_password_resets_token'
);
SET @sql = IF(
    @idx_token = 0,
    'ALTER TABLE password_resets ADD INDEX idx_password_resets_token (token)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_email = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'password_resets'
      AND INDEX_NAME = 'idx_password_resets_email'
);
SET @sql = IF(
    @idx_email = 0,
    'ALTER TABLE password_resets ADD INDEX idx_password_resets_email (email)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
