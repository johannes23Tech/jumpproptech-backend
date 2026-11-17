-- Phase 0 foundation - 2026-11-17
--
-- Realigns the account model to the approved internal product:
--   * one company/portfolio scope (companies + company_id)
--   * eight staff roles plus tenant accounts (staff_role + account_type)
--   * inactive-account support
--
-- Additive and safe to re-run. The legacy users.role column is intentionally
-- kept so existing endpoints keep working while they are migrated to the
-- permission framework in config/permissions.php.
--
-- Run this before deploying the matching API changes.

CREATE TABLE IF NOT EXISTS companies (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(150) NULL,
    registration_number VARCHAR(50) NULL,
    vat_number VARCHAR(50) NULL,
    email VARCHAR(150) NULL,
    phone VARCHAR(20) NULL,
    address VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- users.company_id
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE users ADD COLUMN company_id INT UNSIGNED NULL AFTER id',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'company_id'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- users.staff_role (approved staff roles only; NULL for tenants)
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        "ALTER TABLE users ADD COLUMN staff_role ENUM(
            'super_administrator',
            'administrator',
            'property_manager',
            'finance_accountant',
            'maintenance_manager',
            'maintenance_technician',
            'reception_support',
            'auditor'
        ) NULL AFTER role",
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'staff_role'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- users.account_type
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        "ALTER TABLE users ADD COLUMN account_type ENUM('staff','tenant') NOT NULL DEFAULT 'staff' AFTER role",
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'account_type'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- users.is_active
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE users ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'is_active'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- properties.company_id
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE properties ADD COLUMN company_id INT UNSIGNED NULL AFTER id',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'properties' AND COLUMN_NAME = 'company_id'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- indexes
SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND INDEX_NAME = 'idx_users_company'
);
SET @sql = IF(@idx = 0, 'ALTER TABLE users ADD INDEX idx_users_company (company_id)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND INDEX_NAME = 'idx_users_staff_role'
);
SET @sql = IF(@idx = 0, 'ALTER TABLE users ADD INDEX idx_users_staff_role (staff_role)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'properties' AND INDEX_NAME = 'idx_properties_company'
);
SET @sql = IF(@idx = 0, 'ALTER TABLE properties ADD INDEX idx_properties_company (company_id)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Backfill the account model from legacy roles.
UPDATE users SET account_type = 'tenant' WHERE role = 'tenant';
UPDATE users SET account_type = 'staff' WHERE role <> 'tenant';

UPDATE users
SET staff_role = CASE role
    WHEN 'superadmin' THEN 'super_administrator'
    WHEN 'landlord' THEN 'property_manager'
    WHEN 'agent' THEN 'property_manager'
    WHEN 'maintenance' THEN 'maintenance_technician'
    ELSE staff_role
END
WHERE role <> 'tenant' AND staff_role IS NULL;
