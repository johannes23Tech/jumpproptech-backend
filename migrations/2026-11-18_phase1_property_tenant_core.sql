-- Phase 1 - Property and tenant core - 2026-11-18
--
-- Adds the approved Phase 1 foundation:
--   * an optional building layer under a property
--   * unit archive status and prepaid meter identifier
--   * one revocable, hashed onboarding token per rentable unit (unique QR)
--   * tenant applications submitted through a unit QR link
--   * application supporting documents (Cloudinary URLs)
--
-- Additive and safe to re-run. Approved business rules preserved:
--   * QR is for first-time onboarding only and is never a password.
--   * Tokens are stored as SHA-256 hashes, expire and can be revoked.
--   * Applications capture no employment or income information.
--   * Management approval is required before a tenant/tenancy is active.

CREATE TABLE IF NOT EXISTS buildings (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    property_id INT NOT NULL,
    name VARCHAR(150) NOT NULL,
    address VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_buildings_property (property_id),
    CONSTRAINT fk_buildings_property FOREIGN KEY (property_id)
        REFERENCES properties (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- properties.archived_at (retire without deleting history)
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE properties ADD COLUMN archived_at DATETIME NULL AFTER property_type',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'properties' AND COLUMN_NAME = 'archived_at'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- units.building_id
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE units ADD COLUMN building_id INT UNSIGNED NULL AFTER property_id',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'units' AND COLUMN_NAME = 'building_id'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- units.prepaid_meter_number
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE units ADD COLUMN prepaid_meter_number VARCHAR(60) NULL AFTER included_items',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'units' AND COLUMN_NAME = 'prepaid_meter_number'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- units.archived_at
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE units ADD COLUMN archived_at DATETIME NULL AFTER status',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'units' AND COLUMN_NAME = 'archived_at'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- units index for the building layer
SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'units' AND INDEX_NAME = 'idx_units_building'
);
SET @sql = IF(@idx = 0, 'ALTER TABLE units ADD INDEX idx_units_building (building_id)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS onboarding_tokens (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    unit_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    used_at DATETIME NULL,
    created_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_onboarding_token_hash (token_hash),
    KEY idx_onboarding_unit (unit_id),
    CONSTRAINT fk_onboarding_unit FOREIGN KEY (unit_id)
        REFERENCES units (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tenant_applications (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    unit_id INT NOT NULL,
    token_id INT UNSIGNED NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    id_number VARCHAR(50) NULL,
    emergency_contact_name VARCHAR(100) NULL,
    emergency_contact_phone VARCHAR(20) NULL,
    occupants INT NOT NULL DEFAULT 1,
    notes TEXT NULL,
    status ENUM('submitted', 'reviewing', 'approved', 'rejected') NOT NULL DEFAULT 'submitted',
    rejection_reason VARCHAR(500) NULL,
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    tenant_id INT NULL,
    user_id INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_applications_status (status, created_at),
    KEY idx_applications_unit (unit_id),
    KEY idx_applications_email (email),
    CONSTRAINT fk_applications_unit FOREIGN KEY (unit_id)
        REFERENCES units (id) ON DELETE CASCADE,
    CONSTRAINT fk_applications_token FOREIGN KEY (token_id)
        REFERENCES onboarding_tokens (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS application_documents (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id INT UNSIGNED NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    file_url VARCHAR(500) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_application_documents_application (application_id),
    CONSTRAINT fk_application_documents_application FOREIGN KEY (application_id)
        REFERENCES tenant_applications (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
