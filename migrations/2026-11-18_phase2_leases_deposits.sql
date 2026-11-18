-- Phase 2 - Tenancies, leases and deposits - 2026-11-18
--
-- Adds the approved tenancy lifecycle on top of the Phase 1 tenant record:
--   * tenancy status, move-in/move-out and termination fields
--   * versioned lease records (documents are management-supplied; no clauses
--     are generated or invented by the platform)
--   * signature records per lease version
--   * an append-only deposit ledger with deductions and refunds
--   * move-in / move-out / routine inspections with supporting photos
--
-- Additive and safe to re-run. The existing tenants row remains the tenant
-- identity; leases hold the versioned contract history.

-- ---------------------------------------------------------------------------
-- tenants: tenancy lifecycle
-- ---------------------------------------------------------------------------
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        "ALTER TABLE tenants ADD COLUMN status ENUM('pending','active','notice','ended') NOT NULL DEFAULT 'pending' AFTER unit_id",
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'status'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE tenants ADD COLUMN move_in_date DATE NULL AFTER lease_end',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'move_in_date'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE tenants ADD COLUMN move_out_date DATE NULL AFTER move_in_date',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'move_out_date'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE tenants ADD COLUMN terminated_at DATETIME NULL AFTER move_out_date',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'terminated_at'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE tenants ADD COLUMN termination_reason VARCHAR(500) NULL AFTER terminated_at',
        'SELECT 1')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'termination_reason'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Existing linked tenants become active; unlinked self-registered profiles stay pending.
UPDATE tenants SET status = 'active' WHERE unit_id IS NOT NULL AND status = 'pending';

-- ---------------------------------------------------------------------------
-- leases: one row per contract version
-- ---------------------------------------------------------------------------
-- Older deployments (and the QA clone) can contain a legacy, unused `leases`
-- table with different columns. Preserve it as `leases_legacy` once, then
-- create the versioned table. Runs only when `leases` exists without `version`.
SET @lease_table_exists = (
    SELECT COUNT(*) FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leases'
);
SET @lease_has_version = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leases' AND COLUMN_NAME = 'version'
);
SET @sql = IF(@lease_table_exists = 1 AND @lease_has_version = 0,
    'RENAME TABLE leases TO leases_legacy',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS leases (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id INT NOT NULL,
    unit_id INT NOT NULL,
    version INT NOT NULL DEFAULT 1,
    status ENUM('draft','pending_signature','active','superseded','expired','terminated')
        NOT NULL DEFAULT 'draft',
    supersedes_id INT UNSIGNED NULL,
    title VARCHAR(150) NULL,
    template_reference VARCHAR(150) NULL,
    document_url VARCHAR(500) NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    monthly_rent DECIMAL(10,2) NOT NULL,
    deposit_required DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    notes TEXT NULL,
    created_by INT NULL,
    activated_at DATETIME NULL,
    terminated_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_leases_tenant_version (tenant_id, version),
    KEY idx_leases_unit_status (unit_id, status),
    KEY idx_leases_tenant_status (tenant_id, status),
    CONSTRAINT fk_leases_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_leases_unit FOREIGN KEY (unit_id)
        REFERENCES units (id) ON DELETE CASCADE,
    CONSTRAINT fk_leases_supersedes FOREIGN KEY (supersedes_id)
        REFERENCES leases (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- lease_signatures: one record per signing party per lease version
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lease_signatures (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    lease_id INT UNSIGNED NOT NULL,
    party ENUM('tenant','landlord') NOT NULL,
    signer_name VARCHAR(100) NOT NULL,
    method ENUM('in_person','electronic','scanned') NOT NULL DEFAULT 'in_person',
    evidence_url VARCHAR(500) NULL,
    signed_at DATETIME NOT NULL,
    recorded_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_lease_signature_party (lease_id, party),
    CONSTRAINT fk_lease_signatures_lease FOREIGN KEY (lease_id)
        REFERENCES leases (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- deposit_transactions: append-only deposit ledger
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS deposit_transactions (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id INT NOT NULL,
    lease_id INT UNSIGNED NULL,
    type ENUM('received','deduction','refund','adjustment') NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    method ENUM('cash','eft','other') NULL,
    reference VARCHAR(100) NULL,
    notes TEXT NULL,
    recorded_by INT NULL,
    recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_deposit_transactions_tenant (tenant_id, recorded_at),
    CONSTRAINT fk_deposit_transactions_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_deposit_transactions_lease FOREIGN KEY (lease_id)
        REFERENCES leases (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- inspections: move-in, move-out and routine
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inspections (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id INT NOT NULL,
    unit_id INT NOT NULL,
    lease_id INT UNSIGNED NULL,
    type ENUM('move_in','move_out','routine') NOT NULL,
    status ENUM('draft','completed') NOT NULL DEFAULT 'draft',
    inspected_at DATE NULL,
    inspected_by INT NULL,
    notes TEXT NULL,
    created_by INT NULL,
    completed_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_inspections_tenant_type (tenant_id, type),
    CONSTRAINT fk_inspections_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_inspections_unit FOREIGN KEY (unit_id)
        REFERENCES units (id) ON DELETE CASCADE,
    CONSTRAINT fk_inspections_lease FOREIGN KEY (lease_id)
        REFERENCES leases (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inspection_photos (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    inspection_id INT UNSIGNED NOT NULL,
    file_url VARCHAR(500) NOT NULL,
    caption VARCHAR(150) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_inspection_photos_inspection (inspection_id),
    CONSTRAINT fk_inspection_photos_inspection FOREIGN KEY (inspection_id)
        REFERENCES inspections (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
