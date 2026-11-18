-- Phase 3 - Rent obligations, cash and EFT - 2026-11-18
--
-- Adds the approved rent/payment model on top of the Phase 2 tenancy:
--   * contractual per-obligation due dates (individual to each lease)
--   * a payment state machine (submitted, pending verification, paid,
--     rejected, reversed) with cash and EFT as the only methods
--   * payment attempts with EFT proof-of-payment URLs
--   * database-backed, locked, sequential receipts (never random)
--   * auditable receipt voiding instead of silent renumbering
--
-- Additive and safe to re-run.

-- ---------------------------------------------------------------------------
-- tenants: contractual rent due day (1-31, clamped to month length)
-- ---------------------------------------------------------------------------
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE tenants ADD COLUMN rent_due_day TINYINT UNSIGNED NULL AFTER monthly_rent',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'rent_due_day'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- rent_records: contractual due date, lease link and payment state machine
-- ---------------------------------------------------------------------------
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE rent_records ADD COLUMN due_date DATE NULL AFTER month_for',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'rent_records' AND COLUMN_NAME = 'due_date'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE rent_records ADD COLUMN lease_id INT UNSIGNED NULL AFTER unit_id',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'rent_records' AND COLUMN_NAME = 'lease_id'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE rent_records ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'rent_records' AND COLUMN_NAME = 'updated_at'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Expand the state machine. Existing values are a subset of the new enum.
ALTER TABLE rent_records MODIFY COLUMN status
    ENUM('Pending','Overdue','Submitted','PendingVerification','Paid','Rejected','Reversed')
    NOT NULL DEFAULT 'Pending';

-- Every existing obligation gets a due date. It is not a new financial event;
-- it simply anchors the existing month to a contractual date until management
-- sets a tenant-specific due day and regenerates.
UPDATE rent_records SET due_date = month_for WHERE due_date IS NULL;

-- ---------------------------------------------------------------------------
-- rent_payments: one row per payment attempt / verification event
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rent_payments (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    rent_record_id INT NOT NULL,
    tenant_id INT NOT NULL,
    method ENUM('cash','eft') NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    status ENUM('submitted','verified','rejected','reversed') NOT NULL DEFAULT 'submitted',
    proof_url VARCHAR(500) NULL,
    reference VARCHAR(100) NULL,
    submitted_by INT NULL,
    submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_by INT NULL,
    verified_at DATETIME NULL,
    rejection_reason VARCHAR(500) NULL,
    reversed_by INT NULL,
    reversed_at DATETIME NULL,
    reversal_reason VARCHAR(500) NULL,
    receipt_id INT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_rent_payments_record (rent_record_id, status),
    KEY idx_rent_payments_tenant (tenant_id, submitted_at),
    CONSTRAINT fk_rent_payments_record FOREIGN KEY (rent_record_id)
        REFERENCES rent_records (id) ON DELETE CASCADE,
    CONSTRAINT fk_rent_payments_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- receipts: immutable record of each issued receipt
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS receipts (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    receipt_number VARCHAR(30) NOT NULL,
    rent_record_id INT NOT NULL,
    payment_id INT UNSIGNED NULL,
    tenant_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    method ENUM('cash','eft') NOT NULL,
    status ENUM('issued','voided') NOT NULL DEFAULT 'issued',
    issued_by INT NULL,
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    voided_by INT NULL,
    voided_at DATETIME NULL,
    void_reason VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_receipts_number (receipt_number),
    KEY idx_receipts_record (rent_record_id),
    KEY idx_receipts_tenant (tenant_id, issued_at),
    CONSTRAINT fk_receipts_record FOREIGN KEY (rent_record_id)
        REFERENCES rent_records (id) ON DELETE CASCADE,
    CONSTRAINT fk_receipts_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_receipts_payment FOREIGN KEY (payment_id)
        REFERENCES rent_payments (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- receipt_sequences: locked, per-year sequential receipt counter
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS receipt_sequences (
    year SMALLINT UNSIGNED NOT NULL,
    last_number INT UNSIGNED NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (year)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
