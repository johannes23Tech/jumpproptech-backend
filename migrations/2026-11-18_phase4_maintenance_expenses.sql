-- Phase 4 - Maintenance work orders and expenses - 2026-11-18
--
-- Adds the approved internal maintenance and expense model:
--   * internal technician assignment (replaces external contractor assumption)
--   * work order cost, completion notes and resolved timestamp
--   * suppliers (vendors) and per-property/category budgets
--   * one-manager expense approval workflow (pending -> approved/rejected)
--
-- Additive and safe to re-run.

-- ---------------------------------------------------------------------------
-- suppliers: company-approved vendors for purchases and maintenance
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suppliers (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    trade VARCHAR(50) NULL,
    contact_name VARCHAR(100) NULL,
    phone VARCHAR(20) NULL,
    email VARCHAR(150) NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- budgets: per-property, per-category spending plans
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS budgets (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    property_id INT NOT NULL,
    category VARCHAR(50) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    created_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_budgets_property FOREIGN KEY (property_id)
        REFERENCES properties (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- maintenance: internal technician assignment and work order cost
-- ---------------------------------------------------------------------------
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE maintenance ADD COLUMN technician_id INT NULL AFTER contractor_id',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'maintenance' AND COLUMN_NAME = 'technician_id'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE maintenance ADD COLUMN actual_cost DECIMAL(10,2) NULL AFTER technician_id',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'maintenance' AND COLUMN_NAME = 'actual_cost'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE maintenance ADD COLUMN completion_notes TEXT NULL AFTER actual_cost',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'maintenance' AND COLUMN_NAME = 'completion_notes'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE maintenance ADD COLUMN resolved_at DATETIME NULL AFTER completion_notes',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'maintenance' AND COLUMN_NAME = 'resolved_at'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Ensure technician_id is signed to match users.id (FK compatibility).
SET @sql = (
    SELECT IF(COUNT(*) > 0,
        'ALTER TABLE maintenance MODIFY COLUMN technician_id INT NULL',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'maintenance' AND COLUMN_NAME = 'technician_id' AND COLUMN_TYPE = 'int unsigned'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Internal technician references a staff user.
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE maintenance ADD CONSTRAINT fk_maintenance_technician FOREIGN KEY (technician_id) REFERENCES users (id)',
        'DO 0')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'maintenance' AND CONSTRAINT_NAME = 'fk_maintenance_technician'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- expenses: supplier link and one-manager approval workflow
-- ---------------------------------------------------------------------------
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN supplier_id INT UNSIGNED NULL AFTER property_id',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'supplier_id'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN approval_status ENUM(\'pending\',\'approved\',\'rejected\') NOT NULL DEFAULT \'pending\' AFTER description',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'approval_status'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN approved_by INT NULL AFTER approval_status',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'approved_by'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Ensure budgets.created_by is signed to match users.id.
SET @sql = (
    SELECT IF(COUNT(*) > 0,
        'ALTER TABLE budgets MODIFY COLUMN created_by INT NULL',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'budgets' AND COLUMN_NAME = 'created_by' AND COLUMN_TYPE = 'int unsigned'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN approved_at DATETIME NULL AFTER approved_by',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'approved_at'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN attachment_url VARCHAR(500) NULL AFTER approved_at',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'attachment_url'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD CONSTRAINT fk_expenses_supplier FOREIGN KEY (supplier_id) REFERENCES suppliers (id)',
        'DO 0')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND CONSTRAINT_NAME = 'fk_expenses_supplier'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD CONSTRAINT fk_expenses_approved_by FOREIGN KEY (approved_by) REFERENCES users (id)',
        'DO 0')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND CONSTRAINT_NAME = 'fk_expenses_approved_by'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
