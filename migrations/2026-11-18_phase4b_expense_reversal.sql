-- Phase 4b - Expense reversal - 2026-11-18
--
-- Reversing an approved expense is append-only: the original row and its
-- approval history stay, and the reversal is recorded against the same row.
-- A reversed expense no longer counts as approved spend.
--
-- Additive and safe to re-run.

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN reversed_by INT NULL AFTER approved_at',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'reversed_by'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN reversed_at DATETIME NULL AFTER reversed_by',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'reversed_at'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD COLUMN reversal_reason VARCHAR(500) NULL AFTER reversed_at',
        'DO 0')
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND COLUMN_NAME = 'reversal_reason'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE expenses ADD CONSTRAINT fk_expenses_reversed_by FOREIGN KEY (reversed_by) REFERENCES users (id)',
        'DO 0')
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'expenses' AND CONSTRAINT_NAME = 'fk_expenses_reversed_by'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
