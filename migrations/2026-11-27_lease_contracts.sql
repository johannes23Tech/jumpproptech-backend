-- Lease Contract Generator - 2026-11-27
--
-- Adds the wizard/contract persistence layer alongside the existing versioned
-- `leases` records in 2026-11-18_phase2_leases_deposits.sql.
--
-- CRITICAL POLICY: the platform must NOT invent lease clauses. All legal
-- wording comes from a row in `lease_contract_templates`, which must be
-- supplied/approved by management and reviewed by a qualified South African
-- legal professional. The NEW-LEASE seed below is deliberately a DRAFT
-- structural outline with no legal wording; the RENEWAL seed contains only the
-- user-supplied approved wording. api/generate_lease.php remains retired (410).
--
-- Additive and safe to re-run. Existing tables are untouched.

-- ---------------------------------------------------------------------------
-- lease_contract_templates: management-supplied legal wording only
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lease_contract_templates (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(150) NOT NULL,
    template_type ENUM('new_lease', 'renewal') NOT NULL,
    content LONGTEXT NOT NULL,
    approval_status ENUM('approved', 'pending') NOT NULL DEFAULT 'pending',
    is_default TINYINT(1) NOT NULL DEFAULT 0,
    created_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_contract_templates_type_status (template_type, approval_status),
    CONSTRAINT fk_contract_templates_created_by FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- lease_contracts: one row per contract version
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lease_contracts (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    contract_reference VARCHAR(40) NOT NULL,
    landlord_id INT NULL,
    tenant_id INT NOT NULL,
    unit_id INT NOT NULL,
    template_id INT UNSIGNED NULL,
    previous_contract_id INT UNSIGNED NULL,
    version INT NOT NULL DEFAULT 1,
    contract_type ENUM('new_lease', 'renewal') NOT NULL DEFAULT 'new_lease',
    status ENUM('draft', 'ready_for_review', 'issued', 'awaiting_signature',
                'partially_signed', 'fully_signed', 'active', 'expired',
                'terminated', 'cancelled') NOT NULL DEFAULT 'draft',
    agreement_date DATE NULL,
    commencement_date DATE NOT NULL,
    termination_date DATE NOT NULL,
    monthly_rent DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    deposit_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    payment_due_day TINYINT NULL,
    payment_frequency VARCHAR(40) NULL,
    escalation_percentage DECIMAL(5,2) NULL,
    escalation_date DATE NULL,
    notice_period VARCHAR(100) NULL,
    lease_duration VARCHAR(100) NULL,
    payload JSON NULL,
    generated_document_url VARCHAR(500) NULL,
    signed_document_url VARCHAR(500) NULL,
    issued_at DATETIME NULL,
    landlord_signed_at DATETIME NULL,
    tenant_signed_at DATETIME NULL,
    activated_at DATETIME NULL,
    terminated_at DATETIME NULL,
    archived_at DATETIME NULL,
    termination_reason VARCHAR(500) NULL,
    created_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_lease_contracts_reference (contract_reference),
    KEY idx_contracts_status (status),
    KEY idx_contracts_tenant (tenant_id),
    KEY idx_contracts_unit (unit_id),
    KEY idx_contracts_template (template_id),
    CONSTRAINT fk_contracts_landlord FOREIGN KEY (landlord_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_contracts_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_contracts_unit FOREIGN KEY (unit_id)
        REFERENCES units (id) ON DELETE CASCADE,
    CONSTRAINT fk_contracts_template FOREIGN KEY (template_id)
        REFERENCES lease_contract_templates (id) ON DELETE SET NULL,
    CONSTRAINT fk_contracts_previous FOREIGN KEY (previous_contract_id)
        REFERENCES lease_contracts (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Defensive index guards for databases that already contain a partial table
-- from an earlier deployment (same information_schema + PREPARE convention as
-- the other migrations).
SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE lease_contracts ADD INDEX idx_contracts_status (status)',
        'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lease_contracts'
      AND INDEX_NAME = 'idx_contracts_status'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE lease_contracts ADD INDEX idx_contracts_tenant (tenant_id)',
        'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lease_contracts'
      AND INDEX_NAME = 'idx_contracts_tenant'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE lease_contracts ADD INDEX idx_contracts_unit (unit_id)',
        'SELECT 1')
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lease_contracts'
      AND INDEX_NAME = 'idx_contracts_unit'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ---------------------------------------------------------------------------
-- lease_contract_clauses: optional per-contract clause overrides
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lease_contract_clauses (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    contract_id INT UNSIGNED NOT NULL,
    clause_number INT NOT NULL,
    clause_title VARCHAR(200) NOT NULL,
    clause_content LONGTEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    display_order INT NOT NULL DEFAULT 0,
    source ENUM('template', 'custom') NOT NULL DEFAULT 'custom',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_contract_clauses_contract (contract_id, display_order),
    CONSTRAINT fk_contract_clauses_contract FOREIGN KEY (contract_id)
        REFERENCES lease_contracts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- lease_contract_signatures: one record per signer role per contract
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lease_contract_signatures (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    contract_id INT UNSIGNED NOT NULL,
    signer_role ENUM('landlord', 'tenant', 'additional_tenant', 'witness_1', 'witness_2') NOT NULL,
    signer_name VARCHAR(100) NOT NULL,
    signature_method ENUM('in_person', 'electronic', 'scanned') NOT NULL DEFAULT 'in_person',
    evidence_url VARCHAR(500) NULL,
    signed_at DATETIME NOT NULL,
    recorded_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_contract_signature_role (contract_id, signer_role),
    CONSTRAINT fk_contract_signatures_contract FOREIGN KEY (contract_id)
        REFERENCES lease_contracts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- lease_contract_versions: document history for a contract
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lease_contract_versions (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    contract_id INT UNSIGNED NOT NULL,
    version_number INT NOT NULL,
    previous_contract_id INT UNSIGNED NULL,
    document_url VARCHAR(500) NULL,
    change_summary VARCHAR(500) NULL,
    created_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_contract_versions_contract (contract_id, version_number),
    CONSTRAINT fk_contract_versions_contract FOREIGN KEY (contract_id)
        REFERENCES lease_contracts (id) ON DELETE CASCADE,
    CONSTRAINT fk_contract_versions_previous FOREIGN KEY (previous_contract_id)
        REFERENCES lease_contracts (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- Seed templates (idempotent). No legal wording is authored by the platform.
-- ---------------------------------------------------------------------------

-- NEW LEASE: deliberately NOT approved and contains no clauses. Management
-- must replace this outline with reviewed wording before it can be issued.
INSERT INTO lease_contract_templates
    (name, template_type, content, approval_status, is_default, created_by, created_at, updated_at)
SELECT 'New Lease - DRAFT structural outline (pending legal approval)',
       'new_lease',
       'DRAFT — PENDING LEGAL APPROVAL — DO NOT ISSUE\n\n'
       'NEW LEASE - STRUCTURAL OUTLINE ONLY\n\n'
       'This template is a placeholder. The platform has not authored any legal wording or clauses.\n'
       'Management must supply the approved lease wording and a qualified South African legal\n'
       'professional must review it before this template may be approved or issued.\n\n'
       'Outline (headings only - no clauses):\n'
       '1. Parties\n'
       '2. Property and unit\n'
       '3. Lease period\n'
       '4. Rental and payment terms\n'
       '5. Deposit\n'
       '6. Utilities and occupancy\n'
       '7. Maintenance\n'
       '8. House rules\n'
       '9. Notice / termination\n'
       '10. Signatures\n',
       'pending', 1, NULL, NOW(), NOW()
FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM lease_contract_templates
    WHERE name = 'New Lease - DRAFT structural outline (pending legal approval)'
);

-- RENEWAL: user-supplied wording, reproduced verbatim. Do not change it.
INSERT INTO lease_contract_templates
    (name, template_type, content, approval_status, is_default, created_by, created_at, updated_at)
SELECT 'Residential Lease Renewal Agreement (approved)',
       'renewal',
       'JUMP LIVING\n'
       'RESIDENTIAL LEASE RENEWAL AGREEMENT\n\n'
       'Renewal Reference: {{renewal_reference}}\n'
       'Original Lease Reference: {{original_contract_reference}}\n'
       'Renewal Agreement Date: {{renewal_agreement_date}}\n\n'
       'This Residential Lease Renewal Agreement ("Renewal Agreement") is entered into by the parties to the original Residential Lease Agreement identified below.\n\n'
       '## 1. PARTIES\n\n'
       '### Landlord\n\n'
       'Name: {{landlord_full_name}}\n'
       'ID / Registration Number: {{landlord_id_number}}\n'
       'Contact Number: {{landlord_phone}}\n'
       'Email: {{landlord_email}}\n\n'
       '### Tenant\n\n'
       'Name: {{tenant_full_name}}\n'
       'ID / Passport Number: {{tenant_id_number}}\n'
       'Contact Number: {{tenant_phone}}\n'
       'Email: {{tenant_email}}\n\n'
       '## 2. ORIGINAL LEASE DETAILS\n\n'
       'Original Contract Reference: {{original_contract_reference}}\n\n'
       'Property Address: {{property_address}}\n\n'
       'Unit Number: {{unit_number}}\n\n'
       'Original Lease Commencement Date: {{original_start_date}}\n\n'
       'Original Lease Expiry Date: {{original_end_date}}\n\n'
       'The parties confirm that they previously entered into a Residential Lease Agreement relating to the above premises.\n\n'
       'The parties now wish to renew or extend their rental arrangement on the terms set out in this Renewal Agreement.\n\n'
       '## 3. RENEWAL PERIOD\n\n'
       'The renewed lease shall commence on:\n\n'
       '{{renewal_start_date}}\n\n'
       'The renewed lease shall terminate on:\n\n'
       '{{renewal_end_date}}\n\n'
       'Renewal Duration: {{renewal_duration}}\n\n'
       'Renewal Type: {{renewal_type}}\n\n'
       'The renewal period shall be subject to the terms of this Renewal Agreement and the provisions of the original lease that remain applicable and have not been amended.\n\n'
       '## 4. REVISED RENTAL AMOUNT\n\n'
       'The monthly rental for the renewal period shall be:\n\n'
       '{{renewed_monthly_rent}} ZAR\n\n'
       'Rental Due Date: {{rent_due_day}}\n\n'
       'Previous Monthly Rental: {{previous_monthly_rent}}\n\n'
       'Rental Increase: {{rental_increase_percentage}}%\n\n'
       'Effective Date of Revised Rental: {{rental_effective_date}}\n\n'
       'The revised rental shall become payable from the effective date specified above.\n\n'
       'All payments must be made using the payment method agreed between the parties, subject to any updated payment instructions provided in writing.\n\n'
       '## 5. DEPOSIT\n\n'
       'Existing Deposit Amount: {{existing_deposit_amount}}\n\n'
       'Additional Deposit Required: {{additional_deposit_amount}}\n\n'
       'Total Deposit: {{renewed_deposit_amount}}\n\n'
       'Deposit Status: {{deposit_status}}\n\n'
       'Any additional deposit shall be payable by:\n\n'
       '{{additional_deposit_due_date}}\n\n'
       'The existing deposit shall remain subject to the original agreement and applicable law, unless otherwise lawfully agreed in writing.\n\n'
       'The deposit shall not automatically be treated as rental payment.\n\n'
       '## 6. UPDATED TERMS\n\n'
       'The following terms are amended or updated for the renewal period:\n\n'
       'Utilities: {{updated_utility_terms}}\n\n'
       'Payment Method: {{updated_payment_method}}\n\n'
       'Occupancy: {{updated_occupancy_terms}}\n\n'
       'House Rules: {{updated_house_rules}}\n\n'
       'Maintenance Arrangements: {{updated_maintenance_terms}}\n\n'
       'Notice Period: {{updated_notice_period}}\n\n'
       'Other Conditions: {{updated_special_conditions}}\n\n'
       '## 7. CONTINUATION OF ORIGINAL AGREEMENT\n\n'
       'Except for the specific changes recorded in this Renewal Agreement, the remaining provisions of the original lease shall continue to apply to the renewed tenancy, to the extent lawful and applicable.\n\n'
       'This Renewal Agreement shall be read together with the original lease.\n\n'
       'If a provision of the original lease conflicts with a specific amendment in this Renewal Agreement, the amended provision shall prevail to the extent of the conflict, subject to applicable law.\n\n'
       '## 8. PROPERTY CONDITION\n\n'
       'The parties acknowledge the existing condition of the premises, subject to any updated inspection report or additional documentation attached to this Renewal Agreement.\n\n'
       'New Inspection Report: {{inspection_report_reference}}\n\n'
       'Additional Condition Notes:\n\n'
       '{{condition_notes}}\n\n'
       '## 9. ACKNOWLEDGEMENT\n\n'
       'The parties acknowledge that they have reviewed and agreed to the renewal terms.\n\n'
       'The renewal is subject to applicable South African legislation and the lawful rights and obligations of the parties.\n\n'
       '## 10. SIGNATURES\n\n'
       '### LANDLORD\n\n'
       'Full Name: {{landlord_full_name}}\n\n'
       'Signature: ______________________________\n\n'
       'Date: ______________________________\n\n'
       '### TENANT\n\n'
       'Full Name: {{tenant_full_name}}\n\n'
       'Signature: ______________________________\n\n'
       'Date: ______________________________\n\n'
       '### ADDITIONAL TENANT\n\n'
       'Full Name: {{additional_tenant_name}}\n\n'
       'Signature: ______________________________\n\n'
       'Date: ______________________________\n\n'
       '### WITNESS\n\n'
       'Full Name: ______________________________\n\n'
       'Signature: ______________________________\n\n'
       'Date: ______________________________\n\n'
       'Original Agreement Reference: {{original_contract_reference}}\n'
       'Renewal Agreement Reference: {{renewal_reference}}\n',
       'approved', 1, NULL, NOW(), NOW()
FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM lease_contract_templates
    WHERE name = 'Residential Lease Renewal Agreement (approved)'
);
