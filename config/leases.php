<?php
// config/leases.php
//
// Helpers for tenancy, lease-version and deposit calculations.
//
// Lease documents are supplied by management. The platform stores and versions
// the document; it never generates legal clauses on its own.

require_once __DIR__ . '/security.php';

/**
 * The most relevant lease for a tenant: the active one if present, otherwise
 * the newest version.
 *
 * @return array<string,mixed>|null
 */
function lease_current(PDO $conn, int $tenantId): ?array
{
    $stmt = $conn->prepare(
        "SELECT l.*, u.unit_number, p.name AS property_name
         FROM leases l
         JOIN units u ON l.unit_id = u.id
         JOIN properties p ON u.property_id = p.id
         WHERE l.tenant_id = :tenant_id
         ORDER BY (l.status = 'active') DESC, l.version DESC
         LIMIT 1"
    );
    $stmt->execute([':tenant_id' => $tenantId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row ?: null;
}

/**
 * @return array<int,array<string,mixed>>
 */
function lease_signatures(PDO $conn, int $leaseId): array
{
    $stmt = $conn->prepare(
        'SELECT id, party, signer_name, method, evidence_url, signed_at, created_at
         FROM lease_signatures
         WHERE lease_id = :lease_id
         ORDER BY signed_at ASC'
    );
    $stmt->execute([':lease_id' => $leaseId]);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function lease_next_version(PDO $conn, int $tenantId): int
{
    $stmt = $conn->prepare('SELECT COALESCE(MAX(version), 0) + 1 FROM leases WHERE tenant_id = :tenant_id');
    $stmt->execute([':tenant_id' => $tenantId]);

    return (int) $stmt->fetchColumn();
}

/**
 * Create the next draft lease version for a tenant. Any currently active lease
 * stays active until the new version is explicitly activated.
 */
function lease_create_draft(
    PDO $conn,
    int $tenantId,
    int $unitId,
    string $startDate,
    string $endDate,
    float $monthlyRent,
    float $depositRequired,
    ?int $createdBy = null,
    ?string $title = null,
    ?string $templateReference = null,
    ?string $notes = null
): int {
    $current = lease_current($conn, $tenantId);
    $supersedesId = ($current !== null && $current['status'] === 'active') ? (int) $current['id'] : null;

    $stmt = $conn->prepare(
        "INSERT INTO leases
            (tenant_id, unit_id, version, status, supersedes_id, title, template_reference,
             start_date, end_date, monthly_rent, deposit_required, notes, created_by)
         VALUES
            (:tenant_id, :unit_id, :version, 'draft', :supersedes_id, :title, :template_reference,
             :start_date, :end_date, :monthly_rent, :deposit_required, :notes, :created_by)"
    );
    $stmt->execute([
        ':tenant_id' => $tenantId,
        ':unit_id' => $unitId,
        ':version' => lease_next_version($conn, $tenantId),
        ':supersedes_id' => $supersedesId,
        ':title' => $title !== null && $title !== '' ? $title : null,
        ':template_reference' => $templateReference !== null && $templateReference !== '' ? $templateReference : null,
        ':start_date' => $startDate,
        ':end_date' => $endDate,
        ':monthly_rent' => $monthlyRent,
        ':deposit_required' => $depositRequired,
        ':notes' => $notes !== null && $notes !== '' ? $notes : null,
        ':created_by' => $createdBy,
    ]);

    return (int) $conn->lastInsertId();
}

/**
 * Deposit position for a tenant.
 *
 * Balance = received + adjustments - deductions - refunds.
 *
 * @return array{required:float,received:float,deductions:float,refunds:float,adjustments:float,balance:float,status:string}
 */
function deposit_summary(PDO $conn, int $tenantId): array
{
    $required = 0.0;

    $lease = lease_current($conn, $tenantId);
    if ($lease !== null && $lease['status'] !== 'draft') {
        $required = (float) $lease['deposit_required'];
    }

    if ($required <= 0.0) {
        $stmt = $conn->prepare('SELECT deposit FROM tenants WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $tenantId]);
        $required = (float) ($stmt->fetchColumn() ?: 0.0);
    }

    $stmt = $conn->prepare(
        "SELECT
            COALESCE(SUM(CASE WHEN type = 'received' THEN amount ELSE 0 END), 0) AS received,
            COALESCE(SUM(CASE WHEN type = 'deduction' THEN amount ELSE 0 END), 0) AS deductions,
            COALESCE(SUM(CASE WHEN type = 'refund' THEN amount ELSE 0 END), 0) AS refunds,
            COALESCE(SUM(CASE WHEN type = 'adjustment' THEN amount ELSE 0 END), 0) AS adjustments
         FROM deposit_transactions
         WHERE tenant_id = :tenant_id"
    );
    $stmt->execute([':tenant_id' => $tenantId]);
    $totals = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];

    $received = (float) ($totals['received'] ?? 0);
    $deductions = (float) ($totals['deductions'] ?? 0);
    $refunds = (float) ($totals['refunds'] ?? 0);
    $adjustments = (float) ($totals['adjustments'] ?? 0);
    $balance = round($received + $adjustments - $deductions - $refunds, 2);

    if ($required <= 0.0 && $received <= 0.0 && $deductions <= 0.0 && $refunds <= 0.0) {
        $status = 'not_required';
    } elseif ($received + $adjustments < $required) {
        $status = 'outstanding';
    } elseif ($balance <= 0.0 && ($received > 0.0 || $refunds > 0.0)) {
        $status = 'settled';
    } else {
        $status = 'held';
    }

    return [
        'required' => round($required, 2),
        'received' => round($received, 2),
        'deductions' => round($deductions, 2),
        'refunds' => round($refunds, 2),
        'adjustments' => round($adjustments, 2),
        'balance' => $balance,
        'status' => $status,
    ];
}

/**
 * @return array<int,array<string,mixed>>
 */
function deposit_transactions(PDO $conn, int $tenantId): array
{
    $stmt = $conn->prepare(
        'SELECT id, tenant_id, lease_id, type, amount, method, reference, notes, recorded_by, recorded_at
         FROM deposit_transactions
         WHERE tenant_id = :tenant_id
         ORDER BY recorded_at DESC, id DESC'
    );
    $stmt->execute([':tenant_id' => $tenantId]);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
