<?php
// api/deposits.php
//
// Deposit ledger for a tenancy. Every movement is append-only and audited.
//
// GET  ?tenant_id=<id>  ledger plus computed position (permission: deposits.view)
// POST { id|tenant_id, action } (permission: deposits.manage)

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/leases.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

if ($method === 'GET') {
    permission_require($actor, 'deposits.view');

    $tenantId = filter_var($_GET['tenant_id'] ?? 0, FILTER_VALIDATE_INT);

    if ($tenantId !== false && $tenantId !== null && $tenantId > 0) {
        $stmt = $conn->prepare(
            "SELECT t.id, t.name, t.deposit, t.status, u.unit_number, p.name AS property_name
             FROM tenants t
             LEFT JOIN units u ON t.unit_id = u.id
             LEFT JOIN properties p ON u.property_id = p.id
             WHERE t.id = :id LIMIT 1"
        );
        $stmt->execute([':id' => $tenantId]);
        $tenant = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tenant) {
            security_json_response(404, ['message' => 'Tenant not found.']);
        }

        $tenant['summary'] = deposit_summary($conn, (int) $tenantId);
        $tenant['transactions'] = deposit_transactions($conn, (int) $tenantId);

        echo json_encode($tenant);
        exit();
    }

    // Portfolio view: one summary per tenant, without dumping every ledger row.
    $stmt = $conn->query(
        "SELECT t.id, t.name, t.email, t.deposit, t.status, u.unit_number, p.name AS property_name
         FROM tenants t
         LEFT JOIN units u ON t.unit_id = u.id
         LEFT JOIN properties p ON u.property_id = p.id
         WHERE t.unit_id IS NOT NULL
         ORDER BY t.name ASC"
    );

    $rows = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $row['summary'] = deposit_summary($conn, (int) $row['id']);
        $rows[] = $row;
    }

    echo json_encode($rows);
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'deposits.manage');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $tenantId = filter_var($data->tenant_id ?? 0, FILTER_VALIDATE_INT);
    if ($tenantId === false || $tenantId < 1) {
        security_json_response(400, ['message' => 'A valid tenant is required.']);
    }

    $tenantStmt = $conn->prepare('SELECT id, unit_id FROM tenants WHERE id = :id LIMIT 1');
    $tenantStmt->execute([':id' => $tenantId]);
    $tenant = $tenantStmt->fetch(PDO::FETCH_ASSOC);
    if (!$tenant) {
        security_json_response(404, ['message' => 'Tenant not found.']);
    }

    $type = isset($data->type) && is_string($data->type) ? strtolower(trim($data->type)) : '';
    if (!in_array($type, ['received', 'deduction', 'refund', 'adjustment'], true)) {
        security_json_response(400, ['message' => 'Deposit type must be received, deduction, refund or adjustment.']);
    }

    $amount = filter_var($data->amount ?? null, FILTER_VALIDATE_FLOAT);
    if ($amount === false || $amount <= 0) {
        security_json_response(400, ['message' => 'A positive amount is required.']);
    }

    $methodName = isset($data->method) && is_string($data->method) ? strtolower(trim($data->method)) : '';
    if ($methodName !== '' && !in_array($methodName, ['cash', 'eft', 'other'], true)) {
        security_json_response(400, ['message' => 'Invalid payment method.']);
    }
    if ($type === 'received' && $methodName === '') {
        security_json_response(400, ['message' => 'A payment method is required for a deposit received.']);
    }

    $reference = security_clean_text($data->reference ?? '', 100);
    $notes = security_clean_text($data->notes ?? '', 2000);

    $leaseId = filter_var($data->lease_id ?? 0, FILTER_VALIDATE_INT);
    $leaseId = ($leaseId !== false && $leaseId !== null && $leaseId > 0) ? (int) $leaseId : null;

    if (in_array($type, ['deduction', 'refund'], true)) {
        $summary = deposit_summary($conn, (int) $tenantId);
        if ($amount > $summary['balance']) {
            security_json_response(409, [
                'message' => 'A ' . $type . ' cannot exceed the held deposit balance of R '
                    . number_format($summary['balance'], 2, '.', '') . '.',
            ]);
        }
    }

    try {
        $conn->beginTransaction();

        $stmt = $conn->prepare(
            "INSERT INTO deposit_transactions
                (tenant_id, lease_id, type, amount, method, reference, notes, recorded_by, recorded_at)
             VALUES
                (:tenant_id, :lease_id, :type, :amount, :method, :reference, :notes, :recorded_by, NOW())"
        );
        $stmt->execute([
            ':tenant_id' => (int) $tenantId,
            ':lease_id' => $leaseId,
            ':type' => $type,
            ':amount' => $amount,
            ':method' => $methodName !== '' ? $methodName : null,
            ':reference' => $reference !== '' ? $reference : null,
            ':notes' => $notes !== '' ? $notes : null,
            ':recorded_by' => (int) $user->user_id,
        ]);
        $transactionId = (int) $conn->lastInsertId();

        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Deposit transaction failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The deposit movement could not be recorded.']);
    }

    audit_log($conn, (int) $user->user_id, 'deposit.' . $type, [
        'entity_type' => 'tenant',
        'entity_id' => (int) $tenantId,
        'meta' => ['amount' => $amount, 'method' => $methodName ?: null, 'transaction_id' => $transactionId],
    ]);

    security_json_response(201, [
        'message' => 'Deposit movement recorded.',
        'id' => $transactionId,
        'summary' => deposit_summary($conn, (int) $tenantId),
    ]);
}

security_json_response(405, ['message' => 'Method not allowed.']);
