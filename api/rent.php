<?php
// api/rent.php
//
// Rent obligations and the cash/EFT payment state machine.
//
// GET  list rent records / arrears (permission: payments.view; tenants see
//      only their own records)
// POST action-driven:
//   record_cash  (payments.record_cash)   cash received, issues receipt
//   submit_eft   (tenant own, or payments.verify_eft) upload EFT proof
//   verify_eft   (payments.verify_eft)    proof verified, issues receipt
//   reject_eft   (payments.verify_eft)    proof rejected with a reason
//   reverse      (payments.reverse)       reverses a verified payment
//   generate     (payments.reconcile)     regenerates obligations from lease

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/rent.php';
require_once '../config/leases.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];
$isStaff = permission_is_staff($actor);

/**
 * The tenant id for the signed-in tenant account, or null for staff.
 */
function rent_tenant_id_for_user(PDO $conn, object $user, bool $isStaff): ?int
{
    if ($isStaff) {
        return null;
    }

    $stmt = $conn->prepare('SELECT id FROM tenants WHERE user_id = :user_id ORDER BY id ASC LIMIT 1');
    $stmt->execute([':user_id' => (int) $user->user_id]);
    $id = $stmt->fetchColumn();

    return $id === false ? null : (int) $id;
}

/**
 * @return array<string,mixed>|null
 */
function rent_fetch_record(PDO $conn, int $rentId): ?array
{
    $stmt = $conn->prepare(
        "SELECT r.*, t.name AS tenant_name, t.email AS tenant_email, t.user_id AS tenant_user_id,
                u.unit_number, p.name AS property_name
         FROM rent_records r
         JOIN tenants t ON r.tenant_id = t.id
         JOIN units u ON r.unit_id = u.id
         JOIN properties p ON u.property_id = p.id
         WHERE r.id = :id LIMIT 1"
    );
    $stmt->execute([':id' => $rentId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return null;
    }

    $row['effective_status'] = rent_effective_status($row);

    return $row;
}

function rent_clean_proof_url($value): ?string
{
    if (!is_string($value)) {
        return null;
    }
    $url = trim($value);
    if ($url === '') {
        return null;
    }
    if (strlen($url) > 500 || strpos($url, 'https://res.cloudinary.com/') !== 0) {
        security_json_response(400, ['message' => 'The proof of payment must be an uploaded Cloudinary file.']);
    }

    return $url;
}

$tenantAccountId = rent_tenant_id_for_user($conn, $user, $isStaff);

if (!$isStaff && $tenantAccountId === null) {
    security_json_response(403, ['message' => 'Unauthorized.']);
}

if ($method === 'GET') {
    if ($isStaff) {
        permission_require($actor, 'payments.view');
    }

    $view = isset($_GET['view']) && is_string($_GET['view']) ? strtolower(trim($_GET['view'])) : '';

    // ---------------------------------------------------------------
    // Arrears / aging view.
    // ---------------------------------------------------------------
    if ($view === 'arrears') {
        if (!$isStaff) {
            $summary = rent_arrears_for($conn, (int) $tenantAccountId);
            echo json_encode($summary);
            exit();
        }

        $stmt = $conn->query(
            "SELECT t.id, t.name, t.email, u.unit_number, p.name AS property_name
             FROM tenants t
             LEFT JOIN units u ON t.unit_id = u.id
             LEFT JOIN properties p ON u.property_id = p.id
             WHERE t.unit_id IS NOT NULL AND t.status IN ('active','notice')
             ORDER BY t.name ASC"
        );

        $rows = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $summary = rent_arrears_for($conn, (int) $row['id']);
            if ($summary['total_due'] <= 0) {
                continue;
            }
            $row['arrears'] = $summary;
            $rows[] = $row;
        }

        echo json_encode($rows);
        exit();
    }

    // ---------------------------------------------------------------
    // Standard rent register.
    // ---------------------------------------------------------------
    $sql = "SELECT r.*, t.name AS tenant_name, t.email AS tenant_email,
                   u.unit_number, p.name AS property_name,
                   (SELECT COUNT(*) FROM rent_payments rp
                     WHERE rp.rent_record_id = r.id AND rp.status = 'submitted') AS pending_proofs
            FROM rent_records r
            JOIN tenants t ON r.tenant_id = t.id
            JOIN units u ON r.unit_id = u.id
            JOIN properties p ON u.property_id = p.id";
    $params = [];

    if (!$isStaff) {
        $sql .= ' WHERE r.tenant_id = :tenant_id';
        $params[':tenant_id'] = (int) $tenantAccountId;
    }

    $sql .= ' ORDER BY r.month_for DESC, r.id DESC LIMIT 500';

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $records = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $proofStmt = $conn->prepare(
        "SELECT id, method, status, proof_url, reference, submitted_at, rejection_reason
         FROM rent_payments
         WHERE rent_record_id = :rent_id
         ORDER BY id DESC LIMIT 10"
    );

    foreach ($records as &$record) {
        $record['effective_status'] = rent_effective_status($record);
        $proofStmt->execute([':rent_id' => (int) $record['id']]);
        $record['payments'] = $proofStmt->fetchAll(PDO::FETCH_ASSOC);
    }
    unset($record);

    echo json_encode($records);
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : '';

    // Backwards compatibility with the old UI: a bare method means an
    // authorised staff member is recording a completed payment.
    if ($action === '') {
        $legacyMethod = isset($data->method) && is_string($data->method) ? strtolower(trim($data->method)) : '';
        $action = $legacyMethod === 'cash' ? 'record_cash' : 'verify_eft';
    }

    // -------------------------------------------------------------------
    // Generate obligations from the active lease.
    // -------------------------------------------------------------------
    if ($action === 'generate') {
        if (!$isStaff) {
            security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
        }
        permission_require($actor, 'payments.reconcile');

        $tenantId = filter_var($data->tenant_id ?? 0, FILTER_VALIDATE_INT);
        if ($tenantId === false || $tenantId < 1) {
            security_json_response(400, ['message' => 'A valid tenant is required.']);
        }

        $stmt = $conn->prepare('SELECT id, unit_id, rent_due_day FROM tenants WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $tenantId]);
        $tenant = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$tenant || empty($tenant['unit_id'])) {
            security_json_response(404, ['message' => 'Tenant not found or not linked to a unit.']);
        }

        $lease = lease_current($conn, (int) $tenantId);
        if ($lease === null || $lease['status'] !== 'active') {
            security_json_response(409, ['message' => 'An active lease is required before rent obligations can be generated.']);
        }

        $dueDay = !empty($tenant['rent_due_day']) ? (int) $tenant['rent_due_day'] : 1;
        $created = rent_generate_obligations(
            $conn,
            (int) $tenantId,
            (int) $tenant['unit_id'],
            (int) $lease['id'],
            (string) $lease['start_date'],
            (string) $lease['end_date'],
            (float) $lease['monthly_rent'],
            $dueDay
        );

        audit_log($conn, (int) $user->user_id, 'rent.obligations_generated', [
            'entity_type' => 'tenant',
            'entity_id' => (int) $tenantId,
            'meta' => ['created' => $created, 'lease_id' => (int) $lease['id'], 'due_day' => $dueDay],
        ]);

        security_json_response(200, ['message' => 'Rent obligations generated.', 'created' => $created]);
    }

    $rentId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($rentId === false || $rentId < 1) {
        security_json_response(400, ['message' => 'A valid rent record id is required.']);
    }

    $record = rent_fetch_record($conn, (int) $rentId);
    if (!$record) {
        security_json_response(404, ['message' => 'Rent record not found.']);
    }

    // -------------------------------------------------------------------
    // Tenant submits EFT proof of payment for their own obligation.
    // -------------------------------------------------------------------
    if ($action === 'submit_eft') {
        if ($isStaff) {
            permission_require($actor, 'payments.verify_eft');
        } elseif ((int) $record['tenant_id'] !== (int) $tenantAccountId) {
            security_json_response(403, ['message' => 'You can only submit proof for your own rent.']);
        }

        if (in_array((string) $record['status'], ['Paid'], true)) {
            security_json_response(409, ['message' => 'This rent record has already been paid.']);
        }
        if (in_array((string) $record['status'], ['Submitted', 'PendingVerification'], true)) {
            security_json_response(409, ['message' => 'A proof of payment is already awaiting verification.']);
        }

        $proofUrl = rent_clean_proof_url($data->proof_url ?? null);
        if ($proofUrl === null) {
            security_json_response(400, ['message' => 'Upload proof of payment before submitting.']);
        }

        $reference = security_clean_text($data->reference ?? '', 100);

        try {
            $conn->beginTransaction();

            $conn->prepare(
                "INSERT INTO rent_payments
                    (rent_record_id, tenant_id, method, amount, status, proof_url, reference, submitted_by, submitted_at)
                 VALUES
                    (:rent_record_id, :tenant_id, 'eft', :amount, 'submitted', :proof_url, :reference, :submitted_by, NOW())"
            )->execute([
                ':rent_record_id' => (int) $rentId,
                ':tenant_id' => (int) $record['tenant_id'],
                ':amount' => $record['amount'],
                ':proof_url' => $proofUrl,
                ':reference' => $reference !== '' ? $reference : null,
                ':submitted_by' => (int) $user->user_id,
            ]);

            $conn->prepare("UPDATE rent_records SET status = 'Submitted' WHERE id = :id AND status <> 'Paid'")
                ->execute([':id' => (int) $rentId]);

            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('EFT proof submission failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The proof of payment could not be submitted.']);
        }

        audit_log($conn, (int) $user->user_id, 'rent.eft_submitted', [
            'entity_type' => 'rent_record',
            'entity_id' => (int) $rentId,
            'meta' => ['tenant_id' => (int) $record['tenant_id']],
        ]);

        security_json_response(201, ['message' => 'Proof of payment submitted for verification.']);
    }

    // All remaining actions are staff-only.
    if (!$isStaff) {
        security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
    }

    // -------------------------------------------------------------------
    // Record a cash payment and issue a sequential receipt.
    // -------------------------------------------------------------------
    if ($action === 'record_cash' || $action === 'verify_eft') {
        if ($action === 'record_cash') {
            permission_require($actor, 'payments.record_cash');
            $methodName = 'Cash';
            $paymentMethod = 'cash';
            $paymentId = null;
        } else {
            permission_require($actor, 'payments.verify_eft');
            $methodName = 'EFT';
            $paymentMethod = 'eft';

            $proof = $conn->prepare(
                "SELECT id FROM rent_payments
                 WHERE rent_record_id = :rent_id AND method = 'eft' AND status = 'submitted'
                 ORDER BY id DESC LIMIT 1"
            );
            $proof->execute([':rent_id' => (int) $rentId]);
            $paymentId = $proof->fetchColumn();
            $paymentId = $paymentId === false ? null : (int) $paymentId;
        }

        if ((string) $record['status'] === 'Paid') {
            security_json_response(409, ['message' => 'This rent record has already been paid.']);
        }
        if ($action === 'verify_eft' && $paymentId === null) {
            security_json_response(409, ['message' => 'There is no EFT proof awaiting verification for this record.']);
        }

        try {
            $conn->beginTransaction();

            if ($action === 'record_cash') {
                $conn->prepare(
                    "INSERT INTO rent_payments
                        (rent_record_id, tenant_id, method, amount, status, submitted_by, verified_by, verified_at)
                     VALUES
                        (:rent_record_id, :tenant_id, 'cash', :amount, 'verified', :actor, :actor, NOW())"
                )->execute([
                    ':rent_record_id' => (int) $rentId,
                    ':tenant_id' => (int) $record['tenant_id'],
                    ':amount' => $record['amount'],
                    ':actor' => (int) $user->user_id,
                ]);
                $paymentId = (int) $conn->lastInsertId();
            } else {
                $conn->prepare(
                    "UPDATE rent_payments
                     SET status = 'verified', verified_by = :actor, verified_at = NOW()
                     WHERE id = :id AND status = 'submitted'"
                )->execute([':actor' => (int) $user->user_id, ':id' => $paymentId]);
            }

            $receipt = rent_issue_receipt($conn, $record, $paymentId, $paymentMethod, (int) $user->user_id);

            if ($paymentId !== null) {
                $conn->prepare('UPDATE rent_payments SET receipt_id = :receipt_id WHERE id = :id')
                    ->execute([':receipt_id' => $receipt['id'], ':id' => $paymentId]);
            }

            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('Rent payment recording failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The payment could not be recorded.']);
        }

        audit_log($conn, (int) $user->user_id, 'rent.payment_recorded', [
            'entity_type' => 'rent_record',
            'entity_id' => (int) $rentId,
            'meta' => [
                'method' => $paymentMethod,
                'payment_id' => $paymentId,
                'receipt_number' => $receipt['receipt_number'],
            ],
        ]);

        security_json_response(200, [
            'message' => 'Payment recorded.',
            'receipt_number' => $receipt['receipt_number'],
            'receipt_id' => $receipt['id'],
        ]);
    }

    // -------------------------------------------------------------------
    // Reject an EFT proof with a reason.
    // -------------------------------------------------------------------
    if ($action === 'reject_eft') {
        permission_require($actor, 'payments.verify_eft');

        $reason = security_clean_text($data->reason ?? '', 500);
        if (strlen($reason) < 3) {
            security_json_response(400, ['message' => 'A rejection reason is required.']);
        }

        $proof = $conn->prepare(
            "SELECT id FROM rent_payments
             WHERE rent_record_id = :rent_id AND method = 'eft' AND status = 'submitted'
             ORDER BY id DESC LIMIT 1"
        );
        $proof->execute([':rent_id' => (int) $rentId]);
        $paymentId = $proof->fetchColumn();

        if ($paymentId === false) {
            security_json_response(409, ['message' => 'There is no EFT proof awaiting verification for this record.']);
        }

        try {
            $conn->beginTransaction();

            $conn->prepare(
                "UPDATE rent_payments
                 SET status = 'rejected', rejection_reason = :reason, verified_by = :actor, verified_at = NOW()
                 WHERE id = :id AND status = 'submitted'"
            )->execute([':reason' => $reason, ':actor' => (int) $user->user_id, ':id' => (int) $paymentId]);

            $conn->prepare("UPDATE rent_records SET status = 'Rejected' WHERE id = :id AND status <> 'Paid'")
                ->execute([':id' => (int) $rentId]);

            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('EFT rejection failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The proof of payment could not be rejected.']);
        }

        audit_log($conn, (int) $user->user_id, 'rent.eft_rejected', [
            'entity_type' => 'rent_record',
            'entity_id' => (int) $rentId,
            'meta' => ['payment_id' => (int) $paymentId, 'reason' => $reason],
        ]);

        security_json_response(200, ['message' => 'Proof of payment rejected.']);
    }

    // -------------------------------------------------------------------
    // Reverse a verified payment and void its receipt (auditable).
    // -------------------------------------------------------------------
    if ($action === 'reverse') {
        permission_require($actor, 'payments.reverse');

        $reason = security_clean_text($data->reason ?? '', 500);
        if (strlen($reason) < 3) {
            security_json_response(400, ['message' => 'A reversal reason is required.']);
        }

        $verified = $conn->prepare(
            "SELECT id, receipt_id FROM rent_payments
             WHERE rent_record_id = :rent_id AND status = 'verified'
             ORDER BY id DESC LIMIT 1"
        );
        $verified->execute([':rent_id' => (int) $rentId]);
        $payment = $verified->fetch(PDO::FETCH_ASSOC);

        if (!$payment) {
            security_json_response(409, ['message' => 'There is no verified payment to reverse for this record.']);
        }

        try {
            $conn->beginTransaction();

            $conn->prepare(
                "UPDATE rent_payments
                 SET status = 'reversed', reversed_by = :actor, reversed_at = NOW(), reversal_reason = :reason
                 WHERE id = :id AND status = 'verified'"
            )->execute([':actor' => (int) $user->user_id, ':reason' => $reason, ':id' => (int) $payment['id']]);

            if (!empty($payment['receipt_id'])) {
                $conn->prepare(
                    "UPDATE receipts
                     SET status = 'voided', voided_by = :actor, voided_at = NOW(), void_reason = :reason
                     WHERE id = :id AND status = 'issued'"
                )->execute([':actor' => (int) $user->user_id, ':reason' => $reason, ':id' => (int) $payment['receipt_id']]);
            }

            $conn->prepare(
                "UPDATE rent_records
                 SET status = 'Reversed', payment_method = NULL, paid_date = NULL
                 WHERE id = :id"
            )->execute([':id' => (int) $rentId]);

            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('Rent reversal failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The payment could not be reversed.']);
        }

        audit_log($conn, (int) $user->user_id, 'rent.payment_reversed', [
            'entity_type' => 'rent_record',
            'entity_id' => (int) $rentId,
            'meta' => ['payment_id' => (int) $payment['id'], 'reason' => $reason],
        ]);

        security_json_response(200, ['message' => 'Payment reversed and the receipt was voided.']);
    }

    security_json_response(400, ['message' => 'Unsupported action.']);
}

security_json_response(405, ['message' => 'Method not allowed.']);
