<?php
// api/tenancies.php
//
// Tenancy lifecycle: move-in, notice, renewal and termination.
//
// GET  portfolio tenancy view with lease and deposit summaries (permission: tenants.view)
// POST { id, action } (permission: tenants.manage)

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
    permission_require($actor, 'tenants.view');

    $stmt = $conn->query(
        "SELECT t.id, t.name, t.email, t.phone, t.status, t.unit_id,
                t.lease_start, t.lease_end, t.move_in_date, t.move_out_date,
                t.terminated_at, t.termination_reason, t.monthly_rent, t.deposit,
                u.unit_number, u.status AS unit_status,
                p.name AS property_name, b.name AS building_name
         FROM tenants t
         LEFT JOIN units u ON t.unit_id = u.id
         LEFT JOIN properties p ON u.property_id = p.id
         LEFT JOIN buildings b ON u.building_id = b.id
         WHERE t.unit_id IS NOT NULL OR t.status <> 'pending'
         ORDER BY t.name ASC"
    );

    $tenancies = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $lease = lease_current($conn, (int) $row['id']);
        $row['current_lease'] = $lease === null ? null : [
            'id' => (int) $lease['id'],
            'version' => (int) $lease['version'],
            'status' => $lease['status'],
            'start_date' => $lease['start_date'],
            'end_date' => $lease['end_date'],
            'document_url' => $lease['document_url'],
            'signature_count' => count(lease_signatures($conn, (int) $lease['id'])),
        ];
        $row['deposit_summary'] = deposit_summary($conn, (int) $row['id']);
        $tenancies[] = $row;
    }

    echo json_encode($tenancies);
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'tenants.manage');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $tenantId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($tenantId === false || $tenantId < 1) {
        security_json_response(400, ['message' => 'A valid tenancy id is required.']);
    }

    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : '';

    $stmt = $conn->prepare('SELECT * FROM tenants WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => $tenantId]);
    $tenant = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$tenant) {
        security_json_response(404, ['message' => 'Tenancy not found.']);
    }

    $dateOrToday = static function ($value): string {
        if (is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            return $value;
        }
        return date('Y-m-d');
    };

    // -----------------------------------------------------------------------
    // Move in.
    // -----------------------------------------------------------------------
    if ($action === 'move_in') {
        if ($tenant['status'] === 'ended') {
            security_json_response(409, ['message' => 'This tenancy has already ended.']);
        }
        if (empty($tenant['unit_id'])) {
            security_json_response(409, ['message' => 'Assign a unit before recording move-in.']);
        }

        $moveIn = $dateOrToday($data->move_in_date ?? null);

        $conn->prepare(
            "UPDATE tenants SET status = 'active', move_in_date = :move_in_date, move_out_date = NULL,
                    terminated_at = NULL, termination_reason = NULL
             WHERE id = :id"
        )->execute([':move_in_date' => $moveIn, ':id' => $tenantId]);

        $conn->prepare("UPDATE units SET status = 'Occupied' WHERE id = :unit_id")
            ->execute([':unit_id' => (int) $tenant['unit_id']]);

        audit_log($conn, (int) $user->user_id, 'tenancy.move_in', [
            'entity_type' => 'tenant',
            'entity_id' => $tenantId,
            'meta' => ['move_in_date' => $moveIn],
        ]);

        security_json_response(200, ['message' => 'Move-in recorded.', 'move_in_date' => $moveIn]);
    }

    // -----------------------------------------------------------------------
    // Notice to vacate.
    // -----------------------------------------------------------------------
    if ($action === 'notice') {
        if ($tenant['status'] === 'ended') {
            security_json_response(409, ['message' => 'This tenancy has already ended.']);
        }

        $moveOut = isset($data->move_out_date) && is_string($data->move_out_date)
            ? trim($data->move_out_date)
            : '';
        if ($moveOut !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $moveOut)) {
            security_json_response(400, ['message' => 'Invalid move-out date.']);
        }

        $reason = security_clean_text($data->reason ?? '', 500);

        $conn->prepare(
            "UPDATE tenants SET status = 'notice', move_out_date = :move_out_date,
                    termination_reason = :reason
             WHERE id = :id"
        )->execute([
            ':move_out_date' => $moveOut !== '' ? $moveOut : null,
            ':reason' => $reason !== '' ? $reason : null,
            ':id' => $tenantId,
        ]);

        audit_log($conn, (int) $user->user_id, 'tenancy.notice', [
            'entity_type' => 'tenant',
            'entity_id' => $tenantId,
            'meta' => ['move_out_date' => $moveOut ?: null],
        ]);

        security_json_response(200, ['message' => 'Notice recorded.']);
    }

    if ($action === 'cancel_notice') {
        if ($tenant['status'] !== 'notice') {
            security_json_response(409, ['message' => 'This tenancy is not on notice.']);
        }

        $conn->prepare(
            "UPDATE tenants SET status = 'active', move_out_date = NULL, termination_reason = NULL
             WHERE id = :id"
        )->execute([':id' => $tenantId]);

        audit_log($conn, (int) $user->user_id, 'tenancy.notice_cancelled', [
            'entity_type' => 'tenant',
            'entity_id' => $tenantId,
        ]);

        security_json_response(200, ['message' => 'Notice cancelled.']);
    }

    // -----------------------------------------------------------------------
    // End the tenancy: vacate the unit and terminate the active lease.
    // -----------------------------------------------------------------------
    if ($action === 'end') {
        if ($tenant['status'] === 'ended') {
            security_json_response(409, ['message' => 'This tenancy has already ended.']);
        }

        $moveOut = $dateOrToday($data->move_out_date ?? null);
        $reason = security_clean_text($data->reason ?? '', 500);
        if (strlen($reason) < 3) {
            security_json_response(400, ['message' => 'A reason is required to end a tenancy.']);
        }

        try {
            $conn->beginTransaction();

            $conn->prepare(
                "UPDATE tenants
                 SET status = 'ended', move_out_date = :move_out_date,
                     terminated_at = NOW(), termination_reason = :reason
                 WHERE id = :id"
            )->execute([':move_out_date' => $moveOut, ':reason' => $reason, ':id' => $tenantId]);

            $conn->prepare(
                "UPDATE leases SET status = 'terminated', terminated_at = NOW()
                 WHERE tenant_id = :tenant_id AND status IN ('draft', 'pending_signature', 'active')"
            )->execute([':tenant_id' => $tenantId]);

            if (!empty($tenant['unit_id'])) {
                $conn->prepare(
                    "UPDATE units SET status = 'Vacant'
                     WHERE id = :unit_id AND archived_at IS NULL
                       AND NOT EXISTS (
                           SELECT 1 FROM tenants other
                           WHERE other.unit_id = :unit_id_check
                             AND other.id <> :tenant_id
                             AND other.status IN ('active', 'notice')
                       )"
                )->execute([
                    ':unit_id' => (int) $tenant['unit_id'],
                    ':unit_id_check' => (int) $tenant['unit_id'],
                    ':tenant_id' => $tenantId,
                ]);
            }

            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('Tenancy termination failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The tenancy could not be ended.']);
        }

        audit_log($conn, (int) $user->user_id, 'tenancy.ended', [
            'entity_type' => 'tenant',
            'entity_id' => $tenantId,
            'meta' => ['move_out_date' => $moveOut, 'reason' => $reason],
        ]);

        security_json_response(200, ['message' => 'Tenancy ended and the unit is vacant.']);
    }

    // -----------------------------------------------------------------------
    // Renew: create the next draft lease version from new terms.
    // -----------------------------------------------------------------------
    if ($action === 'renew') {
        if (empty($tenant['unit_id'])) {
            security_json_response(409, ['message' => 'This tenancy has no unit to renew.']);
        }

        $startDate = trim((string) ($data->start_date ?? ''));
        $endDate = trim((string) ($data->end_date ?? ''));
        $monthlyRent = filter_var($data->monthly_rent ?? null, FILTER_VALIDATE_FLOAT);
        $depositRequired = filter_var($data->deposit_required ?? ($tenant['deposit'] ?? 0), FILTER_VALIDATE_FLOAT);

        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $startDate)
            || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $endDate)
            || $endDate < $startDate) {
            security_json_response(400, ['message' => 'A valid renewal start and end date are required.']);
        }
        if ($monthlyRent === false || $monthlyRent <= 0) {
            security_json_response(400, ['message' => 'A valid monthly rent is required.']);
        }
        if ($depositRequired === false || $depositRequired < 0) {
            security_json_response(400, ['message' => 'A valid deposit amount is required.']);
        }

        $notes = security_clean_text($data->notes ?? '', 2000);

        try {
            $conn->beginTransaction();
            $leaseId = lease_create_draft(
                $conn,
                $tenantId,
                (int) $tenant['unit_id'],
                $startDate,
                $endDate,
                (float) $monthlyRent,
                (float) $depositRequired,
                (int) $user->user_id,
                null,
                null,
                $notes
            );
            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('Tenancy renewal failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The renewal could not be created.']);
        }

        audit_log($conn, (int) $user->user_id, 'tenancy.renewal_created', [
            'entity_type' => 'tenant',
            'entity_id' => $tenantId,
            'meta' => ['lease_id' => $leaseId],
        ]);

        security_json_response(201, ['message' => 'Renewal lease version created as a draft.', 'id' => $leaseId]);
    }

    security_json_response(400, ['message' => 'Unsupported action.']);
}

security_json_response(405, ['message' => 'Method not allowed.']);
