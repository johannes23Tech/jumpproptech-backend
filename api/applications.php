<?php
// api/applications.php
//
// Staff review of tenant applications submitted through a unit QR link.
//
// GET  list applications (permission: applications.view)
// POST { id, action: review|reject|approve, ... } (permission: applications.review)
//
// Approval is the only point where a tenant account, tenancy record and first
// rent obligation are created. The applicant's chosen password was validated
// and hashed at submission time; the plaintext is never stored.

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
    permission_require($actor, 'applications.view');

    $status = isset($_GET['status']) && is_string($_GET['status']) ? strtolower(trim($_GET['status'])) : '';
    $allowedStatuses = ['submitted', 'reviewing', 'approved', 'rejected'];

    $sql = "SELECT a.id, a.unit_id, a.full_name, a.email, a.phone, a.id_number,
                   a.emergency_contact_name, a.emergency_contact_phone, a.occupants,
                   a.notes, a.status, a.rejection_reason, a.reviewed_by, a.reviewed_at,
                   a.tenant_id, a.user_id, a.created_at, a.updated_at,
                   u.unit_number, u.monthly_rent AS unit_rent, u.status AS unit_status,
                   p.name AS property_name, b.name AS building_name
            FROM tenant_applications a
            JOIN units u ON a.unit_id = u.id
            JOIN properties p ON u.property_id = p.id
            LEFT JOIN buildings b ON u.building_id = b.id";
    $params = [];

    if ($status !== '' && in_array($status, $allowedStatuses, true)) {
        $sql .= ' WHERE a.status = :status';
        $params[':status'] = $status;
    }
    $sql .= ' ORDER BY a.id DESC LIMIT 300';

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $applications = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($applications !== []) {
        $ids = array_map(static fn (array $row): int => (int) $row['id'], $applications);
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $docStmt = $conn->prepare(
            "SELECT application_id, document_type, file_url
             FROM application_documents
             WHERE application_id IN ($placeholders)
             ORDER BY id"
        );
        $docStmt->execute($ids);

        $byApplication = [];
        foreach ($docStmt->fetchAll(PDO::FETCH_ASSOC) as $document) {
            $byApplication[(int) $document['application_id']][] = [
                'type' => $document['document_type'],
                'url' => $document['file_url'],
            ];
        }
        foreach ($applications as &$application) {
            $application['documents'] = $byApplication[(int) $application['id']] ?? [];
        }
        unset($application);
    }

    echo json_encode($applications);
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'applications.review');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $applicationId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : '';

    if ($applicationId === false || $applicationId < 1) {
        security_json_response(400, ['message' => 'A valid application id is required.']);
    }
    if (!in_array($action, ['review', 'reject', 'approve'], true)) {
        security_json_response(400, ['message' => 'Action must be review, reject or approve.']);
    }

    $stmt = $conn->prepare(
        "SELECT a.*, u.unit_number, u.monthly_rent AS unit_rent, u.status AS unit_status,
                p.landlord_id
         FROM tenant_applications a
         JOIN units u ON a.unit_id = u.id
         JOIN properties p ON u.property_id = p.id
         WHERE a.id = :id
         LIMIT 1"
    );
    $stmt->execute([':id' => $applicationId]);
    $application = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$application) {
        security_json_response(404, ['message' => 'Application not found.']);
    }

    if (in_array($application['status'], ['approved', 'rejected'], true)) {
        security_json_response(409, ['message' => 'This application has already been finalised.']);
    }

    if ($action === 'review') {
        $conn->prepare(
            "UPDATE tenant_applications
             SET status = 'reviewing', reviewed_by = :reviewed_by
             WHERE id = :id AND status = 'submitted'"
        )->execute([':reviewed_by' => (int) $user->user_id, ':id' => $applicationId]);

        audit_log($conn, (int) $user->user_id, 'application.reviewing', [
            'entity_type' => 'tenant_application',
            'entity_id' => $applicationId,
        ]);

        security_json_response(200, ['message' => 'Application marked as under review.']);
    }

    if ($action === 'reject') {
        $reason = security_clean_text($data->rejection_reason ?? '', 500);
        if (strlen($reason) < 3) {
            security_json_response(400, ['message' => 'A rejection reason is required.']);
        }

        $conn->prepare(
            "UPDATE tenant_applications
             SET status = 'rejected', rejection_reason = :reason,
                 reviewed_by = :reviewed_by, reviewed_at = NOW()
             WHERE id = :id"
        )->execute([
            ':reason' => $reason,
            ':reviewed_by' => (int) $user->user_id,
            ':id' => $applicationId,
        ]);

        audit_log($conn, (int) $user->user_id, 'application.rejected', [
            'entity_type' => 'tenant_application',
            'entity_id' => $applicationId,
            'meta' => ['reason' => $reason],
        ]);

        security_json_response(200, ['message' => 'Application rejected.']);
    }

    // -----------------------------------------------------------------------
    // Approve: create the tenant account and tenancy in one transaction.
    // -----------------------------------------------------------------------
    if (in_array($application['unit_status'], ['Occupied', 'Maintenance'], true)) {
        security_json_response(409, ['message' => 'This unit is no longer available for this application.']);
    }

    $leaseStart = trim((string) ($data->lease_start ?? ''));
    $leaseEnd = trim((string) ($data->lease_end ?? ''));
    $datePattern = '/^\d{4}-\d{2}-\d{2}$/';

    if (!preg_match($datePattern, $leaseStart) || !preg_match($datePattern, $leaseEnd) || $leaseEnd < $leaseStart) {
        security_json_response(400, ['message' => 'A valid lease start and end date are required.']);
    }

    $deposit = filter_var($data->deposit ?? 0, FILTER_VALIDATE_FLOAT);
    $monthlyRent = filter_var($data->monthly_rent ?? $application['unit_rent'], FILTER_VALIDATE_FLOAT);

    if ($deposit === false || $deposit < 0 || $monthlyRent === false || $monthlyRent <= 0) {
        security_json_response(400, ['message' => 'A valid deposit and monthly rent are required.']);
    }

    try {
        $conn->beginTransaction();

        // Re-check inside the transaction so two approvals cannot create the
        // same account twice.
        $emailCheck = $conn->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $emailCheck->execute([':email' => $application['email']]);
        if ($emailCheck->fetchColumn() !== false) {
            $conn->rollBack();
            security_json_response(409, ['message' => 'An account with this email already exists.']);
        }

        $userInsert = $conn->prepare(
            "INSERT INTO users (full_name, email, password_hash, phone, role, account_type, subscription_status)
             VALUES (:full_name, :email, :password_hash, :phone, 'tenant', 'tenant', 'active')"
        );
        $userInsert->execute([
            ':full_name' => $application['full_name'],
            ':email' => $application['email'],
            ':password_hash' => $application['password_hash'],
            ':phone' => $application['phone'],
        ]);
        $newUserId = (int) $conn->lastInsertId();

        $ownerId = (int) ($application['landlord_id'] ?? 0);
        if ($ownerId < 1) {
            $ownerId = (int) $user->user_id;
        }

        $tenantInsert = $conn->prepare(
            "INSERT INTO tenants
                (owner_id, user_id, unit_id, status, name, phone, email, lease_start, lease_end,
                 deposit, monthly_rent, id_number, emergency_contact_name, emergency_contact_phone, occupants)
             VALUES
                (:owner_id, :user_id, :unit_id, 'active', :name, :phone, :email, :lease_start, :lease_end,
                 :deposit, :monthly_rent, :id_number, :emergency_name, :emergency_phone, :occupants)"
        );
        $tenantInsert->execute([
            ':owner_id' => $ownerId,
            ':user_id' => $newUserId,
            ':unit_id' => $application['unit_id'],
            ':name' => $application['full_name'],
            ':phone' => $application['phone'],
            ':email' => $application['email'],
            ':lease_start' => $leaseStart,
            ':lease_end' => $leaseEnd,
            ':deposit' => $deposit,
            ':monthly_rent' => $monthlyRent,
            ':id_number' => $application['id_number'],
            ':emergency_name' => $application['emergency_contact_name'],
            ':emergency_phone' => $application['emergency_contact_phone'],
            ':occupants' => (int) $application['occupants'],
        ]);
        $newTenantId = (int) $conn->lastInsertId();

        // Create the first lease version as a draft. Management uploads the
        // approved lease document and records signatures before activating it.
        lease_create_draft(
            $conn,
            $newTenantId,
            (int) $application['unit_id'],
            $leaseStart,
            $leaseEnd,
            (float) $monthlyRent,
            (float) $deposit,
            (int) $user->user_id,
            null,
            null,
            'Created automatically when the application was approved.'
        );

        $conn->prepare("UPDATE units SET status = 'Occupied' WHERE id = :unit_id")
            ->execute([':unit_id' => $application['unit_id']]);

        $conn->prepare(
            "INSERT INTO rent_records (tenant_id, unit_id, month_for, amount, status)
             VALUES (:tenant_id, :unit_id, :month, :amount, 'Pending')"
        )->execute([
            ':tenant_id' => $newTenantId,
            ':unit_id' => $application['unit_id'],
            ':month' => date('Y-m-01'),
            ':amount' => $monthlyRent,
        ]);

        $conn->prepare(
            "UPDATE tenant_applications
             SET status = 'approved', tenant_id = :tenant_id, user_id = :user_id,
                 reviewed_by = :reviewed_by, reviewed_at = NOW()
             WHERE id = :id"
        )->execute([
            ':tenant_id' => $newTenantId,
            ':user_id' => $newUserId,
            ':reviewed_by' => (int) $user->user_id,
            ':id' => $applicationId,
        ]);

        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Application approval failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The application could not be approved.']);
    }

    audit_log($conn, (int) $user->user_id, 'application.approved', [
        'entity_type' => 'tenant_application',
        'entity_id' => $applicationId,
        'meta' => ['tenant_id' => $newTenantId, 'user_id' => $newUserId, 'unit_id' => (int) $application['unit_id']],
    ]);

    security_json_response(200, [
        'message' => 'Application approved. The tenant account is now active.',
        'tenant_id' => $newTenantId,
        'user_id' => $newUserId,
    ]);
}

security_json_response(405, ['message' => 'Method not allowed.']);
