<?php
// api/staff.php
//
// Staff account management for the internal JUMP PROPTECH platform.
// Replaces the retired landlord/agency sign-up flow.
//
// GET    /api/staff.php          - list staff accounts
// POST   /api/staff.php          - create a staff account
// PATCH  /api/staff.php          - change a staff role or active state
//
// All actions require the staff.view / staff.manage permissions and are
// audited. Tenants are never managed through this endpoint.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];

/**
 * @return array<string,mixed>
 */
function staff_read_json(): array
{
    $data = json_decode(file_get_contents('php://input'), true);
    return is_array($data) ? $data : [];
}

function staff_valid_role(string $role): bool
{
    return in_array($role, JPT_STAFF_ROLES, true);
}

if ($method === 'GET') {
    permission_require($actor, 'staff.view');

    $stmt = $conn->prepare(
        "SELECT id, full_name, email, phone, role, staff_role, account_type,
                company_id, is_active
         FROM users
         WHERE role <> 'tenant' AND account_type <> 'tenant'
         ORDER BY id ASC"
    );
    $stmt->execute();

    security_json_response(200, ['staff' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
}

if ($method === 'POST') {
    permission_require($actor, 'staff.manage');

    $data = staff_read_json();
    $fullName = security_clean_text($data['full_name'] ?? '', 100);
    $email = strtolower(trim((string) ($data['email'] ?? '')));
    $phone = security_clean_text($data['phone'] ?? '', 20);
    $staffRole = trim((string) ($data['staff_role'] ?? ''));
    $password = (string) ($data['password'] ?? '');
    $companyId = filter_var($data['company_id'] ?? null, FILTER_VALIDATE_INT);

    if ($fullName === '' || !security_is_email($email) || !staff_valid_role($staffRole)) {
        security_json_response(400, [
            'message' => 'A full name, valid email and approved staff role are required.',
        ]);
    }

    $policyError = security_validate_password($password);
    if ($policyError !== null) {
        security_json_response(400, ['message' => $policyError]);
    }

    $legacyRole = permission_legacy_role_for_staff($staffRole);

    try {
        $check = $conn->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $check->execute([':email' => $email]);
        if ($check->fetchColumn()) {
            security_json_response(409, ['message' => 'An account with this email already exists.']);
        }

        $stmt = $conn->prepare(
            "INSERT INTO users
                (full_name, email, password_hash, phone, role, staff_role,
                 account_type, company_id, subscription_status, token_version, is_active)
             VALUES
                (:full_name, :email, :password_hash, :phone, :role, :staff_role,
                 'staff', :company_id, 'active', 0, 1)"
        );
        $stmt->execute([
            ':full_name' => $fullName,
            ':email' => $email,
            ':password_hash' => security_hash_password($password),
            ':phone' => $phone,
            ':role' => $legacyRole,
            ':staff_role' => $staffRole,
            ':company_id' => $companyId === false ? null : $companyId,
        ]);

        $staffId = (int) $conn->lastInsertId();

        audit_log($conn, (int) $user->user_id, 'staff.created', [
            'entity_type' => 'user',
            'entity_id' => $staffId,
            'meta' => ['staff_role' => $staffRole, 'email' => $email],
        ]);

        security_json_response(201, [
            'message' => 'Staff account created successfully.',
            'id' => $staffId,
        ]);
    } catch (PDOException $e) {
        error_log('Staff creation error: ' . $e->getMessage());
        security_json_response(500, ['message' => 'Staff account could not be created.']);
    }
}

if ($method === 'PATCH') {
    permission_require($actor, 'staff.manage');

    $data = staff_read_json();
    $staffId = filter_var($data['id'] ?? null, FILTER_VALIDATE_INT);
    if ($staffId === false || $staffId < 1) {
        security_json_response(400, ['message' => 'A valid staff id is required.']);
    }

    $updates = [];
    $params = [':id' => $staffId];

    if (isset($data['staff_role'])) {
        $staffRole = trim((string) $data['staff_role']);
        if (!staff_valid_role($staffRole)) {
            security_json_response(400, ['message' => 'Unknown staff role.']);
        }

        // Prevent an administrator from accidentally locking themselves out.
        if ($staffId === (int) $user->user_id && $staffRole !== $user->effective_role) {
            security_json_response(400, ['message' => 'You cannot change your own staff role.']);
        }

        $updates[] = 'staff_role = :staff_role';
        $updates[] = 'role = :legacy_role';
        $params[':staff_role'] = $staffRole;
        $params[':legacy_role'] = permission_legacy_role_for_staff($staffRole);
    }

    if (isset($data['is_active'])) {
        $isActive = filter_var($data['is_active'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($isActive === null) {
            security_json_response(400, ['message' => 'is_active must be true or false.']);
        }
        if ($staffId === (int) $user->user_id && $isActive === false) {
            security_json_response(400, ['message' => 'You cannot deactivate your own account.']);
        }

        $updates[] = 'is_active = :is_active';
        $params[':is_active'] = $isActive ? 1 : 0;
    }

    if ($updates === []) {
        security_json_response(400, ['message' => 'No supported changes were supplied.']);
    }

    $target = $conn->prepare(
        "SELECT id, email, staff_role FROM users
         WHERE id = :id AND role <> 'tenant' AND account_type <> 'tenant' LIMIT 1"
    );
    $target->execute([':id' => $staffId]);
    $existing = $target->fetch(PDO::FETCH_ASSOC);
    if (!$existing) {
        security_json_response(404, ['message' => 'Staff account not found.']);
    }

    try {
        $stmt = $conn->prepare('UPDATE users SET ' . implode(', ', $updates) . ' WHERE id = :id');
        $stmt->execute($params);

        audit_log($conn, (int) $user->user_id, 'staff.updated', [
            'entity_type' => 'user',
            'entity_id' => $staffId,
            'meta' => [
                'email' => $existing['email'],
                'staff_role' => $data['staff_role'] ?? $existing['staff_role'],
                'is_active' => $data['is_active'] ?? null,
            ],
        ]);

        security_json_response(200, ['message' => 'Staff account updated.']);
    } catch (PDOException $e) {
        error_log('Staff update error: ' . $e->getMessage());
        security_json_response(500, ['message' => 'Staff account could not be updated.']);
    }
}

security_json_response(405, ['message' => 'Method not allowed.']);
