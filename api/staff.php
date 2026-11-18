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

/**
 * Detect available columns on users table for schema compatibility.
 * @return array<string,bool>
 */
function staff_users_columns(PDO $conn): array
{
    static $cols = null;
    if ($cols !== null) return $cols;
    $cols = [];
    try {
        $stmt = $conn->query("SHOW COLUMNS FROM users");
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            if (!empty($row['Field'])) $cols[(string) $row['Field']] = true;
        }
    } catch (Throwable $e) {
        // Fallback: assume minimal legacy columns
        foreach (['id','full_name','email','password_hash','phone','role'] as $c) $cols[$c] = true;
    }
    return $cols;
}

function staff_has_col(array $cols, string $name): bool
{
    return isset($cols[$name]);
}

function staff_base_where(array $cols): array
{
    $where = ["(role IS NULL OR role <> 'tenant')"];
    if (staff_has_col($cols, 'account_type')) {
        $where[] = "(account_type IS NULL OR account_type <> 'tenant')";
    }
    return $where;
}

function staff_select_fields(array $cols): array
{
    $select = ['id', 'full_name', 'email'];
    foreach (['phone','role','staff_role','account_type','company_id','is_active','created_at'] as $c) {
        if (staff_has_col($cols, $c)) $select[] = $c;
    }
    return $select;
}

if ($method === 'GET') {
    permission_require($actor, 'staff.view');

    $cols = staff_users_columns($conn);
    $select = staff_select_fields($cols);
    $where = staff_base_where($cols);

    $id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);
    if ($id !== false && $id !== null && $id > 0) {
        $where[] = 'id = :id';
        $sql = "SELECT " . implode(', ', $select) . " FROM users WHERE " . implode(' AND ', $where) . " LIMIT 1";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            security_json_response(404, ['message' => 'Staff account not found.']);
        }
        security_json_response(200, ['staff' => $row]);
    }

    $sql = "SELECT " . implode(', ', $select) . " FROM users WHERE " . implode(' AND ', $where) . " ORDER BY id ASC";
    $stmt = $conn->prepare($sql);
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
    $cols = staff_users_columns($conn);

    try {
        $check = $conn->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $check->execute([':email' => $email]);
        if ($check->fetchColumn()) {
            security_json_response(409, ['message' => 'An account with this email already exists.']);
        }

        $fields = ['full_name', 'email', 'password_hash'];
        $values = [':full_name', ':email', ':password_hash'];
        $params = [
            ':full_name' => $fullName,
            ':email' => $email,
            ':password_hash' => security_hash_password($password),
        ];

        if (staff_has_col($cols, 'phone')) { $fields[] = 'phone'; $values[] = ':phone'; $params[':phone'] = $phone !== '' ? $phone : null; }
        if (staff_has_col($cols, 'role')) { $fields[] = 'role'; $values[] = ':role'; $params[':role'] = $legacyRole; }
        if (staff_has_col($cols, 'staff_role')) { $fields[] = 'staff_role'; $values[] = ':staff_role'; $params[':staff_role'] = $staffRole; }
        if (staff_has_col($cols, 'account_type')) { $fields[] = 'account_type'; $values[] = ':account_type'; $params[':account_type'] = 'staff'; }
        if (staff_has_col($cols, 'company_id')) { $fields[] = 'company_id'; $values[] = ':company_id'; $params[':company_id'] = ($companyId === false ? null : $companyId); }
        if (staff_has_col($cols, 'subscription_status')) { $fields[] = 'subscription_status'; $values[] = ':subscription_status'; $params[':subscription_status'] = 'active'; }
        if (staff_has_col($cols, 'token_version')) { $fields[] = 'token_version'; $values[] = ':token_version'; $params[':token_version'] = 0; }
        if (staff_has_col($cols, 'is_active')) { $fields[] = 'is_active'; $values[] = ':is_active'; $params[':is_active'] = 1; }

        $sql = "INSERT INTO users (" . implode(', ', $fields) . ") VALUES (" . implode(', ', $values) . ")";
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);

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
    } catch (Throwable $e) {
        error_log('Staff creation error: ' . $e->getMessage());
        // More actionable hint without leaking internals.
        security_json_response(500, ['message' => 'Staff account could not be created. Please verify the account details and ensure required database migrations are applied. If the issue persists, check server logs.']);
    }
}

if ($method === 'PATCH') {
    permission_require($actor, 'staff.manage');

    $data = staff_read_json();
    $staffId = filter_var($data['id'] ?? null, FILTER_VALIDATE_INT);
    if ($staffId === false || $staffId < 1) {
        security_json_response(400, ['message' => 'A valid staff id is required.']);
    }

    $cols = staff_users_columns($conn);
    $updates = [];
    $params = [':id' => $staffId];
    $changed = [];

    // Load target first
    $targetCols = ['id','email','full_name'];
    foreach (['phone','role','staff_role','account_type','is_active'] as $c) {
        if (staff_has_col($cols, $c)) $targetCols[] = $c;
    }
    $where = ['id = :id', "(role IS NULL OR role <> 'tenant')"];
    if (staff_has_col($cols, 'account_type')) $where[] = "(account_type IS NULL OR account_type <> 'tenant')";
    $target = $conn->prepare("SELECT " . implode(', ', array_unique($targetCols)) . " FROM users WHERE " . implode(' AND ', $where) . " LIMIT 1");
    $target->execute([':id' => $staffId]);
    $existing = $target->fetch(PDO::FETCH_ASSOC);
    if (!$existing) {
        security_json_response(404, ['message' => 'Staff account not found.']);
    }

    if (array_key_exists('full_name', $data)) {
        $fullName = security_clean_text($data['full_name'] ?? '', 100);
        if ($fullName === '') {
            security_json_response(400, ['message' => 'Full name is required.']);
        }
        $updates[] = 'full_name = :full_name';
        $params[':full_name'] = $fullName;
        $changed[] = 'full_name';
    }

    if (array_key_exists('email', $data)) {
        $email = strtolower(trim((string) ($data['email'] ?? '')));
        if (!security_is_email($email)) {
            security_json_response(400, ['message' => 'A valid email address is required.']);
        }
        $check = $conn->prepare('SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1');
        $check->execute([':email' => $email, ':id' => $staffId]);
        if ($check->fetchColumn()) {
            security_json_response(409, ['message' => 'Another account with this email already exists.']);
        }
        $updates[] = 'email = :email';
        $params[':email'] = $email;
        $changed[] = 'email';
    }

    if (array_key_exists('phone', $data) && staff_has_col($cols, 'phone')) {
        $phone = security_clean_text($data['phone'] ?? '', 20);
        $updates[] = 'phone = :phone';
        $params[':phone'] = $phone !== '' ? $phone : null;
        $changed[] = 'phone';
    }

    if (isset($data['staff_role'])) {
        $staffRole = trim((string) $data['staff_role']);
        if (!staff_valid_role($staffRole)) {
            security_json_response(400, ['message' => 'Unknown staff role.']);
        }

        // Prevent an administrator from accidentally locking themselves out.
        if ($staffId === (int) $user->user_id && $staffRole !== $user->effective_role) {
            security_json_response(400, ['message' => 'You cannot change your own staff role.']);
        }

        if (staff_has_col($cols, 'staff_role')) { $updates[] = 'staff_role = :staff_role'; $params[':staff_role'] = $staffRole; }
        if (staff_has_col($cols, 'role')) { $updates[] = 'role = :legacy_role'; $params[':legacy_role'] = permission_legacy_role_for_staff($staffRole); }
        $changed[] = 'staff_role';
    }

    if (isset($data['is_active'])) {
        $isActive = filter_var($data['is_active'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($isActive === null) {
            security_json_response(400, ['message' => 'is_active must be true or false.']);
        }
        if ($staffId === (int) $user->user_id && $isActive === false) {
            security_json_response(400, ['message' => 'You cannot deactivate your own account.']);
        }

        if (staff_has_col($cols, 'is_active')) {
            $updates[] = 'is_active = :is_active';
            $params[':is_active'] = $isActive ? 1 : 0;
            $changed[] = 'is_active';
        }
        // If deactivating or reactivating sensitive state, bump token_version to invalidate sessions when supported.
        if (staff_has_col($cols, 'token_version')) {
            $updates[] = 'token_version = token_version + 1';
        }
    }

    $passwordChanged = false;
    if (array_key_exists('password', $data)) {
        $password = (string) ($data['password'] ?? '');
        if ($password !== '') {
            $policyError = security_validate_password($password);
            if ($policyError !== null) {
                security_json_response(400, ['message' => $policyError]);
            }
            $updates[] = 'password_hash = :password_hash';
            $params[':password_hash'] = security_hash_password($password);
            if (staff_has_col($cols, 'token_version')) {
                // ensure token version bumped once (avoid duplicate expression issues by handling flag)
                if (!in_array('token_version = token_version + 1', $updates, true)) {
                    $updates[] = 'token_version = token_version + 1';
                }
            }
            $passwordChanged = true;
            $changed[] = 'password';
        }
    }

    if ($updates === []) {
        security_json_response(400, ['message' => 'No supported changes were supplied.']);
    }

    try {
        $stmt = $conn->prepare('UPDATE users SET ' . implode(', ', $updates) . ' WHERE id = :id');
        $stmt->execute($params);

        audit_log($conn, (int) $user->user_id, 'staff.updated', [
            'entity_type' => 'user',
            'entity_id' => $staffId,
            'meta' => [
                'email' => $existing['email'],
                'changed' => $changed,
                'staff_role' => $data['staff_role'] ?? ($existing['staff_role'] ?? null),
                'is_active' => array_key_exists('is_active', $data) ? (bool) $data['is_active'] : null,
                'password_changed' => $passwordChanged,
            ],
        ]);

        security_json_response(200, ['message' => 'Staff account updated.']);
    } catch (Throwable $e) {
        error_log('Staff update error: ' . $e->getMessage());
        security_json_response(500, ['message' => 'Staff account could not be updated. Please verify the details and try again.']);
    }
}

if ($method === 'DELETE') {
    permission_require($actor, 'staff.manage');

    $data = staff_read_json();
    $staffId = filter_var($data['id'] ?? ($_GET['id'] ?? null), FILTER_VALIDATE_INT);
    if ($staffId === false || $staffId < 1) {
        security_json_response(400, ['message' => 'A valid staff id is required.']);
    }

    if ($staffId === (int) $user->user_id) {
        security_json_response(400, ['message' => 'You cannot delete your own account.']);
    }

    $cols = staff_users_columns($conn);
    $where = ['id = :id', "(role IS NULL OR role <> 'tenant')"];
    if (staff_has_col($cols, 'account_type')) $where[] = "(account_type IS NULL OR account_type <> 'tenant')";
    $targetCols = ['id','email','full_name'];
    if (staff_has_col($cols, 'staff_role')) $targetCols[] = 'staff_role';
    $target = $conn->prepare("SELECT " . implode(', ', $targetCols) . " FROM users WHERE " . implode(' AND ', $where) . " LIMIT 1");
    $target->execute([':id' => $staffId]);
    $existing = $target->fetch(PDO::FETCH_ASSOC);
    if (!$existing) {
        security_json_response(404, ['message' => 'Staff account not found.']);
    }

    try {
        // Prefer hard delete if no blocking references; if constrained, caller can deactivate instead.
        $stmt = $conn->prepare('DELETE FROM users WHERE id = :id');
        $stmt->execute([':id' => $staffId]);

        audit_log($conn, (int) $user->user_id, 'staff.deleted', [
            'entity_type' => 'user',
            'entity_id' => $staffId,
            'meta' => ['email' => $existing['email'] ?? null, 'full_name' => $existing['full_name'] ?? null],
        ]);

        security_json_response(200, ['message' => 'Staff account deleted.']);
    } catch (Throwable $e) {
        error_log('Staff delete error: ' . $e->getMessage());
        security_json_response(409, ['message' => 'This staff account cannot be deleted because it is linked to existing records. Deactivate the account instead.']);
    }
}

security_json_response(405, ['message' => 'Method not allowed.']);
