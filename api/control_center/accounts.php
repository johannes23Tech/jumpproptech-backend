<?php
// api/control_center/accounts.php
//
// Super Admin Control Center: registry of all registered accounts (staff +
// tenants) with safe details, and audited high-sensitivity actions.
//
// GET   ?q=&type=all|staff|tenant&status=all|active|inactive&role=&limit=&offset=
// POST  { id, action: activate|deactivate|force_logout|reset_mfa|change_role|trigger_password_reset, ... }

require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/permissions.php';
require_once '../../config/sessions.php';
require_once '../../config/mailer.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
permission_require_super_admin($actor);

$method = $_SERVER['REQUEST_METHOD'];

function cc_bool($v, ?bool $default = null): ?bool
{
    if ($v === null) return $default;
    $b = filter_var($v, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    return $b === null ? $default : $b;
}

if ($method === 'GET') {
    $q = isset($_GET['q']) && is_string($_GET['q']) ? trim($_GET['q']) : '';
    $type = isset($_GET['type']) && is_string($_GET['type']) ? strtolower(trim($_GET['type'])) : 'all';
    $status = isset($_GET['status']) && is_string($_GET['status']) ? strtolower(trim($_GET['status'])) : 'all';
    $role = isset($_GET['role']) && is_string($_GET['role']) ? strtolower(trim($_GET['role'])) : '';
    $limit = filter_var($_GET['limit'] ?? 50, FILTER_VALIDATE_INT);
    $offset = filter_var($_GET['offset'] ?? 0, FILTER_VALIDATE_INT);

    if (!in_array($type, ['all', 'staff', 'tenant'], true)) $type = 'all';
    if (!in_array($status, ['all', 'active', 'inactive'], true)) $status = 'all';
    if ($limit === false || $limit < 1) $limit = 50;
    if ($limit > 200) $limit = 200;
    if ($offset === false || $offset < 0) $offset = 0;

    $where = [];
    $params = [];

    if ($type === 'staff') {
        $where[] = "u.role <> 'tenant' AND u.account_type <> 'tenant'";
    } elseif ($type === 'tenant') {
        $where[] = "(u.role = 'tenant' OR u.account_type = 'tenant')";
    }

    if ($status === 'active') {
        $where[] = 'u.is_active = 1';
    } elseif ($status === 'inactive') {
        $where[] = 'u.is_active = 0';
    }

    if ($role !== '' && in_array($role, array_merge(JPT_STAFF_ROLES, ['tenant']), true)) {
        // Match canonical/effective role intent as best as possible.
        $where[] = '(u.staff_role = :role_filter OR u.role = :role_filter2)';
        $params[':role_filter'] = $role;
        $params[':role_filter2'] = $role;
    }

    if ($q !== '') {
        $where[] = '(u.full_name LIKE :q1 OR u.email LIKE :q2 OR u.phone LIKE :q3 OR CAST(u.id AS CHAR) = :q4)';
        $like = '%' . $q . '%';
        $params[':q1'] = $like;
        $params[':q2'] = $like;
        $params[':q3'] = $like;
        $params[':q4'] = $q;
    }

    $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    // Last successful login and last seen activity from audit logs.
    $sql = "SELECT
                u.id, u.company_id, u.full_name, u.email, u.phone,
                u.role, u.staff_role, u.account_type, u.subscription_status,
                u.is_active, u.created_at, u.token_version,
                u.mfa_enabled,
                (u.mfa_recovery_codes IS NOT NULL AND u.mfa_recovery_codes <> '') AS mfa_recovery_configured,
                t.id AS tenant_id, t.unit_id AS tenant_unit_id, t.status AS tenancy_status,
                t.monthly_rent AS tenant_monthly_rent,
                un.unit_number AS tenant_unit_number,
                p.id AS tenant_property_id, p.name AS tenant_property_name,
                (SELECT MAX(created_at) FROM audit_logs al
                  WHERE al.actor_user_id = u.id AND al.action = 'auth.login.success') AS last_login_at,
                (SELECT MAX(created_at) FROM audit_logs al2
                  WHERE al2.actor_user_id = u.id) AS last_activity_at,
                (SELECT al3.ip FROM audit_logs al3
                  WHERE al3.actor_user_id = u.id AND al3.action = 'auth.login.success'
                  ORDER BY al3.created_at DESC LIMIT 1) AS last_login_ip,
                (SELECT al4.user_agent FROM audit_logs al4
                  WHERE al4.actor_user_id = u.id AND al4.action = 'auth.login.success'
                  ORDER BY al4.created_at DESC LIMIT 1) AS last_login_user_agent
            FROM users u
            LEFT JOIN tenants t ON t.user_id = u.id
            LEFT JOIN units un ON t.unit_id = un.id
            LEFT JOIN properties p ON un.property_id = p.id
            $whereSql
            ORDER BY u.id DESC
            LIMIT :limit OFFSET :offset";

    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) {
        $stmt->bindValue($k, $v);
    }
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $accounts = [];
    foreach ($rows as $row) {
        $effective = permission_role_for_user($row);
        $isTenant = ($row['role'] === 'tenant' || $row['account_type'] === 'tenant');
        $accounts[] = [
            'id' => (int) $row['id'],
            'full_name' => (string) ($row['full_name'] ?? ''),
            'email' => (string) ($row['email'] ?? ''),
            'phone' => $row['phone'],
            'company_id' => isset($row['company_id']) ? (int) $row['company_id'] : null,
            'legacy_role' => $row['role'],
            'staff_role' => $row['staff_role'],
            'effective_role' => $effective,
            'account_type' => $isTenant ? 'tenant' : 'staff',
            'is_active' => (int) ($row['is_active'] ?? 1) === 1,
            'created_at' => $row['created_at'],
            'token_version' => (int) ($row['token_version'] ?? 0),
            'mfa_enabled' => (int) ($row['mfa_enabled'] ?? 0) === 1,
            'mfa_recovery_configured' => (int) ($row['mfa_recovery_configured'] ?? 0) === 1,
            'last_login_at' => $row['last_login_at'],
            'last_activity_at' => $row['last_activity_at'],
            'last_login_ip' => $row['last_login_ip'],
            'last_login_user_agent' => $row['last_login_user_agent'],
            'tenant' => $isTenant ? [
                'tenant_id' => isset($row['tenant_id']) ? (int) $row['tenant_id'] : null,
                'tenancy_status' => $row['tenancy_status'],
                'unit_id' => isset($row['tenant_unit_id']) ? (int) $row['tenant_unit_id'] : null,
                'unit_number' => $row['tenant_unit_number'],
                'property_id' => isset($row['tenant_property_id']) ? (int) $row['tenant_property_id'] : null,
                'property_name' => $row['tenant_property_name'],
                'monthly_rent' => $row['tenant_monthly_rent'],
            ] : null,
        ];
    }

    $countSql = "SELECT COUNT(*) FROM users u $whereSql";
    $countStmt = $conn->prepare($countSql);
    foreach ($params as $k => $v) {
        $countStmt->bindValue($k, $v);
    }
    $countStmt->execute();
    $total = (int) $countStmt->fetchColumn();

    security_json_response(200, [
        'accounts' => $accounts,
        'total' => $total,
        'limit' => $limit,
        'offset' => $offset,
    ]);
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $targetId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : '';

    if ($targetId === false || $targetId < 1) {
        security_json_response(400, ['message' => 'A valid account id is required.']);
    }

    $targetStmt = $conn->prepare(
        "SELECT id, full_name, email, role, staff_role, account_type, is_active, token_version
         FROM users WHERE id = :id LIMIT 1"
    );
    $targetStmt->execute([':id' => $targetId]);
    $target = $targetStmt->fetch(PDO::FETCH_ASSOC);
    if (!$target) {
        security_json_response(404, ['message' => 'Account not found.']);
    }

    $targetIsTenant = ($target['role'] === 'tenant' || $target['account_type'] === 'tenant');
    $targetEffective = permission_role_for_user($target);

    if ($action === 'activate' || $action === 'deactivate') {
        $activate = $action === 'activate';
        if (!$activate && $targetId === (int) $user->user_id) {
            security_json_response(400, ['message' => 'You cannot deactivate your own account.']);
        }

        $conn->prepare('UPDATE users SET is_active = :active WHERE id = :id')
            ->execute([':active' => $activate ? 1 : 0, ':id' => $targetId]);

        if (!$activate) {
            $conn->prepare('UPDATE users SET token_version = token_version + 1 WHERE id = :id')
                ->execute([':id' => $targetId]);
            session_revoke_all_for_user($conn, $targetId, 'account_deactivated');
        }

        audit_log($conn, (int) $user->user_id, $activate ? 'admin.account.activated' : 'admin.account.deactivated', [
            'entity_type' => 'user',
            'entity_id' => $targetId,
            'meta' => ['email' => $target['email'], 'reason' => security_clean_text($data->reason ?? '', 200)],
        ]);

        security_json_response(200, ['message' => $activate ? 'Account activated.' : 'Account deactivated and sessions revoked.']);
    }

    if ($action === 'force_logout') {
        $conn->prepare('UPDATE users SET token_version = token_version + 1 WHERE id = :id')
            ->execute([':id' => $targetId]);
        session_revoke_all_for_user($conn, $targetId, 'admin_force_logout');

        audit_log($conn, (int) $user->user_id, 'admin.account.force_logout', [
            'entity_type' => 'user',
            'entity_id' => $targetId,
            'meta' => ['email' => $target['email']],
        ]);

        security_json_response(200, ['message' => 'All sessions revoked for this account.']);
    }

    if ($action === 'reset_mfa') {
        if ($targetIsTenant && (int) ($target['mfa_enabled'] ?? 0) === 0) {
            // still allow clearing fields defensively
        }
        $conn->prepare(
            "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_recovery_codes = NULL, mfa_last_step = NULL,
                              token_version = token_version + 1
             WHERE id = :id"
        )->execute([':id' => $targetId]);
        session_revoke_all_for_user($conn, $targetId, 'admin_mfa_reset');

        audit_log($conn, (int) $user->user_id, 'admin.account.mfa_reset', [
            'entity_type' => 'user',
            'entity_id' => $targetId,
            'meta' => ['email' => $target['email']],
        ]);

        security_json_response(200, ['message' => 'MFA reset and sessions revoked for this account.']);
    }

    if ($action === 'change_role') {
        if ($targetIsTenant) {
            security_json_response(400, ['message' => 'Tenant account roles cannot be changed here.']);
        }

        $newRole = isset($data->staff_role) && is_string($data->staff_role) ? trim($data->staff_role) : '';
        if (!in_array($newRole, JPT_STAFF_ROLES, true)) {
            security_json_response(400, ['message' => 'A valid staff role is required.']);
        }
        if ($targetId === (int) $user->user_id) {
            security_json_response(400, ['message' => 'You cannot change your own role.']);
        }

        $legacy = permission_legacy_role_for_staff($newRole);
        $conn->prepare(
            "UPDATE users SET staff_role = :staff_role, role = :legacy_role, token_version = token_version + 1
             WHERE id = :id AND role <> 'tenant' AND account_type <> 'tenant'"
        )->execute([
            ':staff_role' => $newRole,
            ':legacy_role' => $legacy,
            ':id' => $targetId,
        ]);
        session_revoke_all_for_user($conn, $targetId, 'admin_role_changed');

        audit_log($conn, (int) $user->user_id, 'admin.account.role_changed', [
            'entity_type' => 'user',
            'entity_id' => $targetId,
            'meta' => [
                'email' => $target['email'],
                'from' => $targetEffective,
                'to' => $newRole,
            ],
        ]);

        security_json_response(200, ['message' => 'Staff role updated and sessions revoked.']);
    }

    if ($action === 'trigger_password_reset') {
        $email = (string) ($target['email'] ?? '');
        if (!security_is_email($email)) {
            security_json_response(400, ['message' => 'Account does not have a valid email address.']);
        }

        try {
            $conn->exec("DELETE FROM password_resets WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY)");
            $token = bin2hex(random_bytes(32));
            $tokenHash = hash('sha256', $token);

            $conn->prepare('DELETE FROM password_resets WHERE email = :email')->execute([':email' => $email]);
            $conn->prepare('INSERT INTO password_resets (email, token) VALUES (:email, :token)')
                ->execute([':email' => $email, ':token' => $tokenHash]);

            $frontend = rtrim(getenv('FRONTEND_URL') ?: 'https://jumpproptech-frontend.vercel.app', '/');
            $resetLink = $frontend . '/reset-password?token=' . $token;

            $emailBody = "
                <div style='font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #E5DDCD; border-radius: 8px;'>
                    <h2 style='color: #C5A059;'>Jump PropTech Password Reset</h2>
                    <p>Hello,</p>
                    <p>An administrator initiated a password reset for your account. This link expires in 30 minutes and can only be used once.</p>
                    <div style='text-align: center; margin: 30px 0;'>
                        <a href='{$resetLink}' style='display: inline-block; padding: 14px 28px; background-color: #C5A059; color: #000; text-decoration: none; font-weight: bold; border-radius: 6px;'>Reset Password</a>
                    </div>
                    <p>If you did not expect this, please contact the office.</p>
                </div>
            ";

            $sent = sendEmail($email, 'Reset Your Jump PropTech Password', $emailBody);
        } catch (Throwable $e) {
            error_log('Admin-triggered password reset failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'Password reset could not be initiated.']);
        }

        audit_log($conn, (int) $user->user_id, 'admin.account.password_reset_triggered', [
            'entity_type' => 'user',
            'entity_id' => $targetId,
            'meta' => ['email' => $email, 'email_sent' => (bool) $sent],
        ]);

        security_json_response(200, [
            'message' => $sent
                ? 'Password reset email sent to the account holder.'
                : 'Password reset initiated, but the email could not be sent. Share a new reset request if needed.',
        ]);
    }

    security_json_response(400, ['message' => 'Unsupported action.']);
}

security_json_response(405, ['message' => 'Method not allowed.']);
