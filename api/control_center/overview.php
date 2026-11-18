<?php
// api/control_center/overview.php
//
// Super Admin Control Center: high-level system/security overview.

require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/permissions.php';
require_once '../../config/sessions.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
permission_require_super_admin($actor);

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    security_json_response(405, ['message' => 'Method not allowed.']);
}

$counts = [
    'total_users' => 0,
    'staff_users' => 0,
    'tenant_users' => 0,
    'active_users' => 0,
    'inactive_users' => 0,
    'mfa_enabled_users' => 0,
    'properties' => 0,
    'units' => 0,
];

try {
    $counts['total_users'] = (int) $conn->query('SELECT COUNT(*) FROM users')->fetchColumn();
    $counts['staff_users'] = (int) $conn->query("SELECT COUNT(*) FROM users WHERE role <> 'tenant' AND account_type <> 'tenant'")->fetchColumn();
    $counts['tenant_users'] = (int) $conn->query("SELECT COUNT(*) FROM users WHERE role = 'tenant' OR account_type = 'tenant'")->fetchColumn();
    $counts['active_users'] = (int) $conn->query('SELECT COUNT(*) FROM users WHERE is_active = 1')->fetchColumn();
    $counts['inactive_users'] = (int) $conn->query('SELECT COUNT(*) FROM users WHERE is_active = 0')->fetchColumn();
    $counts['mfa_enabled_users'] = (int) $conn->query('SELECT COUNT(*) FROM users WHERE mfa_enabled = 1')->fetchColumn();
    $counts['properties'] = (int) $conn->query('SELECT COUNT(*) FROM properties')->fetchColumn();
    $counts['units'] = (int) $conn->query('SELECT COUNT(*) FROM units')->fetchColumn();
} catch (Throwable $e) {
}

$recentSecurity = [];
try {
    $stmt = $conn->prepare(
        "SELECT id, actor_user_id, actor_email, action, entity_type, entity_id, outcome, ip, user_agent, meta, created_at
         FROM audit_logs
         WHERE action LIKE 'auth.%' OR action LIKE 'admin.%' OR action LIKE 'staff.%' OR outcome IN ('failure','denied')
         ORDER BY id DESC
         LIMIT 15"
    );
    $stmt->execute();
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $meta = $row['meta'];
        if (is_string($meta) && $meta !== '') {
            $d = json_decode($meta, true);
            if (json_last_error() === JSON_ERROR_NONE) $meta = $d;
        }
        $recentSecurity[] = [
            'id' => (int) $row['id'],
            'actor_user_id' => isset($row['actor_user_id']) ? (int) $row['actor_user_id'] : null,
            'actor_email' => $row['actor_email'],
            'action' => $row['action'],
            'outcome' => $row['outcome'],
            'ip' => $row['ip'],
            'created_at' => $row['created_at'],
            'meta' => $meta,
        ];
    }
} catch (Throwable $e) {
}

$authStats24h = ['success' => 0, 'failure' => 0, 'denied' => 0];
try {
    $stmt = $conn->query(
        "SELECT outcome, COUNT(*) c FROM audit_logs
         WHERE action LIKE 'auth.%' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY outcome"
    );
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $k = (string) $row['outcome'];
        if (isset($authStats24h[$k])) $authStats24h[$k] = (int) $row['c'];
    }
} catch (Throwable $e) {
}

$activeSessions = null;
try {
    if (session_table($conn)) {
        $activeSessions = (int) $conn->query(
            "SELECT COUNT(*) FROM user_sessions WHERE revoked_at IS NULL AND expires_at > UTC_TIMESTAMP()"
        )->fetchColumn();
    }
} catch (Throwable $e) {
}

security_json_response(200, [
    'counts' => $counts,
    'auth_24h' => $authStats24h,
    'active_sessions_tracked' => $activeSessions,
    'recent_security_events' => $recentSecurity,
]);
