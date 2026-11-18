<?php
// api/control_center/permissions.php
//
// Super Admin Control Center: role/permission matrix audit view.
// GET: returns role definitions, permissions per role, user counts per role,
// and recent role/permission-related audit events.

require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/permissions.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
permission_require_super_admin($actor);

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    security_json_response(405, ['message' => 'Method not allowed.']);
}

$counts = [];
try {
    $stmt = $conn->query(
        "SELECT
            CASE
              WHEN role = 'tenant' OR account_type = 'tenant' THEN 'tenant'
              WHEN staff_role IS NOT NULL AND staff_role <> '' THEN staff_role
              ELSE role
            END AS role_key,
            COUNT(*) AS cnt
         FROM users
         GROUP BY role_key"
    );
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $counts[(string) $row['role_key']] = (int) $row['cnt'];
    }
} catch (Throwable $e) {
    // best effort
}

$recent = [];
try {
    $stmt = $conn->prepare(
        "SELECT id, actor_user_id, actor_email, action, entity_type, entity_id, outcome, meta, created_at
         FROM audit_logs
         WHERE action LIKE 'staff.%' OR action LIKE 'admin.account.role%' OR action LIKE 'admin.account.%'
         ORDER BY id DESC
         LIMIT 50"
    );
    $stmt->execute();
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $meta = $row['meta'];
        if (is_string($meta) && $meta !== '') {
            $d = json_decode($meta, true);
            if (json_last_error() === JSON_ERROR_NONE) $meta = $d;
        }
        $recent[] = [
            'id' => (int) $row['id'],
            'actor_user_id' => isset($row['actor_user_id']) ? (int) $row['actor_user_id'] : null,
            'actor_email' => $row['actor_email'],
            'action' => $row['action'],
            'entity_type' => $row['entity_type'],
            'entity_id' => isset($row['entity_id']) ? (int) $row['entity_id'] : null,
            'outcome' => $row['outcome'],
            'meta' => $meta,
            'created_at' => $row['created_at'],
        ];
    }
} catch (Throwable $e) {
}

$roles = [];
foreach (JPT_STAFF_ROLES as $role) {
    $roles[] = [
        'role' => $role,
        'label' => JPT_STAFF_ROLE_LABELS[$role] ?? $role,
        'permissions' => JPT_ROLE_PERMISSIONS[$role] ?? [],
        'user_count' => $counts[$role] ?? 0,
    ];
}
$roles[] = [
    'role' => 'tenant',
    'label' => JPT_STAFF_ROLE_LABELS['tenant'] ?? 'Tenant',
    'permissions' => [],
    'user_count' => $counts['tenant'] ?? 0,
];

security_json_response(200, [
    'roles' => $roles,
    'legacy_counts' => $counts,
    'recent_changes' => $recent,
    'all_permissions' => array_values(array_unique(array_merge(...array_values(array_map(function ($p) {
        return $p === ['*'] ? ['* (all permissions)'] : $p;
    }, JPT_ROLE_PERMISSIONS))))),
]);
