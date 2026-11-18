<?php
// api/control_center/export.php
//
// Super Admin Control Center: audited data export (CSV/JSON download).
// GET ?type=accounts|audit&format=csv|json&... (same filters as source endpoints, limited)

require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/permissions.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
permission_require_super_admin($actor);

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    security_json_response(405, ['message' => 'Method not allowed.']);
}

$type = isset($_GET['type']) && is_string($_GET['type']) ? strtolower(trim($_GET['type'])) : '';
$format = isset($_GET['format']) && is_string($_GET['format']) ? strtolower(trim($_GET['format'])) : 'csv';
if (!in_array($type, ['accounts', 'audit'], true)) {
    security_json_response(400, ['message' => 'A valid export type is required (accounts or audit).']);
}
if (!in_array($format, ['csv', 'json'], true)) $format = 'csv';

$data = [];
$filename = 'export';

if ($type === 'accounts') {
    $stmt = $conn->query(
        "SELECT u.id, u.full_name, u.email, u.phone, u.role, u.staff_role, u.account_type,
                u.is_active, u.created_at, u.mfa_enabled, u.token_version, u.company_id
         FROM users u
         ORDER BY u.id DESC
         LIMIT 5000"
    );
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $r) {
        $data[] = [
            'id' => (int) $r['id'],
            'full_name' => $r['full_name'],
            'email' => $r['email'],
            'phone' => $r['phone'],
            'effective_role' => permission_role_for_user($r),
            'account_type' => ($r['role'] === 'tenant' || $r['account_type'] === 'tenant') ? 'tenant' : 'staff',
            'is_active' => (int) ($r['is_active'] ?? 1) === 1,
            'mfa_enabled' => (int) ($r['mfa_enabled'] ?? 0) === 1,
            'token_version' => (int) ($r['token_version'] ?? 0),
            'company_id' => $r['company_id'],
            'created_at' => $r['created_at'],
        ];
    }
    $filename = 'accounts_export';
} elseif ($type === 'audit') {
    $stmt = $conn->query(
        "SELECT id, actor_user_id, actor_email, action, entity_type, entity_id, outcome, ip, user_agent, meta, created_at
         FROM audit_logs
         ORDER BY id DESC
         LIMIT 10000"
    );
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $r) {
        $data[] = [
            'id' => (int) $r['id'],
            'actor_user_id' => $r['actor_user_id'],
            'actor_email' => $r['actor_email'],
            'action' => $r['action'],
            'entity_type' => $r['entity_type'],
            'entity_id' => $r['entity_id'],
            'outcome' => $r['outcome'],
            'ip' => $r['ip'],
            'user_agent' => $r['user_agent'],
            'meta' => $r['meta'],
            'created_at' => $r['created_at'],
        ];
    }
    $filename = 'audit_export';
}

audit_log($conn, (int) $user->user_id, 'admin.data.exported', [
    'entity_type' => 'export',
    'meta' => ['type' => $type, 'format' => $format, 'rows' => count($data)],
]);

$ts = gmdate('Ymd_His');
if ($format === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '_' . $ts . '.json"');
    echo json_encode(['exported_at' => gmdate('c'), 'type' => $type, 'count' => count($data), 'rows' => $data], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit();
}

// CSV
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '_' . $ts . '.csv"');
$out = fopen('php://output', 'w');
if ($data) {
    fputcsv($out, array_keys($data[0]));
    foreach ($data as $row) {
        $flat = [];
        foreach ($row as $v) {
            if (is_bool($v)) $v = $v ? '1' : '0';
            elseif (is_array($v) || is_object($v)) $v = json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $flat[] = $v;
        }
        fputcsv($out, $flat);
    }
} else {
    fputcsv($out, ['no_data']);
}
fclose($out);
exit();
