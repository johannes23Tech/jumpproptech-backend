<?php
// api/control_center/audit.php
//
// Super Admin Control Center: audit/activity and auth/security event viewer.
// GET ?q=&action=&outcome=&actor_id=&from=&to=&limit=&offset=

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

$q = isset($_GET['q']) && is_string($_GET['q']) ? trim($_GET['q']) : '';
$action = isset($_GET['action']) && is_string($_GET['action']) ? trim($_GET['action']) : '';
$outcome = isset($_GET['outcome']) && is_string($_GET['outcome']) ? strtolower(trim($_GET['outcome'])) : '';
$actorId = filter_var($_GET['actor_id'] ?? null, FILTER_VALIDATE_INT);
$from = isset($_GET['from']) && is_string($_GET['from']) ? trim($_GET['from']) : '';
$to = isset($_GET['to']) && is_string($_GET['to']) ? trim($_GET['to']) : '';
$limit = filter_var($_GET['limit'] ?? 100, FILTER_VALIDATE_INT);
$offset = filter_var($_GET['offset'] ?? 0, FILTER_VALIDATE_INT);

if ($limit === false || $limit < 1) $limit = 100;
if ($limit > 500) $limit = 500;
if ($offset === false || $offset < 0) $offset = 0;

$where = [];
$params = [];

if ($action !== '') {
    $where[] = 'a.action LIKE :action';
    $params[':action'] = '%' . $action . '%';
}
if (in_array($outcome, ['success', 'failure', 'denied'], true)) {
    $where[] = 'a.outcome = :outcome';
    $params[':outcome'] = $outcome;
}
if ($actorId !== false && $actorId !== null && $actorId > 0) {
    $where[] = 'a.actor_user_id = :actor_id';
    $params[':actor_id'] = $actorId;
}
if ($from !== '' && preg_match('/^\d{4}-\d{2}-\d{2}/', $from)) {
    $where[] = 'a.created_at >= :from';
    $params[':from'] = $from . (strlen($from) === 10 ? ' 00:00:00' : '');
}
if ($to !== '' && preg_match('/^\d{4}-\d{2}-\d{2}/', $to)) {
    $where[] = 'a.created_at <= :to';
    $params[':to'] = $to . (strlen($to) === 10 ? ' 23:59:59' : '');
}
if ($q !== '') {
    $where[] = '(a.action LIKE :q1 OR a.actor_email LIKE :q2 OR a.entity_type LIKE :q3 OR a.ip LIKE :q4 OR CAST(a.entity_id AS CHAR) = :q5 OR CAST(a.actor_user_id AS CHAR) = :q6)';
    $like = '%' . $q . '%';
    $params[':q1'] = $like;
    $params[':q2'] = $like;
    $params[':q3'] = $like;
    $params[':q4'] = $like;
    $params[':q5'] = $q;
    $params[':q6'] = $q;
}

$whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$sql = "SELECT a.id, a.actor_user_id, a.actor_email, a.action, a.entity_type, a.entity_id,
               a.outcome, a.ip, a.user_agent, a.meta, a.created_at,
               u.full_name AS actor_name, u.staff_role AS actor_staff_role, u.role AS actor_legacy_role
        FROM audit_logs a
        LEFT JOIN users u ON a.actor_user_id = u.id
        $whereSql
        ORDER BY a.id DESC
        LIMIT :limit OFFSET :offset";

$stmt = $conn->prepare($sql);
foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}
$stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$events = [];
foreach ($rows as $row) {
    $meta = $row['meta'];
    if (is_string($meta) && $meta !== '') {
        $decoded = json_decode($meta, true);
        if (json_last_error() === JSON_ERROR_NONE) $meta = $decoded;
    }
    $events[] = [
        'id' => (int) $row['id'],
        'actor_user_id' => isset($row['actor_user_id']) ? (int) $row['actor_user_id'] : null,
        'actor_email' => $row['actor_email'],
        'actor_name' => $row['actor_name'],
        'actor_role' => $row['actor_staff_role'] ?: $row['actor_legacy_role'],
        'action' => $row['action'],
        'entity_type' => $row['entity_type'],
        'entity_id' => isset($row['entity_id']) ? (int) $row['entity_id'] : null,
        'outcome' => $row['outcome'],
        'ip' => $row['ip'],
        'user_agent' => $row['user_agent'],
        'meta' => $meta,
        'created_at' => $row['created_at'],
    ];
}

$countStmt = $conn->prepare("SELECT COUNT(*) FROM audit_logs a $whereSql");
foreach ($params as $k => $v) {
    $countStmt->bindValue($k, $v);
}
$countStmt->execute();

security_json_response(200, [
    'events' => $events,
    'total' => (int) $countStmt->fetchColumn(),
    'limit' => $limit,
    'offset' => $offset,
]);
