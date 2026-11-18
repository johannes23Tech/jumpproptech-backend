<?php
// api/control_center/sessions.php
//
// Super Admin Control Center: active/recent session & device visibility and
// revocation (based on user_sessions issuance tracking + token controls).
//
// GET  ?user_id=&status=active|revoked|expired|all&limit=&offset=
// POST { action: revoke_session, id } or { action: revoke_user, user_id }

require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/permissions.php';
require_once '../../config/sessions.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
permission_require_super_admin($actor);

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $userId = filter_var($_GET['user_id'] ?? null, FILTER_VALIDATE_INT);
    $status = isset($_GET['status']) && is_string($_GET['status']) ? strtolower(trim($_GET['status'])) : 'active';
    $limit = filter_var($_GET['limit'] ?? 100, FILTER_VALIDATE_INT);
    $offset = filter_var($_GET['offset'] ?? 0, FILTER_VALIDATE_INT);

    if (!in_array($status, ['active', 'revoked', 'expired', 'all'], true)) $status = 'active';
    if ($limit === false || $limit < 1) $limit = 100;
    if ($limit > 300) $limit = 300;
    if ($offset === false || $offset < 0) $offset = 0;

    if (!session_table($conn)) {
        security_json_response(200, ['sessions' => [], 'total' => 0, 'limit' => $limit, 'offset' => $offset, 'available' => false]);
    }

    $where = [];
    $params = [];

    if ($userId !== false && $userId !== null && $userId > 0) {
        $where[] = 's.user_id = :user_id';
        $params[':user_id'] = $userId;
    }

    if ($status === 'active') {
        $where[] = 's.revoked_at IS NULL AND s.expires_at > UTC_TIMESTAMP()';
    } elseif ($status === 'revoked') {
        $where[] = 's.revoked_at IS NOT NULL';
    } elseif ($status === 'expired') {
        $where[] = 's.revoked_at IS NULL AND s.expires_at <= UTC_TIMESTAMP()';
    }

    $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    $sql = "SELECT s.id, s.user_id, s.ip, s.user_agent, s.issued_at, s.expires_at, s.last_seen_at,
                   s.revoked_at, s.revoke_reason, s.created_at,
                   u.full_name, u.email, u.staff_role, u.role AS legacy_role, u.token_version
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            $whereSql
            ORDER BY s.id DESC
            LIMIT :limit OFFSET :offset";

    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) $stmt->bindValue($k, $v);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();

    $sessions = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $sessions[] = [
            'id' => (int) $row['id'],
            'user_id' => (int) $row['user_id'],
            'user_name' => $row['full_name'],
            'user_email' => $row['email'],
            'user_role' => $row['staff_role'] ?: $row['legacy_role'],
            'ip' => $row['ip'],
            'user_agent' => $row['user_agent'],
            'issued_at' => $row['issued_at'],
            'expires_at' => $row['expires_at'],
            'last_seen_at' => $row['last_seen_at'],
            'revoked_at' => $row['revoked_at'],
            'revoke_reason' => $row['revoke_reason'],
            'token_version' => (int) ($row['token_version'] ?? 0),
        ];
    }

    $countStmt = $conn->prepare("SELECT COUNT(*) FROM user_sessions s $whereSql");
    foreach ($params as $k => $v) $countStmt->bindValue($k, $v);
    $countStmt->execute();

    security_json_response(200, [
        'sessions' => $sessions,
        'total' => (int) $countStmt->fetchColumn(),
        'limit' => $limit,
        'offset' => $offset,
        'available' => true,
        'note' => 'Session records are tracked for logins issued after session tracking was enabled. Token version bumps invalidate older sessions even if not individually listed as revoked.',
    ]);
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : '';

    if ($action === 'revoke_user') {
        $targetUserId = filter_var($data->user_id ?? 0, FILTER_VALIDATE_INT);
        if ($targetUserId === false || $targetUserId < 1) {
            security_json_response(400, ['message' => 'A valid user id is required.']);
        }
        $conn->prepare('UPDATE users SET token_version = token_version + 1 WHERE id = :id')
            ->execute([':id' => $targetUserId]);
        session_revoke_all_for_user($conn, (int) $targetUserId, 'admin_revoke_user_sessions');

        audit_log($conn, (int) $user->user_id, 'admin.sessions.revoked_user', [
            'entity_type' => 'user',
            'entity_id' => (int) $targetUserId,
        ]);
        security_json_response(200, ['message' => 'All sessions revoked for this user.']);
    }

    // Per-session revoke by issuance record id: we cannot recover the raw jti
    // (we store only a hash), so we revoke by bumping token_version for that
    // user (global) and mark records accordingly. This is explicit and safe.
    if ($action === 'revoke_session') {
        $sessionId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
        if ($sessionId === false || $sessionId < 1 || !session_table($conn)) {
            security_json_response(400, ['message' => 'A valid session id is required.']);
        }
        $row = $conn->prepare('SELECT id, user_id, revoked_at FROM user_sessions WHERE id = :id LIMIT 1');
        $row->execute([':id' => $sessionId]);
        $s = $row->fetch(PDO::FETCH_ASSOC);
        if (!$s) {
            security_json_response(404, ['message' => 'Session not found.']);
        }
        $targetUserId = (int) $s['user_id'];
        $conn->prepare('UPDATE users SET token_version = token_version + 1 WHERE id = :id')
            ->execute([':id' => $targetUserId]);
        session_revoke_all_for_user($conn, $targetUserId, 'admin_revoke_session_request');

        audit_log($conn, (int) $user->user_id, 'admin.sessions.revoked', [
            'entity_type' => 'user_session',
            'entity_id' => (int) $sessionId,
            'meta' => ['user_id' => $targetUserId, 'scope' => 'user_all_tokens_rotated'],
        ]);
        security_json_response(200, ['message' => 'User tokens rotated; all sessions for that user were revoked.']);
    }

    security_json_response(400, ['message' => 'Unsupported action.']);
}

security_json_response(405, ['message' => 'Method not allowed.']);
