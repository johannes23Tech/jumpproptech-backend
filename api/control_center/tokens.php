<?php
// api/control_center/tokens.php
//
// Super Admin Control Center: QR/onboarding token oversight across units.
// GET  ?status=active|expired|used|revoked|all&unit_id=&limit=&offset=
// POST { action: revoke, id }

require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/permissions.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
permission_require_super_admin($actor);

$method = $_SERVER['REQUEST_METHOD'];

function cc_qr_status(array $row): string
{
    if (!empty($row['revoked_at'])) return 'revoked';
    if (!empty($row['used_at'])) return 'used';
    if (strtotime((string) $row['expires_at']) <= time()) return 'expired';
    return 'active';
}

if ($method === 'GET') {
    $status = isset($_GET['status']) && is_string($_GET['status']) ? strtolower(trim($_GET['status'])) : 'all';
    $unitId = filter_var($_GET['unit_id'] ?? null, FILTER_VALIDATE_INT);
    $limit = filter_var($_GET['limit'] ?? 100, FILTER_VALIDATE_INT);
    $offset = filter_var($_GET['offset'] ?? 0, FILTER_VALIDATE_INT);

    if (!in_array($status, ['active', 'expired', 'used', 'revoked', 'all'], true)) $status = 'all';
    if ($limit === false || $limit < 1) $limit = 100;
    if ($limit > 300) $limit = 300;
    if ($offset === false || $offset < 0) $offset = 0;

    $sql = "SELECT ot.id, ot.unit_id, ot.expires_at, ot.revoked_at, ot.used_at, ot.created_at, ot.created_by,
                   u.unit_number, u.status AS unit_status,
                   p.id AS property_id, p.name AS property_name,
                   b.name AS building_name,
                   cu.full_name AS created_by_name
            FROM onboarding_tokens ot
            JOIN units u ON ot.unit_id = u.id
            JOIN properties p ON u.property_id = p.id
            LEFT JOIN buildings b ON u.building_id = b.id
            LEFT JOIN users cu ON ot.created_by = cu.id";
    $params = [];
    $conds = [];
    if ($unitId !== false && $unitId !== null && $unitId > 0) {
        $conds[] = 'ot.unit_id = :unit_id';
        $params[':unit_id'] = $unitId;
    }
    if ($conds) $sql .= ' WHERE ' . implode(' AND ', $conds);
    $sql .= ' ORDER BY ot.id DESC LIMIT 1000';

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);

    $all = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $row['status'] = cc_qr_status($row);
        if ($status === 'all' || $row['status'] === $status) {
            $all[] = $row;
        }
    }

    $total = count($all);
    $paged = array_slice($all, $offset, $limit);

    security_json_response(200, [
        'tokens' => $paged,
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
    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : '';
    if ($action !== 'revoke') {
        security_json_response(400, ['message' => 'Unsupported action.']);
    }
    $tokenId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($tokenId === false || $tokenId < 1) {
        security_json_response(400, ['message' => 'A valid token id is required.']);
    }

    $stmt = $conn->prepare(
        "UPDATE onboarding_tokens SET revoked_at = NOW()
         WHERE id = :id AND revoked_at IS NULL AND used_at IS NULL"
    );
    $stmt->execute([':id' => $tokenId]);
    if ($stmt->rowCount() === 0) {
        security_json_response(404, ['message' => 'This QR token is not active.']);
    }

    audit_log($conn, (int) $user->user_id, 'admin.qr.token_revoked', [
        'entity_type' => 'onboarding_token',
        'entity_id' => $tokenId,
    ]);

    security_json_response(200, ['message' => 'QR token revoked.']);
}

security_json_response(405, ['message' => 'Method not allowed.']);
