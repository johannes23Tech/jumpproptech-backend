<?php
// api/qr_tokens.php
//
// Staff management of the unique per-unit onboarding QR token. Only a token
// hash is stored; the raw token and application URL are returned once when
// generated. A new token automatically revokes the unit's previous unused
// tokens so a unit never has two live QR codes.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/onboarding.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

permission_require($actor, 'qr.manage');

function qr_status(array $row): string
{
    if (!empty($row['revoked_at'])) {
        return 'revoked';
    }
    if (!empty($row['used_at'])) {
        return 'used';
    }
    if (strtotime((string) $row['expires_at']) <= time()) {
        return 'expired';
    }

    return 'active';
}

if ($method === 'GET') {
    $unitId = filter_var($_GET['unit_id'] ?? null, FILTER_VALIDATE_INT);

    $sql = "SELECT ot.id, ot.unit_id, ot.expires_at, ot.revoked_at, ot.used_at,
                   ot.created_at, u.unit_number, p.name AS property_name
            FROM onboarding_tokens ot
            JOIN units u ON ot.unit_id = u.id
            JOIN properties p ON u.property_id = p.id";
    $params = [];

    if ($unitId !== false && $unitId !== null && $unitId > 0) {
        $sql .= ' WHERE ot.unit_id = :unit_id';
        $params[':unit_id'] = $unitId;
    }
    $sql .= ' ORDER BY ot.id DESC LIMIT 200';

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);

    $tokens = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $row['status'] = qr_status($row);
        $tokens[] = $row;
    }

    echo json_encode($tokens);
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents('php://input'));

    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    // Revoking an existing token does not require unit details.
    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : 'generate';

    if ($action === 'revoke') {
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

        audit_log($conn, (int) $user->user_id, 'qr.token_revoked', [
            'entity_type' => 'onboarding_token',
            'entity_id' => $tokenId,
        ]);

        security_json_response(200, ['message' => 'QR code revoked.']);
    }

    if ($action !== 'generate') {
        security_json_response(400, ['message' => 'Unsupported action.']);
    }

    $unitId = filter_var($data->unit_id ?? 0, FILTER_VALIDATE_INT);
    if ($unitId === false || $unitId < 1) {
        security_json_response(400, ['message' => 'A valid unit is required.']);
    }

    $days = filter_var($data->expires_in_days ?? ONBOARDING_TOKEN_DEFAULT_DAYS, FILTER_VALIDATE_INT);
    if ($days === false || $days < 1 || $days > ONBOARDING_TOKEN_MAX_DAYS) {
        security_json_response(400, [
            'message' => 'Expiry must be between 1 and ' . ONBOARDING_TOKEN_MAX_DAYS . ' days.',
        ]);
    }

    $unitStmt = $conn->prepare(
        "SELECT u.id, u.unit_number, p.name AS property_name
         FROM units u
         JOIN properties p ON u.property_id = p.id
         WHERE u.id = :unit_id AND u.archived_at IS NULL
         LIMIT 1"
    );
    $unitStmt->execute([':unit_id' => $unitId]);
    $unit = $unitStmt->fetch(PDO::FETCH_ASSOC);

    if (!$unit) {
        security_json_response(404, ['message' => 'Unit not found or archived.']);
    }

    $rawToken = onboarding_generate_token();
    $expiresAt = (new DateTimeImmutable('now'))->modify('+' . $days . ' days')->format('Y-m-d H:i:s');

    try {
        $conn->beginTransaction();

        // A unit has one live QR code at a time. Retire anything unused first.
        $conn->prepare(
            "UPDATE onboarding_tokens SET revoked_at = NOW()
             WHERE unit_id = :unit_id AND revoked_at IS NULL AND used_at IS NULL"
        )->execute([':unit_id' => $unitId]);

        $insert = $conn->prepare(
            "INSERT INTO onboarding_tokens (unit_id, token_hash, expires_at, created_by)
             VALUES (:unit_id, :hash, :expires_at, :created_by)"
        );
        $insert->execute([
            ':unit_id' => $unitId,
            ':hash' => onboarding_token_hash($rawToken),
            ':expires_at' => $expiresAt,
            ':created_by' => (int) $user->user_id,
        ]);
        $tokenId = (int) $conn->lastInsertId();

        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('QR token generation failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The QR code could not be generated.']);
    }

    audit_log($conn, (int) $user->user_id, 'qr.token_generated', [
        'entity_type' => 'onboarding_token',
        'entity_id' => $tokenId,
        'meta' => ['unit_id' => $unitId, 'expires_at' => $expiresAt],
    ]);

    security_json_response(201, [
        'message' => 'QR code generated. Copy or download it now; it will not be shown again.',
        'id' => $tokenId,
        'token' => $rawToken,
        'url' => onboarding_application_url($rawToken),
        'expires_at' => $expiresAt,
        'unit_number' => $unit['unit_number'],
        'property_name' => $unit['property_name'],
    ]);
}

security_json_response(405, ['message' => 'Method not allowed.']);
