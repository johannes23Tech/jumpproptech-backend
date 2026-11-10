<?php
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../middleware/check_role.php';

$user = authenticate();

$data = json_decode(file_get_contents("php://input"));
$logoutAll = is_object($data) && !empty($data->all);

if ($logoutAll) {
    // Global logout: invalidate every token issued before this moment.
    $stmt = $conn->prepare("UPDATE users SET token_version = token_version + 1 WHERE id = :id");
    $stmt->execute([':id' => $user->user_id]);

    audit_log($conn, (int) $user->user_id, 'auth.logout_all', [
        'meta' => ['jti' => $user->jti ?? null],
    ]);

    security_json_response(200, ["message" => "Logged out of all devices."]);
}

// Single-device logout: deny-list this token until its natural expiry.
$expiresAt = isset($user->exp) ? (int) $user->exp : (time() + JWT_EXPIRY);
$revoked = security_revoke_token($conn, (string) $user->jti, $expiresAt);

audit_log($conn, (int) $user->user_id, 'auth.logout', [
    'meta' => ['jti' => $user->jti ?? null, 'revoked' => $revoked],
]);

if (!$revoked) {
    // The token could not be deny-listed. Fail closed for the caller by
    // bumping the version instead of silently pretending it was revoked.
    $stmt = $conn->prepare("UPDATE users SET token_version = token_version + 1 WHERE id = :id");
    $stmt->execute([':id' => $user->user_id]);
    security_json_response(200, ["message" => "Logged out of all devices."]);
}

security_json_response(200, ["message" => "Logged out."]);
