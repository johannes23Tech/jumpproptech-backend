<?php
require_once '../../config/db.php';
require_once '../../config/jwt.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../middleware/check_role.php';
require_once '../../vendor/autoload.php';

use \Firebase\JWT\JWT;

// Authenticate the user (requires a valid JWT token)
$user = authenticate();

$data = json_decode(file_get_contents("php://input"));

if (!is_object($data)
    || empty($data->currentPassword) || !is_string($data->currentPassword)
    || empty($data->newPassword) || !is_string($data->newPassword)) {
    security_json_response(400, ["message" => "Both current and new passwords are required."]);
}

$policyError = security_validate_password($data->newPassword);
if ($policyError !== null) {
    security_json_response(400, ["message" => $policyError]);
}

$retryAfter = security_rate_limit_retry($conn, 'change_password', (string) $user->user_id);
if ($retryAfter > 0) {
    security_json_response(429, ["message" => "Too many attempts. Please try again later."], ["Retry-After" => (string) $retryAfter]);
}

try {
    // 1. Fetch the current user's password hash
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = :user_id LIMIT 1");
    $stmt->execute([':user_id' => $user->user_id]);
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$userData) {
        security_json_response(404, ["message" => "User not found."]);
    }

    // 2. Verify the current password
    if (!password_verify($data->currentPassword, $userData['password_hash'])) {
        security_rate_limit_hit($conn, 'change_password', (string) $user->user_id, 5, 900, 900);
        audit_log($conn, (int) $user->user_id, 'auth.password.change_failed', [
            'outcome' => 'failure',
            'meta' => ['reason' => 'incorrect_current_password'],
        ]);
        security_json_response(401, ["message" => "Incorrect current password."]);
    }

    // 3. Hash the new password and invalidate every other session.
    $newHash = security_hash_password($data->newPassword);

    $conn->beginTransaction();

    $update = $conn->prepare(
        "UPDATE users SET password_hash = :hash, token_version = token_version + 1 WHERE id = :user_id"
    );
    $update->execute([':hash' => $newHash, ':user_id' => $user->user_id]);

    $versionStmt = $conn->prepare("SELECT token_version FROM users WHERE id = :user_id LIMIT 1");
    $versionStmt->execute([':user_id' => $user->user_id]);
    $newVersion = (int) $versionStmt->fetchColumn();

    $conn->commit();

    security_rate_limit_clear($conn, 'change_password', (string) $user->user_id);

    audit_log($conn, (int) $user->user_id, 'auth.password.changed', [
        'entity_type' => 'user',
        'entity_id' => (int) $user->user_id,
        'meta' => ['sessions_invalidated' => true],
    ]);

    // Keep the current device signed in with a fresh token; every other
    // token (older version) is now rejected.
    security_json_response(200, [
        "message" => "Password updated successfully. Other sessions have been signed out.",
        "token" => jwt_issue_access_token([
            'id' => (int) $user->user_id,
            'role' => $user->role,
            'token_version' => $newVersion,
        ]),
    ]);
} catch (Exception $e) {
    if ($conn->inTransaction()) {
        $conn->rollBack();
    }
    error_log("Password change failed: " . $e->getMessage());
    security_json_response(500, ["message" => "Failed to update password. Please try again."]);
}
