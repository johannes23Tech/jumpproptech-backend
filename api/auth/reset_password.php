<?php
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';

const RESET_IP_ATTEMPTS = 10;
const RESET_WINDOW = 900;
const RESET_LOCK = 900;

$data = json_decode(file_get_contents("php://input"));

if (!is_object($data) || !isset($data->token) || !is_string($data->token) || $data->token === '') {
    security_json_response(400, ["message" => "Reset token is required."]);
}

$token = $data->token;
$password = '';
foreach (['password', 'newPassword', 'new_password'] as $passwordField) {
    if (isset($data->$passwordField) && is_string($data->$passwordField)) {
        $password = $data->$passwordField;
        break;
    }
}

if ($token === '' || strlen($token) < 32 || strlen($token) > 128) {
    security_json_response(400, ["message" => "This reset link is invalid or has expired."]);
}

$policyError = security_validate_password($password);
if ($policyError !== null) {
    security_json_response(400, ["message" => $policyError]);
}

$ip = security_client_ip();
$retryAfter = security_rate_limit_retry($conn, 'reset_ip', $ip);
if ($retryAfter > 0) {
    audit_log($conn, null, 'auth.password.reset_denied', [
        'outcome' => 'denied',
        'meta' => ['reason' => 'rate_limited'],
    ]);
    security_json_response(
        429,
        ["message" => "Too many reset attempts. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

$lockSeconds = security_rate_limit_hit($conn, 'reset_ip', $ip, RESET_IP_ATTEMPTS, RESET_WINDOW, RESET_LOCK);
if ($lockSeconds > 0) {
    audit_log($conn, null, 'auth.password.reset_denied', [
        'outcome' => 'denied',
        'meta' => ['reason' => 'locked'],
    ]);
    security_json_response(
        429,
        ["message" => "Too many reset attempts. Please try again later."],
        ["Retry-After" => (string) $lockSeconds]
    );
}

$invalidMessage = "This reset link is invalid or has expired.";

try {
    $tokenHash = hash('sha256', $token);

    // Token must exist, be younger than 30 minutes and not already used.
    $lookup = $conn->prepare(
        "SELECT email FROM password_resets
         WHERE token = :token AND created_at >= DATE_SUB(NOW(), INTERVAL 30 MINUTE)
         ORDER BY id DESC LIMIT 1"
    );
    $lookup->execute([':token' => $tokenHash]);
    $email = $lookup->fetchColumn();

    if (!$email) {
        audit_log($conn, null, 'auth.password.reset_failed', [
            'outcome' => 'failure',
            'meta' => ['reason' => 'invalid_or_expired_token'],
        ]);
        security_json_response(400, ["message" => $invalidMessage]);
    }

    $userStmt = $conn->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $userStmt->execute([':email' => $email]);
    $userId = $userStmt->fetchColumn();

    if (!$userId) {
        // Orphaned token: clean it up and give the same generic answer.
        $conn->prepare("DELETE FROM password_resets WHERE email = :email")->execute([':email' => $email]);
        audit_log($conn, null, 'auth.password.reset_failed', [
            'actor_email' => $email,
            'outcome' => 'failure',
            'meta' => ['reason' => 'orphaned_token'],
        ]);
        security_json_response(400, ["message" => $invalidMessage]);
    }

    $newHash = security_hash_password($password);

    $conn->beginTransaction();

    // Bumping token_version invalidates every existing session for the account.
    $update = $conn->prepare(
        "UPDATE users SET password_hash = :hash, token_version = token_version + 1 WHERE id = :id"
    );
    $update->execute([':hash' => $newHash, ':id' => $userId]);

    // Single use: remove every outstanding token for this account.
    $delete = $conn->prepare("DELETE FROM password_resets WHERE email = :email");
    $delete->execute([':email' => $email]);

    $conn->commit();

    security_rate_limit_clear($conn, 'reset_ip', $ip);

    audit_log($conn, (int) $userId, 'auth.password.reset', [
        'actor_email' => $email,
        'entity_type' => 'user',
        'entity_id' => (int) $userId,
        'meta' => ['sessions_invalidated' => true],
    ]);

    security_json_response(200, ["message" => "Password updated successfully. You can now log in."]);
} catch (Throwable $e) {
    if ($conn->inTransaction()) {
        $conn->rollBack();
    }
    error_log('Password reset error: ' . $e->getMessage());
    security_json_response(500, ["message" => "Password could not be updated. Please try again."]);
}
