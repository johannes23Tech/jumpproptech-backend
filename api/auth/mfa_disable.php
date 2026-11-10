<?php
// POST /api/auth/mfa_disable.php - turn MFA off (password + current code).
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/mfa.php';
require_once '../../middleware/check_role.php';

const MFA_DISABLE_MAX_ATTEMPTS = 5;
const MFA_DISABLE_WINDOW = 900;
const MFA_DISABLE_LOCK = 900;

$user = authenticate();
$userId = (int) $user->user_id;

$data = json_decode(file_get_contents("php://input"));
$password = is_object($data) && isset($data->password) && is_string($data->password)
    ? $data->password
    : '';
$code = is_object($data) && isset($data->code) && is_string($data->code)
    ? trim($data->code)
    : '';

if ($password === '' || $code === '') {
    security_json_response(400, ["message" => "Your password and a current code are required."]);
}

$retryAfter = security_rate_limit_retry($conn, 'mfa_disable', (string) $userId);
if ($retryAfter > 0) {
    security_json_response(
        429,
        ["message" => "Too many attempts. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

$state = mfa_user_state($conn, $userId);
if ($state === null) {
    security_json_response(503, ["message" => "Multi-factor authentication is temporarily unavailable."]);
}
if (empty($state['enabled'])) {
    security_json_response(409, ["message" => "Multi-factor authentication is not enabled."]);
}

$stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $userId]);
$hash = (string) $stmt->fetchColumn();

$verified = $hash !== '' && password_verify($password, $hash);
$usedStep = null;

if ($verified) {
    if (preg_match('/^\d{6}$/', $code)) {
        // Verification is enough: MFA is being removed, so recording the step
        // would only burn a code the user may still need on another device.
        $verified = mfa_verify_code((string) $state['secret'], $code, $usedStep);
    } else {
        $verified = mfa_consume_recovery_code($conn, $userId, $code);
    }
}

if (!$verified) {
    $lockSeconds = security_rate_limit_hit(
        $conn,
        'mfa_disable',
        (string) $userId,
        MFA_DISABLE_MAX_ATTEMPTS,
        MFA_DISABLE_WINDOW,
        MFA_DISABLE_LOCK
    );

    audit_log($conn, $userId, 'auth.mfa.disable_failed', [
        'outcome' => $lockSeconds > 0 ? 'denied' : 'failure',
        'entity_type' => 'user',
        'entity_id' => $userId,
    ]);

    if ($lockSeconds > 0) {
        security_json_response(
            429,
            ["message" => "Too many attempts. Please try again later."],
            ["Retry-After" => (string) $lockSeconds]
        );
    }

    security_json_response(401, ["message" => "Password or code is incorrect."]);
}

try {
    // Disabling a second factor is a security downgrade: invalidate every
    // existing session and hand the current device a fresh token.
    $conn->beginTransaction();

    $update = $conn->prepare(
        "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL,
                          mfa_recovery_codes = NULL, mfa_last_step = NULL,
                          token_version = token_version + 1
         WHERE id = :id"
    );
    $update->execute([':id' => $userId]);

    $versionStmt = $conn->prepare("SELECT token_version, role FROM users WHERE id = :id LIMIT 1");
    $versionStmt->execute([':id' => $userId]);
    $row = $versionStmt->fetch(PDO::FETCH_ASSOC);

    $conn->commit();
} catch (Throwable $e) {
    if ($conn->inTransaction()) {
        $conn->rollBack();
    }
    error_log('MFA disable failed: ' . $e->getMessage());
    security_json_response(500, ["message" => "Multi-factor authentication could not be disabled."]);
}

security_rate_limit_clear($conn, 'mfa_disable', (string) $userId);

audit_log($conn, $userId, 'auth.mfa.disabled', [
    'entity_type' => 'user',
    'entity_id' => $userId,
    'meta' => ['sessions_invalidated' => true],
]);

security_json_response(200, [
    "message" => "Multi-factor authentication has been disabled. Other sessions have been signed out.",
    "enabled" => false,
    "token" => jwt_issue_access_token([
        'id' => $userId,
        'role' => $row['role'] ?? $user->role,
        'token_version' => (int) ($row['token_version'] ?? 0),
    ]),
]);
