<?php
// POST /api/auth/mfa_setup.php - generate a new TOTP secret (not enabled yet).
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/mfa.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$userId = (int) $user->user_id;

$data = json_decode(file_get_contents("php://input"));
$password = is_object($data) && isset($data->password) && is_string($data->password)
    ? $data->password
    : '';

if ($password === '') {
    security_json_response(400, ["message" => "Confirm your password to start MFA setup."]);
}

$retryAfter = security_rate_limit_retry($conn, 'mfa_setup', (string) $userId);
if ($retryAfter > 0) {
    security_json_response(
        429,
        ["message" => "Too many attempts. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

// Requiring the password means a stolen session token alone cannot enrol an
// attacker-controlled authenticator and lock the real owner out.
$passwordStmt = $conn->prepare("SELECT password_hash, email FROM users WHERE id = :id LIMIT 1");
$passwordStmt->execute([':id' => $userId]);
$account = $passwordStmt->fetch(PDO::FETCH_ASSOC);

if (!$account || !password_verify($password, (string) $account['password_hash'])) {
    security_rate_limit_hit($conn, 'mfa_setup', (string) $userId, 5, 900, 900);
    security_json_response(401, ["message" => "Your password is incorrect."]);
}

if (!mfa_ensure_schema($conn)) {
    security_json_response(503, ["message" => "Multi-factor authentication is temporarily unavailable."]);
}

$state = mfa_user_state($conn, $userId);
if ($state === null) {
    security_json_response(503, ["message" => "Multi-factor authentication is temporarily unavailable."]);
}
if (!empty($state['enabled'])) {
    security_json_response(409, ["message" => "Multi-factor authentication is already enabled."]);
}

$secret = mfa_generate_secret();

try {
    // Rotate any previous pending secret. MFA stays disabled until a code is
    // verified, so an interrupted setup can never lock the account out.
    $stmt = $conn->prepare(
        "UPDATE users SET mfa_secret = :secret, mfa_enabled = 0,
                          mfa_recovery_codes = NULL, mfa_last_step = NULL
         WHERE id = :id"
    );
    $stmt->execute([':secret' => $secret, ':id' => $userId]);
} catch (Throwable $e) {
    error_log('MFA setup failed: ' . $e->getMessage());
    security_json_response(500, ["message" => "Multi-factor authentication could not be started."]);
}

audit_log($conn, $userId, 'auth.mfa.setup_started', [
    'entity_type' => 'user',
    'entity_id' => $userId,
]);

security_json_response(200, [
    "message" => "Scan the secret in your authenticator app, then confirm with a code.",
    "secret" => $secret,
    "otpauth_uri" => mfa_otpauth_uri($secret, (string) $account['email']),
]);
