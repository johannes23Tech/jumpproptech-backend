<?php
// POST /api/auth/mfa_login.php - complete login with a TOTP or recovery code.
//
// The client receives an `mfa_token` from login.php after the password is
// verified. This endpoint exchanges it (plus the second factor) for a full
// access token. The challenge token is single-use and expires in 5 minutes.
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/mfa.php';

const MFA_LOGIN_MAX_ATTEMPTS = 7;
const MFA_LOGIN_WINDOW = 900;
const MFA_LOGIN_LOCK = 900;

$data = json_decode(file_get_contents("php://input"));

$challengeToken = is_object($data) && isset($data->mfa_token) && is_string($data->mfa_token)
    ? trim($data->mfa_token)
    : '';
$code = is_object($data) && isset($data->code) && is_string($data->code)
    ? trim($data->code)
    : '';

if ($challengeToken === '' || $code === '') {
    security_json_response(400, ["message" => "A verification code is required."]);
}

$challenge = mfa_decode_challenge_token($conn, $challengeToken);
if ($challenge === null) {
    security_json_response(401, ["message" => "Your login session expired. Please sign in again."]);
}

$userId = (int) $challenge->user_id;

$retryAfter = security_rate_limit_retry($conn, 'mfa_login', (string) $userId);

if ($retryAfter > 0) {
    audit_log($conn, $userId, 'auth.mfa.denied', [
        'outcome' => 'denied',
        'meta' => ['reason' => 'rate_limited'],
    ]);
    security_json_response(
        429,
        ["message" => "Too many attempts. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

try {
    $stmt = $conn->prepare(
        "SELECT id, full_name, email, role, token_version, mfa_enabled,
                mfa_secret, mfa_last_step
         FROM users WHERE id = :id LIMIT 1"
    );
    $stmt->execute([':id' => $userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    error_log('MFA login lookup failed: ' . $e->getMessage());
    security_json_response(500, ["message" => "Login failed. Please try again."]);
}

if (!$user || (int) $user['mfa_enabled'] !== 1 || empty($user['mfa_secret'])) {
    security_json_response(401, ["message" => "Multi-factor authentication is not enabled for this account."]);
}

if ((int) $user['token_version'] !== (int) $challenge->ver) {
    security_json_response(401, ["message" => "Your login session expired. Please sign in again."]);
}

$verified = false;
$replay = false;
$usedStep = null;

if (preg_match('/^\d{6}$/', $code)) {
    if (mfa_verify_code((string) $user['mfa_secret'], $code, $usedStep)) {
        $verified = mfa_consume_totp_step($conn, $userId, (int) $usedStep);
        // The code was valid but its time step was already spent.
        $replay = !$verified;
    }
} else {
    $verified = mfa_consume_recovery_code($conn, $userId, $code);
}

if (!$verified) {
    // A replayed code is not a wrong guess: don't count it towards the lock,
    // otherwise a double-clicked form can lock the account.
    if ($replay) {
        security_json_response(401, [
            "message" => "That code has already been used. Wait for your authenticator to show a new code.",
        ]);
    }

    $lockSeconds = security_rate_limit_hit(
        $conn,
        'mfa_login',
        (string) $userId,
        MFA_LOGIN_MAX_ATTEMPTS,
        MFA_LOGIN_WINDOW,
        MFA_LOGIN_LOCK
    );

    audit_log($conn, $userId, 'auth.mfa.failure', [
        'actor_email' => $user['email'],
        'outcome' => $lockSeconds > 0 ? 'denied' : 'failure',
        'meta' => ['locked' => $lockSeconds > 0],
    ]);

    if ($lockSeconds > 0) {
        security_json_response(
            429,
            ["message" => "Too many attempts. Please try again later."],
            ["Retry-After" => (string) $lockSeconds]
        );
    }

    security_json_response(401, ["message" => "That code is not valid. Please try again."]);
}

// Burn the challenge token so it cannot be replayed.
security_revoke_token($conn, (string) $challenge->jti, (int) $challenge->exp);

security_rate_limit_clear($conn, 'mfa_login', (string) $userId);

audit_log($conn, $userId, 'auth.login.success', [
    'actor_email' => $user['email'],
    'meta' => ['role' => $user['role'], 'mfa' => true],
]);

security_json_response(200, [
    "message" => "Login successful.",
    "token" => jwt_issue_access_token($user),
    "user" => [
        "id" => (int) $user['id'],
        "full_name" => $user['full_name'],
        "email" => $user['email'],
        "role" => $user['role'],
    ],
]);
