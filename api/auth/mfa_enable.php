<?php
// POST /api/auth/mfa_enable.php - confirm a TOTP code and turn MFA on.
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/mfa.php';
require_once '../../middleware/check_role.php';

const MFA_MAX_ATTEMPTS = 5;
const MFA_WINDOW = 900;
const MFA_LOCK = 900;

$user = authenticate();
$userId = (int) $user->user_id;

$data = json_decode(file_get_contents("php://input"));
$code = is_object($data) && isset($data->code) && is_string($data->code)
    ? trim($data->code)
    : '';

if ($code === '') {
    security_json_response(400, ["message" => "Enter the 6-digit code from your authenticator app."]);
}

$retryAfter = security_rate_limit_retry($conn, 'mfa_verify', (string) $userId);
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
if (empty($state['secret'])) {
    security_json_response(400, ["message" => "Start MFA setup before confirming a code."]);
}
if (!empty($state['enabled'])) {
    security_json_response(409, ["message" => "Multi-factor authentication is already enabled."]);
}

$usedStep = null;
if (!mfa_verify_code((string) $state['secret'], $code, $usedStep)) {
    $lockSeconds = security_rate_limit_hit($conn, 'mfa_verify', (string) $userId, MFA_MAX_ATTEMPTS, MFA_WINDOW, MFA_LOCK);

    audit_log($conn, $userId, 'auth.mfa.enable_failed', [
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

    security_json_response(400, ["message" => "That code is not valid. Check your device clock and try again."]);
}

// The code is valid. Generate single-use recovery codes and enable MFA.
$recoveryCodes = mfa_generate_recovery_codes();

try {
    $conn->beginTransaction();

    $stmt = $conn->prepare(
        "UPDATE users SET mfa_enabled = 1, mfa_recovery_codes = :codes,
                          mfa_last_step = :step, token_version = token_version + 1
         WHERE id = :id AND mfa_enabled = 0
           AND (mfa_last_step IS NULL OR mfa_last_step < :step)"
    );
    $stmt->execute([
        ':codes' => mfa_hash_recovery_codes($recoveryCodes),
        ':step' => $usedStep,
        ':id' => $userId,
    ]);

    // rowCount() !== 1 means the code was already used, MFA was enabled by a
    // concurrent request, or the step was replayed. Never hand out recovery
    // codes in that case.
    if ($stmt->rowCount() !== 1) {
        $conn->rollBack();
        security_json_response(409, [
            "message" => "That code has already been used or MFA is already enabled. Start setup again.",
        ]);
    }

    $versionStmt = $conn->prepare("SELECT token_version, role FROM users WHERE id = :id LIMIT 1");
    $versionStmt->execute([':id' => $userId]);
    $row = $versionStmt->fetch(PDO::FETCH_ASSOC);

    $conn->commit();
} catch (Throwable $e) {
    if ($conn->inTransaction()) {
        $conn->rollBack();
    }
    error_log('MFA enable failed: ' . $e->getMessage());
    security_json_response(500, ["message" => "Multi-factor authentication could not be enabled."]);
}

security_rate_limit_clear($conn, 'mfa_verify', (string) $userId);

audit_log($conn, $userId, 'auth.mfa.enabled', [
    'entity_type' => 'user',
    'entity_id' => $userId,
]);

security_json_response(200, [
    "message" => "Multi-factor authentication is now enabled. Store your recovery codes somewhere safe.",
    "enabled" => true,
    // Other sessions are signed out; keep this device signed in.
    "token" => jwt_issue_access_token([
        'id' => $userId,
        'role' => $row['role'] ?? $user->role,
        'token_version' => (int) ($row['token_version'] ?? 0),
    ]),
    // Shown once. The server only keeps bcrypt hashes.
    "recovery_codes" => $recoveryCodes,
]);
