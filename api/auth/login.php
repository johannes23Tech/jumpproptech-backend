<?php
require_once '../../config/db.php';
require_once '../../config/jwt.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/mfa.php';

const LOGIN_MAX_ATTEMPTS = 5;   // per email + IP
const LOGIN_MAX_IP_ATTEMPTS = 50; // per IP, stops spraying many accounts (high enough for shared NAT)
const LOGIN_WINDOW = 900;       // 15 minutes
const LOGIN_LOCK = 900;         // 15 minutes

// A fixed bcrypt hash used to spend the same CPU time on unknown accounts as
// on real ones. Without this, response timing reveals which emails exist.
const LOGIN_DUMMY_HASH = '$2y$12$PKWOMhfWdTWLl56uO4HijeD5BxjBd4sXpePiVYrjWhsgu9Dy6u2MW';

$data = json_decode(file_get_contents("php://input"));

if (!is_object($data)
    || !isset($data->email) || !is_string($data->email) || $data->email === ''
    || !isset($data->password) || !is_string($data->password) || $data->password === '') {
    security_json_response(400, ["message" => "Email and password are required."]);
}

$email = strtolower(trim((string) $data->email));
$ip = security_client_ip();
$emailKey = $email . '|' . $ip;

// Check both the per-account and per-IP buckets before touching credentials.
$retryAfter = max(
    security_rate_limit_retry($conn, 'login', $emailKey),
    security_rate_limit_retry($conn, 'login_ip', $ip)
);

if ($retryAfter > 0) {
    audit_log($conn, null, 'auth.login.denied', [
        'actor_email' => $email,
        'outcome' => 'denied',
        'meta' => ['reason' => 'locked', 'retry_after' => $retryAfter],
    ]);
    security_json_response(
        429,
        ["message" => "Too many login attempts. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

try {
    // Find user by email
    $query = "SELECT id, full_name, email, password_hash, role, token_version
              FROM users WHERE email = :email LIMIT 1";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email);
    $stmt->execute();

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Always run one bcrypt verification, even for unknown emails, so the
    // response time does not reveal whether an account exists.
    $passwordOk = password_verify($data->password, $user['password_hash'] ?? LOGIN_DUMMY_HASH);

    if ($user && $passwordOk) {
        // Successful login: clear the counter for this account. The per-IP
        // counter is left alone so a valid account cannot reset spray limits.
        security_rate_limit_clear($conn, 'login', $emailKey);

        // Transparently upgrade legacy bcrypt cost/hash parameters.
        if (security_password_needs_rehash($user['password_hash'])) {
            try {
                $rehash = $conn->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
                $rehash->execute([
                    ':hash' => security_hash_password($data->password),
                    ':id' => $user['id'],
                ]);
            } catch (Throwable $e) {
                error_log('Password rehash failed: ' . $e->getMessage());
            }
        }

        // If the account has MFA enabled, the password alone is not a login.
        // Return a 5-minute challenge token that only works on mfa_login.php.
        $mfa = mfa_user_state($conn, (int) $user['id']);

        // Fail closed: if MFA state cannot be read we must not assume it is
        // off and grant a password-only session.
        if ($mfa === null) {
            error_log('Login blocked: MFA state unavailable for user ' . (int) $user['id']);
            security_json_response(503, ["message" => "Login is temporarily unavailable. Please try again shortly."]);
        }

        if (!empty($mfa['enabled'])) {
            audit_log($conn, (int) $user['id'], 'auth.mfa.challenge', [
                'actor_email' => $user['email'],
                'meta' => ['role' => $user['role']],
            ]);

            security_json_response(200, [
                "mfa_required" => true,
                "mfa_token" => mfa_issue_challenge_token((int) $user['id'], (int) $user['token_version']),
                "message" => "Enter the 6-digit code from your authenticator app.",
            ]);
        }

        // Generate a full access JWT. `ver` enables global revocation; `jti`
        // enables single-device logout; `scope=access` blocks challenge reuse.
        $jwt = jwt_issue_access_token($user);

        audit_log($conn, (int) $user['id'], 'auth.login.success', [
            'actor_email' => $user['email'],
            'meta' => ['role' => $user['role'], 'mfa' => false],
        ]);

        security_json_response(200, [
            "message" => "Login successful.",
            "token" => $jwt,
            "user" => [
                "id" => $user['id'],
                "full_name" => $user['full_name'],
                "email" => $user['email'],
                "role" => $user['role']
            ]
        ]);
    }

    // Failed login: count it against the account and the source IP.
    $lockSeconds = max(
        security_rate_limit_hit($conn, 'login', $emailKey, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW, LOGIN_LOCK),
        security_rate_limit_hit($conn, 'login_ip', $ip, LOGIN_MAX_IP_ATTEMPTS, LOGIN_WINDOW, LOGIN_LOCK)
    );

    audit_log($conn, null, 'auth.login.failure', [
        'actor_email' => $email,
        'outcome' => $lockSeconds > 0 ? 'denied' : 'failure',
        'meta' => ['locked' => $lockSeconds > 0],
    ]);

    if ($lockSeconds > 0) {
        security_json_response(
            429,
            ["message" => "Too many login attempts. Please try again later."],
            ["Retry-After" => (string) $lockSeconds]
        );
    }

    // Same response for unknown emails and wrong passwords.
    security_json_response(401, ["message" => "Invalid credentials."]);
} catch (Exception $e) {
    error_log('Login error: ' . $e->getMessage());
    security_json_response(500, ["message" => "Login failed. Please try again."]);
}
