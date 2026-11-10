<?php
require_once '../../config/db.php';
require_once '../../config/mailer.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';

const FORGOT_IP_ATTEMPTS = 10;
const FORGOT_EMAIL_ATTEMPTS = 5;
const FORGOT_WINDOW = 900; // 15 minutes
const FORGOT_LOCK = 900;

$data = json_decode(file_get_contents("php://input"));

if (!is_object($data) || empty($data->email)) {
    security_json_response(400, ["message" => "Email is required."]);
}

$email = strtolower(trim((string) $data->email));
$ip = security_client_ip();

// Always return the same response, whether or not the account exists.
$genericMessage = "If an account exists for that email, a password reset link has been sent.";

if (!security_is_email($email)) {
    security_json_response(200, ["message" => $genericMessage]);
}

$retryAfter = max(
    security_rate_limit_retry($conn, 'forgot_ip', $ip),
    security_rate_limit_retry($conn, 'forgot_email', $email)
);

if ($retryAfter > 0) {
    audit_log($conn, null, 'auth.password.reset_request_denied', [
        'actor_email' => $email,
        'outcome' => 'denied',
        'meta' => ['reason' => 'rate_limited'],
    ]);
    security_json_response(
        429,
        ["message" => "Too many reset requests. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

$lockSeconds = max(
    security_rate_limit_hit($conn, 'forgot_ip', $ip, FORGOT_IP_ATTEMPTS, FORGOT_WINDOW, FORGOT_LOCK),
    security_rate_limit_hit($conn, 'forgot_email', $email, FORGOT_EMAIL_ATTEMPTS, FORGOT_WINDOW, FORGOT_LOCK)
);

if ($lockSeconds > 0) {
    audit_log($conn, null, 'auth.password.reset_request_denied', [
        'actor_email' => $email,
        'outcome' => 'denied',
        'meta' => ['reason' => 'locked'],
    ]);
    security_json_response(
        429,
        ["message" => "Too many reset requests. Please try again later."],
        ["Retry-After" => (string) $lockSeconds]
    );
}

try {
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $email]);
    $accountId = $stmt->fetchColumn();

    if ($accountId) {
        // Housekeeping: drop tokens that are past their useful life.
        $conn->exec("DELETE FROM password_resets WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY)");

        $token = bin2hex(random_bytes(32));
        // Store only a hash of the token. A database leak must not reveal
        // usable reset links.
        $tokenHash = hash('sha256', $token);

        $conn->prepare("DELETE FROM password_resets WHERE email = :email")
            ->execute([':email' => $email]);

        $insert = $conn->prepare("INSERT INTO password_resets (email, token) VALUES (:email, :token)");
        $insert->execute([':email' => $email, ':token' => $tokenHash]);

        $frontend = rtrim(getenv('FRONTEND_URL') ?: 'https://jumpproptech-frontend.vercel.app', '/');
        $resetLink = $frontend . "/reset-password?token=" . $token;

        $emailBody = "
            <div style='font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #E5DDCD; border-radius: 8px;'>
                <h2 style='color: #C5A059;'>Jump PropTech Password Reset</h2>
                <p>Hello,</p>
                <p>We received a request to reset your password. This link expires in 30 minutes and can only be used once.</p>
                <div style='text-align: center; margin: 30px 0;'>
                    <a href='{$resetLink}' style='display: inline-block; padding: 14px 28px; background-color: #C5A059; color: #000; text-decoration: none; font-weight: bold; border-radius: 6px;'>Reset Password</a>
                </div>
                <p>If you didn't request this change, you can safely ignore this email.</p>
                <br>
                <p style='font-size: 12px; color: #888; text-align: center;'>Smarter Property Management. Stronger Communities.</p>
            </div>
        ";

        if (!sendEmail($email, "Reset Your Jump PropTech Password", $emailBody)) {
            error_log('Password reset email could not be sent for user: ' . $email);
        }
    }

    audit_log($conn, $accountId ? (int) $accountId : null, 'auth.password.reset_requested', [
        'actor_email' => $email,
        'meta' => ['account_exists' => (bool) $accountId],
    ]);
} catch (Throwable $e) {
    // Do not leak internal details or account existence.
    error_log('Forgot password error: ' . $e->getMessage());
}

security_json_response(200, ["message" => $genericMessage]);
