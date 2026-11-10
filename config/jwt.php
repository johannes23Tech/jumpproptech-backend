<?php
// config/jwt.php - JWT configuration

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/../vendor/autoload.php';

use \Firebase\JWT\JWT;

// Fail closed: never fall back to a secret that exists in source control.
$secret = getenv('JWT_SECRET');
$weakSecrets = [
    '',
    'your_super_secret_jwt_key_change_this_in_production',
    'jumpproptech_super_secret_key_2025',
];

if ($secret === false || in_array($secret, $weakSecrets, true) || strlen($secret) < 32) {
    http_response_code(500);
    echo json_encode(['message' => 'Server configuration error.']);
    exit();
}

define('JWT_SECRET', $secret);
define('JWT_ALGO', 'HS256');
define('JWT_EXPIRY', intval(getenv('JWT_EXPIRY')) ?: 3600); // 1 hour
define('JWT_ISSUER', getenv('JWT_ISSUER') ?: 'jumpproptech');

/**
 * Issue a full access token.
 *
 * Every token carries a `scope` claim so the short-lived MFA challenge token
 * (scope=mfa) can never be replayed as an authenticated session.
 *
 * @param array $user Row with id, role and token_version.
 */
function jwt_issue_access_token(array $user): string
{
    $issuedAt = time();

    return JWT::encode([
        'iss' => JWT_ISSUER,
        'iat' => $issuedAt,
        'exp' => $issuedAt + JWT_EXPIRY,
        'jti' => bin2hex(random_bytes(16)),
        'scope' => 'access',
        'ver' => (int) ($user['token_version'] ?? 0),
        'user_id' => (int) $user['id'],
        'role' => (string) $user['role'],
    ], JWT_SECRET, JWT_ALGO);
}
