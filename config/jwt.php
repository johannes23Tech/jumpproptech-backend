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
 * Mint a full access token and return it with its claims metadata.
 *
 * Every token carries a `scope` claim so the short-lived MFA challenge token
 * (scope=mfa) can never be replayed as an authenticated session.
 *
 * @param array $user Row with id, role and token_version.
 * @return array{token:string,jti:string,iat:int,exp:int,user_id:int}
 */
function jwt_mint_access_token(array $user): array
{
    $issuedAt = time();
    $jti = bin2hex(random_bytes(16));
    $exp = $issuedAt + JWT_EXPIRY;
    $userId = (int) $user['id'];

    $token = JWT::encode([
        'iss' => JWT_ISSUER,
        'iat' => $issuedAt,
        'exp' => $exp,
        'jti' => $jti,
        'scope' => 'access',
        'ver' => (int) ($user['token_version'] ?? 0),
        'user_id' => $userId,
        'role' => (string) $user['role'],
    ], JWT_SECRET, JWT_ALGO);

    return [
        'token' => $token,
        'jti' => $jti,
        'iat' => $issuedAt,
        'exp' => $exp,
        'user_id' => $userId,
    ];
}

/**
 * Issue a full access token (backward-compatible string form).
 *
 * @param array $user Row with id, role and token_version.
 */
function jwt_issue_access_token(array $user): string
{
    return jwt_mint_access_token($user)['token'];
}
