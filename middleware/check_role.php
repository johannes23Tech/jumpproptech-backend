<?php
// middleware/check_role.php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/jwt.php';
require_once __DIR__ . '/../config/security.php';
require_once __DIR__ . '/../config/audit.php';
require_once __DIR__ . '/../config/permissions.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

/**
 * Read a request header case-insensitively. Falls back to $_SERVER when
 * getallheaders() is unavailable (some FPM configurations).
 */
function auth_request_header(string $name): ?string
{
    static $headers = null;

    if ($headers === null) {
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        if (!is_array($headers)) {
            $headers = [];
        }
        foreach ($_SERVER as $key => $value) {
            if (strncmp($key, 'HTTP_', 5) === 0) {
                $header = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                if (!isset($headers[$header])) {
                    $headers[$header] = $value;
                }
            }
        }
    }

    foreach ($headers as $key => $value) {
        if (strcasecmp($key, $name) === 0) {
            return $value;
        }
    }
    return null;
}

function authenticate() {
    global $conn; // Access the PDO connection from db.php

    $authHeader = auth_request_header('Authorization');

    // Check if Authorization header exists
    if ($authHeader === null || $authHeader === '') {
        security_json_response(401, ["message" => "No token provided. Access denied."]);
    }

    // Extract the token (Format: "Bearer <token>")
    $arr = explode(" ", $authHeader);
    $jwt = $arr[1] ?? null;

    if (!$jwt) {
        security_json_response(401, ["message" => "Invalid token format."]);
    }

    try {
        // Decode and verify the signature/issuer/expiry.
        $decoded = JWT::decode($jwt, new Key(JWT_SECRET, JWT_ALGO));

        // Every token must carry a jti and the token version it was issued at.
        if (!isset($decoded->user_id, $decoded->jti, $decoded->ver)) {
            security_json_response(401, ["message" => "Invalid or expired token."]);
        }

        // Reject MFA challenge tokens (scope=mfa) and any other non-access
        // token. Tokens issued before scopes existed have no scope and are
        // still accepted until they expire.
        if (isset($decoded->scope) && $decoded->scope !== 'access') {
            security_json_response(401, ["message" => "Invalid or expired token."]);
        }

        // Never trust the role in the token: fetch the current role,
        // account state and token version from the DB.
        $userStmt = $conn->prepare(
            "SELECT role, subscription_status, token_version,
                    staff_role, account_type, company_id, is_active
             FROM users WHERE id = :id LIMIT 1"
        );
        $userStmt->execute([':id' => $decoded->user_id]);
        $currentUser = $userStmt->fetch(PDO::FETCH_ASSOC);

        if (!$currentUser) {
            security_json_response(401, ["message" => "Invalid or expired token."]);
        }

        // Deactivated accounts lose access immediately, even with a valid token.
        if (isset($currentUser['is_active']) && (int) $currentUser['is_active'] === 0) {
            security_json_response(403, ["message" => "This account is inactive. Contact an administrator."]);
        }

        // Bumping token_version invalidates every token issued before the bump.
        if ((int) $decoded->ver !== (int) $currentUser['token_version']) {
            security_json_response(401, ["message" => "Session expired. Please log in again."]);
        }

        // Single-device logout: reject tokens placed on the denylist.
        if (security_token_is_revoked($conn, (string) $decoded->jti)) {
            security_json_response(401, ["message" => "Session expired. Please log in again."]);
        }

        // Keep the legacy role for endpoints that still use it, and expose the
        // approved role + permission context for new checks.
        $decoded->role = $currentUser['role'];
        $decoded->legacy_role = $currentUser['role'];
        $decoded->staff_role = $currentUser['staff_role'] ?? null;
        $decoded->account_type = $currentUser['account_type'] ?? ($currentUser['role'] === 'tenant' ? 'tenant' : 'staff');
        $decoded->company_id = isset($currentUser['company_id']) ? (int) $currentUser['company_id'] : null;
        $decoded->effective_role = permission_role_for_user($currentUser);

        // The SaaS subscription gate is retired: JUMP PROPTECH is an internal
        // company system, not a subscription product. The column remains
        // dormant for historical records only.
        //
        // Auditor is read-only. Enforce it centrally so every endpoint is
        // covered, not just the screens that hide buttons.
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        if ($decoded->effective_role === 'auditor' && !in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
            audit_log($conn, (int) $decoded->user_id, 'auth.permission_denied', [
                'entity_type' => 'route',
                'outcome' => 'denied',
                'meta' => ['role' => 'auditor', 'method' => $method, 'path' => (string) ($_SERVER['REQUEST_URI'] ?? '')],
            ]);
            security_json_response(403, ["message" => "Auditor accounts are read-only."]);
        }

        return $decoded; // Returns the payload (user_id, role, jti, ver, ...)

    } catch (Exception $e) {
        security_json_response(401, ["message" => "Invalid or expired token."]);
    }
}
?>
