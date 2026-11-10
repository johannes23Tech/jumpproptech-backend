<?php
require_once '../../config/db.php';
require_once '../../config/jwt.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../vendor/autoload.php';

use \Firebase\JWT\JWT;

const REGISTER_IP_ATTEMPTS = 10;
const REGISTER_WINDOW = 3600;
const REGISTER_LOCK = 3600;

$data = json_decode(file_get_contents("php://input"));

if (!is_object($data)
    || empty($data->full_name) || !is_string($data->full_name)
    || empty($data->email) || !is_string($data->email)
    || empty($data->password) || !is_string($data->password)) {
    security_json_response(400, ["message" => "Incomplete data."]);
}

$fullName = security_clean_text($data->full_name, 100);
$email = strtolower(trim($data->email));
$phone = security_clean_text($data->phone ?? '', 20);

if ($fullName === '' || !security_is_email($email)) {
    security_json_response(400, ["message" => "A valid name and email are required."]);
}

$policyError = security_validate_password($data->password);
if ($policyError !== null) {
    security_json_response(400, ["message" => $policyError]);
}

// Cap account creation per source IP so the endpoint cannot be used to mass
// create accounts or to probe the user table.
$ip = security_client_ip();
$retryAfter = security_rate_limit_retry($conn, 'register_ip', $ip);
if ($retryAfter > 0) {
    audit_log($conn, null, 'auth.register.denied', [
        'outcome' => 'denied',
        'meta' => ['reason' => 'rate_limited'],
    ]);
    security_json_response(
        429,
        ["message" => "Too many registration attempts. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

$lockSeconds = security_rate_limit_hit($conn, 'register_ip', $ip, REGISTER_IP_ATTEMPTS, REGISTER_WINDOW, REGISTER_LOCK);
if ($lockSeconds > 0) {
    audit_log($conn, null, 'auth.register.denied', [
        'outcome' => 'denied',
        'meta' => ['reason' => 'locked'],
    ]);
    security_json_response(
        429,
        ["message" => "Too many registration attempts. Please try again later."],
        ["Retry-After" => (string) $lockSeconds]
    );
}

try {
    // Check if email already exists
    $checkQuery = "SELECT id FROM users WHERE email = :email LIMIT 1";
    $stmt = $conn->prepare($checkQuery);
    $stmt->bindParam(':email', $email);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        audit_log($conn, null, 'auth.register.rejected', [
            'actor_email' => $email,
            'outcome' => 'failure',
            'meta' => ['reason' => 'email_exists'],
        ]);
        security_json_response(400, ["message" => "Email already exists."]);
    }

    // Public registration is strictly for tenants
    $role = 'tenant';
    $subStatus = 'active';

    $query = "INSERT INTO users (full_name, email, password_hash, phone, role, subscription_status) 
              VALUES (:full_name, :email, :password_hash, :phone, :role, :sub_status)";

    $stmt = $conn->prepare($query);
    $password_hash = security_hash_password($data->password);

    $stmt->bindParam(':full_name', $fullName);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password_hash', $password_hash);
    $stmt->bindParam(':phone', $phone);
    $stmt->bindParam(':role', $role);
    $stmt->bindParam(':sub_status', $subStatus);

    if ($stmt->execute()) {
        $userId = (int) $conn->lastInsertId();

        // Generate a JWT for auto-login.
        $jwt = jwt_issue_access_token([
            'id' => $userId,
            'role' => $role,
            'token_version' => 0,
        ]);

        audit_log($conn, $userId, 'auth.register.success', [
            'actor_email' => $email,
            'entity_type' => 'user',
            'entity_id' => $userId,
        ]);

        security_json_response(201, [
            "message" => "Account created successfully!",
            "token" => $jwt,
            "user" => [
                "id" => $userId,
                "full_name" => $fullName,
                "email" => $email,
                "role" => $role
            ]
        ]);
    }

    security_json_response(500, ["message" => "User could not be created."]);
} catch (PDOException $e) {
    error_log('Registration error: ' . $e->getMessage());
    security_json_response(500, ["message" => "Account could not be created."]);
}
