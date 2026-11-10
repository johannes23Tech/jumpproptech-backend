<?php
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../middleware/check_role.php';

$user = authenticate();

// Only Super Admin can access this
if ($user->role !== 'superadmin') {
    security_json_response(403, ["message" => "Unauthorized."]);
}

$data = json_decode(file_get_contents("php://input"));

if (!is_object($data)
    || empty($data->full_name) || !is_string($data->full_name)
    || empty($data->email) || !is_string($data->email)
    || empty($data->password) || !is_string($data->password)) {
    security_json_response(400, ["message" => "All fields are required."]);
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

$retryAfter = security_rate_limit_retry($conn, 'create_landlord', (string) $user->user_id);
if ($retryAfter > 0) {
    security_json_response(429, ["message" => "Too many requests. Please try again later."], ["Retry-After" => (string) $retryAfter]);
}

try {
    // Check if email exists
    $check = $conn->prepare("SELECT id FROM users WHERE email = :email");
    $check->execute([':email' => $email]);
    if ($check->rowCount() > 0) {
        audit_log($conn, (int) $user->user_id, 'admin.landlord.create_rejected', [
            'actor_email' => $user->email ?? null,
            'outcome' => 'failure',
            'meta' => ['reason' => 'email_exists', 'target_email' => $email],
        ]);
        security_json_response(400, ["message" => "Email already exists."]);
    }

    // Create Landlord
    $role = 'landlord';
    $hash = security_hash_password($data->password);

    $query = "INSERT INTO users (full_name, email, password_hash, phone, role)
              VALUES (:name, :email, :hash, :phone, :role)";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':name' => $fullName,
        ':email' => $email,
        ':hash' => $hash,
        ':phone' => $phone,
        ':role' => $role
    ]);

    $newId = (int) $conn->lastInsertId();

    security_rate_limit_hit($conn, 'create_landlord', (string) $user->user_id, 20, 3600, 3600);

    audit_log($conn, (int) $user->user_id, 'admin.landlord.created', [
        'actor_email' => $user->email ?? null,
        'entity_type' => 'user',
        'entity_id' => $newId,
        'meta' => ['target_email' => $email],
    ]);

    security_json_response(201, ["message" => "Landlord created successfully.", "id" => $newId]);
} catch (PDOException $e) {
    error_log('Landlord creation failed: ' . $e->getMessage());
    security_json_response(500, ["message" => "Landlord could not be created."]);
}
