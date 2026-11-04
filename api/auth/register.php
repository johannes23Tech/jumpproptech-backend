<?php
// api/auth/register.php - Modernized registration

require_once '../../config/db.php';
require_once '../../config/config.php';

header('Content-Type: application/json');

$input = file_get_contents("php://input");
$data = json_decode($input);

if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(["message" => "Invalid JSON format."]);
    exit();
}

// Validate required fields
if (empty($data->full_name) || empty($data->email) || empty($data->password)) {
    http_response_code(400);
    echo json_encode(["message" => "Full name, email, and password are required."]);
    exit();
}

// Sanitize and validate
$fullName = trim(htmlspecialchars($data->full_name));
$email = filter_var(trim($data->email), FILTER_SANITIZE_EMAIL);
$phone = isset($data->phone) ? trim($data->phone) : '';

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(["message" => "Invalid email format."]);
    exit();
}

// Password strength check
if (strlen($data->password) < 8) {
    http_response_code(400);
    echo json_encode(["message" => "Password must be at least 8 characters long."]);
    exit();
}

try {
    // Check if email already exists
    $checkQuery = "SELECT id FROM users WHERE email = :email LIMIT 1";
    $stmt = $conn->prepare($checkQuery);
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
    $stmt->execute();
    
    if ($stmt->rowCount() > 0) {
        http_response_code(409);
        echo json_encode(["message" => "Email already exists."]);
        exit();
    }
    
    // Force role to tenant - landlords can only be created by super admin
    $role = 'tenant';
    $passwordHash = password_hash($data->password, PASSWORD_BCRYPT, ['cost' => 12]);
    
    $query = "INSERT INTO users (full_name, email, password_hash, phone, role) 
              VALUES (:full_name, :email, :password_hash, :phone, :role)";
    
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':full_name', $fullName, PDO::PARAM_STR);
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
    $stmt->bindParam(':password_hash', $passwordHash, PDO::PARAM_STR);
    $stmt->bindParam(':phone', $phone, PDO::PARAM_STR);
    $stmt->bindParam(':role', $role, PDO::PARAM_STR);
    
    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode([
            "message" => "User registered successfully as Tenant.",
            "user_id" => $conn->lastInsertId()
        ]);
    } else {
        http_response_code(500);
        echo json_encode(["message" => "Failed to create user."]);
    }
    
} catch (PDOException $e) {
    error_log("Registration error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["message" => "An error occurred during registration."]);
}
