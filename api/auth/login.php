<?php
// api/auth/login.php - Modernized login

require_once '../../config/db.php';
require_once '../../config/jwt.php';
require_once '../../vendor/autoload.php';

use Firebase\JWT\JWT;

header('Content-Type: application/json');

// Get JSON input
$input = file_get_contents("php://input");
$data = json_decode($input);

if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(["message" => "Invalid JSON format."]);
    exit();
}

// Validate input
if (empty($data->email) || empty($data->password)) {
    http_response_code(400);
    echo json_encode(["message" => "Email and password are required."]);
    exit();
}

// Sanitize email
$email = filter_var(trim($data->email), FILTER_SANITIZE_EMAIL);
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(["message" => "Invalid email format."]);
    exit();
}

try {
    // Find user by email
    $query = "SELECT id, full_name, email, password_hash, role, subscription_status FROM users WHERE email = :email LIMIT 1";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
    $stmt->execute();
    
    if ($stmt->rowCount() === 0) {
        http_response_code(401);
        echo json_encode(["message" => "Invalid credentials."]);
        exit();
    }
    
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // Verify password
    if (!password_verify($data->password, $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(["message" => "Invalid credentials."]);
        exit();
    }
    
    // Generate JWT token
    $issuedAt = time();
    $expirationTime = $issuedAt + JWT_EXPIRY;
    
    $payload = [
        'iss' => JWT_ISSUER,
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'user_id' => intval($user['id']),
        'role' => $user['role'],
        'email' => $user['email']
    ];
    
    $jwt = JWT::encode($payload, JWT_SECRET, JWT_ALGO);
    
    http_response_code(200);
    echo json_encode([
        "message" => "Login successful",
        "token" => $jwt,
        "user" => [
            "id" => intval($user['id']),
            "full_name" => $user['full_name'],
            "email" => $user['email'],
            "role" => $user['role'],
            "subscription_status" => $user['subscription_status'] ?? null
        ]
    ]);
    
} catch (PDOException $e) {
    error_log("Login error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["message" => "An error occurred during login."]);
}
