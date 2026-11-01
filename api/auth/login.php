<?php
require_once '../../config/db.php';
require_once '../../vendor/autoload.php'; // Loads the JWT library we just installed

use \Firebase\JWT\JWT;

// Define your secret key (In a real app, keep this in a secure .env file)
define('JWT_SECRET', 'jumpproptech_super_secret_key_2025');

$data = json_decode(file_get_contents("php://input"));

if (!empty($data->email) && !empty($data->password)) {
    
    // Find user by email
    $query = "SELECT id, full_name, email, password_hash, role FROM users WHERE email = :email LIMIT 1";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $data->email);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Verify the password matches the hash in the database
        if (password_verify($data->password, $user['password_hash'])) {
            
            // Generate JWT Token
            $issuedAt = time();
            $expirationTime = $issuedAt + (60 * 60 * 24); // Valid for 24 hours
            $payload = [
                'iss' => 'jumpproptech', // Issuer
                'iat' => $issuedAt,      // Issued at
                'exp' => $expirationTime,// Expiration
                'user_id' => $user['id'],
                'role' => $user['role']  // Landlord, Agent, Tenant, Maintenance
            ];

            $jwt = JWT::encode($payload, JWT_SECRET, 'HS256');

            http_response_code(200);
            echo json_encode([
                "message" => "Login successful.",
                "token" => $jwt,
                "user" => [
                    "id" => $user['id'],
                    "full_name" => $user['full_name'],
                    "email" => $user['email'],
                    "role" => $user['role']
                ]
            ]);
        } else {
            http_response_code(401);
            echo json_encode(["message" => "Invalid password."]);
        }
    } else {
        http_response_code(404);
        echo json_encode(["message" => "User not found."]);
    }
} else {
    http_response_code(400);
    echo json_encode(["message" => "Email and password are required."]);
}
?>