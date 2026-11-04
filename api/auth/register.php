<?php
require_once '../../config/db.php';
require_once '../../vendor/autoload.php';

use \Firebase\JWT\JWT;
define('JWT_SECRET', 'jumpproptech_super_secret_key_2025');

$data = json_decode(file_get_contents("php://input"));

if (!empty($data->full_name) && !empty($data->email) && !empty($data->password)) {
    try {
        // Check if email already exists
        $checkQuery = "SELECT id FROM users WHERE email = :email LIMIT 1";
        $stmt = $conn->prepare($checkQuery);
        $stmt->bindParam(':email', $data->email);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            http_response_code(400);
            echo json_encode(["message" => "Email already exists."]);
            exit();
        }

        // Public registration is strictly for tenants
        $role = 'tenant';
        $subStatus = 'active';
        
        // FIXED: Assign phone to a variable before binding
        $phone = isset($data->phone) ? $data->phone : '';

        $query = "INSERT INTO users (full_name, email, password_hash, phone, role, subscription_status) 
                  VALUES (:full_name, :email, :password_hash, :phone, :role, :sub_status)";
        
        $stmt = $conn->prepare($query);
        $password_hash = password_hash($data->password, PASSWORD_BCRYPT);
        
        $stmt->bindParam(':full_name', $data->full_name);
        $stmt->bindParam(':email', $data->email);
        $stmt->bindParam(':password_hash', $password_hash);
        $stmt->bindParam(':phone', $phone);
        $stmt->bindParam(':role', $role);
        $stmt->bindParam(':sub_status', $subStatus);

        if ($stmt->execute()) {
            $userId = $conn->lastInsertId();

            // Generate JWT for auto-login
            $issuedAt = time();
            $payload = [
                'iss' => 'jumpproptech',
                'iat' => $issuedAt,
                'exp' => $issuedAt + (60 * 60 * 24), // 24 hours
                'user_id' => $userId,
                'role' => $role
            ];
            $jwt = JWT::encode($payload, JWT_SECRET, 'HS256');

            http_response_code(201);
            echo json_encode([
                "message" => "Account created successfully!",
                "token" => $jwt,
                "user" => [
                    "id" => $userId,
                    "full_name" => $data->full_name,
                    "email" => $data->email,
                    "role" => $role
                ]
            ]);
        } else {
            http_response_code(500);
            echo json_encode(["message" => "User could not be created."]);
        }
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(["message" => "DB Error: " . $e->getMessage()]);
    }
} else {
    http_response_code(400);
    echo json_encode(["message" => "Incomplete data."]);
}
?>