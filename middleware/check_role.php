<?php
// middleware/check_role.php

require_once __DIR__ . '/../vendor/autoload.php';
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

// Define your secret key (Must match the one in login.php)
define('JWT_SECRET', 'jumpproptech_super_secret_key_2025');

function authenticate() {
    global $conn; // Access the PDO connection from db.php

    $headers = getallheaders();
    
    // Check if Authorization header exists
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["message" => "No token provided. Access denied."]);
        exit();
    }

    // Extract the token (Format: "Bearer <token>")
    $authHeader = $headers['Authorization'];
    $arr = explode(" ", $authHeader);
    $jwt = $arr[1] ?? null;

    if (!$jwt) {
        http_response_code(401);
        echo json_encode(["message" => "Invalid token format."]);
        exit();
    }

    try {
        // Decode the token
        $decoded = JWT::decode($jwt, new Key(JWT_SECRET, 'HS256'));
        
        // ==========================================
        // SUBSCRIPTION CHECK (Monetization)
        // ==========================================
        // Superadmins bypass this check. Tenants bypass this check (they are free).
        if ($decoded->role !== 'superadmin' && $decoded->role !== 'tenant' && $decoded->role !== 'maintenance') {
            $stmt = $conn->prepare("SELECT subscription_status FROM users WHERE id = :id");
            $stmt->execute([':id' => $decoded->user_id]);
            $status = $stmt->fetchColumn();

            if ($status === 'expired') {
                http_response_code(402); // 402 Payment Required
                echo json_encode(["message" => "Your subscription has expired. Please renew your plan to continue managing your properties."]);
                exit();
            }
        }

        return $decoded; // Returns the payload (user_id, role, etc.)
        
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["message" => "Invalid or expired token."]);
        exit();
    }
}
?>