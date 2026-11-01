<?php
require_once __DIR__ . '/../vendor/autoload.php';
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

define('JWT_SECRET', 'jumpproptech_super_secret_key_2025');

function authenticate() {
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

    if ($jwt) {
        try {
            // Decode the token
            $decoded = JWT::decode($jwt, new Key(JWT_SECRET, 'HS256'));
            return $decoded; // Returns the payload (user_id, role, etc.)
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(["message" => "Invalid or expired token."]);
            exit();
        }
    } else {
        http_response_code(401);
        echo json_encode(["message" => "Invalid token format."]);
        exit();
    }
}
?>