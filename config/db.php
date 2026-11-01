<?php
// config/db.php

// 1. SECURE CORS POLICY (Allows your Vercel app to connect)
header("Access-Control-Allow-Origin: https://jumpproptech-frontend.vercel.app"); 
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// 2. AIVEN DATABASE CREDENTIALS
// IMPORTANT: Replace these with your actual Aiven details!
$host = 'your-aiven-host.aivencloud.com'; // e.g., mysql-3a1b2c4d.aivencloud.com
$port = '12345';                          // e.g., 12345 (Aiven gives you a specific port)
$db_name = 'defaultdb';                   // Usually 'defaultdb' on Aiven free tier
$username = 'avnadmin';                   // Usually 'avnadmin'
$password = 'YOUR_AIVEN_PASSWORD';        // The password Aiven generated for you

try {
    // 3. SECURE PDO CONNECTION (Aiven requires SSL)
    $dsn = "mysql:host=$host;port=$port;dbname=$db_name;charset=utf8mb4";
    
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        // Aiven requires the CA certificate to establish a secure connection.
        // Make sure you have downloaded 'ca.pem' from Aiven and placed it 
        // in the root of your backend folder (next to the config folder).
        PDO::MYSQL_ATTR_SSL_CA => __DIR__ . '/../ca.pem', 
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
    ];
    
    $conn = new PDO($dsn, $username, $password, $options);
    
} catch(PDOException $e) {
    // Log the exact error for debugging in Render logs
    error_log("Database connection failed: " . $e->getMessage());
    
    // Return a generic JSON error to the frontend
    http_response_code(500);
    echo json_encode(["error" => "Database connection failed. Please check server logs."]);
    exit();
}
?>