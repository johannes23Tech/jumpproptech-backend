<?php
// config/db.php

// Load the configuration (CORS, Timezone, Env vars)
require_once __DIR__ . '/config.php';

// Fetch credentials from environment variables (with fallbacks for local testing)
$host = getenv('DB_HOST') ?: 'jumpproptech-db.mysql.database.azure.com';
$db_name = getenv('DB_NAME') ?: 'jumpproptech';
$username = getenv('DB_USER') ?: 'jumpproptech';
$password = getenv('DB_PASS') ?: 'Matlola@2026';

try {
    $dsn = "mysql:host=$host;dbname=$db_name;charset=utf8mb4";
    
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        // FIXED: Using the correct filename present in your GitHub repo
        PDO::MYSQL_ATTR_SSL_CA => __DIR__ . '/../DigiCertGlobalRootG2.crt.pem', 
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
    ];
    
    $conn = new PDO($dsn, $username, $password, $options);
    
} catch(PDOException $e) {
    http_response_code(500);
    
    // If we are in development, show the exact error. If production, hide it.
    $details = getenv('APP_ENV') === 'production' ? "Check server logs." : $e->getMessage();
    
    echo json_encode([
        "error" => "Database connection failed.",
        "details" => $details
    ]);
    exit();
}
?>