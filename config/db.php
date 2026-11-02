<?php
// config/db.php



header("Access-Control-Allow-Origin: https://jumpproptech-frontend.vercel.app"); 
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// --- AZURE DATABASE CREDENTIALS ---
$host = 'jumpproptech-db.mysql.database.azure.com';
$db_name = 'jumpproptech'; 
$username = 'jumpproptech'; 
$password = 'Matlola@2026'; 

try {
    $dsn = "mysql:host=$host;dbname=$db_name;charset=utf8mb4";
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        // Path to the Azure CA certificate we downloaded
        PDO::MYSQL_ATTR_SSL_CA => __DIR__ . '/../DigiCertGlobalRootG2.crt.pem', 
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
    ];
    
    $conn = new PDO($dsn, $username, $password, $options);
} catch(PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["error" => "Database connection failed."]);
    exit();
}
?>