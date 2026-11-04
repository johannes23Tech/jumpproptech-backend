<?php
// config/db.php - Modern database connection

require_once __DIR__ . '/config.php';

$host = getenv('DB_HOST') ?: 'jumpproptech-db.mysql.database.azure.com';
$db_name = getenv('DB_NAME') ?: 'jumpproptech';
$username = getenv('DB_USER') ?: 'jumpproptech';
$password = getenv('DB_PASS') ?: '';

try {
    $dsn = "mysql:host=$host;dbname=$db_name;charset=utf8mb4";
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::MYSQL_ATTR_SSL_CA => __DIR__ . '/../DigiCertGlobalRootG2.crt.pem',
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => getenv('DB_SSL_VERIFY') === 'true',
    ];
    
    $conn = new PDO($dsn, $username, $password, $options);
} catch(PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["error" => "Database connection failed."]);
    exit();
}
