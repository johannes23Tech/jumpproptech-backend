<?php
// config/db.php

require_once __DIR__ . '/config.php';

// Fetch credentials
$host = getenv('DB_HOST') ?: 'jumpproptech-db.mysql.database.azure.com';
$db_name = getenv('DB_NAME') ?: 'jumpproptech';
$username = getenv('DB_USER') ?: 'jumpproptech';
$password = getenv('DB_PASS') ?: 'Matlola@2026';
$port = '3306'; // Force the default Azure port

// 1. Define the ABSOLUTE path to the certificate
$ca_path = '/var/www/html/DigiCertGlobalRootG2.crt.pem';

// 2. Check if the file exists and is readable
if (!file_exists($ca_path)) {
    http_response_code(500);
    echo json_encode([
        "error" => "Certificate Missing",
        "details" => "PHP cannot find the certificate at: " . $ca_path
    ]);
    exit();
}

try {
    // 3. Explicitly include the port in the DSN
    $dsn = "mysql:host=$host;port=$port;dbname=$db_name;charset=utf8mb4";
    
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::MYSQL_ATTR_SSL_CA => $ca_path, 
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
    ];
    
    $conn = new PDO($dsn, $username, $password, $options);
    
} catch(PDOException $e) {
    http_response_code(500);
    
    $details = $e->getMessage();
    
    // If it fails, run a quick DNS check to see if the host is even reachable
    if (strpos($details, '2002') !== false) {
        $ip = gethostbyname($host);
        $details .= " | Host resolved to IP: $ip";
    }

    echo json_encode([
        "error" => "Database connection failed.",
        "details" => $details
    ]);
    exit();
}
?>