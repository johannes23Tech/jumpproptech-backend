<?php
// config/db.php

// Load the configuration (CORS, Timezone, Env vars)
require_once __DIR__ . '/config.php';

// Fail closed: credentials must come from the environment, never from source.
$host = getenv('DB_HOST');
$db_name = getenv('DB_NAME');
$username = getenv('DB_USER');
$password = getenv('DB_PASS');

if ($host === false || $db_name === false || $username === false || $password === false) {
    http_response_code(500);
    // Never tell the caller which setting is missing or echo internals.
    echo json_encode(["error" => "Service temporarily unavailable."]);
    exit();
}

try {
    $dsn = "mysql:host=$host;dbname=$db_name;charset=utf8mb4";

    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        // Use real server-side prepares. This removes the emulation layer that
        // has historically been a source of subtle SQL-injection edge cases.
        PDO::ATTR_EMULATE_PREPARES => false,
    ];

    // Only use the Azure CA bundle for Azure hosts. Local development does not
    // need it, and certificate verification must stay enabled in production.
    $caFile = __DIR__ . '/../DigiCertGlobalRootG2.crt.pem';
    if (stripos($host, 'azure') !== false && file_exists($caFile)) {
        $options[PDO::MYSQL_ATTR_SSL_CA] = $caFile;
        $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
    }

    $conn = new PDO($dsn, $username, $password, $options);

} catch(PDOException $e) {
    http_response_code(500);
    error_log('Database connection failed: ' . $e->getMessage());
    echo json_encode(["error" => "Database connection failed."]);
    exit();
}
?>