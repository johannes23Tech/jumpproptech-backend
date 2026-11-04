<?php
header("Content-Type: application/json");
$start = microtime(true);

try {
    // Manually load the config
    require_once __DIR__ . '/../config/db.php';
    
    // If we reach this line, the connection was successful
    $time = round(microtime(true) - $start, 2);
    echo json_encode([
        "status" => "SUCCESS",
        "message" => "Connected to Azure MySQL in {$time} seconds."
    ]);
} catch (Exception $e) {
    $time = round(microtime(true) - $start, 2);
    echo json_encode([
        "status" => "FAILED",
        "message" => "Connection failed after {$time} seconds.",
        "error" => $e->getMessage()
    ]);
}
?>