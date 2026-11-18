<?php
// scratch/setup_db.php – create minimal schema for testing
require_once __DIR__ . '/../config/db.php';

// Create properties table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS properties (
    id INT AUTO_INCREMENT PRIMARY KEY,
    landlord_id INT NOT NULL,
    company_id INT NULL,
    name VARCHAR(100) NOT NULL,
    address VARCHAR(255) NOT NULL,
    property_type ENUM('Precast Structure','Backroom','Apartment Block','House') NOT NULL,
    archived_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

$conn->exec($sql);

echo "✅ DB schema ready\n";
?>