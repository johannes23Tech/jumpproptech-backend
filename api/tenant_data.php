<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $query = "SELECT t.*, u.unit_number, p.name as property_name 
              FROM tenants t 
              JOIN units u ON t.unit_id = u.id 
              JOIN properties p ON u.property_id = p.id 
              WHERE t.user_id = :user_id LIMIT 1";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    $tenant = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$tenant) {
        echo json_encode(["message" => "Tenant profile not found."]);
        exit();
    }

    // Fetch Rent Records WITH Tenant and Property details for the receipt
    $rentQuery = "SELECT r.*, t.name as tenant_name, t.email as tenant_email, u.unit_number, p.name as property_name 
                  FROM rent_records r 
                  JOIN tenants t ON r.tenant_id = t.id 
                  JOIN units u ON r.unit_id = u.id 
                  JOIN properties p ON u.property_id = p.id
                  WHERE r.tenant_id = :tenant_id ORDER BY r.id DESC";
    $rentStmt = $conn->prepare($rentQuery);
    $rentStmt->bindParam(':tenant_id', $tenant['id']);
    $rentStmt->execute();
    $rent = $rentStmt->fetchAll(PDO::FETCH_ASSOC);

    // Fetch Maintenance
    $maintQuery = "SELECT * FROM maintenance WHERE tenant_id = :tenant_id ORDER BY id DESC";
    $maintStmt = $conn->prepare($maintQuery);
    $maintStmt->bindParam(':tenant_id', $tenant['id']);
    $maintStmt->execute();
    $maintenance = $maintStmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        "tenant" => $tenant,
        "rent" => $rent,
        "maintenance" => $maintenance
    ]);
    exit();
}
?>