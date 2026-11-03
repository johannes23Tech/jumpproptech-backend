<?php
require_once '../../config/db.php';
require_once '../../middleware/check_role.php';

$user = authenticate();

// SECURITY: Only superadmins can access this
if ($user->role !== 'superadmin') {
    http_response_code(403);
    echo json_encode(["message" => "Unauthorized. Super Admin access required."]);
    exit();
}

// 1. Total Landlords
$landlords = $conn->query("SELECT COUNT(*) FROM users WHERE role = 'landlord'")->fetchColumn();

// 2. Total Properties & Units
$properties = $conn->query("SELECT COUNT(*) FROM properties")->fetchColumn();
$units = $conn->query("SELECT COUNT(*) FROM units")->fetchColumn();

// 3. Total Rent Processed (All time)
$rent = $conn->query("SELECT SUM(amount) FROM rent_records WHERE status = 'Paid'")->fetchColumn();

// 4. Recent Signups (Last 5 Landlords)
$recentSignups = $conn->query("SELECT full_name, email, created_at FROM users WHERE role = 'landlord' ORDER BY created_at DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);

echo json_encode([
    "total_landlords" => $landlords ?: 0,
    "total_properties" => $properties ?: 0,
    "total_units" => $units ?: 0,
    "total_rent_processed" => $rent ?: 0,
    "recent_signups" => $recentSignups
]);
?>