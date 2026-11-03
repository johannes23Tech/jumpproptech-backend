<?php
require_once '../../config/db.php';
require_once '../../middleware/check_role.php';

$user = authenticate();

if ($user->role !== 'superadmin') {
    http_response_code(403);
    echo json_encode(["message" => "Unauthorized. Super Admin access required."]);
    exit();
}

// 1. Global Stats
$landlords = $conn->query("SELECT COUNT(*) FROM users WHERE role = 'landlord'")->fetchColumn();
$properties = $conn->query("SELECT COUNT(*) FROM properties")->fetchColumn();
$units = $conn->query("SELECT COUNT(*) FROM units")->fetchColumn();
$rent = $conn->query("SELECT SUM(amount) FROM rent_records WHERE status = 'Paid'")->fetchColumn();

// 2. Recent Signups (WITH ID and SUBSCRIPTION_STATUS for the toggle buttons)
$recentSignups = $conn->query("SELECT id, full_name, email, created_at, subscription_status FROM users WHERE role = 'landlord' ORDER BY created_at DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);

echo json_encode([
    "total_landlords" => $landlords ?: 0,
    "total_properties" => $properties ?: 0,
    "total_units" => $units ?: 0,
    "total_rent_processed" => $rent ?: 0,
    "recent_signups" => $recentSignups
]);
?>