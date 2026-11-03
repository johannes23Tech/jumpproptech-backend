<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();

// 1. Fetch existing stats
$query = "SELECT 
    (SELECT COUNT(*) FROM properties WHERE landlord_id = :user_id) as total_properties,
    (SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = :user_id) as total_units,
    (SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = :user_id AND u.status = 'Occupied') as occupied,
    (SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = :user_id AND u.status = 'Vacant') as vacant,
    (SELECT SUM(amount) FROM rent_records r JOIN tenants t ON r.tenant_id = t.id WHERE t.owner_id = :user_id AND r.status = 'Paid') as collected,
    (SELECT SUM(amount) FROM rent_records r JOIN tenants t ON r.tenant_id = t.id WHERE t.owner_id = :user_id AND r.status = 'Pending') as pending";

$stmt = $conn->prepare($query);
$stmt->bindParam(':user_id', $user->user_id);
$stmt->execute();
$stats = $stmt->fetch(PDO::FETCH_ASSOC);

// 2. Fetch Chart Data (Last 6 Months)
$chartData = [];
$months = [];
for ($i = 5; $i >= 0; $i--) {
    $monthStr = date('Y-m', strtotime("-$i months"));
    $months[$monthStr] = [
        'month' => date('M', strtotime("-$i months")),
        'income' => 0,
        'expense' => 0
    ];
}

// Get Income per month
$rentQuery = "SELECT DATE_FORMAT(r.month_for, '%Y-%m') as month, SUM(r.amount) as total 
              FROM rent_records r JOIN tenants t ON r.tenant_id = t.id 
              WHERE t.owner_id = :user_id AND r.status = 'Paid' 
              GROUP BY month";
$rentStmt = $conn->prepare($rentQuery);
$rentStmt->execute([':user_id' => $user->user_id]);
foreach ($rentStmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    if (isset($months[$row['month']])) {
        $months[$row['month']]['income'] = (float)$row['total'];
    }
}

// Get Expenses per month
$expQuery = "SELECT DATE_FORMAT(expense_date, '%Y-%m') as month, SUM(amount) as total 
             FROM expenses WHERE owner_id = :user_id 
             GROUP BY month";
$expStmt = $conn->prepare($expQuery);
$expStmt->execute([':user_id' => $user->user_id]);
foreach ($expStmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    if (isset($months[$row['month']])) {
        $months[$row['month']]['expense'] = (float)$row['total'];
    }
}

$stats['chart_data'] = array_values($months);

echo json_encode($stats);
?>