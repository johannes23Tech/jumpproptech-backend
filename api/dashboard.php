<?php
require_once '../config/db.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;

if (!permission_is_staff($actor)) {
    security_json_response(403, ["message" => "Unauthorized. Staff access required."]);
}

permission_require($actor, 'properties.view');

$canViewPayments = permission_can($actor, 'payments.view');
$canViewExpenses = permission_can($actor, 'expenses.view');

// 1. Company-wide portfolio counts. JUMP PROPTECH owns the portfolio, so the
// old per-landlord filter is retired.
$stats = $conn->query(
    "SELECT
        (SELECT COUNT(*) FROM properties) as total_properties,
        (SELECT COUNT(*) FROM units) as total_units,
        (SELECT COUNT(*) FROM units WHERE status = 'Occupied') as occupied,
        (SELECT COUNT(*) FROM units WHERE status = 'Vacant') as vacant"
)->fetch(PDO::FETCH_ASSOC);

// 2. Financial totals are only returned to staff who may see them.
$stats['collected'] = 0;
$stats['pending'] = 0;

if ($canViewPayments) {
    $money = $conn->query(
        "SELECT
            SUM(CASE WHEN status = 'Paid' THEN amount ELSE 0 END) as collected,
            SUM(CASE WHEN status = 'Pending' THEN amount ELSE 0 END) as pending
         FROM rent_records"
    )->fetch(PDO::FETCH_ASSOC);

    $stats['collected'] = (float) ($money['collected'] ?? 0);
    $stats['pending'] = (float) ($money['pending'] ?? 0);
}

// 3. Chart data (last 6 months).
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

if ($canViewPayments) {
    $rentQuery = "SELECT DATE_FORMAT(month_for, '%Y-%m') as month, SUM(amount) as total
                  FROM rent_records
                  WHERE status = 'Paid'
                  GROUP BY month";
    foreach ($conn->query($rentQuery)->fetchAll(PDO::FETCH_ASSOC) as $row) {
        if (isset($months[$row['month']])) {
            $months[$row['month']]['income'] = (float) $row['total'];
        }
    }
}

if ($canViewExpenses) {
    $expQuery = "SELECT DATE_FORMAT(expense_date, '%Y-%m') as month, SUM(amount) as total
                 FROM expenses
                 GROUP BY month";
    foreach ($conn->query($expQuery)->fetchAll(PDO::FETCH_ASSOC) as $row) {
        if (isset($months[$row['month']])) {
            $months[$row['month']]['expense'] = (float) $row['total'];
        }
    }
}

$stats['chart_data'] = array_values($months);

echo json_encode($stats);
