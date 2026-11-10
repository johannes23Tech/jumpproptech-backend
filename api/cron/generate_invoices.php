<?php
require_once '../../config/db.php';
require_once '../../config/mailer.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';

$expected = getenv('CRON_SECRET');
if ($expected === false || strlen($expected) < 16) {
    http_response_code(403);
    exit("Unauthorized");
}

// Read the secret from a header, never from the query string: URLs end up in
// access logs, proxy logs, monitoring tools and browser history.
$secret = '';
if (!empty($_SERVER['HTTP_X_CRON_SECRET'])) {
    $secret = (string) $_SERVER['HTTP_X_CRON_SECRET'];
} else {
    $authHeader = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (stripos($authHeader, 'Bearer ') === 0) {
        $secret = substr($authHeader, 7);
    }
}

// Temporary migration escape hatch only. Leave this unset in production.
if ($secret === '' && getenv('CRON_ALLOW_QUERY_SECRET') === '1') {
    $secret = (string) ($_GET['key'] ?? '');
}

if ($secret === '' || !hash_equals($expected, $secret)) {
    http_response_code(403);
    exit("Unauthorized");
}

header('Cache-Control: no-store');

$e = static function ($value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
};

$nextMonth = date('Y-m-01', strtotime('+1 month'));

// Get all active tenants
$query = "SELECT t.name, t.email, t.monthly_rent, u.unit_number, p.name as property_name 
          FROM tenants t 
          JOIN units u ON t.unit_id = u.id 
          JOIN properties p ON u.property_id = p.id";
$stmt = $conn->query($query);
$tenants = $stmt->fetchAll(PDO::FETCH_ASSOC);

$sent = 0;
$failed = 0;
foreach ($tenants as $t) {
    if (!security_is_email($t['email'] ?? '')) {
        $failed++;
        continue;
    }

    // Escape every database value before building the HTML email.
    $body = "
        <div style='font-family: Arial; padding: 20px; border: 1px solid #ddd;'>
            <h2 style='color: #C5A059;'>Jump PropTech Invoice</h2>
            <p>Hi {$e($t['name'])},</p>
            <p>Your rent invoice for the upcoming month is now available.</p>
            <ul>
                <li><strong>Property:</strong> {$e($t['property_name'])} - Unit {$e($t['unit_number'])}</li>
                <li><strong>Amount Due:</strong> R {$e($t['monthly_rent'])}</li>
                <li><strong>Due Date:</strong> 1st of next month</li>
            </ul>
            <p>Please log into your tenant portal to view your statement.</p>
        </div>
    ";

    if (sendEmail($t['email'], "Rent Invoice - " . date('F Y', strtotime('+1 month')), $body)) {
        $sent++;
    } else {
        $failed++;
    }
}

audit_log($conn, null, 'system.invoices.sent', [
    'meta' => ['sent' => $sent, 'failed' => $failed, 'month' => $nextMonth],
]);

echo json_encode(["message" => "Invoices sent", "count" => $sent, "failed" => $failed]);
