<?php
require_once '../../config/db.php';
require_once '../../config/mailer.php';

$secret = $_GET['key'] ?? '';
if ($secret !== 'JumpPropTechCron2026') { http_response_code(403); exit("Unauthorized"); }

$today = date('Y-m-d');
$nextMonth = date('Y-m-01', strtotime('+1 month'));

// Get all active tenants
$query = "SELECT t.name, t.email, t.monthly_rent, u.unit_number, p.name as property_name 
          FROM tenants t 
          JOIN units u ON t.unit_id = u.id 
          JOIN properties p ON u.property_id = p.id";
$stmt = $conn->query($query);
$tenants = $stmt->fetchAll(PDO::FETCH_ASSOC);

$sent = 0;
foreach ($tenants as $t) {
    $body = "
        <div style='font-family: Arial; padding: 20px; border: 1px solid #ddd;'>
            <h2 style='color: #C5A059;'>Jump PropTech Invoice</h2>
            <p>Hi {$t['name']},</p>
            <p>Your rent invoice for the upcoming month is now available.</p>
            <ul>
                <li><strong>Property:</strong> {$t['property_name']} - Unit {$t['unit_number']}</li>
                <li><strong>Amount Due:</strong> R {$t['monthly_rent']}</li>
                <li><strong>Due Date:</strong> 1st of next month</li>
            </ul>
            <p>Please log into your tenant portal to view your statement.</p>
        </div>
    ";
    if (sendEmail($t['email'], "Rent Invoice - " . date('F Y', strtotime('+1 month')), $body)) $sent++;
}
echo json_encode(["message" => "Invoices sent", "count" => $sent]);
?>