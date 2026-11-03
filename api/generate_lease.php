<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';
require_once '../vendor/autoload.php';

use Dompdf\Dompdf;

$user = authenticate();
$tenant_id = $_GET['tenant_id'] ?? 0;

$stmt = $conn->prepare("SELECT t.*, u.unit_number, p.name as property_name, p.address FROM tenants t JOIN units u ON t.unit_id = u.id JOIN properties p ON u.property_id = p.id WHERE t.id = :id AND t.owner_id = :owner");
$stmt->execute([':id' => $tenant_id, ':owner' => $user->user_id]);
$tenant = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$tenant) { exit("Tenant not found"); }

$html = "
    <h1 style='text-align: center;'>RESIDENTIAL LEASE AGREEMENT</h1>
    <p>This agreement is made on " . date('Y-m-d') . " between the Landlord and <strong>{$tenant['name']}</strong>.</p>
    <p><strong>Property:</strong> {$tenant['property_name']}, {$tenant['address']}, Unit {$tenant['unit_number']}</p>
    <p><strong>Rent:</strong> R {$tenant['monthly_rent']} per month.</p>
    <p><strong>Lease Period:</strong> {$tenant['lease_start']} to {$tenant['lease_end']}</p>
    <br><br>
    <p>Signed: ________________________ (Landlord)</p>
    <br>
    <p>Signed: ________________________ (Tenant)</p>
";

$dompdf = new Dompdf();
$dompdf->loadHtml($html);
$dompdf->setPaper('A4', 'portrait');
$dompdf->render();
$dompdf->stream("Lease_{$tenant['name']}.pdf", ["Attachment" => true]);
?>