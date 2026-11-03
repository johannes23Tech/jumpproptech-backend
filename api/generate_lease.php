<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';
require_once '../vendor/autoload.php';

use Dompdf\Dompdf;

$user = authenticate();
$tenant_id = $_GET['tenant_id'] ?? 0;

// Fetch Tenant, Unit, Property, and Landlord details
$query = "SELECT 
            t.name as tenant_name, t.id_number, t.phone, t.email, t.lease_start, t.lease_end, t.deposit, t.monthly_rent,
            u.unit_number, u.size_dimensions, u.is_furnished,
            p.name as property_name, p.address,
            l.full_name as landlord_name
          FROM tenants t 
          JOIN units u ON t.unit_id = u.id 
          JOIN properties p ON u.property_id = p.id
          JOIN users l ON t.owner_id = l.id
          WHERE t.id = :tenant_id AND t.owner_id = :owner_id";
          
$stmt = $conn->prepare($query);
$stmt->execute([':tenant_id' => $tenant_id, ':owner_id' => $user->user_id]);
$data = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$data) {
    http_response_code(404);
    echo json_encode(["message" => "Tenant not found or unauthorized."]);
    exit();
}

$furnished = $data['is_furnished'] ? "Fully Furnished" : "Unfurnished";
$today = date('d F Y');

// Build the HTML Lease Document
$html = "
<html>
<head>
    <style>
        body { font-family: 'Helvetica', sans-serif; color: #333; line-height: 1.6; padding: 40px; }
        h1 { color: #C5A059; text-align: center; border-bottom: 2px solid #C5A059; padding-bottom: 10px; }
        h2 { color: #0A0A0A; font-size: 18px; margin-top: 30px; }
        p { font-size: 14px; }
        .details-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .details-table td { padding: 10px; border: 1px solid #ddd; font-size: 14px; }
        .details-table td:first-child { font-weight: bold; background-color: #FAF7F2; width: 40%; }
        .signatures { margin-top: 60px; display: flex; justify-content: space-between; }
        .sig-box { width: 45%; border-top: 1px solid #333; padding-top: 10px; text-align: center; font-size: 12px; }
    </style>
</head>
<body>
    <h1>RESIDENTIAL LEASE AGREEMENT</h1>
    
    <p>This lease agreement is made and entered into on this <strong>{$today}</strong>, between:</p>
    
    <h2>1. THE LANDLORD</h2>
    <p><strong>{$data['landlord_name']}</strong></p>
    
    <h2>2. THE TENANT</h2>
    <p><strong>{$data['tenant_name']}</strong><br>
    ID/Passport: {$data['id_number']}<br>
    Phone: {$data['phone']}<br>
    Email: {$data['email']}</p>
    
    <h2>3. THE PREMISES</h2>
    <p>The Landlord hereby lets to the Tenant the premises described as:<br>
    <strong>{$data['property_name']} - Unit {$data['unit_number']}</strong><br>
    Address: {$data['address']}<br>
    Room Size: {$data['size_dimensions']} ({$furnished})</p>
    
    <h2>4. TERM AND RENTAL</h2>
    <table class='details-table'>
        <tr><td>Lease Start Date</td><td>{$data['lease_start']}</td></tr>
        <tr><td>Lease End Date</td><td>{$data['lease_end']}</td></tr>
        <tr><td>Monthly Rent</td><td>R {$data['monthly_rent']}</td></tr>
        <tr><td>Deposit Paid</td><td>R {$data['deposit']}</td></tr>
    </table>

    <h2>5. GENERAL TERMS</h2>
    <p>The Tenant agrees to pay the rent on or before the 1st of every month. The Tenant agrees to keep the premises clean, report any maintenance issues immediately via the Jump PropTech platform, and respect the house rules provided in the Tenant Portal.</p>

    <div class='signatures'>
        <div class='sig-box'>Landlord Signature</div>
        <div class='sig-box'>Tenant Signature</div>
    </div>
</body>
</html>
";

// Generate PDF
$dompdf = new Dompdf();
$dompdf->loadHtml($html);
$dompdf->setPaper('A4', 'portrait');
$dompdf->render();

// Stream the PDF to the browser (Attachment = true forces download)
$dompdf->stream("Lease_{$data['tenant_name']}.pdf", ["Attachment" => true]);
?>