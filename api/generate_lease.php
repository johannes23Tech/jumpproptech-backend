<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';
require_once '../vendor/autoload.php';

use Dompdf\Dompdf;

$user = authenticate();

// Only property-side accounts may generate a lease.
if (!in_array($user->role, ['landlord', 'agent', 'superadmin'], true)) {
    security_json_response(403, ["message" => "Unauthorized."]);
}

$tenantId = filter_var($_GET['tenant_id'] ?? 0, FILTER_VALIDATE_INT);
if ($tenantId === false || $tenantId < 1) {
    security_json_response(400, ["message" => "A valid tenant id is required."]);
}

// Fetch Tenant, Unit, Property, and Landlord details. The owner/agent
// predicate is applied unless the caller is a superadmin.
$query = "SELECT 
            t.name as tenant_name, t.id_number, t.phone, t.email, t.lease_start, t.lease_end, t.deposit, t.monthly_rent,
            u.unit_number, u.size_dimensions, u.is_furnished,
            p.name as property_name, p.address,
            l.full_name as landlord_name
          FROM tenants t 
          JOIN units u ON t.unit_id = u.id 
          JOIN properties p ON u.property_id = p.id
          JOIN users l ON t.owner_id = l.id
          WHERE t.id = :tenant_id";

$params = [':tenant_id' => $tenantId];

if ($user->role !== 'superadmin') {
    $query .= " AND (t.owner_id = :uid_owner OR p.landlord_id = :uid_landlord OR p.agent_id = :uid_agent)";
    $params[':uid_owner'] = $user->user_id;
    $params[':uid_landlord'] = $user->user_id;
    $params[':uid_agent'] = $user->user_id;
}

$stmt = $conn->prepare($query);
$stmt->execute($params);
$data = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$data) {
    security_json_response(404, ["message" => "Tenant not found or unauthorized."]);
}

// Escape every database value before it is interpolated into the document.
// Without this, a tenant name such as </td></tr><script>... can break the
// document structure or inject markup into the generated PDF.
$e = static function ($value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
};

$furnished = $data['is_furnished'] ? 'Fully Furnished' : 'Unfurnished';
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
    <p><strong>{$e($data['landlord_name'])}</strong></p>
    
    <h2>2. THE TENANT</h2>
    <p><strong>{$e($data['tenant_name'])}</strong><br>
    ID/Passport: {$e($data['id_number'])}<br>
    Phone: {$e($data['phone'])}<br>
    Email: {$e($data['email'])}</p>
    
    <h2>3. THE PREMISES</h2>
    <p>The Landlord hereby lets to the Tenant the premises described as:<br>
    <strong>{$e($data['property_name'])} - Unit {$e($data['unit_number'])}</strong><br>
    Address: {$e($data['address'])}<br>
    Room Size: {$e($data['size_dimensions'])} ({$e($furnished)})</p>
    
    <h2>4. TERM AND RENTAL</h2>
    <table class='details-table'>
        <tr><td>Lease Start Date</td><td>{$e($data['lease_start'])}</td></tr>
        <tr><td>Lease End Date</td><td>{$e($data['lease_end'])}</td></tr>
        <tr><td>Monthly Rent</td><td>R {$e($data['monthly_rent'])}</td></tr>
        <tr><td>Deposit Paid</td><td>R {$e($data['deposit'])}</td></tr>
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

audit_log($conn, (int) $user->user_id, 'lease.generated', [
    'entity_type' => 'tenant',
    'entity_id' => $tenantId,
]);

// Stream the PDF to the browser (Attachment = true forces download)
$filename = 'Lease_' . security_sanitize_filename((string) $data['tenant_name']) . '.pdf';
$dompdf->stream($filename, ["Attachment" => true]);
