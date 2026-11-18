<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/tenant_profile.php';
require_once '../config/leases.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // Provision a profile row for a tenant who registered before being linked
    // to a unit, then read it with LEFT JOINs so an unassigned tenant still
    // gets a usable payload (unit/property/rent simply come back as null/0).
    $profile = tenant_profile_ensure($conn, (int) $user->user_id);
    if ($profile === null) {
        error_log('Tenant data row could not be provisioned for user ' . $user->user_id);
        security_json_response(404, ["message" => "Tenant profile not found."]);
    }

    $query = "SELECT t.*, u.unit_number, u.size_dimensions, u.included_items,
                     u.prepaid_meter_number, u.monthly_rent AS unit_rent,
                     b.name AS building_name,
                     p.name as property_name, p.address as property_address
              FROM tenants t 
              LEFT JOIN units u ON t.unit_id = u.id 
              LEFT JOIN buildings b ON u.building_id = b.id
              LEFT JOIN properties p ON u.property_id = p.id 
              WHERE t.user_id = :user_id LIMIT 1";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    $tenant = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$tenant) {
        security_json_response(404, ["message" => "Tenant profile not found."]);
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

    // Current lease version. Only the tenant's own document and signatures are
    // exposed; internal notes and staff identifiers are not.
    $lease = lease_current($conn, (int) $tenant['id']);
    $leasePayload = null;
    if ($lease !== null) {
        $leasePayload = [
            'id' => (int) $lease['id'],
            'version' => (int) $lease['version'],
            'status' => $lease['status'],
            'title' => $lease['title'],
            'document_url' => $lease['document_url'],
            'start_date' => $lease['start_date'],
            'end_date' => $lease['end_date'],
            'monthly_rent' => $lease['monthly_rent'],
            'deposit_required' => $lease['deposit_required'],
            'activated_at' => $lease['activated_at'],
            'signatures' => array_map(
                static fn (array $signature): array => [
                    'party' => $signature['party'],
                    'signer_name' => $signature['signer_name'],
                    'method' => $signature['method'],
                    'signed_at' => $signature['signed_at'],
                ],
                lease_signatures($conn, (int) $lease['id'])
            ),
        ];
    }

    // Deposit position and append-only ledger.
    $deposit = deposit_summary($conn, (int) $tenant['id']);
    $deposit['transactions'] = deposit_transactions($conn, (int) $tenant['id']);

    // The tenant's own inspections and photos.
    $inspectionStmt = $conn->prepare(
        'SELECT id, tenant_id, type, status, inspected_at, notes, completed_at, created_at
         FROM inspections WHERE tenant_id = :tenant_id ORDER BY id DESC'
    );
    $inspectionStmt->execute([':tenant_id' => $tenant['id']]);
    $inspections = $inspectionStmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($inspections as &$inspection) {
        $photoStmt = $conn->prepare(
            'SELECT id, file_url AS url, caption, created_at
             FROM inspection_photos WHERE inspection_id = :id ORDER BY id ASC'
        );
        $photoStmt->execute([':id' => $inspection['id']]);
        $inspection['photos'] = $photoStmt->fetchAll(PDO::FETCH_ASSOC);
    }
    unset($inspection);

    echo json_encode([
        "tenant" => $tenant,
        "rent" => $rent,
        "maintenance" => $maintenance,
        "lease" => $leasePayload,
        "deposit" => $deposit,
        "inspections" => $inspections
    ]);
    exit();
}
?>
