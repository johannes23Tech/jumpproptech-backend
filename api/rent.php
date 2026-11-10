<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $query = "SELECT r.*, t.name as tenant_name, t.email as tenant_email, u.unit_number, p.name as property_name 
              FROM rent_records r 
              JOIN tenants t ON r.tenant_id = t.id 
              JOIN units u ON r.unit_id = u.id 
              JOIN properties p ON u.property_id = p.id
              WHERE t.owner_id = :user_id ORDER BY r.id DESC";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!is_object($data) || empty($data->id)) {
        security_json_response(400, ["message" => "Rent record id is required."]);
    }

    $rentId = filter_var($data->id, FILTER_VALIDATE_INT);
    if ($rentId === false || $rentId < 1) {
        security_json_response(400, ["message" => "A valid rent record id is required."]);
    }

    $paymentMethod = security_clean_text($data->method ?? '', 50);
    if ($paymentMethod === '') {
        $paymentMethod = 'EFT';
    }

    // Authorize against the record owner, not just the record id.
    if ($user->role === 'tenant') {
        $check = $conn->prepare("SELECT r.id, r.status FROM rent_records r JOIN tenants t ON r.tenant_id = t.id WHERE r.id = :id AND t.user_id = :uid LIMIT 1");
        $check->execute([':id' => $rentId, ':uid' => $user->user_id]);
    } elseif ($user->role === 'landlord' || $user->role === 'agent') {
        $check = $conn->prepare("SELECT r.id, r.status FROM rent_records r JOIN tenants t ON r.tenant_id = t.id WHERE r.id = :id AND t.owner_id = :uid LIMIT 1");
        $check->execute([':id' => $rentId, ':uid' => $user->user_id]);
    } elseif ($user->role === 'superadmin') {
        $check = $conn->prepare("SELECT id, status FROM rent_records WHERE id = :id LIMIT 1");
        $check->execute([':id' => $rentId]);
    } else {
        security_json_response(403, ["message" => "Unauthorized."]);
    }

    $record = $check->fetch(PDO::FETCH_ASSOC);

    if (!$record) {
        security_json_response(404, ["message" => "Rent record not found."]);
    }

    // Never issue a second receipt for a record that is already paid.
    if ($record['status'] === 'Paid') {
        audit_log($conn, (int) $user->user_id, 'rent.payment_rejected', [
            'entity_type' => 'rent_record',
            'entity_id' => $rentId,
            'outcome' => 'failure',
            'meta' => ['reason' => 'already_paid'],
        ]);
        security_json_response(409, ["message" => "This rent record has already been paid."]);
    }

    $receiptNum = "RCP-" . date('Y') . "-" . strtoupper(substr(bin2hex(random_bytes(4)), 0, 5));

    $query = "UPDATE rent_records SET status = 'Paid', payment_method = :method, paid_date = :date, receipt_number = :receipt WHERE id = :id";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':method' => $paymentMethod,
        ':date' => date('Y-m-d'),
        ':receipt' => $receiptNum,
        ':id' => $rentId
    ]);

    audit_log($conn, (int) $user->user_id, 'rent.payment_recorded', [
        'entity_type' => 'rent_record',
        'entity_id' => $rentId,
        'meta' => ['receipt_number' => $receiptNum, 'method' => $paymentMethod],
    ]);

    security_json_response(200, ["message" => "Payment recorded.", "receipt_number" => $receiptNum]);
}
