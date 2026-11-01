<?php
require_once '../config/db.php';
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
    
    $receiptNum = "RCP-" . date('Y') . "-" . strtoupper(substr(uniqid(), -5));
    
    $query = "UPDATE rent_records SET status = 'Paid', payment_method = :method, paid_date = :date, receipt_number = :receipt WHERE id = :id";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':method' => $data->method, 
        ':date' => date('Y-m-d'), 
        ':receipt' => $receiptNum,
        ':id' => $data->id
    ]);
    
    echo json_encode(["message" => "Payment recorded.", "receipt_number" => $receiptNum]);
}
?>