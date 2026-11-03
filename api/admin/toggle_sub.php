<?php
require_once '../../config/db.php';
require_once '../../middleware/check_role.php';

$user = authenticate();

if ($user->role !== 'superadmin') {
    http_response_code(403);
    echo json_encode(["message" => "Unauthorized"]);
    exit();
}

$data = json_decode(file_get_contents("php://input"));

$query = "UPDATE users SET subscription_status = :status WHERE id = :id AND role = 'landlord'";
$stmt = $conn->prepare($query);
$stmt->execute([
    ':status' => $data->status, 
    ':id' => $data->landlord_id
]);

echo json_encode(["message" => "Subscription updated."]);
?>