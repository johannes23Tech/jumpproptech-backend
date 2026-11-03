<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $query = "SELECT t.*, u.email as login_email FROM tenants t JOIN users u ON t.user_id = u.id WHERE t.user_id = :user_id LIMIT 1";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    echo json_encode($stmt->fetch(PDO::FETCH_ASSOC));
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    try {
        $query = "UPDATE tenants 
                  SET phone = :phone, 
                      alt_email = :alt_email,
                      emergency_contact_name = :ec_name, 
                      emergency_contact_phone = :ec_phone, 
                      emergency_contact_email = :ec_email,
                      emergency_relationship = :ec_relation
                  WHERE user_id = :user_id";
                  
        $stmt = $conn->prepare($query);
        $stmt->execute([
            ':phone' => $data->phone,
            ':alt_email' => $data->alt_email,
            ':ec_name' => $data->emergency_contact_name,
            ':ec_phone' => $data->emergency_contact_phone,
            ':ec_email' => $data->emergency_contact_email,
            ':ec_relation' => $data->emergency_relationship,
            ':user_id' => $user->user_id
        ]);

        echo json_encode(["message" => "Profile updated successfully."]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(["message" => "Error: " . $e->getMessage()]);
    }
}
?>