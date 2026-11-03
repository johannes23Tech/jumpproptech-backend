<?php
require_once '../../config/db.php';
require_once '../../middleware/check_role.php';

$user = authenticate();

// Only Super Admin can access this
if ($user->role !== 'superadmin') {
    http_response_code(403);
    echo json_encode(["message" => "Unauthorized."]);
    exit();
}

$data = json_decode(file_get_contents("php://input"));

if (empty($data->full_name) || empty($data->email) || empty($data->password)) {
    http_response_code(400);
    echo json_encode(["message" => "All fields are required."]);
    exit();
}

try {
    // Check if email exists
    $check = $conn->prepare("SELECT id FROM users WHERE email = :email");
    $check->execute([':email' => $data->email]);
    if ($check->rowCount() > 0) {
        http_response_code(400);
        echo json_encode(["message" => "Email already exists."]);
        exit();
    }

    // Create Landlord
    $role = 'landlord';
    $hash = password_hash($data->password, PASSWORD_BCRYPT);
    
    $query = "INSERT INTO users (full_name, email, password_hash, role) VALUES (:name, :email, :hash, :role)";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':name' => $data->full_name,
        ':email' => $data->email,
        ':hash' => $hash,
        ':role' => $role
    ]);

    echo json_encode(["message" => "Landlord created successfully."]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["message" => "Error: " . $e->getMessage()]);
}
?>