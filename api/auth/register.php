<?php
require_once '../../config/db.php';

$data = json_decode(file_get_contents("php://input"));

if (!empty($data->full_name) && !empty($data->email) && !empty($data->password)) {
    
    // Check if email already exists
    $checkQuery = "SELECT id FROM users WHERE email = :email LIMIT 1";
    $stmt = $conn->prepare($checkQuery);
    $stmt->bindParam(':email', $data->email);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        http_response_code(400);
        echo json_encode(["message" => "Email already exists."]);
        exit();
    }

    // SECURITY: Force the role to 'tenant'. 
    // Landlords can only be created by the Super Admin via the admin endpoint.
    $role = 'tenant';

    $query = "INSERT INTO users (full_name, email, password_hash, phone, role) 
              VALUES (:full_name, :email, :password_hash, :phone, :role)";
    
    $stmt = $conn->prepare($query);
    
    $password_hash = password_hash($data->password, PASSWORD_BCRYPT);
    $phone = isset($data->phone) ? $data->phone : '';

    $stmt->bindParam(':full_name', $data->full_name);
    $stmt->bindParam(':email', $data->email);
    $stmt->bindParam(':password_hash', $password_hash);
    $stmt->bindParam(':phone', $phone);
    $stmt->bindParam(':role', $role);

    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(["message" => "User registered successfully as Tenant."]);
    } else {
        http_response_code(500);
        echo json_encode(["message" => "User could not be created."]);
    }

} else {
    http_response_code(400);
    echo json_encode(["message" => "Incomplete data."]);
}
?>