<?php
require_once '../../config/db.php';

// Get the raw JSON data sent from React
$data = json_decode(file_get_contents("php://input"));

// Validate required fields
if (!empty($data->full_name) && !empty($data->email) && !empty($data->password) && !empty($data->role)) {
    
    // 1. Check if email already exists
    $checkQuery = "SELECT id FROM users WHERE email = :email LIMIT 1";
    $stmt = $conn->prepare($checkQuery);
    $stmt->bindParam(':email', $data->email);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        http_response_code(400);
        echo json_encode(["message" => "Email already exists."]);
        exit();
    }

    // 2. Insert new user
    $query = "INSERT INTO users (full_name, email, password_hash, phone, role) 
              VALUES (:full_name, :email, :password_hash, :phone, :role)";
    
    $stmt = $conn->prepare($query);
    
    // Hash the password securely
    $password_hash = password_hash($data->password, PASSWORD_BCRYPT);
    
    // Optional phone number
    $phone = isset($data->phone) ? $data->phone : '';

    // Bind parameters to prevent SQL injection
    $stmt->bindParam(':full_name', $data->full_name);
    $stmt->bindParam(':email', $data->email);
    $stmt->bindParam(':password_hash', $password_hash);
    $stmt->bindParam(':phone', $phone);
    $stmt->bindParam(':role', $data->role);

    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(["message" => "User registered successfully."]);
    } else {
        http_response_code(500);
        echo json_encode(["message" => "User could not be created."]);
    }

} else {
    http_response_code(400);
    echo json_encode(["message" => "Incomplete data. Please fill in all required fields."]);
}
?>