<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

// Verify user and get their ID/Role
$user = authenticate();

// Only Landlords and Agents can access properties
if ($user->role !== 'landlord' && $user->role !== 'agent') {
    http_response_code(403);
    echo json_encode(["message" => "Unauthorized access."]);
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];

// --- GET: Fetch Properties ---
if ($method === 'GET') {
    // If landlord, get their properties. If agent, get assigned properties (simplified for now).
    $query = "SELECT * FROM properties WHERE landlord_id = :user_id ORDER BY created_at DESC";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    
    $properties = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($properties);
    exit();
}

// --- POST: Create Property ---
if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!empty($data->name) && !empty($data->address) && !empty($data->property_type)) {
        $query = "INSERT INTO properties (landlord_id, name, address, property_type) 
                  VALUES (:landlord_id, :name, :address, :property_type)";
        
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':landlord_id', $user->user_id);
        $stmt->bindParam(':name', $data->name);
        $stmt->bindParam(':address', $data->address);
        $stmt->bindParam(':property_type', $data->property_type);

        if ($stmt->execute()) {
            http_response_code(201);
            echo json_encode(["message" => "Property created successfully."]);
        } else {
            http_response_code(500);
            echo json_encode(["message" => "Failed to create property."]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["message" => "Incomplete data."]);
    }
}
?>