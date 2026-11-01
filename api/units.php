<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();

if ($user->role !== 'landlord' && $user->role !== 'agent') {
    http_response_code(403);
    echo json_encode(["message" => "Unauthorized access."]);
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];

// --- GET: Fetch Units ---
if ($method === 'GET') {
    // Changed 'created_at' to 'id' to prevent SQL crash
    $query = "SELECT units.*, properties.name as property_name 
              FROM units 
              JOIN properties ON units.property_id = properties.id 
              WHERE properties.landlord_id = :user_id 
              ORDER BY units.id DESC";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    
    $units = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($units);
    exit();
}

// --- POST: Create Unit ---
if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!empty($data->property_id) && !empty($data->unit_number) && !empty($data->size_dimensions)) {
        $query = "INSERT INTO units (property_id, unit_number, size_dimensions, is_furnished, included_items, monthly_rent, status) 
                  VALUES (:property_id, :unit_number, :size_dimensions, :is_furnished, :included_items, :monthly_rent, :status)";
        
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':property_id', $data->property_id);
        $stmt->bindParam(':unit_number', $data->unit_number);
        $stmt->bindParam(':size_dimensions', $data->size_dimensions);
        
        $isFurnished = $data->is_furnished ? 1 : 0;
        $stmt->bindParam(':is_furnished', $isFurnished);
        
        $stmt->bindParam(':included_items', $data->included_items);
        $stmt->bindParam(':monthly_rent', $data->monthly_rent);
        $stmt->bindParam(':status', $data->status);

        if ($stmt->execute()) {
            http_response_code(201);
            echo json_encode(["message" => "Unit created successfully."]);
        } else {
            http_response_code(500);
            echo json_encode(["message" => "Failed to create unit."]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["message" => "Incomplete data."]);
    }
}
?>