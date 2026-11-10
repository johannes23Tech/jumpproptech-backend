<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';

$user = authenticate();

if ($user->role !== 'landlord' && $user->role !== 'agent') {
    security_json_response(403, ["message" => "Unauthorized access."]);
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

    if (!is_object($data)) {
        security_json_response(400, ["message" => "Incomplete data."]);
    }

    $propertyId = filter_var($data->property_id ?? null, FILTER_VALIDATE_INT);
    $unitNumber = security_clean_text($data->unit_number ?? '', 50);
    $sizeDimensions = security_clean_text($data->size_dimensions ?? '', 50);
    $includedItems = security_clean_text($data->included_items ?? '', 2000);
    $monthlyRent = filter_var($data->monthly_rent ?? null, FILTER_VALIDATE_FLOAT);
    $status = isset($data->status) && is_string($data->status) ? $data->status : 'Vacant';
    $allowedStatuses = ['Vacant', 'Occupied', 'Maintenance'];

    if ($propertyId === false || $propertyId < 1
        || $unitNumber === ''
        || $sizeDimensions === ''
        || $monthlyRent === false || $monthlyRent < 0
        || !in_array($status, $allowedStatuses, true)) {
        security_json_response(400, ["message" => "Incomplete or invalid unit data."]);
    }

    // Authorize: the property must belong to the caller (or be assigned to them).
    $check = $conn->prepare("SELECT id FROM properties WHERE id = :pid AND (landlord_id = :uid_owner OR agent_id = :uid_agent) LIMIT 1");
    $check->execute([':pid' => $propertyId, ':uid_owner' => $user->user_id, ':uid_agent' => $user->user_id]);

    if (!$check->fetchColumn()) {
        security_json_response(404, ["message" => "Property not found."]);
    }

    $query = "INSERT INTO units (property_id, unit_number, size_dimensions, is_furnished, included_items, monthly_rent, status) 
              VALUES (:property_id, :unit_number, :size_dimensions, :is_furnished, :included_items, :monthly_rent, :status)";
    
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':property_id' => $propertyId,
        ':unit_number' => $unitNumber,
        ':size_dimensions' => $sizeDimensions,
        ':is_furnished' => !empty($data->is_furnished) ? 1 : 0,
        ':included_items' => $includedItems,
        ':monthly_rent' => $monthlyRent,
        ':status' => $status,
    ]);

    $unitId = (int) $conn->lastInsertId();

    audit_log($conn, (int) $user->user_id, 'unit.created', [
        'entity_type' => 'unit',
        'entity_id' => $unitId,
        'meta' => ['property_id' => (int) $propertyId],
    ]);

    security_json_response(201, ["message" => "Unit created successfully.", "id" => $unitId]);
}
