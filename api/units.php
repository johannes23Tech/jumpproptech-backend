<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;

permission_require($actor, 'units.view');

$method = $_SERVER['REQUEST_METHOD'];

// --- GET: Fetch Units ---
if ($method === 'GET') {
    // Single-company portfolio: all authorised staff see the full register.
    $query = "SELECT units.*, properties.name as property_name 
              FROM units 
              JOIN properties ON units.property_id = properties.id 
              ORDER BY units.id DESC";
    $stmt = $conn->prepare($query);
    $stmt->execute();
    
    $units = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($units);
    exit();
}

// --- POST: Create Unit ---
if ($method === 'POST') {
    permission_require($actor, 'units.manage');

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

    // Authorize: the property must exist in the company register.
    $check = $conn->prepare("SELECT id FROM properties WHERE id = :pid LIMIT 1");
    $check->execute([':pid' => $propertyId]);

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
