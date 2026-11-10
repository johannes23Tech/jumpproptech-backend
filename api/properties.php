<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';

// Verify user and get their ID/Role
$user = authenticate();

if (!in_array($user->role, ['landlord', 'agent', 'superadmin'], true)) {
    security_json_response(403, ["message" => "Unauthorized access."]);
}

$method = $_SERVER['REQUEST_METHOD'];

// --- GET: Fetch Properties ---
if ($method === 'GET') {
    if ($user->role === 'superadmin') {
        $query = "SELECT * FROM properties ORDER BY created_at DESC";
        $stmt = $conn->prepare($query);
        $stmt->execute();
    } else {
        // Landlords see their properties; agents are scoped by their account.
        $query = "SELECT * FROM properties WHERE landlord_id = :user_id ORDER BY created_at DESC";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':user_id', $user->user_id);
        $stmt->execute();
    }
    
    $properties = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($properties);
    exit();
}

// --- POST: Create Property ---
if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    $landlordId = (int) $user->user_id;
    if ($user->role === 'superadmin') {
        $landlordId = filter_var(
            is_object($data) ? ($data->landlord_id ?? null) : null,
            FILTER_VALIDATE_INT
        );
        if ($landlordId === false || $landlordId < 1) {
            security_json_response(400, ["message" => "A valid landlord_id is required."]);
        }

        $landlordCheck = $conn->prepare(
            "SELECT id FROM users WHERE id = :landlord_id AND role = 'landlord' LIMIT 1"
        );
        $landlordCheck->execute([':landlord_id' => $landlordId]);
        if (!$landlordCheck->fetchColumn()) {
            security_json_response(404, ["message" => "Landlord not found."]);
        }
    }

    $name = is_object($data) && isset($data->name) && is_string($data->name)
        ? security_clean_text($data->name, 100) : '';
    $address = is_object($data) && isset($data->address) && is_string($data->address)
        ? security_clean_text($data->address, 255) : '';
    $propertyType = is_object($data) && isset($data->property_type) && is_string($data->property_type)
        ? trim($data->property_type) : '';

    // property_type is an ENUM in the database; reject anything else before
    // MySQL has a chance to coerce it to an empty string.
    $allowedTypes = ['Precast Structure', 'Backroom', 'Apartment Block', 'House'];

    if ($name === '' || $address === '' || !in_array($propertyType, $allowedTypes, true)) {
        security_json_response(400, [
            "message" => "Name, address and a valid property type are required."
        ]);
    }

    $query = "INSERT INTO properties (landlord_id, name, address, property_type)
              VALUES (:landlord_id, :name, :address, :property_type)";

    $stmt = $conn->prepare($query);
    if ($stmt->execute([
        ':landlord_id' => $landlordId,
        ':name' => $name,
        ':address' => $address,
        ':property_type' => $propertyType,
    ])) {
        $propertyId = (int) $conn->lastInsertId();

        audit_log($conn, (int) $user->user_id, 'property.created', [
            'entity_type' => 'property',
            'entity_id' => $propertyId,
            'meta' => ['landlord_id' => $landlordId],
        ]);

        security_json_response(201, ["message" => "Property created successfully.", "id" => $propertyId]);
    }

    security_json_response(500, ["message" => "Failed to create property."]);
}
