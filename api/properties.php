<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

// Verify user and get their ID/Role
$user = authenticate();
$actor = (array) $user;

if (permission_is_staff($actor)) {
    permission_require($actor, 'properties.view');
} else {
    security_json_response(403, ["message" => "Unauthorized access."]);
}

$method = $_SERVER['REQUEST_METHOD'];

// --- GET: Fetch Properties ---
// JUMP PROPTECH is a single-company portfolio. Every authorised staff member
// sees the company register; the old per-landlord filter is retired.
if ($method === 'GET') {
    $includeArchived = isset($_GET['include_archived']) && (string) $_GET['include_archived'] === '1';

    $sql = "SELECT properties.*,
                   (SELECT COUNT(*) FROM units
                     WHERE units.property_id = properties.id AND units.archived_at IS NULL) AS unit_count
            FROM properties"
        . ($includeArchived ? '' : ' WHERE properties.archived_at IS NULL')
        . ' ORDER BY properties.created_at DESC';

    $stmt = $conn->prepare($sql);
    $stmt->execute();

    $properties = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($properties);
    exit();
}

// --- POST: Create Property ---
if ($method === 'POST') {
    permission_require($actor, 'properties.manage');

    $data = json_decode(file_get_contents("php://input"));

    $landlordId = (int) $user->user_id; // historical creator reference
    $companyId = isset($user->company_id) && $user->company_id ? (int) $user->company_id : null;

    $name = is_object($data) && isset($data->name) && is_string($data->name)
        ? security_clean_text($data->name, 100) : '';
    $address = is_object($data) && isset($data->address) && is_string($data->address)
        ? security_clean_text($data->address, 255) : '';
    $city = is_object($data) && isset($data->city) && is_string($data->city)
        ? security_clean_text($data->city, 100) : '';
    $province = is_object($data) && isset($data->province) && is_string($data->province)
        ? security_clean_text($data->province, 100) : '';
    $suburb = is_object($data) && isset($data->suburb) && is_string($data->suburb)
        ? security_clean_text($data->suburb, 100) : '';
    $postalCode = is_object($data) && isset($data->postal_code) && is_string($data->postal_code)
        ? security_clean_text($data->postal_code, 20) : '';
    $description = is_object($data) && isset($data->description) && is_string($data->description)
        ? security_clean_text($data->description, 2000) : '';
    $propertyType = is_object($data) && isset($data->property_type) && is_string($data->property_type)
        ? trim($data->property_type) : '';

    // property_type is an ENUM in the database; reject anything else before
    // MySQL has a chance to coerce it to an empty string.
    $allowedTypes = ['Precast Structure', 'Backroom', 'Apartment Block', 'House'];

    // Validate required fields with detailed feedback
    $validationErrors = [];
    if ($name === '') {
        $validationErrors[] = 'Name is required.';
    }
    if ($address === '') {
        $validationErrors[] = 'Address is required.';
    }
    // Allow case‑insensitive matching for property type
    $typeMatch = false;
    foreach ($allowedTypes as $type) {
        if (strcasecmp($propertyType, $type) === 0) {
            $propertyType = $type; // normalize to canonical value
            $typeMatch = true;
            break;
        }
    }
    if (!$typeMatch) {
        $validationErrors[] = 'A valid property type is required (allowed: ' . implode(", ", $allowedTypes) . ').';
    }
    if ($validationErrors) {
        security_json_response(400, [
            "message" => implode(' ', $validationErrors)
        ]);
    }

    $query = "INSERT INTO properties
                (landlord_id, company_id, name, address, city, province, suburb, postal_code, description, property_type)
              VALUES
                (:landlord_id, :company_id, :name, :address, :city, :province, :suburb, :postal_code, :description, :property_type)";

    $stmt = $conn->prepare($query);
    if ($stmt->execute([
        ':landlord_id' => $landlordId,
        ':company_id' => $companyId,
        ':name' => $name,
        ':address' => $address,
        ':city' => $city !== '' ? $city : null,
        ':province' => $province !== '' ? $province : null,
        ':suburb' => $suburb !== '' ? $suburb : null,
        ':postal_code' => $postalCode !== '' ? $postalCode : null,
        ':description' => $description !== '' ? $description : null,
        ':property_type' => $propertyType,
    ])) {
        $propertyId = (int) $conn->lastInsertId();

        audit_log($conn, (int) $user->user_id, 'property.created', [
            'entity_type' => 'property',
            'entity_id' => $propertyId,
            'meta' => ['company_id' => $companyId],
        ]);

        security_json_response(201, ["message" => "Property created successfully.", "id" => $propertyId]);
    }

    security_json_response(500, ["message" => "Failed to create property."]);
}

// --- PATCH: update or archive a property ---
if ($method === 'PATCH') {
    permission_require($actor, 'properties.manage');

    $data = json_decode(file_get_contents("php://input"));

    if (!is_object($data)) {
        security_json_response(400, ["message" => "Invalid request body."]);
    }

    $propertyId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($propertyId === false || $propertyId < 1) {
        security_json_response(400, ["message" => "A valid property id is required."]);
    }

    $fields = [];
    $params = [':id' => $propertyId];

    if (isset($data->name)) {
        $name = security_clean_text($data->name, 100);
        if ($name === '') {
            security_json_response(400, ["message" => "Property name cannot be empty."]);
        }
        $fields[] = 'name = :name';
        $params[':name'] = $name;
    }
    if (isset($data->address)) {
        $address = security_clean_text($data->address, 255);
        if ($address === '') {
            security_json_response(400, ["message" => "Property address cannot be empty."]);
        }
        $fields[] = 'address = :address';
        $params[':address'] = $address;
    }
    if (isset($data->property_type)) {
        $propertyType = is_string($data->property_type) ? trim($data->property_type) : '';
        $allowedTypes = ['Precast Structure', 'Backroom', 'Apartment Block', 'House'];
        if (!in_array($propertyType, $allowedTypes, true)) {
            security_json_response(400, ["message" => "Invalid property type."]);
        }
        $fields[] = 'property_type = :property_type';
        $params[':property_type'] = $propertyType;
    }
    $optionalText = [
        'city' => 100,
        'province' => 100,
        'suburb' => 100,
        'postal_code' => 20,
        'description' => 2000,
    ];
    foreach ($optionalText as $field => $max) {
        if (array_key_exists($field, (array) $data)) {
            $value = is_string($data->$field) ? security_clean_text($data->$field, $max) : '';
            $fields[] = "$field = :$field";
            $params[":$field"] = $value !== '' ? $value : null;
        }
    }
    if (isset($data->archived)) {
        $fields[] = $data->archived ? 'archived_at = NOW()' : 'archived_at = NULL';
    }

    if ($fields === []) {
        security_json_response(400, ["message" => "Nothing to update."]);
    }

    $stmt = $conn->prepare('UPDATE properties SET ' . implode(', ', $fields) . ' WHERE id = :id');
    $stmt->execute($params);

    $check = $conn->prepare('SELECT id FROM properties WHERE id = :id LIMIT 1');
    $check->execute([':id' => $propertyId]);
    if ($check->fetchColumn() === false) {
        security_json_response(404, ["message" => "Property not found."]);
    }

    audit_log($conn, (int) $user->user_id, 'property.updated', [
        'entity_type' => 'property',
        'entity_id' => $propertyId,
        'meta' => ['archived' => $data->archived ?? null],
    ]);

    security_json_response(200, ["message" => "Property updated."]);
}

security_json_response(405, ["message" => "Method not allowed."]);
