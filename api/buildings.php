<?php
// api/buildings.php
//
// Optional building/block layer inside a company-owned property. Properties
// can still hold units directly; buildings add structure for larger sites.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

if ($method === 'GET') {
    permission_require($actor, 'properties.view');

    $propertyId = filter_var($_GET['property_id'] ?? null, FILTER_VALIDATE_INT);

    $sql = "SELECT b.*, p.name AS property_name,
                   (SELECT COUNT(*) FROM units u WHERE u.building_id = b.id AND u.archived_at IS NULL) AS unit_count
            FROM buildings b
            JOIN properties p ON b.property_id = p.id";
    $params = [];

    if ($propertyId !== false && $propertyId !== null && $propertyId > 0) {
        $sql .= ' WHERE b.property_id = :property_id';
        $params[':property_id'] = $propertyId;
    }
    $sql .= ' ORDER BY b.name ASC';

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'properties.manage');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $propertyId = filter_var($data->property_id ?? 0, FILTER_VALIDATE_INT);
    $name = security_clean_text($data->name ?? '', 150);
    $address = security_clean_text($data->address ?? '', 255);

    if ($propertyId === false || $propertyId < 1 || $name === '') {
        security_json_response(400, ['message' => 'A property and building name are required.']);
    }

    $propertyCheck = $conn->prepare(
        'SELECT id FROM properties WHERE id = :id AND archived_at IS NULL LIMIT 1'
    );
    $propertyCheck->execute([':id' => $propertyId]);
    if ($propertyCheck->fetchColumn() === false) {
        security_json_response(404, ['message' => 'Property not found or archived.']);
    }

    $insert = $conn->prepare(
        'INSERT INTO buildings (property_id, name, address) VALUES (:property_id, :name, :address)'
    );
    $insert->execute([
        ':property_id' => $propertyId,
        ':name' => $name,
        ':address' => $address !== '' ? $address : null,
    ]);
    $buildingId = (int) $conn->lastInsertId();

    audit_log($conn, (int) $user->user_id, 'building.created', [
        'entity_type' => 'building',
        'entity_id' => $buildingId,
        'meta' => ['property_id' => (int) $propertyId],
    ]);

    security_json_response(201, ['message' => 'Building created successfully.', 'id' => $buildingId]);
}

if ($method === 'PATCH') {
    permission_require($actor, 'properties.manage');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $buildingId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($buildingId === false || $buildingId < 1) {
        security_json_response(400, ['message' => 'A valid building id is required.']);
    }

    $fields = [];
    $params = [':id' => $buildingId];

    if (isset($data->name)) {
        $name = security_clean_text($data->name, 150);
        if ($name === '') {
            security_json_response(400, ['message' => 'Building name cannot be empty.']);
        }
        $fields[] = 'name = :name';
        $params[':name'] = $name;
    }
    if (isset($data->address)) {
        $fields[] = 'address = :address';
        $address = security_clean_text($data->address, 255);
        $params[':address'] = $address !== '' ? $address : null;
    }

    if ($fields === []) {
        security_json_response(400, ['message' => 'Nothing to update.']);
    }

    $stmt = $conn->prepare('UPDATE buildings SET ' . implode(', ', $fields) . ' WHERE id = :id');
    $stmt->execute($params);

    if ($stmt->rowCount() === 0) {
        $check = $conn->prepare('SELECT id FROM buildings WHERE id = :id LIMIT 1');
        $check->execute([':id' => $buildingId]);
        if ($check->fetchColumn() === false) {
            security_json_response(404, ['message' => 'Building not found.']);
        }
    }

    audit_log($conn, (int) $user->user_id, 'building.updated', [
        'entity_type' => 'building',
        'entity_id' => $buildingId,
    ]);

    security_json_response(200, ['message' => 'Building updated.']);
}

security_json_response(405, ['message' => 'Method not allowed.']);
