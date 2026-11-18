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
    // Archived units are hidden unless explicitly requested.
    $includeArchived = isset($_GET['include_archived']) && (string) $_GET['include_archived'] === '1';

    $query = "SELECT units.*, properties.name as property_name,
                     buildings.name as building_name,
                     (SELECT COUNT(*) FROM onboarding_tokens ot
                       WHERE ot.unit_id = units.id
                         AND ot.revoked_at IS NULL
                         AND ot.used_at IS NULL
                         AND ot.expires_at > NOW()) as active_qr_tokens
              FROM units
              JOIN properties ON units.property_id = properties.id
              LEFT JOIN buildings ON units.building_id = buildings.id"
        . ($includeArchived ? '' : ' WHERE units.archived_at IS NULL')
        . " ORDER BY units.id DESC";
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
    $buildingId = filter_var($data->building_id ?? 0, FILTER_VALIDATE_INT);
    $unitNumber = security_clean_text($data->unit_number ?? '', 50);
    $sizeDimensions = security_clean_text($data->size_dimensions ?? '', 50);
    $includedItems = security_clean_text($data->included_items ?? '', 2000);
    $prepaidMeter = security_clean_text($data->prepaid_meter_number ?? '', 60);
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
    $check = $conn->prepare("SELECT id FROM properties WHERE id = :pid AND archived_at IS NULL LIMIT 1");
    $check->execute([':pid' => $propertyId]);

    if (!$check->fetchColumn()) {
        security_json_response(404, ["message" => "Property not found."]);
    }

    // A building must belong to the same property.
    if ($buildingId !== false && $buildingId !== null && $buildingId > 0) {
        $buildingCheck = $conn->prepare(
            'SELECT id FROM buildings WHERE id = :bid AND property_id = :pid LIMIT 1'
        );
        $buildingCheck->execute([':bid' => $buildingId, ':pid' => $propertyId]);
        if ($buildingCheck->fetchColumn() === false) {
            security_json_response(404, ["message" => "Building not found for this property."]);
        }
    } else {
        $buildingId = null;
    }

    $query = "INSERT INTO units (property_id, building_id, unit_number, size_dimensions, is_furnished, included_items, prepaid_meter_number, monthly_rent, status) 
              VALUES (:property_id, :building_id, :unit_number, :size_dimensions, :is_furnished, :included_items, :prepaid_meter, :monthly_rent, :status)";

    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':property_id' => $propertyId,
        ':building_id' => $buildingId,
        ':unit_number' => $unitNumber,
        ':size_dimensions' => $sizeDimensions,
        ':is_furnished' => !empty($data->is_furnished) ? 1 : 0,
        ':included_items' => $includedItems,
        ':prepaid_meter' => $prepaidMeter !== '' ? $prepaidMeter : null,
        ':monthly_rent' => $monthlyRent,
        ':status' => $status,
    ]);

    $unitId = (int) $conn->lastInsertId();

    audit_log($conn, (int) $user->user_id, 'unit.created', [
        'entity_type' => 'unit',
        'entity_id' => $unitId,
        'meta' => ['property_id' => (int) $propertyId, 'building_id' => $buildingId],
    ]);

    security_json_response(201, ["message" => "Unit created successfully.", "id" => $unitId]);
}

// --- PATCH: Update or archive a unit ---
if ($method === 'PATCH') {
    permission_require($actor, 'units.manage');

    $data = json_decode(file_get_contents("php://input"));

    if (!is_object($data)) {
        security_json_response(400, ["message" => "Invalid request body."]);
    }

    $unitId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($unitId === false || $unitId < 1) {
        security_json_response(400, ["message" => "A valid unit id is required."]);
    }

    $unitStmt = $conn->prepare('SELECT id, property_id FROM units WHERE id = :id LIMIT 1');
    $unitStmt->execute([':id' => $unitId]);
    $unit = $unitStmt->fetch(PDO::FETCH_ASSOC);
    if (!$unit) {
        security_json_response(404, ["message" => "Unit not found."]);
    }

    $fields = [];
    $params = [':id' => $unitId];

    if (isset($data->unit_number)) {
        $unitNumber = security_clean_text($data->unit_number, 50);
        if ($unitNumber === '') {
            security_json_response(400, ["message" => "Unit number cannot be empty."]);
        }
        $fields[] = 'unit_number = :unit_number';
        $params[':unit_number'] = $unitNumber;
    }
    if (isset($data->size_dimensions)) {
        $size = security_clean_text($data->size_dimensions, 50);
        if ($size === '') {
            security_json_response(400, ["message" => "Size cannot be empty."]);
        }
        $fields[] = 'size_dimensions = :size_dimensions';
        $params[':size_dimensions'] = $size;
    }
    if (isset($data->monthly_rent)) {
        $rent = filter_var($data->monthly_rent, FILTER_VALIDATE_FLOAT);
        if ($rent === false || $rent < 0) {
            security_json_response(400, ["message" => "A valid monthly rent is required."]);
        }
        $fields[] = 'monthly_rent = :monthly_rent';
        $params[':monthly_rent'] = $rent;
    }
    if (isset($data->status)) {
        $status = is_string($data->status) ? $data->status : '';
        if (!in_array($status, ['Vacant', 'Occupied', 'Maintenance'], true)) {
            security_json_response(400, ["message" => "Invalid unit status."]);
        }
        $fields[] = 'status = :status';
        $params[':status'] = $status;
    }
    if (isset($data->is_furnished)) {
        $fields[] = 'is_furnished = :is_furnished';
        $params[':is_furnished'] = $data->is_furnished ? 1 : 0;
    }
    if (isset($data->included_items)) {
        $fields[] = 'included_items = :included_items';
        $params[':included_items'] = security_clean_text($data->included_items, 2000);
    }
    if (isset($data->prepaid_meter_number)) {
        $meter = security_clean_text($data->prepaid_meter_number, 60);
        $fields[] = 'prepaid_meter_number = :prepaid_meter';
        $params[':prepaid_meter'] = $meter !== '' ? $meter : null;
    }
    if (isset($data->building_id)) {
        $buildingId = filter_var($data->building_id, FILTER_VALIDATE_INT);
        if ($buildingId === false || $buildingId < 1) {
            $fields[] = 'building_id = NULL';
        } else {
            $buildingCheck = $conn->prepare(
                'SELECT id FROM buildings WHERE id = :bid AND property_id = :pid LIMIT 1'
            );
            $buildingCheck->execute([':bid' => $buildingId, ':pid' => $unit['property_id']]);
            if ($buildingCheck->fetchColumn() === false) {
                security_json_response(404, ["message" => "Building not found for this property."]);
            }
            $fields[] = 'building_id = :building_id';
            $params[':building_id'] = $buildingId;
        }
    }
    if (isset($data->archived)) {
        $fields[] = $data->archived ? 'archived_at = NOW()' : 'archived_at = NULL';
    }

    if ($fields === []) {
        security_json_response(400, ["message" => "Nothing to update."]);
    }

    $stmt = $conn->prepare('UPDATE units SET ' . implode(', ', $fields) . ' WHERE id = :id');
    $stmt->execute($params);

    audit_log($conn, (int) $user->user_id, 'unit.updated', [
        'entity_type' => 'unit',
        'entity_id' => $unitId,
        'meta' => ['archived' => $data->archived ?? null],
    ]);

    security_json_response(200, ["message" => "Unit updated."]);
}

security_json_response(405, ["message" => "Method not allowed."]);
