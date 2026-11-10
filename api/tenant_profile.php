<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/tenant_profile.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

// This endpoint owns the tenant self-service profile only. Without this gate a
// landlord/admin request would lazily provision a tenant row for itself.
if ($user->role !== 'tenant') {
    security_json_response(403, ["message" => "Unauthorized. Tenant access required."]);
}

if ($method === 'GET') {
    // Legacy self-registrations have a user account but no tenants row yet.
    // Provision it so the profile page has something to load and edit.
    if (tenant_profile_ensure($conn, (int) $user->user_id) === null) {
        error_log('Tenant profile row could not be provisioned for user ' . $user->user_id);
        security_json_response(500, ["message" => "Profile could not be loaded. Please try again."]);
    }

    // OPTIMIZATION: Only select the specific columns needed for the profile page
    $query = "SELECT 
                t.phone, t.id_number, t.occupants, t.second_occupant_name, 
                t.vehicle_type, t.vehicle_details, t.emergency_contact_name, 
                t.emergency_contact_phone, t.emergency_relationship, t.emergency_contact_email, 
                t.alt_email, t.id_document, 
                u.email as login_email
              FROM tenants t 
              JOIN users u ON t.user_id = u.id 
              WHERE t.user_id = :user_id LIMIT 1";
              
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    echo json_encode($stmt->fetch(PDO::FETCH_ASSOC));
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!is_object($data)) {
        security_json_response(400, ["message" => "Invalid request body."]);
    }

    // Validate/sanitize before touching the database. Free-text fields are
    // stripped of tags and control characters; emails and the document must
    // be well formed. This stops stored XSS at the input boundary.
    $phone = security_clean_text($data->phone ?? '', 20);
    $idNumber = security_clean_text($data->id_number ?? '', 50);
    $secondOccupant = security_clean_text($data->second_occupant_name ?? '', 100);
    $vehicleType = security_clean_text($data->vehicle_type ?? '', 50);
    $vehicleDetails = security_clean_text($data->vehicle_details ?? '', 255);
    $ecName = security_clean_text($data->emergency_contact_name ?? '', 100);
    $ecPhone = security_clean_text($data->emergency_contact_phone ?? '', 20);
    $ecRelation = security_clean_text($data->emergency_relationship ?? '', 50);

    $occupants = filter_var($data->occupants ?? 1, FILTER_VALIDATE_INT);
    if ($occupants === false || $occupants < 1 || $occupants > 50) {
        security_json_response(400, ["message" => "Occupants must be a number between 1 and 50."]);
    }

    $ecEmail = trim((string) ($data->emergency_contact_email ?? ''));
    if ($ecEmail !== '' && !security_is_email($ecEmail)) {
        security_json_response(400, ["message" => "Emergency contact email is not valid."]);
    }

    $altEmail = trim((string) ($data->alt_email ?? ''));
    if ($altEmail !== '' && !security_is_email($altEmail)) {
        security_json_response(400, ["message" => "Alternate email is not valid."]);
    }

    $idDocument = null;
    $updateDocument = property_exists($data, 'id_document');
    if ($updateDocument && $data->id_document !== '' && $data->id_document !== null) {
        $idDocument = security_clean_document($data->id_document);
        if ($idDocument === null) {
            security_json_response(400, ["message" => "ID document must be an image or an https link."]);
        }
    }

    try {
        // Create the profile row for a tenant who registered before being
        // linked to a unit, so the update actually persists.
        $tenant = tenant_profile_ensure($conn, (int) $user->user_id);
        if ($tenant === null) {
            error_log('Tenant profile row could not be provisioned for user ' . $user->user_id);
            security_json_response(500, ["message" => "Profile could not be updated. Please try again."]);
        }

        $query = "UPDATE tenants 
                  SET phone = :phone, 
                      id_number = :id_number,
                      occupants = :occupants,
                      second_occupant_name = :second_occ,
                      vehicle_type = :vehicle_type,
                      vehicle_details = :vehicle_details,
                      emergency_contact_name = :ec_name, 
                      emergency_contact_phone = :ec_phone, 
                      emergency_relationship = :ec_relation,
                      emergency_contact_email = :ec_email,
                      alt_email = :alt_email";

        $params = [
            ':phone' => $phone,
            ':id_number' => $idNumber,
            ':occupants' => $occupants,
            ':second_occ' => $secondOccupant,
            ':vehicle_type' => $vehicleType,
            ':vehicle_details' => $vehicleDetails,
            ':ec_name' => $ecName,
            ':ec_phone' => $ecPhone,
            ':ec_relation' => $ecRelation,
            ':ec_email' => $ecEmail !== '' ? $ecEmail : null,
            ':alt_email' => $altEmail !== '' ? $altEmail : null,
            ':user_id' => $user->user_id
        ];

        if ($updateDocument) {
            $query .= ", id_document = :id_doc";
            $params[':id_doc'] = $idDocument;
        }

        $query .= " WHERE user_id = :user_id";

        $stmt = $conn->prepare($query);
        $stmt->execute($params);

        audit_log($conn, (int) $user->user_id, 'tenant.profile.updated', [
            'actor_email' => $tenant['email'] ?? null,
            'entity_type' => 'tenant',
            'entity_id' => (int) $tenant['id'],
            'meta' => ['id_document_updated' => $updateDocument],
        ]);

        echo json_encode(["message" => "Profile updated successfully."]);
    } catch (Exception $e) {
        error_log('Tenant profile update failed: ' . $e->getMessage());
        security_json_response(500, ["message" => "Profile could not be updated. Please try again."]);
    }
}
?>
