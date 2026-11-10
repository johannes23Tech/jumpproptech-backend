<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

// Tenant and maintenance accounts must not list or create tenants.
if (!in_array($user->role, ['landlord', 'agent'], true)) {
    http_response_code(403);
    echo json_encode(["message" => "Unauthorized. Landlord or agent access required."]);
    exit();
}

if ($method === 'GET') {
    // OPTIMIZATION: Explicitly select only necessary fields to reduce payload size
    $query = "SELECT 
                t.id, t.name, t.phone, t.email, t.lease_start, t.lease_end, t.deposit, t.monthly_rent,
                t.id_number, t.alt_email, t.emergency_contact_name, t.emergency_contact_phone, 
                t.emergency_contact_email, t.emergency_relationship, t.vehicle_type, t.vehicle_details,
                t.id_document,
                u.unit_number, 
                p.name as property_name 
              FROM tenants t 
              JOIN units u ON t.unit_id = u.id 
              JOIN properties p ON u.property_id = p.id
              WHERE t.owner_id = :user_id ORDER BY t.id DESC";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':user_id', $user->user_id);
    $stmt->execute();
    echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!is_object($data) || empty($data->name) || empty($data->email) || empty($data->password) || empty($data->unit_id)) {
        http_response_code(400);
        echo json_encode(["message" => "Name, email, password and unit are required."]);
        exit();
    }

    $name = security_clean_text($data->name, 100);
    $email = strtolower(trim((string) $data->email));
    $phone = security_clean_text($data->phone ?? '', 20);

    if ($name === '' || !security_is_email($email)) {
        http_response_code(400);
        echo json_encode(["message" => "A valid name and email are required."]);
        exit();
    }

    // Enforce the same password policy as register/reset. Without this, a
    // landlord could create a tenant account that bypasses the policy.
    $policyError = security_validate_password((string) $data->password);
    if ($policyError !== null) {
        security_json_response(400, ["message" => $policyError]);
    }

    $unitId = filter_var($data->unit_id, FILTER_VALIDATE_INT);
    $leaseStart = trim((string) ($data->lease_start ?? ''));
    $leaseEnd = trim((string) ($data->lease_end ?? ''));
    $deposit = filter_var($data->deposit ?? 0, FILTER_VALIDATE_FLOAT);
    $monthlyRent = filter_var($data->monthly_rent ?? 0, FILTER_VALIDATE_FLOAT);
    $datePattern = '/^\d{4}-\d{2}-\d{2}$/';

    if ($unitId === false || $unitId < 1
        || !preg_match($datePattern, $leaseStart)
        || !preg_match($datePattern, $leaseEnd)
        || $leaseEnd < $leaseStart
        || $deposit === false || $deposit < 0
        || $monthlyRent === false || $monthlyRent < 0) {
        security_json_response(400, [
            "message" => "A valid unit, lease period and non-negative deposit/rent are required."
        ]);
    }

    // Authorize: the unit must belong to a property owned by the caller
    // (or assigned to them as agent). The property owner becomes the tenant owner.
    $unitStmt = $conn->prepare(
        "SELECT p.landlord_id
         FROM units u
         JOIN properties p ON u.property_id = p.id
         WHERE u.id = :unit_id AND (p.landlord_id = :uid_owner OR p.agent_id = :uid_agent)
         LIMIT 1"
    );
    $unitStmt->execute([':unit_id' => $unitId, ':uid_owner' => $user->user_id, ':uid_agent' => $user->user_id]);
    $ownerId = $unitStmt->fetchColumn();

    if (!$ownerId) {
        http_response_code(404);
        echo json_encode(["message" => "Unit not found."]);
        exit();
    }

    try {
        $conn->beginTransaction();

        // 1. Check if email already exists
        $checkEmail = $conn->prepare("SELECT id FROM users WHERE email = :email");
        $checkEmail->execute([':email' => $email]);
        if ($checkEmail->rowCount() > 0) {
            http_response_code(400);
            echo json_encode(["message" => "This email is already registered to a user. Please use a different email."]);
            exit();
        }

        // 2. Create a User Account for the Tenant
        // Tenants are 'active' by default (they don't pay the SaaS subscription)
        $userQuery = "INSERT INTO users (full_name, email, password_hash, phone, role, subscription_status) 
                      VALUES (:name, :email, :password, :phone, 'tenant', 'active')";
        $userStmt = $conn->prepare($userQuery);
        $hashedPassword = security_hash_password((string) $data->password);
        $userStmt->execute([
            ':name' => $name, 
            ':email' => $email, 
            ':password' => $hashedPassword, 
            ':phone' => $phone
        ]);
        $newUserId = $conn->lastInsertId();

        // 3. Create the Tenant Record
        $query = "INSERT INTO tenants (owner_id, user_id, unit_id, name, phone, email, lease_start, lease_end, deposit, monthly_rent) 
                  VALUES (:owner_id, :user_id, :unit_id, :name, :phone, :email, :lease_start, :lease_end, :deposit, :monthly_rent)";
        $stmt = $conn->prepare($query);
        $stmt->execute([
            ':owner_id' => $ownerId, 
            ':user_id' => $newUserId, 
            ':unit_id' => $unitId,
            ':name' => $name, 
            ':phone' => $phone, 
            ':email' => $email,
            ':lease_start' => $leaseStart, 
            ':lease_end' => $leaseEnd,
            ':deposit' => $deposit, 
            ':monthly_rent' => $monthlyRent
        ]);
        $tenantId = $conn->lastInsertId();

        // 4. Update Unit status to Occupied
        $updateUnit = $conn->prepare("UPDATE units SET status = 'Occupied' WHERE id = :unit_id");
        $updateUnit->execute([':unit_id' => $unitId]);

        // 5. Create initial Pending Rent Record
        $rentQuery = "INSERT INTO rent_records (tenant_id, unit_id, month_for, amount, status) VALUES (:tenant_id, :unit_id, :month, :amount, 'Pending')";
        $rentStmt = $conn->prepare($rentQuery);
        $rentStmt->execute([
            ':tenant_id' => $tenantId, 
            ':unit_id' => $unitId,
            ':month' => date('Y-m-01'), 
            ':amount' => $monthlyRent
        ]);

        $conn->commit();

        audit_log($conn, (int) $user->user_id, 'tenant.created', [
            'entity_type' => 'tenant',
            'entity_id' => (int) $tenantId,
            'meta' => ['unit_id' => $unitId, 'owner_id' => (int) $ownerId],
        ]);

        echo json_encode(["message" => "Tenant and User Account created successfully."]);
    } catch (Exception $e) {
        $conn->rollBack();
        error_log('Tenant creation error: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(["message" => "Tenant could not be created."]);
    }
}
?>