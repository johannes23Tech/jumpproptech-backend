<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

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
    
    try {
        $conn->beginTransaction();

        // 1. Check if email already exists
        $checkEmail = $conn->prepare("SELECT id FROM users WHERE email = :email");
        $checkEmail->execute([':email' => $data->email]);
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
        $hashedPassword = password_hash($data->password, PASSWORD_BCRYPT);
        $userStmt->execute([
            ':name' => $data->name, 
            ':email' => $data->email, 
            ':password' => $hashedPassword, 
            ':phone' => $data->phone
        ]);
        $newUserId = $conn->lastInsertId();

        // 3. Create the Tenant Record
        $query = "INSERT INTO tenants (owner_id, user_id, unit_id, name, phone, email, lease_start, lease_end, deposit, monthly_rent) 
                  VALUES (:owner_id, :user_id, :unit_id, :name, :phone, :email, :lease_start, :lease_end, :deposit, :monthly_rent)";
        $stmt = $conn->prepare($query);
        $stmt->execute([
            ':owner_id' => $user->user_id, 
            ':user_id' => $newUserId, 
            ':unit_id' => $data->unit_id,
            ':name' => $data->name, 
            ':phone' => $data->phone, 
            ':email' => $data->email,
            ':lease_start' => $data->lease_start, 
            ':lease_end' => $data->lease_end,
            ':deposit' => $data->deposit, 
            ':monthly_rent' => $data->monthly_rent
        ]);
        $tenantId = $conn->lastInsertId();

        // 4. Update Unit status to Occupied
        $updateUnit = $conn->prepare("UPDATE units SET status = 'Occupied' WHERE id = :unit_id");
        $updateUnit->execute([':unit_id' => $data->unit_id]);

        // 5. Create initial Pending Rent Record
        $rentQuery = "INSERT INTO rent_records (tenant_id, unit_id, month_for, amount, status) VALUES (:tenant_id, :unit_id, :month, :amount, 'Pending')";
        $rentStmt = $conn->prepare($rentQuery);
        $rentStmt->execute([
            ':tenant_id' => $tenantId, 
            ':unit_id' => $data->unit_id,
            ':month' => date('Y-m-01'), 
            ':amount' => $data->monthly_rent
        ]);

        $conn->commit();
        echo json_encode(["message" => "Tenant and User Account created successfully."]);
    } catch (Exception $e) {
        $conn->rollBack();
        http_response_code(500);
        echo json_encode(["message" => "Error: " . $e->getMessage()]);
    }
}
?>