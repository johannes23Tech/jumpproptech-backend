<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $query = "SELECT t.*, u.unit_number FROM tenants t JOIN units u ON t.unit_id = u.id WHERE t.owner_id = :user_id ORDER BY t.id DESC";
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

        // 1. Create a User Account for the Tenant (so they can log in)
        $userQuery = "INSERT INTO users (full_name, email, password_hash, phone, role) VALUES (:name, :email, :password, :phone, 'tenant')";
        $userStmt = $conn->prepare($userQuery);
        $hashedPassword = password_hash($data->password, PASSWORD_BCRYPT);
        $userStmt->execute([
            ':name' => $data->name, ':email' => $data->email, 
            ':password' => $hashedPassword, ':phone' => $data->phone
        ]);
        $newUserId = $conn->lastInsertId();

        // 2. Create the Tenant Record
        $query = "INSERT INTO tenants (owner_id, user_id, unit_id, name, phone, email, lease_start, lease_end, deposit, monthly_rent) 
                  VALUES (:owner_id, :user_id, :unit_id, :name, :phone, :email, :lease_start, :lease_end, :deposit, :monthly_rent)";
        $stmt = $conn->prepare($query);
        $stmt->execute([
            ':owner_id' => $user->user_id, ':user_id' => $newUserId, ':unit_id' => $data->unit_id,
            ':name' => $data->name, ':phone' => $data->phone, ':email' => $data->email,
            ':lease_start' => $data->lease_start, ':lease_end' => $data->lease_end,
            ':deposit' => $data->deposit, ':monthly_rent' => $data->monthly_rent
        ]);
        $tenantId = $conn->lastInsertId();

        // 3. Update Unit status to Occupied
        $updateUnit = $conn->prepare("UPDATE units SET status = 'Occupied' WHERE id = :unit_id");
        $updateUnit->execute([':unit_id' => $data->unit_id]);

        // 4. Create initial Pending Rent Record
        $rentQuery = "INSERT INTO rent_records (tenant_id, unit_id, month_for, amount, status) VALUES (:tenant_id, :unit_id, :month, :amount, 'Pending')";
        $rentStmt = $conn->prepare($rentQuery);
        $rentStmt->execute([
            ':tenant_id' => $tenantId, ':unit_id' => $data->unit_id,
            ':month' => date('Y-m-01'), ':amount' => $data->monthly_rent
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