<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];

if (!permission_is_staff($actor)) {
    security_json_response(403, ["message" => "Unauthorized. Staff access required."]);
}

if ($method === 'GET') {
    permission_require($actor, 'suppliers.view');

    $stmt = $conn->query("SELECT * FROM suppliers ORDER BY name ASC");
    echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'suppliers.manage');

    $data = json_decode(file_get_contents("php://input"));
    if (!is_object($data)) {
        security_json_response(400, ["message" => "Invalid request body."]);
    }

    // Support delete action
    if (isset($data->action) && $data->action === 'delete') {
        $id = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
        if ($id === false || $id < 1) {
            security_json_response(400, ["message" => "A valid supplier id is required."]);
        }
        $conn->prepare("DELETE FROM suppliers WHERE id = :id")->execute([':id' => $id]);
        audit_log($conn, (int) $user->user_id, 'supplier.deleted', [
            'entity_type' => 'supplier',
            'entity_id' => $id,
        ]);
        echo json_encode(["message" => "Supplier deleted."]);
        exit();
    }

    $name = security_clean_text($data->name ?? '', 100);
    $trade = security_clean_text($data->trade ?? '', 50);
    $contactName = security_clean_text($data->contact_name ?? '', 100);
    $phone = security_clean_text($data->phone ?? '', 20);
    $email = strtolower(trim((string) ($data->email ?? '')));
    $isActive = isset($data->is_active) ? (int) $data->is_active : 1;

    if ($name === '') {
        security_json_response(400, ["message" => "Supplier name is required."]);
    }
    if ($email !== '' && !security_is_email($email)) {
        security_json_response(400, ["message" => "A valid email is required."]);
    }

    $conn->prepare(
        "INSERT INTO suppliers (name, trade, contact_name, phone, email, is_active)
         VALUES (:name, :trade, :contact_name, :phone, :email, :is_active)"
    )->execute([
        ':name' => $name,
        ':trade' => $trade,
        ':contact_name' => $contactName,
        ':phone' => $phone,
        ':email' => $email,
        ':is_active' => $isActive
    ]);

    audit_log($conn, (int) $user->user_id, 'supplier.created', [
        'entity_type' => 'supplier',
        'entity_id' => (int) $conn->lastInsertId(),
    ]);

    security_json_response(200, ["message" => "Supplier saved."]);
}

security_json_response(405, ["message" => "Method not allowed."]);
