<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // Fetch expenses with property names
    $query = "SELECT e.*, p.name as property_name 
              FROM expenses e 
              JOIN properties p ON e.property_id = p.id 
              WHERE e.owner_id = :user_id ORDER BY e.expense_date DESC";
    $stmt = $conn->prepare($query);
    $stmt->execute([':user_id' => $user->user_id]);
    $expenses = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Fetch total rent collected this month
    $rentQuery = "SELECT SUM(amount) as total_rent FROM rent_records WHERE status = 'Paid' AND tenant_id IN (SELECT id FROM tenants WHERE owner_id = :user_id)";
    $rentStmt = $conn->prepare($rentQuery);
    $rentStmt->execute([':user_id' => $user->user_id]);
    $rentData = $rentStmt->fetch(PDO::FETCH_ASSOC);

    echo json_encode([
        "expenses" => $expenses,
        "total_rent" => $rentData['total_rent'] ?? 0
    ]);
    exit();
}

if ($method === 'POST') {
    if (!in_array($user->role, ['landlord', 'agent', 'superadmin'], true)) {
        security_json_response(403, ["message" => "Unauthorized."]);
    }

    $data = json_decode(file_get_contents("php://input"));

    if (!is_object($data)) {
        security_json_response(400, ["message" => "Invalid request body."]);
    }

    $propertyId = filter_var($data->property_id ?? 0, FILTER_VALIDATE_INT);
    $amount = filter_var($data->amount ?? null, FILTER_VALIDATE_FLOAT);
    $category = security_clean_text($data->category ?? '', 50);
    $description = security_clean_text($data->description ?? '', 2000);
    $expenseDate = trim((string) ($data->expense_date ?? ''));

    $date = DateTime::createFromFormat('Y-m-d', $expenseDate);

    if (!$propertyId || $propertyId < 1
        || $category === ''
        || $amount === false || $amount < 0
        || !$date || $date->format('Y-m-d') !== $expenseDate) {
        security_json_response(400, ["message" => "A valid property, category, amount and date are required."]);
    }

    // A non-admin may only add expenses to a property they own or manage.
    if ($user->role === 'superadmin') {
        $check = $conn->prepare("SELECT landlord_id FROM properties WHERE id = :pid LIMIT 1");
        $check->execute([':pid' => $propertyId]);
        $property = $check->fetch(PDO::FETCH_ASSOC);

        if (!$property) {
            security_json_response(404, ["message" => "Property not found."]);
        }
        $ownerId = (int) $property['landlord_id'];
    } else {
        $check = $conn->prepare(
            "SELECT id FROM properties
             WHERE id = :pid AND (landlord_id = :uid_landlord OR agent_id = :uid_agent)
             LIMIT 1"
        );
        $check->execute([
            ':pid' => $propertyId,
            ':uid_landlord' => $user->user_id,
            ':uid_agent' => $user->user_id,
        ]);

        if (!$check->fetchColumn()) {
            security_json_response(404, ["message" => "Property not found."]);
        }
        $ownerId = (int) $user->user_id;
    }

    $query = "INSERT INTO expenses (owner_id, property_id, category, amount, expense_date, description) 
              VALUES (:owner_id, :property_id, :category, :amount, :date, :desc)";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':owner_id' => $ownerId,
        ':property_id' => $propertyId,
        ':category' => $category,
        ':amount' => $amount,
        ':date' => $expenseDate,
        ':desc' => $description
    ]);

    audit_log($conn, (int) $user->user_id, 'expense.created', [
        'entity_type' => 'expense',
        'entity_id' => (int) $conn->lastInsertId(),
        'meta' => ['property_id' => $propertyId, 'amount' => $amount],
    ]);

    security_json_response(200, ["message" => "Expense added successfully."]);
}
?>
