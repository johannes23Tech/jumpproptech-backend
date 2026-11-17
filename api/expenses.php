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
    permission_require($actor, 'expenses.view');

    // Single-company portfolio: authorised staff see every company expense.
    $query = "SELECT e.*, p.name as property_name 
              FROM expenses e 
              JOIN properties p ON e.property_id = p.id 
              ORDER BY e.expense_date DESC";
    $stmt = $conn->prepare($query);
    $stmt->execute();
    $expenses = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Company-wide rent collected to date.
    $rentQuery = "SELECT SUM(amount) as total_rent FROM rent_records WHERE status = 'Paid'";
    $rentData = $conn->query($rentQuery)->fetch(PDO::FETCH_ASSOC);

    echo json_encode([
        "expenses" => $expenses,
        "total_rent" => $rentData['total_rent'] ?? 0
    ]);
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'expenses.submit');

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

    // The property must exist in the company register. expenses.owner_id stays
    // as a historical creator/owner reference for existing reports.
    $check = $conn->prepare("SELECT landlord_id FROM properties WHERE id = :pid LIMIT 1");
    $check->execute([':pid' => $propertyId]);
    $property = $check->fetch(PDO::FETCH_ASSOC);

    if (!$property) {
        security_json_response(404, ["message" => "Property not found."]);
    }

    $ownerId = (int) ($property['landlord_id'] ?? 0);
    if ($ownerId < 1) {
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

security_json_response(405, ["message" => "Method not allowed."]);
