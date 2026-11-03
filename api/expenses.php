<?php
require_once '../config/db.php';
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
    $data = json_decode(file_get_contents("php://input"));
    
    $query = "INSERT INTO expenses (owner_id, property_id, category, amount, expense_date, description) 
              VALUES (:owner_id, :property_id, :category, :amount, :date, :desc)";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':owner_id' => $user->user_id,
        ':property_id' => $data->property_id,
        ':category' => $data->category,
        ':amount' => $data->amount,
        ':date' => $data->expense_date,
        ':desc' => $data->description
    ]);
    
    echo json_encode(["message" => "Expense added successfully."]);
}
?>