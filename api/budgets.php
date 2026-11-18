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
    permission_require($actor, 'budgets.view');

    $stmt = $conn->query(
        "SELECT b.*, p.name as property_name
         FROM budgets b
         JOIN properties p ON b.property_id = p.id
         ORDER BY b.period_start DESC, b.id DESC"
    );
    $budgets = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Spend counts only approved, non-reversed expenses inside the period.
    $spend = $conn->prepare(
        "SELECT COALESCE(SUM(amount), 0) FROM expenses
         WHERE property_id = :property_id AND category = :category
           AND approval_status = 'approved' AND reversed_at IS NULL
           AND expense_date BETWEEN :period_start AND :period_end"
    );

    foreach ($budgets as &$budget) {
        $spend->execute([
            ':property_id' => (int) $budget['property_id'],
            ':category' => (string) $budget['category'],
            ':period_start' => (string) $budget['period_start'],
            ':period_end' => (string) $budget['period_end'],
        ]);
        $spent = (float) $spend->fetchColumn();
        $budget['spent'] = round($spent, 2);
        $budget['remaining'] = round((float) $budget['amount'] - $spent, 2);
    }
    unset($budget);

    echo json_encode($budgets);
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'budgets.manage');

    $data = json_decode(file_get_contents("php://input"));
    if (!is_object($data)) {
        security_json_response(400, ["message" => "Invalid request body."]);
    }

    // Support delete action
    if (isset($data->action) && $data->action === 'delete') {
        $id = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
        if ($id === false || $id < 1) {
            security_json_response(400, ["message" => "A valid budget id is required."]);
        }
        $conn->prepare("DELETE FROM budgets WHERE id = :id")->execute([':id' => $id]);
        audit_log($conn, (int) $user->user_id, 'budget.deleted', [
            'entity_type' => 'budget',
            'entity_id' => $id,
        ]);
        echo json_encode(["message" => "Budget deleted."]);
        exit();
    }

    $propertyId = filter_var($data->property_id ?? 0, FILTER_VALIDATE_INT);
    $category = security_clean_text($data->category ?? '', 50);
    $amount = filter_var($data->amount ?? null, FILTER_VALIDATE_FLOAT);
    $periodStart = trim((string) ($data->period_start ?? ''));
    $periodEnd = trim((string) ($data->period_end ?? ''));

    $start = DateTime::createFromFormat('Y-m-d', $periodStart);
    $end = DateTime::createFromFormat('Y-m-d', $periodEnd);

    if (!$propertyId || $propertyId < 1
        || $category === ''
        || $amount === false || $amount < 0
        || !$start || $start->format('Y-m-d') !== $periodStart
        || !$end || $end->format('Y-m-d') !== $periodEnd
        || $end < $start) {
        security_json_response(400, ["message" => "A valid property, category, amount and date range are required."]);
    }

    $check = $conn->prepare("SELECT id FROM properties WHERE id = :pid LIMIT 1");
    $check->execute([':pid' => $propertyId]);
    if (!$check->fetchColumn()) {
        security_json_response(404, ["message" => "Property not found."]);
    }

    $conn->prepare(
        "INSERT INTO budgets (property_id, category, amount, period_start, period_end, created_by)
         VALUES (:property_id, :category, :amount, :period_start, :period_end, :created_by)"
    )->execute([
        ':property_id' => $propertyId,
        ':category' => $category,
        ':amount' => $amount,
        ':period_start' => $periodStart,
        ':period_end' => $periodEnd,
        ':created_by' => (int) $user->user_id
    ]);

    audit_log($conn, (int) $user->user_id, 'budget.created', [
        'entity_type' => 'budget',
        'entity_id' => (int) $conn->lastInsertId(),
        'meta' => ['property_id' => $propertyId, 'amount' => $amount],
    ]);

    security_json_response(200, ["message" => "Budget saved."]);
}

security_json_response(405, ["message" => "Method not allowed."]);
