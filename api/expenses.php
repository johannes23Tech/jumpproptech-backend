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
    $query = "SELECT e.*, p.name as property_name,
                    s.name as supplier_name, s.trade as supplier_trade,
                    approver.full_name as approved_by_name,
                    reverser.full_name as reversed_by_name
              FROM expenses e
              JOIN properties p ON e.property_id = p.id
              LEFT JOIN suppliers s ON e.supplier_id = s.id
              LEFT JOIN users approver ON e.approved_by = approver.id
              LEFT JOIN users reverser ON e.reversed_by = reverser.id
              ORDER BY e.expense_date DESC";
    $stmt = $conn->prepare($query);
    $stmt->execute();
    $expenses = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Company-wide rent collected to date (Paid rent records).
    $rentQuery = "SELECT SUM(amount) as total_rent FROM rent_records WHERE status = 'Paid'";
    $rentData = $conn->query($rentQuery)->fetch(PDO::FETCH_ASSOC);

    echo json_encode([
        "expenses" => $expenses,
        "total_rent" => $rentData['total_rent'] ?? 0
    ]);
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    if (!is_object($data)) {
        security_json_response(400, ["message" => "Invalid request body."]);
    }

    // STAFF: Approve or reject a pending expense (one-manager approval).
    if (isset($data->action) && is_string($data->action) && in_array($data->action, ['approve', 'reject', 'reverse'], true)) {
        $expenseId = filter_var($data->expense_id ?? 0, FILTER_VALIDATE_INT);
        if ($expenseId === false || $expenseId < 1) {
            security_json_response(400, ["message" => "A valid expense id is required."]);
        }

        if ($data->action === 'reverse') {
            permission_require($actor, 'expenses.approve');

            $check = $conn->prepare("SELECT id, approval_status, reversed_at FROM expenses WHERE id = :id LIMIT 1");
            $check->execute([':id' => $expenseId]);
            $expense = $check->fetch(PDO::FETCH_ASSOC);

            if (!$expense) {
                security_json_response(404, ["message" => "Expense not found."]);
            }
            if ($expense['approval_status'] !== 'approved') {
                security_json_response(409, ["message" => "Only an approved expense can be reversed."]);
            }
            if (!empty($expense['reversed_at'])) {
                security_json_response(409, ["message" => "This expense has already been reversed."]);
            }

            $reason = security_clean_text($data->reason ?? '', 500);
            if (strlen($reason) < 3) {
                security_json_response(400, ["message" => "A reversal reason is required."]);
            }

            $conn->prepare(
                "UPDATE expenses SET reversed_by = :by, reversed_at = NOW(), reversal_reason = :reason
                 WHERE id = :id AND reversed_at IS NULL"
            )->execute([
                ':by' => (int) $user->user_id,
                ':reason' => $reason,
                ':id' => $expenseId,
            ]);

            audit_log($conn, (int) $user->user_id, 'expense.reversed', [
                'entity_type' => 'expense',
                'entity_id' => $expenseId,
                'meta' => ['reason' => $reason],
            ]);

            echo json_encode(["message" => "Expense reversed."]);
            exit();
        }

        $permission = $data->action === 'approve' ? 'expenses.approve' : 'expenses.submit';
        permission_require($actor, $permission);

        $check = $conn->prepare("SELECT id, approval_status, reversed_at FROM expenses WHERE id = :id LIMIT 1");
        $check->execute([':id' => $expenseId]);
        $expense = $check->fetch(PDO::FETCH_ASSOC);

        if (!$expense) {
            security_json_response(404, ["message" => "Expense not found."]);
        }
        if (!empty($expense['reversed_at'])) {
            security_json_response(409, ["message" => "A reversed expense cannot be changed."]);
        }

        if ($expense['approval_status'] !== 'pending') {
            security_json_response(409, ["message" => "This expense has already been {$expense['approval_status']}."]);
        }

        $reason = $data->action === 'reject' ? security_clean_text($data->reason ?? '', 500) : null;
        if ($data->action === 'reject' && (strlen($reason) < 3)) {
            security_json_response(400, ["message" => "A rejection reason is required."]);
        }

        $conn->prepare(
            "UPDATE expenses SET approval_status = :status, approved_by = :by, approved_at = NOW()
             WHERE id = :id AND approval_status = 'pending'"
        )->execute([
            ':status' => $data->action === 'approve' ? 'approved' : 'rejected',
            ':by' => (int) $user->user_id,
            ':id' => $expenseId
        ]);

        audit_log($conn, (int) $user->user_id, 'expense.' . $data->action, [
            'entity_type' => 'expense',
            'entity_id' => $expenseId,
            'meta' => ['reason' => $reason],
        ]);

        echo json_encode(["message" => "Expense " . $data->action . "d."]);
        exit();
    }

    // STAFF: Submit a new expense (starts as pending, needs one-manager approval).
    permission_require($actor, 'expenses.submit');

    $propertyId = filter_var($data->property_id ?? 0, FILTER_VALIDATE_INT);
    $supplierId = empty($data->supplier_id) ? null : filter_var($data->supplier_id, FILTER_VALIDATE_INT);
    $amount = filter_var($data->amount ?? null, FILTER_VALIDATE_FLOAT);
    $category = security_clean_text($data->category ?? '', 50);
    $description = security_clean_text($data->description ?? '', 2000);
    $expenseDate = trim((string) ($data->expense_date ?? ''));
    $attachmentUrl = null;
    if (isset($data->attachment_url) && $data->attachment_url !== '') {
        $attachmentUrl = security_clean_text($data->attachment_url, 500);
        if (strlen($attachmentUrl) > 0 && strpos($attachmentUrl, 'https://res.cloudinary.com/') !== 0) {
            security_json_response(400, ["message" => "The attachment must be an uploaded Cloudinary file."]);
        }
    }

    $date = DateTime::createFromFormat('Y-m-d', $expenseDate);

    if (!$propertyId || $propertyId < 1
        || $category === ''
        || $amount === false || $amount < 0
        || !$date || $date->format('Y-m-d') !== $expenseDate) {
        security_json_response(400, ["message" => "A valid property, category, amount and date are required."]);
    }

    if ($supplierId !== null && ($supplierId < 1)) {
        security_json_response(400, ["message" => "A valid supplier is required."]);
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

    // Supplier must exist if provided.
    if ($supplierId !== null) {
        $supplierCheck = $conn->prepare("SELECT id FROM suppliers WHERE id = :sid AND is_active = 1 LIMIT 1");
        $supplierCheck->execute([':sid' => $supplierId]);
        if (!$supplierCheck->fetchColumn()) {
            security_json_response(404, ["message" => "Supplier not found or inactive."]);
        }
    }

    $query = "INSERT INTO expenses (owner_id, property_id, supplier_id, category, amount, expense_date, description, attachment_url, approval_status)
              VALUES (:owner_id, :property_id, :supplier_id, :category, :amount, :date, :desc, :attachment, 'pending')";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':owner_id' => $ownerId,
        ':property_id' => $propertyId,
        ':supplier_id' => $supplierId,
        ':category' => $category,
        ':amount' => $amount,
        ':date' => $expenseDate,
        ':desc' => $description,
        ':attachment' => $attachmentUrl
    ]);

    audit_log($conn, (int) $user->user_id, 'expense.created', [
        'entity_type' => 'expense',
        'entity_id' => (int) $conn->lastInsertId(),
        'meta' => ['property_id' => $propertyId, 'amount' => $amount, 'supplier_id' => $supplierId],
    ]);

    security_json_response(200, ["message" => "Expense submitted for approval."]);
}

security_json_response(405, ["message" => "Method not allowed."]);
