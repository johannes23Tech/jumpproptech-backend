<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];
$isStaff = permission_is_staff($actor);
$isTenant = ($user->role === 'tenant');

if (!$isStaff && !$isTenant) {
    security_json_response(403, ["message" => "Unauthorized access."]);
}

if ($method === 'GET') {
    if ($isStaff) {
        permission_require($actor, 'maintenance.view');

        // Single-company portfolio: authorised staff see every ticket.
        $tickets = $conn->query(
            "SELECT m.*, t.name as tenant_name, u.unit_number,
                    tech.full_name as technician_name
             FROM maintenance m
             JOIN tenants t ON m.tenant_id = t.id
             JOIN units u ON m.unit_id = u.id
             LEFT JOIN users tech ON m.technician_id = tech.id
             ORDER BY m.id DESC"
        );

        // Internal maintenance staff (eligible for ticket assignment).
        $staff = $conn->query(
            "SELECT u.id, u.full_name, u.staff_role
             FROM users u
             WHERE u.account_type = 'staff' AND u.is_active = 1
               AND u.staff_role IN ('maintenance_manager','maintenance_technician','administrator','super_administrator')
             ORDER BY u.full_name ASC"
        );

        echo json_encode([
            "tickets" => $tickets->fetchAll(PDO::FETCH_ASSOC),
            "staff" => $staff->fetchAll(PDO::FETCH_ASSOC)
        ]);
        exit();
    }

    // Tenant: only their own tickets.
    $stmt = $conn->prepare(
        "SELECT m.*, u.unit_number, tech.full_name as technician_name
         FROM maintenance m
         JOIN units u ON m.unit_id = u.id
         LEFT JOIN users tech ON m.technician_id = tech.id
         WHERE m.tenant_id = (SELECT id FROM tenants WHERE user_id = :user_id LIMIT 1)
         ORDER BY m.id DESC"
    );
    $stmt->execute([':user_id' => $user->user_id]);
    echo json_encode(["tickets" => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    // TENANT: Log a new issue against their own unit.
    if ($isTenant) {
        $tQuery = $conn->prepare("SELECT id, unit_id FROM tenants WHERE user_id = :user_id LIMIT 1");
        $tQuery->execute([':user_id' => $user->user_id]);
        $tenant = $tQuery->fetch(PDO::FETCH_ASSOC);

        if (!$tenant) {
            security_json_response(404, ["message" => "Tenant record not found."]);
        }

        if (empty($tenant['unit_id'])) {
            security_json_response(400, [
                "message" => "No unit has been assigned to you yet. Please contact JUMP staff."
            ]);
        }

        $description = security_clean_text($data->description ?? '', 2000);
        if ($description === '') {
            security_json_response(400, ["message" => "A description is required."]);
        }

        $photo = null;
        if (isset($data->photo) && $data->photo !== '') {
            $photo = security_clean_document($data->photo);
            if ($photo === null) {
                security_json_response(400, ["message" => "Photo must be an image or an https link."]);
            }
        }

        $query = "INSERT INTO maintenance (tenant_id, unit_id, category, description, priority, photo) VALUES (:tid, :uid, :cat, :desc, :prio, :photo)";
        $stmt = $conn->prepare($query);
        $stmt->execute([
            ':tid' => $tenant['id'], ':uid' => $tenant['unit_id'],
            ':cat' => security_clean_text($data->category ?? '', 50),
            ':desc' => $description,
            ':prio' => security_clean_text($data->priority ?? 'Routine', 20),
            ':photo' => $photo
        ]);

        audit_log($conn, (int) $user->user_id, 'maintenance.ticket_created', [
            'entity_type' => 'maintenance',
            'entity_id' => (int) $conn->lastInsertId(),
        ]);

        echo json_encode(["message" => "Ticket created."]);
        exit();
    }

    // STAFF: action-based work-order management.
    if (!$isStaff) {
        security_json_response(403, ["message" => "Unauthorized. Staff access required."]);
    }

    $ticketId = filter_var($data->ticket_id ?? 0, FILTER_VALIDATE_INT);
    if ($ticketId === false || $ticketId < 1) {
        security_json_response(400, ["message" => "A valid ticket id is required."]);
    }

    // The company-wide register is authoritative; no landlord scoping.
    $check = $conn->prepare("SELECT id, status, technician_id FROM maintenance WHERE id = :id LIMIT 1");
    $check->execute([':id' => $ticketId]);
    $ticket = $check->fetch(PDO::FETCH_ASSOC);

    if (!$ticket) {
        security_json_response(404, ["message" => "Ticket not found."]);
    }

    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : 'assign';

    // -------------------------------------------------------------------
    // Assign an internal technician (or clear assignment).
    // -------------------------------------------------------------------
    if ($action === 'assign_technician' || $action === 'assign') {
        permission_require($actor, 'maintenance.assign');

        $technicianId = empty($data->technician_id) ? null : (int) $data->technician_id;
        $severity = security_clean_text($data->severity ?? 'Routine', 20);

        if ($technicianId !== null) {
            $techCheck = $conn->prepare(
                "SELECT id FROM users WHERE id = :id AND account_type = 'staff' AND is_active = 1
                 AND staff_role IN ('maintenance_manager','maintenance_technician','administrator','super_administrator') LIMIT 1"
            );
            $techCheck->execute([':id' => $technicianId]);
            if (!$techCheck->fetchColumn()) {
                security_json_response(400, ["message" => "The technician must be an active internal maintenance staff member."]);
            }
        }

        $conn->prepare(
            "UPDATE maintenance SET technician_id = :tid, severity = :sev, status = 'In Progress' WHERE id = :id"
        )->execute([
            ':tid' => $technicianId,
            ':sev' => $severity,
            ':id' => $ticketId
        ]);

        audit_log($conn, (int) $user->user_id, 'maintenance.ticket_assigned', [
            'entity_type' => 'maintenance',
            'entity_id' => $ticketId,
            'meta' => ['technician_id' => $technicianId, 'severity' => $severity],
        ]);

        echo json_encode(["message" => "Ticket assigned to internal technician."]);
        exit();
    }

    // -------------------------------------------------------------------
    // Record work cost and/or completion notes.
    // -------------------------------------------------------------------
    if ($action === 'update_cost_notes') {
        permission_require($actor, 'maintenance.update');

        $actualCost = empty($data->actual_cost) ? null : filter_var($data->actual_cost, FILTER_VALIDATE_FLOAT);
        if ($actualCost !== null && ($actualCost === false || $actualCost < 0)) {
            security_json_response(400, ["message" => "Actual cost must be a non-negative number."]);
        }

        $notes = security_clean_text($data->completion_notes ?? '', 2000);

        $conn->prepare(
            "UPDATE maintenance SET actual_cost = :cost, completion_notes = :notes WHERE id = :id"
        )->execute([
            ':cost' => $actualCost,
            ':notes' => $notes !== '' ? $notes : null,
            ':id' => $ticketId
        ]);

        audit_log($conn, (int) $user->user_id, 'maintenance.ticket_cost_notes', [
            'entity_type' => 'maintenance',
            'entity_id' => $ticketId,
            'meta' => ['actual_cost' => $actualCost],
        ]);

        echo json_encode(["message" => "Work order cost and notes updated."]);
        exit();
    }

    // -------------------------------------------------------------------
    // Resolve a ticket (requires a technician and completion notes).
    // -------------------------------------------------------------------
    if ($action === 'resolve') {
        permission_require($actor, 'maintenance.update');

        if (empty($ticket['technician_id'])) {
            security_json_response(409, ["message" => "A technician must be assigned before the ticket can be resolved."]);
        }

        $notes = security_clean_text($data->completion_notes ?? '', 2000);
        if ($notes === '') {
            security_json_response(400, ["message" => "Completion notes are required to resolve the ticket."]);
        }

        $conn->prepare(
            "UPDATE maintenance SET status = 'Resolved', completion_notes = :notes, resolved_at = NOW() WHERE id = :id"
        )->execute([
            ':notes' => $notes,
            ':id' => $ticketId
        ]);

        audit_log($conn, (int) $user->user_id, 'maintenance.ticket_resolved', [
            'entity_type' => 'maintenance',
            'entity_id' => $ticketId,
            'meta' => ['technician_id' => (int) $ticket['technician_id']],
        ]);

        echo json_encode(["message" => "Ticket marked as Resolved."]);
        exit();
    }

    security_json_response(400, ["message" => "Unsupported maintenance action."]);
}

security_json_response(405, ["message" => "Method not allowed."]);
