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
            "SELECT m.*, t.name as tenant_name, u.unit_number, c.name as contractor_name 
             FROM maintenance m 
             JOIN tenants t ON m.tenant_id = t.id 
             JOIN units u ON m.unit_id = u.id 
             LEFT JOIN contractors c ON m.contractor_id = c.id
             ORDER BY m.id DESC"
        );

        $contractors = $conn->query("SELECT * FROM contractors ORDER BY name ASC");

        echo json_encode([
            "tickets" => $tickets->fetchAll(PDO::FETCH_ASSOC),
            "contractors" => $contractors->fetchAll(PDO::FETCH_ASSOC)
        ]);
        exit();
    }

    // Tenant: only their own tickets.
    $stmt = $conn->prepare(
        "SELECT m.*, c.name as contractor_name 
         FROM maintenance m 
         LEFT JOIN contractors c ON m.contractor_id = c.id 
         WHERE m.tenant_id = (SELECT id FROM tenants WHERE user_id = :user_id LIMIT 1) 
         ORDER BY m.id DESC"
    );
    $stmt->execute([':user_id' => $user->user_id]);
    echo json_encode(["tickets" => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    // STAFF: Add a new contractor / supplier.
    if (isset($data->action) && $data->action === 'add_contractor') {
        permission_require($actor, 'maintenance.assign');

        $query = "INSERT INTO contractors (name, trade, phone, owner_id) VALUES (:name, :trade, :phone, :owner_id)";
        $stmt = $conn->prepare($query);
        $stmt->execute([
            ':name' => security_clean_text($data->name ?? '', 100),
            ':trade' => security_clean_text($data->trade ?? '', 100),
            ':phone' => security_clean_text($data->phone ?? '', 20),
            ':owner_id' => $user->user_id
        ]);

        audit_log($conn, (int) $user->user_id, 'contractor.created', [
            'entity_type' => 'contractor',
            'entity_id' => (int) $conn->lastInsertId(),
        ]);

        echo json_encode(["message" => "Contractor added successfully."]);
        exit();
    }

    // TENANT: Log a new issue against their own unit.
    if ($isTenant) {
        $tQuery = $conn->prepare("SELECT id, unit_id FROM tenants WHERE user_id = :user_id LIMIT 1");
        $tQuery->execute([':user_id' => $user->user_id]);
        $tenant = $tQuery->fetch(PDO::FETCH_ASSOC);

        if (!$tenant) {
            security_json_response(404, ["message" => "Tenant record not found."]);
        }

        // A self-registered tenant has a profile but no unit until staff link
        // them; maintenance tickets require a unit (NOT NULL FK).
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

    // STAFF: Assign or resolve an existing ticket.
    if (empty($data->ticket_id)) {
        security_json_response(400, ["message" => "Ticket id is required."]);
    }

    $ticketId = filter_var($data->ticket_id, FILTER_VALIDATE_INT);
    if ($ticketId === false || $ticketId < 1) {
        security_json_response(400, ["message" => "A valid ticket id is required."]);
    }

    // The company-wide register is authoritative; no landlord scoping.
    $check = $conn->prepare("SELECT id FROM maintenance WHERE id = :id LIMIT 1");
    $check->execute([':id' => $ticketId]);

    if (!$check->fetchColumn()) {
        security_json_response(404, ["message" => "Ticket not found."]);
    }

    if (isset($data->status) && $data->status === 'Resolved') {
        permission_require($actor, 'maintenance.update');

        $query = "UPDATE maintenance SET status = 'Resolved' WHERE id = :id";
        $stmt = $conn->prepare($query);
        $stmt->execute([':id' => $ticketId]);

        audit_log($conn, (int) $user->user_id, 'maintenance.ticket_resolved', [
            'entity_type' => 'maintenance',
            'entity_id' => $ticketId,
        ]);

        echo json_encode(["message" => "Ticket marked as Resolved."]);
        exit();
    }

    permission_require($actor, 'maintenance.assign');

    $severity = security_clean_text($data->severity ?? 'Routine', 20);
    $contractorId = empty($data->contractor_id) ? null : (int) $data->contractor_id;

    $query = "UPDATE maintenance SET contractor_id = :cid, severity = :sev, status = 'In Progress' WHERE id = :id";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':cid' => $contractorId,
        ':sev' => $severity,
        ':id' => $ticketId
    ]);

    audit_log($conn, (int) $user->user_id, 'maintenance.ticket_assigned', [
        'entity_type' => 'maintenance',
        'entity_id' => $ticketId,
        'meta' => ['contractor_id' => $contractorId],
    ]);

    echo json_encode(["message" => "Ticket assigned."]);
    exit();
}

security_json_response(405, ["message" => "Method not allowed."]);
