<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    if ($user->role === 'landlord' || $user->role === 'agent') {
        $tickets = $conn->prepare("SELECT m.*, t.name as tenant_name, u.unit_number, c.name as contractor_name 
                                   FROM maintenance m 
                                   JOIN tenants t ON m.tenant_id = t.id 
                                   JOIN units u ON m.unit_id = u.id 
                                   LEFT JOIN contractors c ON m.contractor_id = c.id
                                   WHERE t.owner_id = :user_id ORDER BY m.id DESC");
        $tickets->execute([':user_id' => $user->user_id]);
        
        $contractors = $conn->prepare("SELECT * FROM contractors WHERE owner_id = :user_id");
        $contractors->execute([':user_id' => $user->user_id]);

        echo json_encode([
            "tickets" => $tickets->fetchAll(PDO::FETCH_ASSOC),
            "contractors" => $contractors->fetchAll(PDO::FETCH_ASSOC)
        ]);
    } else {
        $stmt = $conn->prepare("SELECT m.*, c.name as contractor_name FROM maintenance m LEFT JOIN contractors c ON m.contractor_id = c.id WHERE m.tenant_id = (SELECT id FROM tenants WHERE user_id = :user_id) ORDER BY m.id DESC");
        $stmt->execute([':user_id' => $user->user_id]);
        echo json_encode(["tickets" => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    }
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));

    // LANDLORD: Add a new contractor
    if (isset($data->action) && $data->action === 'add_contractor') {
        if ($user->role !== 'landlord' && $user->role !== 'agent') {
            http_response_code(403);
            echo json_encode(["message" => "Unauthorized."]);
            exit();
        }

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

    // TENANT: Log new issue
    if ($user->role === 'tenant') {
        $tQuery = $conn->prepare("SELECT id, unit_id FROM tenants WHERE user_id = :user_id LIMIT 1");
        $tQuery->execute([':user_id' => $user->user_id]);
        $tenant = $tQuery->fetch(PDO::FETCH_ASSOC);

        if (!$tenant) {
            security_json_response(404, ["message" => "Tenant record not found."]);
        }

        // A self-registered tenant has a profile but no unit until the landlord
        // links them; maintenance tickets require a unit (NOT NULL FK).
        if (empty($tenant['unit_id'])) {
            security_json_response(400, [
                "message" => "No unit has been assigned to you yet. Please contact your landlord."
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
    }

    // LANDLORD: Assign ticket OR Resolve ticket
    if ($user->role === 'landlord' || $user->role === 'agent') {
        if (empty($data->ticket_id)) {
            http_response_code(400);
            echo json_encode(["message" => "Ticket id is required."]);
            exit();
        }

        // Authorize: the ticket must belong to the caller's property.
        $check = $conn->prepare(
            "SELECT m.id
             FROM maintenance m
             JOIN tenants t ON m.tenant_id = t.id
             LEFT JOIN units u ON m.unit_id = u.id
             LEFT JOIN properties p ON u.property_id = p.id
             WHERE m.id = :id AND (t.owner_id = :uid_owner OR p.landlord_id = :uid_landlord OR p.agent_id = :uid_agent)
             LIMIT 1"
        );
        $check->execute([
            ':id' => $data->ticket_id,
            ':uid_owner' => $user->user_id,
            ':uid_landlord' => $user->user_id,
            ':uid_agent' => $user->user_id,
        ]);

        if (!$check->fetchColumn()) {
            http_response_code(404);
            echo json_encode(["message" => "Ticket not found."]);
            exit();
        }

        if (isset($data->status) && $data->status === 'Resolved') {
            $query = "UPDATE maintenance SET status = 'Resolved' WHERE id = :id";
            $stmt = $conn->prepare($query);
            $stmt->execute([':id' => $data->ticket_id]);

            audit_log($conn, (int) $user->user_id, 'maintenance.ticket_resolved', [
                'entity_type' => 'maintenance',
                'entity_id' => (int) $data->ticket_id,
            ]);

            echo json_encode(["message" => "Ticket marked as Resolved."]);
        } else {
            $severity = security_clean_text($data->severity ?? 'Routine', 20);
            $query = "UPDATE maintenance SET contractor_id = :cid, severity = :sev, status = 'In Progress' WHERE id = :id";
            $stmt = $conn->prepare($query);
            $stmt->execute([
                ':cid' => empty($data->contractor_id) ? null : (int) $data->contractor_id, 
                ':sev' => $severity, 
                ':id' => $data->ticket_id
            ]);

            audit_log($conn, (int) $user->user_id, 'maintenance.ticket_assigned', [
                'entity_type' => 'maintenance',
                'entity_id' => (int) $data->ticket_id,
                'meta' => ['contractor_id' => empty($data->contractor_id) ? null : (int) $data->contractor_id],
            ]);

            echo json_encode(["message" => "Ticket assigned."]);
        }
    }
}
?>