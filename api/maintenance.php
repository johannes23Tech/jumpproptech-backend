<?php
require_once '../config/db.php';
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

    // TENANT: Log new issue
    if ($user->role === 'tenant') {
        $tQuery = $conn->prepare("SELECT id, unit_id FROM tenants WHERE user_id = :user_id LIMIT 1");
        $tQuery->execute([':user_id' => $user->user_id]);
        $tenant = $tQuery->fetch(PDO::FETCH_ASSOC);

        $query = "INSERT INTO maintenance (tenant_id, unit_id, category, description, priority, photo) VALUES (:tid, :uid, :cat, :desc, :prio, :photo)";
        $stmt = $conn->prepare($query);
        $stmt->execute([
            ':tid' => $tenant['id'], ':uid' => $tenant['unit_id'],
            ':cat' => $data->category, ':desc' => $data->description,
            ':prio' => $data->priority, ':photo' => $data->photo
        ]);
        echo json_encode(["message" => "Ticket created."]);
    }

    // LANDLORD: Assign ticket OR Resolve ticket
    if ($user->role === 'landlord' || $user->role === 'agent') {
        
        // If the request is to resolve the ticket
        if (isset($data->status) && $data->status === 'Resolved') {
            $query = "UPDATE maintenance SET status = 'Resolved' WHERE id = :id";
            $stmt = $conn->prepare($query);
            $stmt->execute([':id' => $data->ticket_id]);
            echo json_encode(["message" => "Ticket marked as Resolved."]);
        } 
        // Otherwise, it's assigning a contractor or changing severity
        else {
            $query = "UPDATE maintenance SET contractor_id = :cid, severity = :sev, status = 'In Progress' WHERE id = :id";
            $stmt = $conn->prepare($query);
            $stmt->execute([
                ':cid' => empty($data->contractor_id) ? null : $data->contractor_id, 
                ':sev' => $data->severity ?? 'Routine', 
                ':id' => $data->ticket_id
            ]);
            echo json_encode(["message" => "Ticket assigned."]);
        }
    }
}
?>