<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // If Landlord hits /messages without a tenant ID, show their Inbox (list of tenants)
    if (($user->role === 'landlord' || $user->role === 'agent') && !isset($_GET['tenant_id'])) {
        $stmt = $conn->prepare("SELECT t.id, t.name, u.unit_number 
                                FROM tenants t 
                                JOIN units u ON t.unit_id = u.id 
                                WHERE t.owner_id = :uid ORDER BY t.name ASC");
        $stmt->execute([':uid' => $user->user_id]);
        echo json_encode(["inbox" => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
        exit();
    }

    $tenant_id = 0;
    $other_user_id = 0;
    $chat_title = "";

    if ($user->role === 'tenant') {
        $q = $conn->prepare("SELECT t.id, t.name as tenant_name, u.full_name as landlord_name, t.owner_id 
                             FROM tenants t JOIN users u ON t.owner_id = u.id 
                             WHERE t.user_id = :uid LIMIT 1");
        $q->execute([':uid' => $user->user_id]);
        $data = $q->fetch(PDO::FETCH_ASSOC);
        
        if ($data) {
            $tenant_id = $data['id'];
            $other_user_id = $data['owner_id'];
            $chat_title = "Property Manager";
        }
    } else {
        $tenant_id = $_GET['tenant_id'] ?? 0;
        $q = $conn->prepare("SELECT t.user_id, t.name as tenant_name 
                             FROM tenants t 
                             WHERE t.id = :tid AND t.owner_id = :uid LIMIT 1");
        $q->execute([':tid' => $tenant_id, ':uid' => $user->user_id]);
        $data = $q->fetch(PDO::FETCH_ASSOC);
        
        if ($data) {
            $other_user_id = $data['user_id'];
            $chat_title = $data['tenant_name'];
        }
    }

    if (!$tenant_id) {
        echo json_encode(["messages" => [], "my_id" => $user->user_id, "tenant_id" => 0, "other_id" => 0, "chat_title" => "No Chat Found"]);
        exit();
    }

    $query = "SELECT * FROM messages 
              WHERE tenant_id = :tid 
              AND (sender_id = :uid OR receiver_id = :uid)
              ORDER BY created_at ASC";
    $stmt = $conn->prepare($query);
    $stmt->execute([':tid' => $tenant_id, ':uid' => $user->user_id]);
    
    echo json_encode([
        "messages" => $stmt->fetchAll(PDO::FETCH_ASSOC),
        "my_id" => $user->user_id,
        "tenant_id" => $tenant_id,
        "other_id" => $other_user_id,
        "chat_title" => $chat_title
    ]);
    exit();
}

if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));
    
    $query = "INSERT INTO messages (sender_id, receiver_id, tenant_id, message) VALUES (:sender, :receiver, :tid, :msg)";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':sender' => $user->user_id,
        ':receiver' => $data->receiver_id,
        ':tid' => $data->tenant_id,
        ':msg' => $data->message
    ]);
    echo json_encode(["message" => "Sent"]);
}
?>