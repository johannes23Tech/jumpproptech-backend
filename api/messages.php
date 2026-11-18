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
    // Staff without a tenant id get the company-wide tenant inbox.
    if ($isStaff && !isset($_GET['tenant_id'])) {
        permission_require($actor, 'messages.view');

        $stmt = $conn->query(
            "SELECT t.id, t.name, u.unit_number 
             FROM tenants t 
             JOIN units u ON t.unit_id = u.id 
             ORDER BY t.name ASC"
        );
        echo json_encode(["inbox" => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
        exit();
    }

    $tenant_id = 0;
    $other_user_id = 0;
    $chat_title = "";

    if ($isTenant) {
        $q = $conn->prepare(
            "SELECT t.id, t.name as tenant_name, u.full_name as landlord_name, t.owner_id 
             FROM tenants t 
             JOIN users u ON t.owner_id = u.id 
             WHERE t.user_id = :uid LIMIT 1"
        );
        $q->execute([':uid' => $user->user_id]);
        $data = $q->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            $tenant_id = (int) $data['id'];
            $other_user_id = (int) $data['owner_id'];
            $chat_title = "JUMP Support";
        }
    } else {
        permission_require($actor, 'messages.view');

        $tenant_id = filter_var($_GET['tenant_id'] ?? 0, FILTER_VALIDATE_INT) ?: 0;
        $q = $conn->prepare(
            "SELECT t.user_id, t.name as tenant_name 
             FROM tenants t 
             WHERE t.id = :tid LIMIT 1"
        );
        $q->execute([':tid' => $tenant_id]);
        $data = $q->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            $other_user_id = (int) $data['user_id'];
            $chat_title = (string) $data['tenant_name'];
        }
    }

    if (!$tenant_id) {
        echo json_encode(["messages" => [], "my_id" => $user->user_id, "tenant_id" => 0, "other_id" => 0, "chat_title" => "No Chat Found"]);
        exit();
    }

    // A thread is only visible to its two participants.
    $query = "SELECT * FROM messages 
              WHERE tenant_id = :tid 
              AND (sender_id = :uid_sender OR receiver_id = :uid_receiver)
              ORDER BY created_at ASC";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':tid' => $tenant_id,
        ':uid_sender' => $user->user_id,
        ':uid_receiver' => $user->user_id,
    ]);

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

    if (empty($data->tenant_id) || empty($data->receiver_id) || empty($data->message)) {
        security_json_response(400, ["message" => "Tenant, receiver and message are required."]);
    }

    $dataTenantId = (int) $data->tenant_id;
    $dataReceiverId = (int) $data->receiver_id;

    // Authorize the sender, the thread and the receiver together.
    if ($isTenant) {
        $tStmt = $conn->prepare("SELECT id, owner_id FROM tenants WHERE user_id = :uid LIMIT 1");
        $tStmt->execute([':uid' => $user->user_id]);
        $tenant = $tStmt->fetch(PDO::FETCH_ASSOC);

        if (!$tenant
            || $dataTenantId !== (int) $tenant['id']
            || $dataReceiverId !== (int) $tenant['owner_id']) {
            security_json_response(403, ["message" => "Unauthorized."]);
        }
    } else {
        permission_require($actor, 'messages.send');

        // Company-wide staff may message any tenant, but the receiver must be
        // that tenant's linked user account.
        $tStmt = $conn->prepare(
            "SELECT t.id, t.user_id
             FROM tenants t
             WHERE t.id = :tid
             LIMIT 1"
        );
        $tStmt->execute([':tid' => $dataTenantId]);
        $tenant = $tStmt->fetch(PDO::FETCH_ASSOC);

        if (!$tenant || $dataReceiverId !== (int) $tenant['user_id']) {
            security_json_response(403, ["message" => "Unauthorized."]);
        }
    }

    // Strip tags/control characters so message bodies cannot store markup.
    $message = security_clean_text($data->message, 5000);
    if ($message === '') {
        security_json_response(400, ["message" => "Message is required."]);
    }

    $query = "INSERT INTO messages (sender_id, receiver_id, tenant_id, message) VALUES (:sender, :receiver, :tid, :msg)";
    $stmt = $conn->prepare($query);
    $stmt->execute([
        ':sender' => $user->user_id,
        ':receiver' => $dataReceiverId,
        ':tid' => $dataTenantId,
        ':msg' => $message
    ]);

    audit_log($conn, (int) $user->user_id, 'message.sent', [
        'entity_type' => 'tenant',
        'entity_id' => $dataTenantId,
    ]);

    echo json_encode(["message" => "Sent"]);
    exit();
}

security_json_response(405, ["message" => "Method not allowed."]);
