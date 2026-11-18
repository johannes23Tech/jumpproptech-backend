<?php
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/permissions.php';
require_once '../../middleware/check_role.php';

$user = authenticate();

// DORMANT: the SaaS subscription gate is retired. This endpoint is kept for
// historical records only and is restricted to system administrators.
permission_require((array) $user, 'settings.manage');

$data = json_decode(file_get_contents("php://input"));

if (!is_object($data)) {
    security_json_response(400, ["message" => "Invalid request body."]);
}

// Only these subscription states are meaningful. Anything else (including
// values that would be stored as an arbitrary string) is rejected.
$allowedStatuses = ['active', 'expired', 'suspended', 'past_due'];
$status = isset($data->status) && is_string($data->status)
    ? strtolower(trim($data->status))
    : '';
$landlordId = filter_var($data->landlord_id ?? null, FILTER_VALIDATE_INT);

if ($landlordId === false || $landlordId < 1 || !in_array($status, $allowedStatuses, true)) {
    security_json_response(400, [
        "message" => "A valid landlord id and status (" . implode(', ', $allowedStatuses) . ") are required."
    ]);
}

// Confirm the target really is a landlord before changing anything.
$check = $conn->prepare("SELECT id FROM users WHERE id = :id AND role = 'landlord' LIMIT 1");
$check->execute([':id' => $landlordId]);

if (!$check->fetchColumn()) {
    security_json_response(404, ["message" => "Landlord not found."]);
}

$stmt = $conn->prepare("UPDATE users SET subscription_status = :status WHERE id = :id AND role = 'landlord'");
$stmt->execute([
    ':status' => $status,
    ':id' => $landlordId,
]);

audit_log($conn, (int) $user->user_id, 'admin.subscription.updated', [
    'actor_email' => $user->email ?? null,
    'entity_type' => 'user',
    'entity_id' => (int) $landlordId,
    'meta' => ['status' => $status],
]);

security_json_response(200, ["message" => "Subscription updated.", "status" => $status]);
