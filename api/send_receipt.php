<?php
require_once '../config/db.php';
require_once '../config/mailer.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$data = json_decode(file_get_contents("php://input"));

if (!is_object($data)) {
    security_json_response(400, ["message" => "Invalid request body."]);
}

$rentId = isset($data->rent_id) ? filter_var($data->rent_id, FILTER_VALIDATE_INT) : false;
$receiptNumber = isset($data->receipt_number) ? trim((string) $data->receipt_number) : '';

if ((!$rentId || $rentId < 1) && $receiptNumber === '') {
    security_json_response(400, ["message" => "A rent record id or receipt number is required."]);
}

// Resolve the record from the database. The recipient email is never taken
// from the request: it is the tenant's registered address.
$query = "SELECT r.id, r.receipt_number, r.status, r.amount, r.paid_date,
                 t.user_id AS tenant_user_id,
                 t.owner_id AS tenant_owner_id,
                 tu.email AS tenant_email,
                 p.landlord_id AS property_landlord_id,
                 p.agent_id AS property_agent_id
          FROM rent_records r
          JOIN tenants t ON r.tenant_id = t.id
          LEFT JOIN units un ON r.unit_id = un.id
          LEFT JOIN properties p ON un.property_id = p.id
          LEFT JOIN users tu ON t.user_id = tu.id
          WHERE ";

$params = [];
if ($rentId) {
    $query .= "r.id = :rent_id";
    $params[':rent_id'] = $rentId;
} else {
    $query .= "r.receipt_number = :receipt_number";
    $params[':receipt_number'] = $receiptNumber;
}
$query .= " LIMIT 1";

$stmt = $conn->prepare($query);
$stmt->execute($params);
$record = $stmt->fetch(PDO::FETCH_ASSOC);

// Authorization: only the tenant, the property owner/agent, or a superadmin.
$allowed = false;
if ($record) {
    if ($user->role === 'superadmin') {
        $allowed = true;
    } elseif ($user->role === 'tenant') {
        $allowed = (int) $record['tenant_user_id'] === (int) $user->user_id;
    } elseif (in_array($user->role, ['landlord', 'agent'], true)) {
        $allowed = (int) $record['tenant_owner_id'] === (int) $user->user_id
            || (int) $record['property_landlord_id'] === (int) $user->user_id
            || (int) $record['property_agent_id'] === (int) $user->user_id;
    }
}

if (!$record || !$allowed) {
    security_json_response(404, ["message" => "Receipt not found."]);
}

if ($record['status'] !== 'Paid' || empty($record['receipt_number'])) {
    security_json_response(400, ["message" => "A receipt is only available once payment has been recorded."]);
}

if (empty($record['tenant_email']) || !security_is_email($record['tenant_email'])) {
    security_json_response(422, ["message" => "The tenant has no valid email address on file."]);
}

// Cap outbound receipt emails per user to prevent mail abuse.
$retryAfter = security_rate_limit_retry($conn, 'send_receipt', (string) $user->user_id);
if ($retryAfter > 0) {
    security_json_response(
        429,
        ["message" => "Too many receipt emails. Please try again later."],
        ["Retry-After" => (string) $retryAfter]
    );
}

$safeReceipt = htmlspecialchars($record['receipt_number'], ENT_QUOTES, 'UTF-8');
$safeAmount = htmlspecialchars(number_format((float) $record['amount'], 2), ENT_QUOTES, 'UTF-8');
$safeDate = htmlspecialchars((string) $record['paid_date'], ENT_QUOTES, 'UTF-8');
$subject = 'Payment Receipt - ' . str_replace(["\r", "\n"], '', $record['receipt_number']);

$emailBody = "
    <div style='font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #E5DDCD; border-radius: 8px;'>
        <h2 style='color: #C5A059;'>Jump PropTech Payment Receipt</h2>
        <p>Thank you for your payment. Your receipt details are below:</p>
        <div style='background: #FAF7F2; padding: 20px; border-radius: 8px; margin: 20px 0;'>
            <p style='margin: 5px 0;'><strong>Receipt Number:</strong> {$safeReceipt}</p>
            <p style='margin: 5px 0;'><strong>Amount:</strong> {$safeAmount}</p>
            <p style='margin: 5px 0;'><strong>Paid On:</strong> {$safeDate}</p>
            <p style='margin: 5px 0;'><strong>Status:</strong> <span style='color: #2E7D32; font-weight: bold;'>PAID</span></p>
        </div>
        <p>You can log in to your tenant portal to download the official PDF copy of this receipt.</p>
        <br>
        <p style='font-size: 12px; color: #888; text-align: center;'>Smarter Property Management. Stronger Communities.</p>
    </div>
";

$emailSent = sendEmail($record['tenant_email'], $subject, $emailBody);

// Count this send whether it succeeded or not.
security_rate_limit_hit($conn, 'send_receipt', (string) $user->user_id, 10, 900, 900);

if ($emailSent) {
    audit_log($conn, (int) $user->user_id, 'receipt.emailed', [
        'entity_type' => 'rent_record',
        'entity_id' => (int) $record['id'],
        'meta' => ['receipt_number' => $record['receipt_number']],
    ]);
    security_json_response(200, ["message" => "Receipt emailed successfully!"]);
}

audit_log($conn, (int) $user->user_id, 'receipt.email_failed', [
    'entity_type' => 'rent_record',
    'entity_id' => (int) $record['id'],
    'outcome' => 'failure',
]);

error_log('Receipt email could not be sent for rent record ' . $record['id']);
security_json_response(500, ["message" => "Failed to send email."]);
