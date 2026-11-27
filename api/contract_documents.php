<?php
// api/contract_documents.php
//
// GET /api/contract_documents.php?id=N&type=generated|signed
//     -> { url, expires_at }   (permission: contracts.view)
//
// Documents are stored as Cloudinary URLs only. This deployment has no
// Cloudinary signing key configured, so no short-lived signed URL is claimed:
// the stored URL is returned and expires_at is null (no expiry to report).
// Never substitute a locally generated document for a management-supplied one.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/contracts.php';
require_once '../middleware/check_role.php';

// Defence in depth: never expose PDO or other exception details to the client.
set_exception_handler(static function (Throwable $e): void {
    error_log('Unhandled contract document API error: ' . $e->getMessage());
    security_json_response(500, ['message' => 'The request could not be completed.']);
});

$user = authenticate();
$actor = (array) $user;

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    security_json_response(405, ['message' => 'Method not allowed.']);
}

permission_require($actor, 'contracts.view');

$contractId = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);
if ($contractId === false || $contractId === null || $contractId < 1) {
    security_json_response(400, ['message' => 'A valid contract id is required.']);
}

$type = isset($_GET['type']) && is_string($_GET['type'])
    ? strtolower(trim($_GET['type'])) : 'generated';
if (!in_array($type, ['generated', 'signed'], true)) {
    security_json_response(400, ['message' => 'Type must be generated or signed.']);
}

$column = $type === 'signed' ? 'signed_document_url' : 'generated_document_url';
try {
    $stmt = $conn->prepare("SELECT $column FROM lease_contracts WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $contractId]);
    $url = $stmt->fetchColumn();
} catch (Throwable $e) {
    error_log('Contract document lookup failed: ' . $e->getMessage());
    security_json_response(500, ['message' => 'The document could not be loaded.']);
}

if ($url === false || !contract_valid_document_url($url)) {
    security_json_response(404, ['message' => 'Document not available for this contract.']);
}

// Without a configured Cloudinary signing key we return the stored URL and do
// not invent an expiry. expires_at = null means the URL has no server-set expiry.
security_json_response(200, [
    'url' => (string) $url,
    'expires_at' => null,
]);
