<?php
// api/contract_templates.php
//
// Management-supplied lease contract templates.
//
// GET  /api/contract_templates.php -> list (permission: contracts.view)
// POST /api/contract_templates.php { action: create|update, ... }
//      (permission: templates.manage; Administrator / Super Administrator only)
//
// POLICY: all legal wording lives in this table. The platform never authors or
// invents clauses. Setting approval_status to 'approved' means management has
// supplied the wording and a qualified South African legal professional has
// reviewed it; only management may change the content of an approved row.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/contracts.php';
require_once '../middleware/check_role.php';

// Defence in depth: never expose PDO or other exception details to the client.
set_exception_handler(static function (Throwable $e): void {
    error_log('Unhandled template API error: ' . $e->getMessage());
    security_json_response(500, ['message' => 'The request could not be completed.']);
});

$user = authenticate();
$actor = (array) $user;

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    permission_require($actor, 'contracts.view');

    try {
        $stmt = $conn->prepare(
            'SELECT id, name, template_type, content, approval_status, is_default, created_at, updated_at
             FROM lease_contract_templates
             ORDER BY is_default DESC, id ASC'
        );
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        error_log('Contract template list failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'Templates could not be loaded.']);
    }

    echo json_encode(array_map(static function (array $row): array {
        return [
            'id' => (int) $row['id'],
            'name' => (string) $row['name'],
            'template_type' => (string) $row['template_type'],
            'content' => (string) $row['content'],
            'approval_status' => (string) $row['approval_status'],
            'is_default' => (bool) $row['is_default'],
            'created_at' => $row['created_at'],
            'updated_at' => $row['updated_at'],
        ];
    }, $rows));
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    security_json_response(405, ['message' => 'Method not allowed.']);
}

permission_require($actor, 'templates.manage');

$role = permission_role_for_user($actor);
$isManagement = in_array($role, ['super_administrator', 'administrator'], true);
if (!$isManagement) {
    security_json_response(403, ['message' => 'Only management may manage contract templates.']);
}

$data = json_decode(file_get_contents('php://input'));
if (!is_object($data)) {
    security_json_response(400, ['message' => 'Invalid request body.']);
}

$action = isset($data->action) && is_string($data->action)
    ? strtolower(trim($data->action)) : '';
if (!in_array($action, ['create', 'update'], true)) {
    security_json_response(400, ['message' => 'Action must be create or update.']);
}

$actorId = (int) ($user->user_id ?? 0);

if ($action === 'create') {
    $name = security_clean_text($data->name ?? '', 150);
    $type = strtolower(trim((string) ($data->template_type ?? '')));
    $content = is_string($data->content ?? null) ? $data->content : '';
    $approval = strtolower(trim((string) ($data->approval_status ?? 'pending')));
    $isDefault = filter_var($data->is_default ?? 0, FILTER_VALIDATE_INT);

    if ($name === '' || !in_array($type, ['new_lease', 'renewal'], true)) {
        security_json_response(400, ['message' => 'A name and valid template type are required.']);
    }
    if (trim($content) === '' || strlen($content) > 1000000) {
        security_json_response(400, ['message' => 'Template content is required and must be under 1 MB.']);
    }
    if (!in_array($approval, ['approved', 'pending'], true)) {
        security_json_response(400, ['message' => 'Invalid approval status.']);
    }
    if ($isDefault === false || $isDefault === null) {
        $isDefault = 0;
    }
    $isDefault = $isDefault === 1 ? 1 : 0;

    try {
        $stmt = $conn->prepare(
            'INSERT INTO lease_contract_templates
                (name, template_type, content, approval_status, is_default, created_by)
             VALUES (:name, :template_type, :content, :approval_status, :is_default, :created_by)'
        );
        $stmt->execute([
            ':name' => $name,
            ':template_type' => $type,
            ':content' => $content,
            ':approval_status' => $approval,
            ':is_default' => $isDefault,
            ':created_by' => $actorId > 0 ? $actorId : null,
        ]);
        $templateId = (int) $conn->lastInsertId();
    } catch (Throwable $e) {
        error_log('Contract template creation failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The template could not be created.']);
    }

    audit_log($conn, $actorId, 'template.create', [
        'entity_type' => 'contract_template',
        'entity_id' => $templateId,
        'meta' => ['template_type' => $type, 'approval_status' => $approval],
    ]);

    security_json_response(201, ['message' => 'Template created.', 'id' => $templateId]);
}

// ---------------------------------------------------------------------------
// update
// ---------------------------------------------------------------------------
$templateId = filter_var($data->id ?? null, FILTER_VALIDATE_INT);
if ($templateId === false || $templateId === null || $templateId < 1) {
    security_json_response(400, ['message' => 'A valid template id is required.']);
}

try {
    $stmt = $conn->prepare(
        'SELECT id, approval_status FROM lease_contract_templates WHERE id = :id LIMIT 1'
    );
    $stmt->execute([':id' => $templateId]);
    $template = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    error_log('Contract template lookup failed: ' . $e->getMessage());
    security_json_response(500, ['message' => 'The template could not be loaded.']);
}
if (!$template) {
    security_json_response(404, ['message' => 'Template not found.']);
}

// Defence in depth: even if templates.manage were granted more widely, an
// approved template's wording can only be changed by management.
if (($template['approval_status'] ?? 'pending') === 'approved'
    && !$isManagement
    && property_exists($data, 'content')) {
    security_json_response(403, ['message' => 'Approved legal wording can only be changed by management.']);
}

$fields = [];
$params = [':id' => $templateId];

if (property_exists($data, 'name')) {
    $name = security_clean_text($data->name, 150);
    if ($name === '') {
        security_json_response(400, ['message' => 'Template name cannot be empty.']);
    }
    $fields[] = 'name = :name';
    $params[':name'] = $name;
}
if (property_exists($data, 'template_type')) {
    $type = strtolower(trim((string) ($data->template_type ?? '')));
    if (!in_array($type, ['new_lease', 'renewal'], true)) {
        security_json_response(400, ['message' => 'Invalid template type.']);
    }
    $fields[] = 'template_type = :template_type';
    $params[':template_type'] = $type;
}
if (property_exists($data, 'content')) {
    $content = is_string($data->content) ? $data->content : '';
    if (trim($content) === '' || strlen($content) > 1000000) {
        security_json_response(400, ['message' => 'Template content is required and must be under 1 MB.']);
    }
    $fields[] = 'content = :content';
    $params[':content'] = $content;
}
if (property_exists($data, 'approval_status')) {
    $approval = strtolower(trim((string) ($data->approval_status ?? '')));
    if (!in_array($approval, ['approved', 'pending'], true)) {
        security_json_response(400, ['message' => 'Invalid approval status.']);
    }
    $fields[] = 'approval_status = :approval_status';
    $params[':approval_status'] = $approval;
}
if (property_exists($data, 'is_default')) {
    $isDefault = filter_var($data->is_default, FILTER_VALIDATE_INT);
    $fields[] = 'is_default = :is_default';
    $params[':is_default'] = ($isDefault !== false && $isDefault !== null && $isDefault === 1) ? 1 : 0;
}

if ($fields === []) {
    security_json_response(400, ['message' => 'Nothing to update.']);
}

try {
    $conn->prepare('UPDATE lease_contract_templates SET ' . implode(', ', $fields) . ' WHERE id = :id')
        ->execute($params);
} catch (Throwable $e) {
    error_log('Contract template update failed: ' . $e->getMessage());
    security_json_response(500, ['message' => 'The template could not be updated.']);
}

audit_log($conn, $actorId, 'template.update', [
    'entity_type' => 'contract_template',
    'entity_id' => $templateId,
    'meta' => ['fields' => array_map(static function (string $field): string {
        return strtok($field, ' ');
    }, $fields)],
]);

security_json_response(200, ['message' => 'Template updated.']);
