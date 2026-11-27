<?php
// api/contracts.php
//
// Staff-facing lease contract register and wizard persistence.
//
// GET  list / stats / single contract (permission: contracts.view)
// POST { action: create|update|issue|record_signature|upload_signed|renew|
//               terminate|cancel|archive|activate } (permission: contracts.manage)
//
// POLICY: this endpoint never generates legal text. Every contract uses a row
// from lease_contract_templates; issuance is blocked while that row is pending
// legal approval. api/generate_lease.php remains retired (410).

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/contracts.php';
require_once '../middleware/check_role.php';

// Defence in depth: never expose PDO or other exception details to the client.
set_exception_handler(static function (Throwable $e): void {
    error_log('Unhandled contract API error: ' . $e->getMessage());
    security_json_response(500, ['message' => 'The request could not be completed.']);
});

$user = authenticate();
$actor = (array) $user;
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

// Query-string contract (no REST router):
//   GET ?view=stats -> stats, GET ?id=N -> single, GET (no params) -> list.
if ($method === 'GET') {
    permission_require($actor, 'contracts.view');

    // Stats must be checked before the generic list branch.
    $view = isset($_GET['view']) && is_string($_GET['view'])
        ? strtolower(trim($_GET['view'])) : '';
    $detailId = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);

    // -----------------------------------------------------------------------
    // GET /api/contracts/stats
    // -----------------------------------------------------------------------
    if ($view === 'stats') {
        try {
            $sql = "SELECT COUNT(*) AS total,
                           SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) AS draft,
                           SUM(CASE WHEN status = 'ready_for_review' THEN 1 ELSE 0 END) AS ready_for_review,
                           SUM(CASE WHEN status = 'issued' THEN 1 ELSE 0 END) AS issued,
                           SUM(CASE WHEN status = 'awaiting_signature' THEN 1 ELSE 0 END) AS awaiting_signature,
                           SUM(CASE WHEN status = 'partially_signed' THEN 1 ELSE 0 END) AS partially_signed,
                           SUM(CASE WHEN status = 'fully_signed' THEN 1 ELSE 0 END) AS fully_signed,
                           SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
                           SUM(CASE WHEN status = 'active'
                                     AND termination_date >= CURDATE()
                                     AND termination_date <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)
                                    THEN 1 ELSE 0 END) AS expiring_soon,
                           SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) AS expired,
                           SUM(CASE WHEN status = 'terminated' THEN 1 ELSE 0 END) AS terminated,
                           SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
                    FROM lease_contracts";
            $row = $conn->query($sql)->fetch(PDO::FETCH_ASSOC) ?: [];
        } catch (Throwable $e) {
            error_log('Contract stats failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'Contract statistics could not be loaded.']);
        }

        security_json_response(200, [
            'total' => (int) ($row['total'] ?? 0),
            'draft' => (int) ($row['draft'] ?? 0),
            'ready_for_review' => (int) ($row['ready_for_review'] ?? 0),
            'issued' => (int) ($row['issued'] ?? 0),
            'awaiting_signature' => (int) ($row['awaiting_signature'] ?? 0),
            'partially_signed' => (int) ($row['partially_signed'] ?? 0),
            'fully_signed' => (int) ($row['fully_signed'] ?? 0),
            'active' => (int) ($row['active'] ?? 0),
            'expiring_soon' => (int) ($row['expiring_soon'] ?? 0),
            'expired' => (int) ($row['expired'] ?? 0),
            'terminated' => (int) ($row['terminated'] ?? 0),
            'cancelled' => (int) ($row['cancelled'] ?? 0),
        ]);
    }

    // -----------------------------------------------------------------------
    // GET /api/contracts.php?id=N
    // -----------------------------------------------------------------------
    if ($detailId !== false && $detailId !== null && $detailId > 0) {
        try {
            $contract = contract_find($conn, (int) $detailId);
            if ($contract === null) {
                security_json_response(404, ['message' => 'Contract not found.']);
            }

            $tenantStmt = $conn->prepare('SELECT * FROM tenants WHERE id = :id LIMIT 1');
            $tenantStmt->execute([':id' => (int) $contract['tenant_id']]);
            $tenantRow = $tenantStmt->fetch(PDO::FETCH_ASSOC) ?: [];

            $landlord = ['name' => null, 'email' => null, 'phone' => null, 'id_number' => null];
            if ((int) ($contract['landlord_id'] ?? 0) > 0) {
                $landlordStmt = $conn->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
                $landlordStmt->execute([':id' => (int) $contract['landlord_id']]);
                $landlordRow = $landlordStmt->fetch(PDO::FETCH_ASSOC) ?: [];
                $landlord = [
                    'name' => $landlordRow['full_name'] ?? null,
                    'email' => $landlordRow['email'] ?? null,
                    'phone' => $landlordRow['phone'] ?? null,
                    'id_number' => $landlordRow['id_number'] ?? null,
                ];
            }

            $detail = contract_serialize_detail($contract, [
                'tenant' => [
                    'name' => $tenantRow['name'] ?? null,
                    'email' => $tenantRow['email'] ?? null,
                    'phone' => $tenantRow['phone'] ?? null,
                    'id_number' => $tenantRow['id_number'] ?? null,
                ],
                'property' => [
                    'name' => $contract['property_name'] ?? null,
                    'address' => $contract['property_address'] ?? null,
                ],
                'unit' => ['unit_number' => $contract['unit_number'] ?? null],
                'landlord' => $landlord,
                'clauses' => contract_clauses($conn, (int) $contract['id']),
                'signatures' => contract_signatures($conn, (int) $contract['id']),
                'versions' => contract_versions($conn, (int) $contract['id']),
                'audit' => contract_audit($conn, (int) $contract['id']),
            ]);
        } catch (Throwable $e) {
            error_log('Contract detail failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The contract could not be loaded.']);
        }

        security_json_response(200, $detail);
    }

    // -----------------------------------------------------------------------
    // GET /api/contracts — filtered summary list
    // -----------------------------------------------------------------------
    $sql = "SELECT c.*, t.name AS tenant_name,
                   u.unit_number, u.property_id,
                   p.name AS property_name, p.address AS property_address
            FROM lease_contracts c
            JOIN tenants t ON c.tenant_id = t.id
            JOIN units u ON c.unit_id = u.id
            JOIN properties p ON u.property_id = p.id";
    $where = [];
    $params = [];

    $status = isset($_GET['status']) && is_string($_GET['status'])
        ? strtolower(trim($_GET['status'])) : '';
    if ($status !== '') {
        if ($status === 'expiring_soon') {
            $where[] = "c.status = 'active'
                        AND c.termination_date >= CURDATE()
                        AND c.termination_date <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)";
        } elseif (in_array($status, CONTRACT_STATUSES, true)) {
            $where[] = 'c.status = :status';
            $params[':status'] = $status;
        } else {
            security_json_response(400, ['message' => 'Invalid contract status filter.']);
        }
    }

    foreach (['tenant_id' => 'c.tenant_id', 'property_id' => 'u.property_id', 'unit_id' => 'c.unit_id'] as $key => $column) {
        $value = filter_var($_GET[$key] ?? null, FILTER_VALIDATE_INT);
        if ($value !== false && $value !== null && $value > 0) {
            $where[] = $column . ' = :' . $key;
            $params[':' . $key] = (int) $value;
        }
    }

    $from = isset($_GET['from']) && is_string($_GET['from']) ? trim($_GET['from']) : '';
    $to = isset($_GET['to']) && is_string($_GET['to']) ? trim($_GET['to']) : '';
    if ($from !== '' && contract_valid_date($from)) {
        $where[] = 'COALESCE(c.agreement_date, DATE(c.created_at)) >= :from_date';
        $params[':from_date'] = $from;
    }
    if ($to !== '' && contract_valid_date($to)) {
        $where[] = 'COALESCE(c.agreement_date, DATE(c.created_at)) <= :to_date';
        $params[':to_date'] = $to;
    }

    $q = isset($_GET['q']) && is_string($_GET['q']) ? trim($_GET['q']) : '';
    if ($q !== '') {
        $where[] = '(c.contract_reference LIKE :q OR t.name LIKE :q OR u.unit_number LIKE :q)';
        $params[':q'] = '%' . $q . '%';
    }

    if ($where !== []) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY c.id DESC LIMIT :limit OFFSET :offset';

    $limit = filter_var($_GET['limit'] ?? 300, FILTER_VALIDATE_INT);
    $limit = ($limit === false || $limit < 1) ? 300 : min($limit, 300);
    $offset = filter_var($_GET['offset'] ?? 0, FILTER_VALIDATE_INT);
    $offset = ($offset === false || $offset < 0) ? 0 : $offset;

    try {
        $stmt = $conn->prepare($sql);
        foreach ($params as $name => $value) {
            $stmt->bindValue($name, $value);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        error_log('Contract list failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'Contracts could not be loaded.']);
    }

    echo json_encode(array_map('contract_serialize_summary', $rows));
    exit();
}

if ($method !== 'POST') {
    security_json_response(405, ['message' => 'Method not allowed.']);
}

permission_require($actor, 'contracts.manage');

$data = json_decode(file_get_contents('php://input'));
if (!is_object($data)) {
    security_json_response(400, ['message' => 'Invalid request body.']);
}

$action = strtolower(trim((string) ($data->action ?? '')));
$allowedActions = [
    'create', 'update', 'issue', 'record_signature', 'upload_signed',
    'renew', 'terminate', 'cancel', 'archive', 'activate',
];
if (!in_array($action, $allowedActions, true)) {
    security_json_response(400, ['message' => 'Unsupported contract action.']);
}

$actorId = (int) ($user->user_id ?? 0);

/**
 * Read and validate the id used by every action except create.
 */
function contract_request_id($value): int
{
    $id = filter_var($value, FILTER_VALIDATE_INT);
    if ($id === false || $id === null || $id < 1) {
        security_json_response(400, ['message' => 'A valid contract id is required.']);
    }
    return (int) $id;
}

/**
 * Optional wizard fields shared by create/renew/update.
 *
 * @param stdClass $data
 * @return array<string,mixed> Validated columns, or null when validation fails.
 */
function contract_optional_fields(stdClass $data, ?string &$error): array
{
    $error = null;
    $fields = [];

    if (property_exists($data, 'payment_due_day') && $data->payment_due_day !== null && $data->payment_due_day !== '') {
        $day = filter_var($data->payment_due_day, FILTER_VALIDATE_INT);
        if ($day === false || $day < 1 || $day > 31) {
            $error = 'Payment due day must be between 1 and 31.';
            return [];
        }
        $fields['payment_due_day'] = (int) $day;
    } elseif (property_exists($data, 'payment_due_day')) {
        $fields['payment_due_day'] = null;
    }

    $textFields = [
        'payment_frequency' => 40,
        'notice_period' => 100,
        'lease_duration' => 100,
    ];
    foreach ($textFields as $field => $max) {
        if (property_exists($data, $field)) {
            $fields[$field] = security_clean_text($data->{$field}, $max) ?: null;
        }
    }

    if (property_exists($data, 'escalation_percentage') && $data->escalation_percentage !== null && $data->escalation_percentage !== '') {
        if (!contract_valid_amount($data->escalation_percentage)) {
            $error = 'Invalid escalation percentage.';
            return [];
        }
        $fields['escalation_percentage'] = round((float) $data->escalation_percentage, 2);
    } elseif (property_exists($data, 'escalation_percentage')) {
        $fields['escalation_percentage'] = null;
    }

    if (property_exists($data, 'escalation_date')) {
        $value = trim((string) ($data->escalation_date ?? ''));
        if ($value === '') {
            $fields['escalation_date'] = null;
        } elseif (contract_valid_date($value)) {
            $fields['escalation_date'] = $value;
        } else {
            $error = 'Invalid escalation date.';
            return [];
        }
    }

    return $fields;
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------
if ($action === 'create') {
    $tenantId = filter_var($data->tenant_id ?? null, FILTER_VALIDATE_INT);
    $unitId = filter_var($data->unit_id ?? null, FILTER_VALIDATE_INT);
    $templateId = filter_var($data->template_id ?? null, FILTER_VALIDATE_INT);
    if ($tenantId === false || $tenantId === null || $tenantId < 1
        || $unitId === false || $unitId === null || $unitId < 1
        || $templateId === false || $templateId === null || $templateId < 1) {
        security_json_response(400, ['message' => 'A valid tenant, unit and template are required.']);
    }

    $tenantCheck = $conn->prepare('SELECT id FROM tenants WHERE id = :id LIMIT 1');
    $tenantCheck->execute([':id' => $tenantId]);
    if ($tenantCheck->fetchColumn() === false) {
        security_json_response(404, ['message' => 'Tenant not found.']);
    }

    $unitCheck = $conn->prepare(
        'SELECT p.landlord_id FROM units u JOIN properties p ON u.property_id = p.id WHERE u.id = :id LIMIT 1'
    );
    $unitCheck->execute([':id' => $unitId]);
    $landlordId = $unitCheck->fetchColumn();
    if ($landlordId === false) {
        security_json_response(404, ['message' => 'Unit not found.']);
    }
    $landlordId = ($landlordId === null || (int) $landlordId < 1) ? $actorId : (int) $landlordId;

    $templateCheck = $conn->prepare('SELECT id FROM lease_contract_templates WHERE id = :id LIMIT 1');
    $templateCheck->execute([':id' => $templateId]);
    if ($templateCheck->fetchColumn() === false) {
        security_json_response(404, ['message' => 'Contract template not found.']);
    }

    $contractType = strtolower(trim((string) ($data->contract_type ?? 'new_lease')));
    if (!in_array($contractType, CONTRACT_TYPES, true)) {
        security_json_response(400, ['message' => 'Invalid contract type.']);
    }

    $agreementDate = trim((string) ($data->agreement_date ?? ''));
    $startDate = trim((string) ($data->commencement_date ?? ''));
    $endDate = trim((string) ($data->termination_date ?? ''));
    if (!contract_valid_date($agreementDate)
        || !contract_valid_date($startDate)
        || !contract_valid_date($endDate)
        || $endDate <= $startDate) {
        security_json_response(400, ['message' => 'Valid agreement, commencement and termination dates are required.']);
    }

    if (!contract_valid_amount($data->monthly_rent ?? null) || !contract_valid_amount($data->deposit_amount ?? null)) {
        security_json_response(400, ['message' => 'Valid non-negative monthly rent and deposit are required.']);
    }

    $payload = contract_payload_normalize($data->payload ?? null);
    if ($payload === null) {
        security_json_response(400, ['message' => 'Payload must be a JSON object.']);
    }

    $generatedUrl = null;
    if (property_exists($data, 'generated_document_url')
        && $data->generated_document_url !== null
        && $data->generated_document_url !== '') {
        $generatedUrl = contract_clean_document_url($data->generated_document_url);
        if ($generatedUrl === null) {
            security_json_response(400, ['message' => 'The generated document must be an uploaded Cloudinary file.']);
        }
    }

    $optionalError = null;
    $optional = contract_optional_fields($data, $optionalError);
    if ($optionalError !== null) {
        security_json_response(400, ['message' => $optionalError]);
    }

    try {
        $conn->beginTransaction();
        $reference = contract_reference_generate($conn);
        $newId = contract_insert($conn, array_merge([
            'contract_reference' => $reference,
            'landlord_id' => $landlordId,
            'tenant_id' => (int) $tenantId,
            'unit_id' => (int) $unitId,
            'template_id' => (int) $templateId,
            'version' => 1,
            'contract_type' => $contractType,
            'agreement_date' => $agreementDate,
            'commencement_date' => $startDate,
            'termination_date' => $endDate,
            'monthly_rent' => round((float) $data->monthly_rent, 2),
            'deposit_amount' => round((float) $data->deposit_amount, 2),
            'payload' => contract_payload_encode($payload),
            'generated_document_url' => $generatedUrl,
            'created_by' => $actorId,
        ], $optional));
        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Contract creation failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The contract could not be created.']);
    }

    audit_log($conn, $actorId, 'contract.create', [
        'entity_type' => 'contract',
        'entity_id' => $newId,
        'meta' => ['tenant_id' => (int) $tenantId, 'contract_type' => $contractType],
    ]);

    security_json_response(201, [
        'id' => $newId,
        'contract_reference' => $reference,
        'status' => 'draft',
    ]);
}

// All remaining actions need an existing contract.
$contractId = contract_request_id($data->id ?? null);
try {
    $contract = contract_find($conn, $contractId);
} catch (Throwable $e) {
    error_log('Contract lookup failed: ' . $e->getMessage());
    security_json_response(500, ['message' => 'The contract could not be loaded.']);
}
if ($contract === null) {
    security_json_response(404, ['message' => 'Contract not found.']);
}

// ---------------------------------------------------------------------------
// update (draft / ready_for_review only)
// ---------------------------------------------------------------------------
if ($action === 'update') {
    if (!contract_is_editable($contract)) {
        security_json_response(409, ['message' => 'This contract has been signed or activated and can no longer be edited.']);
    }

    $fields = [];
    $params = [':id' => $contractId];
    $start = (string) $contract['commencement_date'];
    $end = (string) $contract['termination_date'];

    foreach (['agreement_date', 'commencement_date', 'termination_date'] as $field) {
        if (!property_exists($data, $field)) {
            continue;
        }
        $value = trim((string) ($data->{$field} ?? ''));
        if (!contract_valid_date($value)) {
            security_json_response(400, ['message' => 'Invalid ' . str_replace('_', ' ', $field) . '.']);
        }
        $fields[] = $field . ' = :' . $field;
        $params[':' . $field] = $value;
        if ($field === 'commencement_date') {
            $start = $value;
        }
        if ($field === 'termination_date') {
            $end = $value;
        }
    }
    if ($end <= $start) {
        security_json_response(400, ['message' => 'The termination date must be after the commencement date.']);
    }

    foreach (['monthly_rent', 'deposit_amount'] as $field) {
        if (!property_exists($data, $field)) {
            continue;
        }
        if (!contract_valid_amount($data->{$field})) {
            security_json_response(400, ['message' => 'Invalid ' . str_replace('_', ' ', $field) . '.']);
        }
        $fields[] = $field . ' = :' . $field;
        $params[':' . $field] = round((float) $data->{$field}, 2);
    }

    if (property_exists($data, 'payload')) {
        $payload = contract_payload_normalize($data->payload);
        if ($payload === null) {
            security_json_response(400, ['message' => 'Payload must be a JSON object.']);
        }
        $fields[] = 'payload = :payload';
        $params[':payload'] = contract_payload_encode($payload);
    }

    if (property_exists($data, 'generated_document_url')) {
        $generatedUrl = contract_clean_document_url($data->generated_document_url);
        if ($generatedUrl === null) {
            security_json_response(400, ['message' => 'The generated document must be an uploaded Cloudinary file.']);
        }
        $fields[] = 'generated_document_url = :generated_document_url';
        $params[':generated_document_url'] = $generatedUrl;
    }

    if (property_exists($data, 'template_id')) {
        $templateId = filter_var($data->template_id, FILTER_VALIDATE_INT);
        if ($templateId === false || $templateId === null || $templateId < 1) {
            security_json_response(400, ['message' => 'A valid template is required.']);
        }
        $templateCheck = $conn->prepare('SELECT id FROM lease_contract_templates WHERE id = :id LIMIT 1');
        $templateCheck->execute([':id' => $templateId]);
        if ($templateCheck->fetchColumn() === false) {
            security_json_response(404, ['message' => 'Contract template not found.']);
        }
        $fields[] = 'template_id = :template_id';
        $params[':template_id'] = (int) $templateId;
    }

    $optionalError = null;
    $optional = contract_optional_fields($data, $optionalError);
    if ($optionalError !== null) {
        security_json_response(400, ['message' => $optionalError]);
    }
    foreach ($optional as $field => $value) {
        $fields[] = $field . ' = :' . $field;
        $params[':' . $field] = $value;
    }

    if (property_exists($data, 'status')) {
        $target = strtolower(trim((string) ($data->status ?? '')));
        if (!in_array($target, CONTRACT_EDITABLE_STATUSES, true)
            || !contract_transition_allowed((string) $contract['status'], $target)) {
            security_json_response(409, ['message' => 'That status change is not allowed.']);
        }
        $fields[] = 'status = :status';
        $params[':status'] = $target;
    }

    if ($fields === []) {
        security_json_response(400, ['message' => 'Nothing to update.']);
    }

    try {
        $conn->prepare('UPDATE lease_contracts SET ' . implode(', ', $fields) . ' WHERE id = :id')->execute($params);
    } catch (Throwable $e) {
        error_log('Contract update failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The contract could not be updated.']);
    }

    audit_log($conn, $actorId, 'contract.update', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
    ]);

    security_json_response(200, ['message' => 'Contract updated.']);
}

// ---------------------------------------------------------------------------
// issue — blocked until the template is legally approved
// ---------------------------------------------------------------------------
if ($action === 'issue') {
    if (!in_array((string) $contract['status'], ['draft', 'ready_for_review'], true)
        || !contract_transition_allowed((string) $contract['status'], 'issued')) {
        security_json_response(409, ['message' => 'Only an unreviewed contract can be issued.']);
    }

    $templateStmt = $conn->prepare('SELECT approval_status FROM lease_contract_templates WHERE id = :id LIMIT 1');
    $templateStmt->execute([':id' => (int) ($contract['template_id'] ?? 0)]);
    $template = $templateStmt->fetch(PDO::FETCH_ASSOC);
    if (!$template || ($template['approval_status'] ?? 'pending') !== 'approved') {
        security_json_response(409, [
            'message' => 'This contract template is pending legal approval and cannot be issued.',
        ]);
    }

    $conn->prepare("UPDATE lease_contracts SET status = 'issued', issued_at = NOW() WHERE id = :id")
        ->execute([':id' => $contractId]);

    audit_log($conn, $actorId, 'contract.issue', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
    ]);

    security_json_response(200, ['message' => 'Contract issued.', 'status' => 'issued']);
}

// ---------------------------------------------------------------------------
// record_signature
// ---------------------------------------------------------------------------
if ($action === 'record_signature') {
    if (!in_array((string) $contract['status'], ['issued', 'awaiting_signature', 'partially_signed'], true)) {
        security_json_response(409, ['message' => 'This contract cannot be signed in its current status.']);
    }

    $role = strtolower(trim((string) ($data->signer_role ?? '')));
    if (!in_array($role, CONTRACT_SIGNER_ROLES, true)) {
        security_json_response(400, ['message' => 'Invalid signer role.']);
    }

    $signerName = security_clean_text($data->signer_name ?? '', 100);
    if ($signerName === '') {
        security_json_response(400, ['message' => 'The signer name is required.']);
    }

    $method = strtolower(trim((string) ($data->signature_method ?? 'in_person')));
    if (!in_array($method, CONTRACT_SIGNATURE_METHODS, true)) {
        security_json_response(400, ['message' => 'Invalid signature method.']);
    }

    $rawSignedAt = trim((string) ($data->signed_at ?? ''));
    if ($rawSignedAt === '') {
        $signedAt = date('Y-m-d H:i:s');
    } elseif (!contract_valid_datetime($rawSignedAt)) {
        security_json_response(400, ['message' => 'Invalid signature date.']);
    } else {
        $signedAt = date('Y-m-d H:i:s', strtotime($rawSignedAt));
    }

    $evidenceUrl = null;
    if (property_exists($data, 'evidence_url') && $data->evidence_url !== null && $data->evidence_url !== '') {
        $evidenceUrl = contract_clean_document_url($data->evidence_url);
        if ($evidenceUrl === null) {
            security_json_response(400, ['message' => 'Signature evidence must be an uploaded Cloudinary file.']);
        }
    }

    try {
        $conn->beginTransaction();

        $conn->prepare(
            "INSERT INTO lease_contract_signatures
                (contract_id, signer_role, signer_name, signature_method, evidence_url, signed_at, recorded_by)
             VALUES
                (:contract_id, :signer_role, :signer_name, :signature_method, :evidence_url, :signed_at, :recorded_by)
             ON DUPLICATE KEY UPDATE
                signer_name = VALUES(signer_name),
                signature_method = VALUES(signature_method),
                evidence_url = VALUES(evidence_url),
                signed_at = VALUES(signed_at),
                recorded_by = VALUES(recorded_by)"
        )->execute([
            ':contract_id' => $contractId,
            ':signer_role' => $role,
            ':signer_name' => $signerName,
            ':signature_method' => $method,
            ':evidence_url' => $evidenceUrl,
            ':signed_at' => $signedAt,
            ':recorded_by' => $actorId,
        ]);

        $signatureStmt = $conn->prepare(
            "SELECT signer_role FROM lease_contract_signatures
             WHERE contract_id = :id AND signer_role IN ('landlord', 'tenant')"
        );
        $signatureStmt->execute([':id' => $contractId]);
        $signedRoles = $signatureStmt->fetchAll(PDO::FETCH_COLUMN);
        $newStatus = (in_array('landlord', $signedRoles, true) && in_array('tenant', $signedRoles, true))
            ? 'fully_signed' : 'partially_signed';

        $updates = ['status = :status'];
        $updateParams = [':status' => $newStatus, ':id' => $contractId];
        if ($role === 'landlord') {
            $updates[] = 'landlord_signed_at = :signed_at';
            $updateParams[':signed_at'] = $signedAt;
        } elseif ($role === 'tenant') {
            $updates[] = 'tenant_signed_at = :signed_at';
            $updateParams[':signed_at'] = $signedAt;
        }
        $conn->prepare('UPDATE lease_contracts SET ' . implode(', ', $updates) . ' WHERE id = :id')
            ->execute($updateParams);

        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Contract signature failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The signature could not be recorded.']);
    }

    audit_log($conn, $actorId, 'contract.record_signature', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
        'meta' => ['signer_role' => $role, 'signature_method' => $method, 'status' => $newStatus],
    ]);

    security_json_response(200, ['message' => 'Signature recorded.', 'status' => $newStatus]);
}

// ---------------------------------------------------------------------------
// upload_signed
// ---------------------------------------------------------------------------
if ($action === 'upload_signed') {
    if (in_array((string) $contract['status'], ['cancelled', 'terminated', 'expired'], true)) {
        security_json_response(409, ['message' => 'This contract is closed and cannot accept a signed document.']);
    }

    $url = contract_clean_document_url($data->signed_document_url ?? null);
    if ($url === null) {
        security_json_response(400, ['message' => 'The signed document must be an uploaded Cloudinary file.']);
    }

    $conn->prepare('UPDATE lease_contracts SET signed_document_url = :url WHERE id = :id')
        ->execute([':url' => $url, ':id' => $contractId]);

    audit_log($conn, $actorId, 'contract.upload_signed', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
    ]);

    security_json_response(200, ['message' => 'Signed contract uploaded.']);
}

// ---------------------------------------------------------------------------
// renew — new version linked to the previous contract
// ---------------------------------------------------------------------------
if ($action === 'renew') {
    $startDate = trim((string) ($data->commencement_date ?? ''));
    $endDate = trim((string) ($data->termination_date ?? ''));
    if (!contract_valid_date($startDate) || !contract_valid_date($endDate) || $endDate <= $startDate) {
        security_json_response(400, ['message' => 'Valid renewal commencement and termination dates are required.']);
    }
    if (!contract_valid_amount($data->monthly_rent ?? null) || !contract_valid_amount($data->deposit_amount ?? null)) {
        security_json_response(400, ['message' => 'Valid non-negative monthly rent and deposit are required.']);
    }

    $payload = contract_payload_normalize($data->payload ?? null);
    if ($payload === null) {
        security_json_response(400, ['message' => 'Payload must be a JSON object.']);
    }

    $agreementDate = date('Y-m-d');
    if (property_exists($data, 'agreement_date') && trim((string) ($data->agreement_date ?? '')) !== '') {
        $agreementDate = trim((string) $data->agreement_date);
        if (!contract_valid_date($agreementDate)) {
            security_json_response(400, ['message' => 'Invalid agreement date.']);
        }
    }

    $optionalError = null;
    $optional = contract_optional_fields($data, $optionalError);
    if ($optionalError !== null) {
        security_json_response(400, ['message' => $optionalError]);
    }

    $inherited = [];
    foreach (['payment_due_day', 'payment_frequency', 'escalation_percentage', 'escalation_date',
              'notice_period', 'lease_duration'] as $field) {
        if (array_key_exists($field, $contract) && $contract[$field] !== null) {
            $inherited[$field] = $contract[$field];
        }
    }

    try {
        $conn->beginTransaction();
        $reference = contract_reference_generate($conn);
        $newId = contract_insert($conn, array_merge([
            'contract_reference' => $reference,
            'landlord_id' => $contract['landlord_id'] !== null ? (int) $contract['landlord_id'] : $actorId,
            'tenant_id' => (int) $contract['tenant_id'],
            'unit_id' => (int) $contract['unit_id'],
            'template_id' => $contract['template_id'] !== null ? (int) $contract['template_id'] : null,
            'previous_contract_id' => $contractId,
            'version' => (int) $contract['version'] + 1,
            'contract_type' => 'renewal',
            'agreement_date' => $agreementDate,
            'commencement_date' => $startDate,
            'termination_date' => $endDate,
            'monthly_rent' => round((float) $data->monthly_rent, 2),
            'deposit_amount' => round((float) $data->deposit_amount, 2),
            'payload' => contract_payload_encode($payload),
            'created_by' => $actorId,
        ], $inherited, $optional));
        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Contract renewal failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The contract could not be renewed.']);
    }

    audit_log($conn, $actorId, 'contract.renew', [
        'entity_type' => 'contract',
        'entity_id' => $newId,
        'meta' => ['previous_contract_id' => $contractId, 'version' => (int) $contract['version'] + 1],
    ]);

    security_json_response(201, [
        'id' => $newId,
        'contract_reference' => $reference,
        'status' => 'draft',
    ]);
}

// ---------------------------------------------------------------------------
// terminate
// ---------------------------------------------------------------------------
if ($action === 'terminate') {
    if ((string) $contract['status'] !== 'active') {
        security_json_response(409, ['message' => 'Only an active contract can be terminated.']);
    }

    $reason = security_clean_text($data->reason ?? '', 500);
    if (strlen($reason) < 3) {
        security_json_response(400, ['message' => 'A termination reason is required.']);
    }

    $conn->prepare(
        "UPDATE lease_contracts
         SET status = 'terminated', terminated_at = NOW(), termination_reason = :reason
         WHERE id = :id"
    )->execute([':reason' => $reason, ':id' => $contractId]);

    audit_log($conn, $actorId, 'contract.terminate', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
        'meta' => ['reason' => $reason],
    ]);

    security_json_response(200, ['message' => 'Contract terminated.', 'status' => 'terminated']);
}

// ---------------------------------------------------------------------------
// cancel
// ---------------------------------------------------------------------------
if ($action === 'cancel') {
    if (!contract_transition_allowed((string) $contract['status'], 'cancelled')
        || (string) $contract['status'] === 'cancelled') {
        security_json_response(409, ['message' => 'This contract cannot be cancelled in its current status.']);
    }

    $conn->prepare("UPDATE lease_contracts SET status = 'cancelled' WHERE id = :id")
        ->execute([':id' => $contractId]);

    audit_log($conn, $actorId, 'contract.cancel', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
    ]);

    security_json_response(200, ['message' => 'Contract cancelled.', 'status' => 'cancelled']);
}

// ---------------------------------------------------------------------------
// archive (flag only; status is preserved)
// ---------------------------------------------------------------------------
if ($action === 'archive') {
    $conn->prepare('UPDATE lease_contracts SET archived_at = COALESCE(archived_at, NOW()) WHERE id = :id')
        ->execute([':id' => $contractId]);

    audit_log($conn, $actorId, 'contract.archive', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
    ]);

    security_json_response(200, ['message' => 'Contract archived.']);
}

// ---------------------------------------------------------------------------
// activate (fully signed only)
// ---------------------------------------------------------------------------
if ($action === 'activate') {
    if ((string) $contract['status'] !== 'fully_signed'
        || !contract_transition_allowed((string) $contract['status'], 'active')) {
        security_json_response(409, ['message' => 'Only a fully signed contract can be activated.']);
    }

    try {
        $conn->beginTransaction();
        $conn->prepare("UPDATE lease_contracts SET status = 'active', activated_at = NOW() WHERE id = :id")
            ->execute([':id' => $contractId]);
        contract_apply_activation($conn, $contract);
        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Contract activation failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The contract could not be activated.']);
    }

    audit_log($conn, $actorId, 'contract.activate', [
        'entity_type' => 'contract',
        'entity_id' => $contractId,
        'meta' => ['tenant_id' => (int) $contract['tenant_id'], 'version' => (int) $contract['version']],
    ]);

    security_json_response(200, ['message' => 'Contract activated.', 'status' => 'active']);
}

security_json_response(400, ['message' => 'Unsupported contract action.']);
