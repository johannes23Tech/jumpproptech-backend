<?php
// config/contracts.php
//
// Helpers for the Lease Contract Generator.
//
// POLICY: this file never authors legal wording. Contract text comes only from
// a lease_contract_templates row that management supplied and a qualified
// South African legal professional approved. api/generate_lease.php stays
// retired; the helpers below only store, reference and audit those rows.

require_once __DIR__ . '/security.php';

const CONTRACT_STATUSES = [
    'draft', 'ready_for_review', 'issued', 'awaiting_signature',
    'partially_signed', 'fully_signed', 'active', 'expired',
    'terminated', 'cancelled',
];

const CONTRACT_EDITABLE_STATUSES = ['draft', 'ready_for_review'];

const CONTRACT_TYPES = ['new_lease', 'renewal'];

const CONTRACT_SIGNER_ROLES = ['landlord', 'tenant', 'additional_tenant', 'witness_1', 'witness_2'];

const CONTRACT_SIGNATURE_METHODS = ['in_person', 'electronic', 'scanned'];

const CONTRACT_EXPIRING_DAYS = 30;

// Allowed lifecycle transitions. Archiving is a flag and does not change status.
const CONTRACT_TRANSITIONS = [
    'draft'              => ['ready_for_review', 'issued', 'cancelled'],
    'ready_for_review'   => ['draft', 'issued', 'cancelled'],
    'issued'             => ['awaiting_signature', 'partially_signed', 'fully_signed', 'cancelled'],
    'awaiting_signature' => ['partially_signed', 'fully_signed', 'cancelled'],
    'partially_signed'   => ['fully_signed', 'cancelled'],
    'fully_signed'       => ['active', 'cancelled'],
    'active'             => ['expired', 'terminated'],
    'expired'            => [],
    'terminated'         => [],
    'cancelled'          => [],
];

function contract_valid_date($value): bool
{
    if (!is_string($value) || preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) !== 1) {
        return false;
    }

    return checkdate((int) substr($value, 5, 2), (int) substr($value, 8, 2), (int) substr($value, 0, 4));
}

function contract_valid_datetime($value): bool
{
    return is_string($value) && trim($value) !== '' && strtotime($value) !== false;
}

function contract_valid_amount($value): bool
{
    return is_numeric($value) && (float) $value >= 0.0 && is_finite((float) $value);
}

/**
 * Cloudinary-only document URLs. Stored URLs are always plain https URLs;
 * never a data URI, javascript: URI or a file on the local server.
 */
function contract_valid_document_url($value): bool
{
    if (!is_string($value)) {
        return false;
    }
    $url = trim($value);

    return $url !== ''
        && strlen($url) <= 500
        && preg_match('/\s/', $url) !== 1
        && strpos($url, 'https://res.cloudinary.com/') === 0;
}

function contract_clean_document_url($value): ?string
{
    return contract_valid_document_url($value) ? trim($value) : null;
}

/**
 * LC-YYYYMMDD-XXXX. Random bytes avoid a predictable sequence; the UNIQUE
 * index plus this DB check make concurrent collisions a retry, never a duplicate.
 */
function contract_reference_generate(PDO $conn): string
{
    $stmt = $conn->prepare('SELECT 1 FROM lease_contracts WHERE contract_reference = :ref LIMIT 1');

    for ($attempt = 0; $attempt < 25; $attempt++) {
        $reference = 'LC-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(2)));
        $stmt->execute([':ref' => $reference]);
        if ($stmt->fetchColumn() === false) {
            return $reference;
        }
    }

    throw new RuntimeException('Unable to allocate a unique contract reference.');
}

/**
 * Convert nested stdClass values from a decoded request body into arrays.
 */
function contract_payload_convert($value)
{
    if (is_object($value)) {
        $out = [];
        foreach (get_object_vars($value) as $key => $item) {
            $out[$key] = contract_payload_convert($item);
        }
        return $out;
    }
    if (is_array($value)) {
        $out = [];
        foreach ($value as $key => $item) {
            $out[$key] = contract_payload_convert($item);
        }
        return $out;
    }

    return $value;
}

/**
 * Normalise wizard operational data. Only a JSON object (or stdClass) is
 * accepted; a JSON list or scalar is invalid. Returns null when invalid.
 *
 * @return array<string,mixed>|null
 */
function contract_payload_normalize($value): ?array
{
    if (is_string($value)) {
        $decoded = json_decode($value);
        if (json_last_error() !== JSON_ERROR_NONE || !is_object($decoded)) {
            return null;
        }
        $value = $decoded;
    }
    if (!is_object($value) && !is_array($value)) {
        return null;
    }

    $payload = contract_payload_convert($value);
    if ($payload !== [] && array_is_list($payload)) {
        return null;
    }

    return $payload;
}

function contract_payload_encode(array $payload): string
{
    $encoded = json_encode(
        $payload === [] ? new stdClass() : $payload,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );

    return $encoded === false ? '{}' : $encoded;
}

/**
 * @return stdClass Always an object so an empty payload serialises as {}.
 */
function contract_payload_decode($value): stdClass
{
    if ($value instanceof stdClass) {
        return $value;
    }
    if (is_array($value)) {
        return (object) contract_payload_convert($value);
    }
    if (is_string($value) && $value !== '') {
        $decoded = json_decode($value);
        if (is_object($decoded)) {
            return $decoded;
        }
    }

    return new stdClass();
}

/**
 * @return array<string,mixed>|null
 */
function contract_find(PDO $conn, int $id): ?array
{
    $stmt = $conn->prepare(
        "SELECT c.*, t.name AS tenant_name,
                u.unit_number, u.property_id,
                p.name AS property_name, p.address AS property_address
         FROM lease_contracts c
         JOIN tenants t ON c.tenant_id = t.id
         JOIN units u ON c.unit_id = u.id
         JOIN properties p ON u.property_id = p.id
         WHERE c.id = :id
         LIMIT 1"
    );
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row !== false ? $row : null;
}

function contract_is_editable(array $row): bool
{
    return in_array((string) ($row['status'] ?? ''), CONTRACT_EDITABLE_STATUSES, true);
}

function contract_transition_allowed(string $from, string $to): bool
{
    if ($from === $to) {
        return true;
    }

    return in_array($to, CONTRACT_TRANSITIONS[$from] ?? [], true);
}

/**
 * Derived status: an active contract expiring in the next 30 days is reported
 * as expiring_soon. No background job or stored status is required.
 */
function contract_is_expiring_soon(array $row, ?int $days = null): bool
{
    $endDate = (string) ($row['termination_date'] ?? '');
    if ((string) ($row['status'] ?? '') !== 'active' || !contract_valid_date($endDate)) {
        return false;
    }

    try {
        $today = new DateTimeImmutable('today');
        $end = new DateTimeImmutable($endDate);
        $limit = $today->modify('+' . max(0, $days ?? CONTRACT_EXPIRING_DAYS) . ' days');
    } catch (Throwable $e) {
        return false;
    }

    return $end >= $today && $end <= $limit;
}

function contract_effective_status(array $row): string
{
    return contract_is_expiring_soon($row) ? 'expiring_soon' : (string) ($row['status'] ?? 'draft');
}

function contract_nullable_int($value): ?int
{
    return $value === null || $value === '' ? null : (int) $value;
}

function contract_nullable_float($value): ?float
{
    return $value === null || $value === '' ? null : round((float) $value, 2);
}

/**
 * Exact summary shape returned by GET /api/contracts.
 *
 * @param array<string,mixed> $row
 * @return array<string,mixed>
 */
function contract_serialize_summary(array $row): array
{
    return [
        'id' => (int) ($row['id'] ?? 0),
        'contract_reference' => (string) ($row['contract_reference'] ?? ''),
        'tenant_id' => (int) ($row['tenant_id'] ?? 0),
        'tenant_name' => (string) ($row['tenant_name'] ?? ''),
        'property_id' => contract_nullable_int($row['property_id'] ?? null),
        'property_name' => (string) ($row['property_name'] ?? ''),
        'unit_id' => (int) ($row['unit_id'] ?? 0),
        'unit_number' => (string) ($row['unit_number'] ?? ''),
        'template_id' => contract_nullable_int($row['template_id'] ?? null),
        'contract_type' => (string) ($row['contract_type'] ?? 'new_lease'),
        'status' => contract_effective_status($row),
        'agreement_date' => $row['agreement_date'] ?? null,
        'commencement_date' => $row['commencement_date'] ?? null,
        'termination_date' => $row['termination_date'] ?? null,
        'monthly_rent' => round((float) ($row['monthly_rent'] ?? 0), 2),
        'deposit_amount' => round((float) ($row['deposit_amount'] ?? 0), 2),
        'issued_at' => $row['issued_at'] ?? null,
        'landlord_signed_at' => $row['landlord_signed_at'] ?? null,
        'tenant_signed_at' => $row['tenant_signed_at'] ?? null,
        'previous_contract_id' => contract_nullable_int($row['previous_contract_id'] ?? null),
        'version' => (int) ($row['version'] ?? 1),
        'created_at' => $row['created_at'] ?? null,
        'updated_at' => $row['updated_at'] ?? null,
    ];
}

/**
 * @param array<string,mixed> $row
 * @param array<string,mixed> $extra tenant, property, unit, landlord, clauses,
 *                                   signatures, versions, audit
 * @return array<string,mixed>
 */
function contract_serialize_detail(array $row, array $extra = []): array
{
    $contract = contract_serialize_summary($row);
    $contract['tenant'] = $extra['tenant'] ?? [
        'name' => null, 'email' => null, 'phone' => null, 'id_number' => null,
    ];
    $contract['property'] = $extra['property'] ?? ['name' => null, 'address' => null];
    $contract['unit'] = $extra['unit'] ?? ['unit_number' => null];
    $contract['landlord'] = $extra['landlord'] ?? [
        'name' => null, 'email' => null, 'phone' => null, 'id_number' => null,
    ];
    $contract['payment_due_day'] = contract_nullable_int($row['payment_due_day'] ?? null);
    $contract['payment_frequency'] = $row['payment_frequency'] ?? null;
    $contract['escalation_percentage'] = $row['escalation_percentage'] ?? null;
    $contract['escalation_date'] = $row['escalation_date'] ?? null;
    $contract['notice_period'] = $row['notice_period'] ?? null;
    $contract['lease_duration'] = $row['lease_duration'] ?? null;
    $contract['generated_document_url'] = $row['generated_document_url'] ?? null;
    $contract['signed_document_url'] = $row['signed_document_url'] ?? null;
    $contract['archived_at'] = $row['archived_at'] ?? null;
    $contract['termination_reason'] = $row['termination_reason'] ?? null;
    $contract['landlord_id'] = (int) ($row['landlord_id'] ?? 0);
    $contract['template_id'] = contract_nullable_int($row['template_id'] ?? null);
    $contract['payload'] = contract_payload_decode($row['payload'] ?? null);
    $contract['clauses'] = $extra['clauses'] ?? [];
    $contract['signatures'] = $extra['signatures'] ?? [];
    $contract['versions'] = $extra['versions'] ?? [];
    $contract['audit'] = $extra['audit'] ?? [];
    $contract['can_edit'] = contract_is_editable($row);

    return $contract;
}

/**
 * @return array<int,array<string,mixed>>
 */
function contract_clauses(PDO $conn, int $contractId): array
{
    $stmt = $conn->prepare(
        'SELECT id, contract_id, clause_number, clause_title, clause_content,
                enabled, display_order, source, created_at
         FROM lease_contract_clauses
         WHERE contract_id = :id
         ORDER BY display_order ASC, clause_number ASC, id ASC'
    );
    $stmt->execute([':id' => $contractId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

    return array_map(static function (array $row): array {
        return [
            'id' => (int) $row['id'],
            'contract_id' => (int) $row['contract_id'],
            'clause_number' => (int) $row['clause_number'],
            'clause_title' => (string) $row['clause_title'],
            'clause_content' => (string) $row['clause_content'],
            'enabled' => (bool) $row['enabled'],
            'display_order' => (int) $row['display_order'],
            'source' => (string) $row['source'],
            'created_at' => $row['created_at'],
        ];
    }, $rows);
}

/**
 * @return array<int,array<string,mixed>>
 */
function contract_signatures(PDO $conn, int $contractId): array
{
    $stmt = $conn->prepare(
        'SELECT id, contract_id, signer_role, signer_name, signature_method,
                evidence_url, signed_at, recorded_by, created_at
         FROM lease_contract_signatures
         WHERE contract_id = :id
         ORDER BY signed_at ASC, id ASC'
    );
    $stmt->execute([':id' => $contractId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

    return array_map(static function (array $row): array {
        return [
            'id' => (int) $row['id'],
            'contract_id' => (int) $row['contract_id'],
            'signer_role' => (string) $row['signer_role'],
            'signer_name' => (string) $row['signer_name'],
            'signature_method' => (string) $row['signature_method'],
            'evidence_url' => $row['evidence_url'],
            'signed_at' => $row['signed_at'],
            'recorded_by' => contract_nullable_int($row['recorded_by'] ?? null),
            'created_at' => $row['created_at'],
        ];
    }, $rows);
}

/**
 * @return array<int,array<string,mixed>>
 */
function contract_versions(PDO $conn, int $contractId): array
{
    $stmt = $conn->prepare(
        'SELECT id, contract_id, version_number, previous_contract_id, document_url,
                change_summary, created_by, created_at
         FROM lease_contract_versions
         WHERE contract_id = :id
         ORDER BY version_number DESC, id DESC
         LIMIT 100'
    );
    $stmt->execute([':id' => $contractId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

    return array_map(static function (array $row): array {
        return [
            'id' => (int) $row['id'],
            'contract_id' => (int) $row['contract_id'],
            'version_number' => (int) $row['version_number'],
            'previous_contract_id' => contract_nullable_int($row['previous_contract_id'] ?? null),
            'document_url' => $row['document_url'],
            'change_summary' => $row['change_summary'],
            'created_by' => contract_nullable_int($row['created_by'] ?? null),
            'created_at' => $row['created_at'],
        ];
    }, $rows);
}

/**
 * @return array<int,array<string,mixed>>
 */
function contract_audit(PDO $conn, int $contractId): array
{
    $stmt = $conn->prepare(
        "SELECT a.id, a.actor_user_id, a.actor_email, a.action, a.entity_type,
                a.entity_id, a.outcome, a.meta, a.created_at,
                u.full_name AS actor_name
         FROM audit_logs a
         LEFT JOIN users u ON a.actor_user_id = u.id
         WHERE a.entity_type = 'contract' AND a.entity_id = :id
         ORDER BY a.id DESC
         LIMIT 100"
    );
    $stmt->execute([':id' => $contractId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];

    $events = [];
    foreach ($rows as $row) {
        $meta = $row['meta'];
        if (is_string($meta) && $meta !== '') {
            $decoded = json_decode($meta, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $meta = $decoded;
            }
        }
        $events[] = [
            'id' => (int) $row['id'],
            'actor_user_id' => contract_nullable_int($row['actor_user_id'] ?? null),
            'actor_email' => $row['actor_email'],
            'actor_name' => $row['actor_name'],
            'action' => (string) $row['action'],
            'entity_type' => $row['entity_type'],
            'entity_id' => contract_nullable_int($row['entity_id'] ?? null),
            'outcome' => (string) $row['outcome'],
            'meta' => $meta,
            'created_at' => $row['created_at'],
        ];
    }

    return $events;
}

/**
 * Insert a new contract row. Caller supplies validated values; the status
 * always starts as draft. MUST be called inside a transaction by the API.
 *
 * @param array<string,mixed> $values
 */
function contract_insert(PDO $conn, array $values): int
{
    $allowed = [
        'contract_reference', 'landlord_id', 'tenant_id', 'unit_id', 'template_id',
        'previous_contract_id', 'version', 'contract_type', 'agreement_date',
        'commencement_date', 'termination_date', 'monthly_rent', 'deposit_amount',
        'payment_due_day', 'payment_frequency', 'escalation_percentage',
        'escalation_date', 'notice_period', 'lease_duration', 'payload', 'created_by',
    ];

    $columns = [];
    $marks = [];
    $params = [];
    foreach ($allowed as $column) {
        if (!array_key_exists($column, $values)) {
            continue;
        }
        $columns[] = $column;
        $marks[] = ':' . $column;
        $params[':' . $column] = $values[$column];
    }

    $sql = 'INSERT INTO lease_contracts (' . implode(', ', $columns) . ') VALUES (' . implode(', ', $marks) . ')';
    $stmt = $conn->prepare($sql);
    $stmt->execute($params);

    return (int) $conn->lastInsertId();
}

/**
 * Optional tenancy integration on activation. Opt out with
 * CONTRACTS_SKIP_TENANCY_SYNC=1 when another module owns tenancy state.
 * MUST be called inside the activation transaction.
 *
 * @param array<string,mixed> $row
 */
function contract_apply_activation(PDO $conn, array $row): void
{
    if (getenv('CONTRACTS_SKIP_TENANCY_SYNC') === '1') {
        return;
    }

    $conn->prepare(
        "UPDATE tenants
         SET status = 'active', lease_start = :start, lease_end = :end,
             monthly_rent = :rent, deposit = :deposit
         WHERE id = :tenant_id"
    )->execute([
        ':start' => $row['commencement_date'],
        ':end' => $row['termination_date'],
        ':rent' => $row['monthly_rent'],
        ':deposit' => $row['deposit_amount'],
        ':tenant_id' => (int) $row['tenant_id'],
    ]);

    $conn->prepare("UPDATE units SET status = 'Occupied' WHERE id = :unit_id AND archived_at IS NULL")
        ->execute([':unit_id' => (int) $row['unit_id']]);
}
