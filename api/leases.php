<?php
// api/leases.php
//
// Versioned lease records for a tenancy.
//
// GET  list leases (permission: leases.view)
// POST { action: create|update|sign|activate|delete } (permission: leases.manage)
//
// Management supplies the lease document. The platform stores, versions and
// tracks signatures; it does not generate legal clauses.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/leases.php';
require_once '../config/rent.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

function lease_clean_document_url($value): ?string
{
    if (!is_string($value)) {
        return null;
    }
    $url = trim($value);
    if ($url === '') {
        return null;
    }
    if (strlen($url) > 500 || strpos($url, 'https://res.cloudinary.com/') !== 0) {
        security_json_response(400, ['message' => 'The lease document must be an uploaded Cloudinary file.']);
    }

    return $url;
}

function lease_valid_date($value): bool
{
    return is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) === 1;
}

if ($method === 'GET') {
    permission_require($actor, 'leases.view');

    $tenantId = filter_var($_GET['tenant_id'] ?? 0, FILTER_VALIDATE_INT);
    $status = isset($_GET['status']) && is_string($_GET['status']) ? strtolower(trim($_GET['status'])) : '';

    $sql = "SELECT l.*, t.name AS tenant_name, t.email AS tenant_email,
                   u.unit_number, p.name AS property_name, b.name AS building_name,
                   (SELECT COUNT(*) FROM lease_signatures s WHERE s.lease_id = l.id) AS signature_count
            FROM leases l
            JOIN tenants t ON l.tenant_id = t.id
            JOIN units u ON l.unit_id = u.id
            JOIN properties p ON u.property_id = p.id
            LEFT JOIN buildings b ON u.building_id = b.id";
    $params = [];
    $clauses = [];

    if ($tenantId !== false && $tenantId !== null && $tenantId > 0) {
        $clauses[] = 'l.tenant_id = :tenant_id';
        $params[':tenant_id'] = $tenantId;
    }
    if ($status !== '' && in_array($status, ['draft', 'pending_signature', 'active', 'superseded', 'expired', 'terminated'], true)) {
        $clauses[] = 'l.status = :status';
        $params[':status'] = $status;
    }
    if ($clauses !== []) {
        $sql .= ' WHERE ' . implode(' AND ', $clauses);
    }
    $sql .= ' ORDER BY l.id DESC LIMIT 300';

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $leases = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($leases as &$lease) {
        $lease['signatures'] = lease_signatures($conn, (int) $lease['id']);
    }
    unset($lease);

    echo json_encode($leases);
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'leases.manage');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $action = isset($data->action) && is_string($data->action) ? strtolower(trim($data->action)) : 'create';

    // -----------------------------------------------------------------------
    // Create a new draft version.
    // -----------------------------------------------------------------------
    if ($action === 'create') {
        $tenantId = filter_var($data->tenant_id ?? 0, FILTER_VALIDATE_INT);
        if ($tenantId === false || $tenantId < 1) {
            security_json_response(400, ['message' => 'A valid tenant is required.']);
        }

        $tenantStmt = $conn->prepare('SELECT id, unit_id FROM tenants WHERE id = :id LIMIT 1');
        $tenantStmt->execute([':id' => $tenantId]);
        $tenant = $tenantStmt->fetch(PDO::FETCH_ASSOC);
        if (!$tenant || empty($tenant['unit_id'])) {
            security_json_response(404, ['message' => 'Tenant not found or not linked to a unit.']);
        }

        $startDate = trim((string) ($data->start_date ?? ''));
        $endDate = trim((string) ($data->end_date ?? ''));
        $monthlyRent = filter_var($data->monthly_rent ?? null, FILTER_VALIDATE_FLOAT);
        $depositRequired = filter_var($data->deposit_required ?? 0, FILTER_VALIDATE_FLOAT);

        if (!lease_valid_date($startDate) || !lease_valid_date($endDate) || $endDate < $startDate) {
            security_json_response(400, ['message' => 'A valid lease start and end date are required.']);
        }
        if ($monthlyRent === false || $monthlyRent <= 0) {
            security_json_response(400, ['message' => 'A valid monthly rent is required.']);
        }
        if ($depositRequired === false || $depositRequired < 0) {
            security_json_response(400, ['message' => 'A valid deposit amount is required.']);
        }

        $documentUrl = lease_clean_document_url($data->document_url ?? null);
        $title = security_clean_text($data->title ?? '', 150);
        $templateReference = security_clean_text($data->template_reference ?? '', 150);
        $notes = security_clean_text($data->notes ?? '', 2000);

        try {
            $conn->beginTransaction();
            $leaseId = lease_create_draft(
                $conn,
                (int) $tenantId,
                (int) $tenant['unit_id'],
                $startDate,
                $endDate,
                (float) $monthlyRent,
                (float) $depositRequired,
                (int) $user->user_id,
                $title,
                $templateReference,
                $notes
            );

            if ($documentUrl !== null) {
                $conn->prepare('UPDATE leases SET document_url = :url WHERE id = :id')
                    ->execute([':url' => $documentUrl, ':id' => $leaseId]);
            }

            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('Lease creation failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The lease could not be created.']);
        }

        audit_log($conn, (int) $user->user_id, 'lease.created', [
            'entity_type' => 'lease',
            'entity_id' => $leaseId,
            'meta' => ['tenant_id' => (int) $tenantId],
        ]);

        security_json_response(201, ['message' => 'Lease version created.', 'id' => $leaseId]);
    }

    $leaseId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($leaseId === false || $leaseId < 1) {
        security_json_response(400, ['message' => 'A valid lease id is required.']);
    }

    $leaseStmt = $conn->prepare(
        "SELECT l.*, t.unit_id AS tenant_unit, t.name AS tenant_name, t.rent_due_day
         FROM leases l JOIN tenants t ON l.tenant_id = t.id
         WHERE l.id = :id LIMIT 1"
    );
    $leaseStmt->execute([':id' => $leaseId]);
    $lease = $leaseStmt->fetch(PDO::FETCH_ASSOC);

    if (!$lease) {
        security_json_response(404, ['message' => 'Lease not found.']);
    }

    // -----------------------------------------------------------------------
    // Update a lease that has not been finalised.
    // -----------------------------------------------------------------------
    if ($action === 'update') {
        if (!in_array($lease['status'], ['draft', 'pending_signature'], true)) {
            security_json_response(409, ['message' => 'Only a draft or unsigned lease can be edited. Create a new version instead.']);
        }

        $fields = [];
        $params = [':id' => $leaseId];

        if (isset($data->start_date)) {
            if (!lease_valid_date($data->start_date)) {
                security_json_response(400, ['message' => 'Invalid lease start date.']);
            }
            $fields[] = 'start_date = :start_date';
            $params[':start_date'] = $data->start_date;
        }
        if (isset($data->end_date)) {
            if (!lease_valid_date($data->end_date)) {
                security_json_response(400, ['message' => 'Invalid lease end date.']);
            }
            $fields[] = 'end_date = :end_date';
            $params[':end_date'] = $data->end_date;
        }
        if (isset($data->monthly_rent)) {
            $rent = filter_var($data->monthly_rent, FILTER_VALIDATE_FLOAT);
            if ($rent === false || $rent <= 0) {
                security_json_response(400, ['message' => 'Invalid monthly rent.']);
            }
            $fields[] = 'monthly_rent = :monthly_rent';
            $params[':monthly_rent'] = $rent;
        }
        if (isset($data->deposit_required)) {
            $deposit = filter_var($data->deposit_required, FILTER_VALIDATE_FLOAT);
            if ($deposit === false || $deposit < 0) {
                security_json_response(400, ['message' => 'Invalid deposit amount.']);
            }
            $fields[] = 'deposit_required = :deposit_required';
            $params[':deposit_required'] = $deposit;
        }
        if (isset($data->document_url)) {
            $fields[] = 'document_url = :document_url';
            $params[':document_url'] = lease_clean_document_url($data->document_url);
        }
        if (isset($data->title)) {
            $fields[] = 'title = :title';
            $params[':title'] = security_clean_text($data->title, 150) ?: null;
        }
        if (isset($data->template_reference)) {
            $fields[] = 'template_reference = :template_reference';
            $params[':template_reference'] = security_clean_text($data->template_reference, 150) ?: null;
        }
        if (isset($data->notes)) {
            $fields[] = 'notes = :notes';
            $params[':notes'] = security_clean_text($data->notes, 2000) ?: null;
        }

        if ($fields === []) {
            security_json_response(400, ['message' => 'Nothing to update.']);
        }

        $conn->prepare('UPDATE leases SET ' . implode(', ', $fields) . ' WHERE id = :id')->execute($params);

        audit_log($conn, (int) $user->user_id, 'lease.updated', [
            'entity_type' => 'lease',
            'entity_id' => $leaseId,
        ]);

        security_json_response(200, ['message' => 'Lease updated.']);
    }

    // -----------------------------------------------------------------------
    // Record a signature for one party.
    // -----------------------------------------------------------------------
    if ($action === 'sign') {
        if (in_array($lease['status'], ['superseded', 'expired', 'terminated'], true)) {
            security_json_response(409, ['message' => 'This lease version can no longer be signed.']);
        }

        $party = isset($data->party) && is_string($data->party) ? strtolower(trim($data->party)) : '';
        if (!in_array($party, ['tenant', 'landlord'], true)) {
            security_json_response(400, ['message' => 'Signature party must be tenant or landlord.']);
        }

        $signerName = security_clean_text($data->signer_name ?? '', 100);
        if ($signerName === '') {
            security_json_response(400, ['message' => 'The signer name is required.']);
        }

        $methodName = isset($data->method) && is_string($data->method) ? strtolower(trim($data->method)) : 'in_person';
        if (!in_array($methodName, ['in_person', 'electronic', 'scanned'], true)) {
            security_json_response(400, ['message' => 'Invalid signature method.']);
        }

        $evidenceUrl = lease_clean_document_url($data->evidence_url ?? null);
        $signedAt = trim((string) ($data->signed_at ?? ''));
        if ($signedAt === '') {
            $signedAt = date('Y-m-d H:i:s');
        } elseif (strtotime($signedAt) === false) {
            security_json_response(400, ['message' => 'Invalid signature date.']);
        }

        $stmt = $conn->prepare(
            "INSERT INTO lease_signatures (lease_id, party, signer_name, method, evidence_url, signed_at, recorded_by)
             VALUES (:lease_id, :party, :signer_name, :method, :evidence_url, :signed_at, :recorded_by)
             ON DUPLICATE KEY UPDATE
                signer_name = VALUES(signer_name),
                method = VALUES(method),
                evidence_url = VALUES(evidence_url),
                signed_at = VALUES(signed_at),
                recorded_by = VALUES(recorded_by)"
        );
        $stmt->execute([
            ':lease_id' => $leaseId,
            ':party' => $party,
            ':signer_name' => $signerName,
            ':method' => $methodName,
            ':evidence_url' => $evidenceUrl,
            ':signed_at' => date('Y-m-d H:i:s', strtotime($signedAt)),
            ':recorded_by' => (int) $user->user_id,
        ]);

        if ($lease['status'] === 'draft') {
            $conn->prepare("UPDATE leases SET status = 'pending_signature' WHERE id = :id")
                ->execute([':id' => $leaseId]);
        }

        audit_log($conn, (int) $user->user_id, 'lease.signed', [
            'entity_type' => 'lease',
            'entity_id' => $leaseId,
            'meta' => ['party' => $party, 'method' => $methodName],
        ]);

        security_json_response(200, ['message' => 'Signature recorded.']);
    }

    // -----------------------------------------------------------------------
    // Activate: supersede the previous active version and apply the terms.
    // -----------------------------------------------------------------------
    if ($action === 'activate') {
        if (!in_array($lease['status'], ['draft', 'pending_signature'], true)) {
            security_json_response(409, ['message' => 'Only a draft or pending-signature lease can be activated.']);
        }

        $signatureCount = (int) $conn->query('SELECT COUNT(*) FROM lease_signatures WHERE lease_id = ' . (int) $leaseId)->fetchColumn();
        if (empty($lease['document_url']) && $signatureCount === 0) {
            security_json_response(409, [
                'message' => 'Upload the signed lease document or record a signature before activating it.',
            ]);
        }

        try {
            $conn->beginTransaction();

            $conn->prepare(
                "UPDATE leases SET status = 'superseded'
                 WHERE tenant_id = :tenant_id AND id <> :id AND status = 'active'"
            )->execute([':tenant_id' => (int) $lease['tenant_id'], ':id' => $leaseId]);

            $conn->prepare(
                "UPDATE leases SET status = 'active', activated_at = NOW() WHERE id = :id"
            )->execute([':id' => $leaseId]);

            $conn->prepare(
                "UPDATE tenants
                 SET status = 'active', lease_start = :start_date, lease_end = :end_date,
                     monthly_rent = :monthly_rent, deposit = :deposit
                 WHERE id = :tenant_id"
            )->execute([
                ':start_date' => $lease['start_date'],
                ':end_date' => $lease['end_date'],
                ':monthly_rent' => $lease['monthly_rent'],
                ':deposit' => $lease['deposit_required'],
                ':tenant_id' => (int) $lease['tenant_id'],
            ]);

            $conn->prepare("UPDATE units SET status = 'Occupied' WHERE id = :unit_id AND archived_at IS NULL")
                ->execute([':unit_id' => (int) $lease['unit_id']]);

            // Rent obligations are generated from the activated lease terms,
            // using the tenant's individual contractual due day.
            rent_generate_obligations(
                $conn,
                (int) $lease['tenant_id'],
                (int) $lease['unit_id'],
                (int) $leaseId,
                (string) $lease['start_date'],
                (string) $lease['end_date'],
                (float) $lease['monthly_rent'],
                !empty($lease['rent_due_day']) ? (int) $lease['rent_due_day'] : 1
            );

            $conn->commit();
        } catch (Throwable $e) {
            if ($conn->inTransaction()) {
                $conn->rollBack();
            }
            error_log('Lease activation failed: ' . $e->getMessage());
            security_json_response(500, ['message' => 'The lease could not be activated.']);
        }

        audit_log($conn, (int) $user->user_id, 'lease.activated', [
            'entity_type' => 'lease',
            'entity_id' => $leaseId,
            'meta' => ['tenant_id' => (int) $lease['tenant_id'], 'version' => (int) $lease['version']],
        ]);

        security_json_response(200, ['message' => 'Lease activated.']);
    }

    // -----------------------------------------------------------------------
    // Delete an unsigned draft.
    // -----------------------------------------------------------------------
    if ($action === 'delete') {
        if ($lease['status'] !== 'draft') {
            security_json_response(409, ['message' => 'Only an unactivated draft can be deleted.']);
        }
        $signatureCount = (int) $conn->query('SELECT COUNT(*) FROM lease_signatures WHERE lease_id = ' . (int) $leaseId)->fetchColumn();
        if ($signatureCount > 0) {
            security_json_response(409, ['message' => 'A signed lease cannot be deleted.']);
        }

        $conn->prepare('DELETE FROM leases WHERE id = :id')->execute([':id' => $leaseId]);

        audit_log($conn, (int) $user->user_id, 'lease.deleted', [
            'entity_type' => 'lease',
            'entity_id' => $leaseId,
            'meta' => ['tenant_id' => (int) $lease['tenant_id']],
        ]);

        security_json_response(200, ['message' => 'Draft lease deleted.']);
    }

    security_json_response(400, ['message' => 'Unsupported action.']);
}

security_json_response(405, ['message' => 'Method not allowed.']);
