<?php
// api/inspections.php
//
// Move-in, move-out and routine inspection records with supporting photos.
//
// GET   list inspections, optionally by tenant (permission: leases.view)
// POST  create an inspection with photos (permission: leases.manage)
// PATCH update notes/date or complete an inspection (permission: leases.manage)

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$method = $_SERVER['REQUEST_METHOD'];

if (!permission_is_staff($actor)) {
    security_json_response(403, ['message' => 'Unauthorized. Staff access required.']);
}

/**
 * Validate an inspection photo payload.
 *
 * @param mixed $photos
 * @return array<int,array{url:string,caption:?string}>
 */
function inspection_clean_photos($photos): array
{
    if (!is_array($photos)) {
        return [];
    }

    $clean = [];
    foreach (array_slice($photos, 0, 12) as $photo) {
        if (!is_object($photo) && !is_array($photo)) {
            continue;
        }
        $photo = (array) $photo;
        $url = isset($photo['url']) && is_string($photo['url']) ? trim($photo['url']) : '';
        if ($url === '' || strlen($url) > 500 || strpos($url, 'https://res.cloudinary.com/') !== 0) {
            continue;
        }
        $caption = isset($photo['caption']) && is_string($photo['caption'])
            ? security_clean_text($photo['caption'], 150)
            : '';
        $clean[] = ['url' => $url, 'caption' => $caption !== '' ? $caption : null];
    }

    return $clean;
}

function inspection_photos_for(PDO $conn, int $inspectionId): array
{
    $stmt = $conn->prepare(
        'SELECT id, file_url AS url, caption, created_at
         FROM inspection_photos WHERE inspection_id = :id ORDER BY id ASC'
    );
    $stmt->execute([':id' => $inspectionId]);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

if ($method === 'GET') {
    permission_require($actor, 'leases.view');

    $tenantId = filter_var($_GET['tenant_id'] ?? 0, FILTER_VALIDATE_INT);

    $sql = "SELECT i.*, t.name AS tenant_name, u.unit_number, p.name AS property_name,
                   (SELECT COUNT(*) FROM inspection_photos ph WHERE ph.inspection_id = i.id) AS photo_count
            FROM inspections i
            JOIN tenants t ON i.tenant_id = t.id
            JOIN units u ON i.unit_id = u.id
            JOIN properties p ON u.property_id = p.id";
    $params = [];

    if ($tenantId !== false && $tenantId !== null && $tenantId > 0) {
        $sql .= ' WHERE i.tenant_id = :tenant_id';
        $params[':tenant_id'] = (int) $tenantId;
    }
    $sql .= ' ORDER BY i.id DESC LIMIT 200';

    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $inspections = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($inspections as &$inspection) {
        $inspection['photos'] = inspection_photos_for($conn, (int) $inspection['id']);
    }
    unset($inspection);

    echo json_encode($inspections);
    exit();
}

if ($method === 'POST') {
    permission_require($actor, 'leases.manage');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

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

    $type = isset($data->type) && is_string($data->type) ? strtolower(trim($data->type)) : '';
    if (!in_array($type, ['move_in', 'move_out', 'routine'], true)) {
        security_json_response(400, ['message' => 'Inspection type must be move_in, move_out or routine.']);
    }

    $inspectedAt = trim((string) ($data->inspected_at ?? ''));
    if ($inspectedAt === '') {
        $inspectedAt = date('Y-m-d');
    } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $inspectedAt)) {
        security_json_response(400, ['message' => 'Invalid inspection date.']);
    }

    $notes = security_clean_text($data->notes ?? '', 4000);
    $status = isset($data->status) && $data->status === 'completed' ? 'completed' : 'draft';
    $photos = inspection_clean_photos($data->photos ?? []);

    $leaseId = filter_var($data->lease_id ?? 0, FILTER_VALIDATE_INT);
    $leaseId = ($leaseId !== false && $leaseId !== null && $leaseId > 0) ? (int) $leaseId : null;

    try {
        $conn->beginTransaction();

        $stmt = $conn->prepare(
            "INSERT INTO inspections
                (tenant_id, unit_id, lease_id, type, status, inspected_at, inspected_by, notes, created_by, completed_at)
             VALUES
                (:tenant_id, :unit_id, :lease_id, :type, :status, :inspected_at, :inspected_by, :notes, :created_by, :completed_at)"
        );
        $stmt->execute([
            ':tenant_id' => (int) $tenantId,
            ':unit_id' => (int) $tenant['unit_id'],
            ':lease_id' => $leaseId,
            ':type' => $type,
            ':status' => $status,
            ':inspected_at' => $inspectedAt,
            ':inspected_by' => (int) $user->user_id,
            ':notes' => $notes !== '' ? $notes : null,
            ':created_by' => (int) $user->user_id,
            ':completed_at' => $status === 'completed' ? date('Y-m-d H:i:s') : null,
        ]);
        $inspectionId = (int) $conn->lastInsertId();

        if ($photos !== []) {
            $photoStmt = $conn->prepare(
                'INSERT INTO inspection_photos (inspection_id, file_url, caption)
                 VALUES (:inspection_id, :url, :caption)'
            );
            foreach ($photos as $photo) {
                $photoStmt->execute([
                    ':inspection_id' => $inspectionId,
                    ':url' => $photo['url'],
                    ':caption' => $photo['caption'],
                ]);
            }
        }

        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Inspection creation failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The inspection could not be saved.']);
    }

    audit_log($conn, (int) $user->user_id, 'inspection.created', [
        'entity_type' => 'inspection',
        'entity_id' => $inspectionId,
        'meta' => ['tenant_id' => (int) $tenantId, 'type' => $type, 'photos' => count($photos)],
    ]);

    security_json_response(201, [
        'message' => 'Inspection saved.',
        'id' => $inspectionId,
        'photos' => inspection_photos_for($conn, $inspectionId),
    ]);
}

if ($method === 'PATCH') {
    permission_require($actor, 'leases.manage');

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $inspectionId = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($inspectionId === false || $inspectionId < 1) {
        security_json_response(400, ['message' => 'A valid inspection id is required.']);
    }

    $stmt = $conn->prepare('SELECT * FROM inspections WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => $inspectionId]);
    $inspection = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$inspection) {
        security_json_response(404, ['message' => 'Inspection not found.']);
    }

    $fields = [];
    $params = [':id' => $inspectionId];

    if (isset($data->notes)) {
        $fields[] = 'notes = :notes';
        $params[':notes'] = security_clean_text($data->notes, 4000) ?: null;
    }
    if (isset($data->inspected_at)) {
        if (!is_string($data->inspected_at) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $data->inspected_at)) {
            security_json_response(400, ['message' => 'Invalid inspection date.']);
        }
        $fields[] = 'inspected_at = :inspected_at';
        $params[':inspected_at'] = $data->inspected_at;
    }
    if (isset($data->status)) {
        $status = is_string($data->status) ? strtolower(trim($data->status)) : '';
        if (!in_array($status, ['draft', 'completed'], true)) {
            security_json_response(400, ['message' => 'Invalid inspection status.']);
        }
        $fields[] = 'status = :status';
        $params[':status'] = $status;
        $fields[] = 'completed_at = ' . ($status === 'completed' ? 'NOW()' : 'NULL');
    }

    try {
        $conn->beginTransaction();

        if ($fields !== []) {
            $conn->prepare('UPDATE inspections SET ' . implode(', ', $fields) . ' WHERE id = :id')->execute($params);
        }

        $photos = inspection_clean_photos($data->photos ?? []);
        if ($photos !== []) {
            $photoStmt = $conn->prepare(
                'INSERT INTO inspection_photos (inspection_id, file_url, caption)
                 VALUES (:inspection_id, :url, :caption)'
            );
            foreach ($photos as $photo) {
                $photoStmt->execute([
                    ':inspection_id' => $inspectionId,
                    ':url' => $photo['url'],
                    ':caption' => $photo['caption'],
                ]);
            }
        }

        if ($fields === [] && $photos === []) {
            $conn->rollBack();
            security_json_response(400, ['message' => 'Nothing to update.']);
        }

        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Inspection update failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'The inspection could not be updated.']);
    }

    audit_log($conn, (int) $user->user_id, 'inspection.updated', [
        'entity_type' => 'inspection',
        'entity_id' => $inspectionId,
        'meta' => ['status' => $data->status ?? null],
    ]);

    security_json_response(200, ['message' => 'Inspection updated.', 'photos' => inspection_photos_for($conn, $inspectionId)]);
}

security_json_response(405, ['message' => 'Method not allowed.']);
