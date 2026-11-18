<?php
// api/public/onboarding.php
//
// Public, unauthenticated QR onboarding endpoint.
//
// GET  ?token=<raw>   -> minimal unit/property context for the application page
// POST { token, ... } -> submit one tenant application for that unit
//
// Security rules:
//   * only a SHA-256 hash of the token is stored and looked up
//   * tokens are single-use, expire, and can be revoked by staff
//   * the response never exposes tenant records, staff data or company finance
//   * rate-limited per client IP; no employment or income fields are accepted

require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/audit.php';
require_once '../../config/onboarding.php';

$method = $_SERVER['REQUEST_METHOD'];
$ip = security_client_ip();

// ---------------------------------------------------------------------------
// GET: resolve a QR token to the unit context. Never consumes the token.
// ---------------------------------------------------------------------------
if ($method === 'GET') {
    $retry = security_rate_limit_retry($conn, 'onboard_lookup', $ip);
    if ($retry > 0) {
        security_json_response(429, ['message' => 'Please wait before trying again.'], ['Retry-After' => (string) $retry]);
    }
    security_rate_limit_hit($conn, 'onboard_lookup', $ip, 120, 3600, 900);

    $token = isset($_GET['token']) && is_string($_GET['token']) ? trim($_GET['token']) : '';
    $unit = onboarding_find_active_token($conn, $token);

    if ($unit === null) {
        security_json_response(404, [
            'message' => 'This onboarding link is invalid, expired or already used. Please ask the office for a new QR code.',
        ]);
    }

    echo json_encode([
        'valid' => true,
        'property_name' => $unit['property_name'],
        'building_name' => $unit['building_name'] ?? null,
        'unit_number' => $unit['unit_number'],
        'monthly_rent' => (float) $unit['monthly_rent'],
        'expires_at' => $unit['expires_at'],
    ]);
    exit();
}

// ---------------------------------------------------------------------------
// POST: submit a first-time application.
// ---------------------------------------------------------------------------
if ($method === 'POST') {
    $retry = security_rate_limit_retry($conn, 'onboard_apply', $ip);
    if ($retry > 0) {
        security_json_response(429, ['message' => 'Too many applications from this connection. Please try again later.'], ['Retry-After' => (string) $retry]);
    }
    if (security_rate_limit_hit($conn, 'onboard_apply', $ip, 10, 3600, 1800) > 0) {
        security_json_response(429, ['message' => 'Too many applications from this connection. Please try again later.']);
    }

    $data = json_decode(file_get_contents('php://input'));
    if (!is_object($data)) {
        security_json_response(400, ['message' => 'Invalid request body.']);
    }

    $token = isset($data->token) && is_string($data->token) ? trim($data->token) : '';
    $unit = onboarding_find_active_token($conn, $token);
    if ($unit === null) {
        security_json_response(404, [
            'message' => 'This onboarding link is invalid, expired or already used. Please ask the office for a new QR code.',
        ]);
    }

    $fullName = security_clean_text($data->full_name ?? '', 100);
    $email = strtolower(trim((string) ($data->email ?? '')));
    $phone = security_clean_text($data->phone ?? '', 20);
    $idNumber = security_clean_text($data->id_number ?? '', 50);
    $emergencyName = security_clean_text($data->emergency_contact_name ?? '', 100);
    $emergencyPhone = security_clean_text($data->emergency_contact_phone ?? '', 20);
    $notes = security_clean_text($data->notes ?? '', 2000);
    $occupants = filter_var($data->occupants ?? 1, FILTER_VALIDATE_INT);

    if ($fullName === '' || !security_is_email($email) || $phone === '') {
        security_json_response(400, ['message' => 'Full name, a valid email address and a phone number are required.']);
    }

    if ($occupants === false || $occupants < 1 || $occupants > 20) {
        security_json_response(400, ['message' => 'Number of occupants must be between 1 and 20.']);
    }

    $password = isset($data->password) && is_string($data->password) ? $data->password : '';
    $policyError = security_validate_password($password);
    if ($policyError !== null) {
        security_json_response(400, ['message' => $policyError]);
    }

    // An existing account must sign in instead of creating a second account.
    $emailCheck = $conn->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $emailCheck->execute([':email' => $email]);
    if ($emailCheck->fetchColumn() !== false) {
        audit_log($conn, null, 'application.submitted', [
            'actor_email' => $email,
            'outcome' => 'failure',
            'meta' => ['reason' => 'email_already_registered', 'unit_id' => (int) $unit['unit_id']],
        ]);
        security_json_response(409, [
            'message' => 'This email cannot be used for a new application. Please sign in or contact the office.',
        ]);
    }

    // One open application per person per unit.
    $openCheck = $conn->prepare(
        "SELECT id FROM tenant_applications
         WHERE unit_id = :unit_id AND email = :email AND status IN ('submitted', 'reviewing')
         LIMIT 1"
    );
    $openCheck->execute([':unit_id' => $unit['unit_id'], ':email' => $email]);
    if ($openCheck->fetchColumn() !== false) {
        security_json_response(409, ['message' => 'You already have an application in progress for this unit.']);
    }

    $documents = onboarding_clean_documents($data->documents ?? []);

    try {
        $conn->beginTransaction();

        $insert = $conn->prepare(
            "INSERT INTO tenant_applications
                (unit_id, token_id, full_name, email, phone, password_hash, id_number,
                 emergency_contact_name, emergency_contact_phone, occupants, notes)
             VALUES
                (:unit_id, :token_id, :full_name, :email, :phone, :password_hash, :id_number,
                 :emergency_name, :emergency_phone, :occupants, :notes)"
        );
        $insert->execute([
            ':unit_id' => $unit['unit_id'],
            ':token_id' => $unit['token_id'],
            ':full_name' => $fullName,
            ':email' => $email,
            ':phone' => $phone,
            ':password_hash' => security_hash_password($password),
            ':id_number' => $idNumber !== '' ? $idNumber : null,
            ':emergency_name' => $emergencyName !== '' ? $emergencyName : null,
            ':emergency_phone' => $emergencyPhone !== '' ? $emergencyPhone : null,
            ':occupants' => $occupants,
            ':notes' => $notes !== '' ? $notes : null,
        ]);
        $applicationId = (int) $conn->lastInsertId();

        if ($documents !== []) {
            $docStmt = $conn->prepare(
                'INSERT INTO application_documents (application_id, document_type, file_url)
                 VALUES (:application_id, :type, :url)'
            );
            foreach ($documents as $document) {
                $docStmt->execute([
                    ':application_id' => $applicationId,
                    ':type' => $document['type'],
                    ':url' => $document['url'],
                ]);
            }
        }

        // The QR link is first-time only: consume it with the application.
        $conn->prepare('UPDATE onboarding_tokens SET used_at = NOW() WHERE id = :id')
            ->execute([':id' => $unit['token_id']]);

        $conn->commit();
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Application submission failed: ' . $e->getMessage());
        security_json_response(500, ['message' => 'Your application could not be submitted. Please try again.']);
    }

    audit_log($conn, null, 'application.submitted', [
        'actor_email' => $email,
        'entity_type' => 'tenant_application',
        'entity_id' => $applicationId,
        'meta' => ['unit_id' => (int) $unit['unit_id'], 'documents' => count($documents)],
    ]);

    security_json_response(201, [
        'message' => 'Application submitted. Management will review it and contact you.',
        'reference' => 'APP-' . str_pad((string) $applicationId, 6, '0', STR_PAD_LEFT),
    ]);
}

security_json_response(405, ['message' => 'Method not allowed.']);
