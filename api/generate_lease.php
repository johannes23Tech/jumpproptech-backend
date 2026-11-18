<?php
// api/generate_lease.php
//
// Retired in Phase 2.
//
// The previous implementation generated a lease PDF containing clause wording
// invented by the platform. The approved specification requires lease templates
// and legal wording to be supplied and approved by management and reviewed by a
// qualified South African legal professional. The platform therefore stores and
// versions management-supplied lease documents via /api/leases.php instead of
// generating legal text.
//
// This endpoint is kept only to return a clear, non-destructive response to
// older clients.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;

permission_require($actor, 'leases.view');

security_json_response(410, [
    'message' => 'Generated lease PDFs are retired. Upload the management-approved lease document on the Leases screen instead.',
]);
