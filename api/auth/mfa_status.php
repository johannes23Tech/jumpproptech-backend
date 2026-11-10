<?php
// GET /api/auth/mfa_status.php - is MFA enabled for the current account?
require_once '../../config/db.php';
require_once '../../config/security.php';
require_once '../../config/mfa.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
$state = mfa_user_state($conn, (int) $user->user_id);

if ($state === null) {
    security_json_response(503, ["message" => "Security settings are temporarily unavailable."]);
}

security_json_response(200, [
    "enabled" => !empty($state['enabled']),
    "recovery_codes_remaining" => count($state['recovery_codes']),
]);
