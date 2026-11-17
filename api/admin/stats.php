<?php
// api/admin/stats.php
//
// Internal system overview for authorised administrators. The retired SaaS
// subscription metrics are no longer returned as the primary figures.

require_once '../../config/db.php';
require_once '../../config/permissions.php';
require_once '../../middleware/check_role.php';

$user = authenticate();
permission_require((array) $user, 'settings.manage');

$staff = (int) $conn->query("SELECT COUNT(*) FROM users WHERE role <> 'tenant'")->fetchColumn();
$properties = (int) $conn->query("SELECT COUNT(*) FROM properties")->fetchColumn();
$units = (int) $conn->query("SELECT COUNT(*) FROM units")->fetchColumn();
$rent = $conn->query("SELECT SUM(amount) FROM rent_records WHERE status = 'Paid'")->fetchColumn();

$recentStaff = $conn->query(
    "SELECT id, full_name, email, created_at, role, staff_role, is_active
     FROM users
     WHERE role <> 'tenant'
     ORDER BY created_at DESC
     LIMIT 5"
)->fetchAll(PDO::FETCH_ASSOC);

echo json_encode([
    // total_landlords is kept as a compatibility alias for older clients.
    "total_staff" => $staff,
    "total_landlords" => $staff,
    "total_properties" => $properties,
    "total_units" => $units,
    "total_rent_processed" => $rent ?: 0,
    "recent_signups" => $recentStaff,
]);
