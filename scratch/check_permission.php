<?php
require_once __DIR__ . '/../config/permissions.php';

function test_user($role, $staff_role=null, $account_type='staff') {
    $user = [
        'role' => $role,
        'staff_role' => $staff_role ?? '',
        'account_type' => $account_type,
        'user_id' => 1,
    ];
    $can = permission_can($user, 'properties.manage');
    echo "User role=$role, staff_role={$user['staff_role']} => ".($can?'CAN':'CANNOT')." manage properties\n";
}

test_user('admin');
test_user('superadmin');
test_user('landlord');
?>