<?php
// config/permissions.php
//
// Central authorization vocabulary for JUMP PROPTECH.
//
// The target product has eight staff roles plus tenants. The legacy schema
// still stores five account roles (superadmin, landlord, agent, maintenance,
// tenant). This file maps the legacy roles onto the approved staff roles while
// new accounts are created with an explicit staff_role.
//
// Rules:
// - Permissions are additive and deny-by-default.
// - The database is the source of truth; never trust a role in a JWT.
// - Hiding a button in the UI is not authorization. Call permission_require()
//   on the server before serving or mutating protected data.

require_once __DIR__ . '/security.php';

const JPT_STAFF_ROLES = [
    'super_administrator',
    'administrator',
    'property_manager',
    'finance_accountant',
    'maintenance_manager',
    'maintenance_technician',
    'reception_support',
    'auditor',
];

const JPT_STAFF_ROLE_LABELS = [
    'super_administrator' => 'Super Administrator',
    'administrator' => 'Administrator',
    'property_manager' => 'Property Manager',
    'finance_accountant' => 'Finance / Accountant',
    'maintenance_manager' => 'Maintenance Manager',
    'maintenance_technician' => 'Maintenance Technician',
    'reception_support' => 'Reception / Support',
    'auditor' => 'Auditor (read-only)',
    'tenant' => 'Tenant',
];

// Legacy users.role -> approved staff role.
const JPT_LEGACY_STAFF_ROLE_MAP = [
    'superadmin' => 'super_administrator',
    'admin' => 'administrator',
    'super admin' => 'super_administrator',
    'landlord' => 'property_manager',
    'agent' => 'property_manager',
    'maintenance' => 'maintenance_technician',
];

// Approved permissions per staff role. `*` grants every permission.
// Keep this aligned with docs/PERMISSIONS.md.
const JPT_ROLE_PERMISSIONS = [
    'super_administrator' => ['*'],
    'administrator' => [
        'staff.view', 'staff.manage', 'settings.manage', 'audit.view',
        'properties.view', 'properties.manage', 'units.view', 'units.manage',
        'tenants.view', 'tenants.manage', 'applications.view', 'applications.review',
        'leases.view', 'leases.manage', 'deposits.view', 'deposits.manage',
        'contracts.view', 'contracts.manage', 'templates.manage',
        'payments.view', 'payments.record_cash', 'payments.verify_eft', 'payments.reconcile',
        'payments.reverse', 'arrears.view', 'arrears.apply_penalty',
        'maintenance.view', 'maintenance.create', 'maintenance.triage',
        'maintenance.assign', 'maintenance.update',
        'expenses.view', 'expenses.submit', 'expenses.approve',
        'suppliers.view', 'suppliers.manage', 'budgets.view', 'budgets.manage', 'utilities.view', 'utilities.manage',
        'reports.view', 'reports.export', 'notifications.view', 'notifications.manage',
        'flux.use', 'qr.manage', 'messages.view', 'messages.send',
    ],
    'property_manager' => [
        'properties.view', 'properties.manage', 'units.view', 'units.manage',
        'tenants.view', 'tenants.manage', 'applications.view', 'applications.review',
        'leases.view', 'leases.manage', 'deposits.view', 'deposits.manage',
        'contracts.view', 'contracts.manage',
        'payments.view', 'arrears.view',
        'maintenance.view', 'maintenance.create', 'maintenance.triage', 'maintenance.assign',
        'expenses.view', 'expenses.submit',
        'suppliers.view', 'budgets.view',
        'utilities.view', 'utilities.manage',
        'reports.view', 'reports.export', 'notifications.view',
        'flux.use', 'qr.manage', 'messages.view', 'messages.send',
    ],
    'finance_accountant' => [
        'properties.view', 'units.view', 'tenants.view',
        'leases.view', 'deposits.view', 'deposits.manage',
        'contracts.view',
        'payments.view', 'payments.record_cash', 'payments.verify_eft', 'payments.reconcile',
        'payments.reverse', 'arrears.view', 'arrears.apply_penalty',
        'expenses.view', 'expenses.submit', 'expenses.approve',
        'suppliers.view', 'suppliers.manage', 'budgets.view', 'budgets.manage', 'utilities.view',
        'reports.view', 'reports.export', 'notifications.view',
        'flux.use', 'messages.view', 'messages.send',
    ],
    'maintenance_manager' => [
        'properties.view', 'units.view', 'tenants.view',
        'maintenance.view', 'maintenance.create', 'maintenance.triage',
        'maintenance.assign', 'maintenance.update',
        'expenses.view', 'expenses.submit',
        'suppliers.view', 'budgets.view',
        'utilities.view', 'utilities.manage',
        'reports.view', 'notifications.view',
        'flux.use', 'messages.view', 'messages.send',
    ],
    'maintenance_technician' => [
        'properties.view', 'units.view',
        'maintenance.view', 'maintenance.update',
        'suppliers.view',
        'notifications.view', 'messages.view', 'messages.send',
    ],
    'reception_support' => [
        'properties.view', 'units.view', 'tenants.view',
        'applications.view', 'applications.review',
        'contracts.view',
        'maintenance.view', 'maintenance.create',
        'suppliers.view', 'budgets.view',
        'utilities.view',
        'reports.view',
        'notifications.view', 'messages.view', 'messages.send',
    ],
    'auditor' => [
        'properties.view', 'units.view', 'tenants.view',
        'applications.view', 'leases.view', 'deposits.view',
        'contracts.view',
        'payments.view', 'arrears.view', 'maintenance.view',
        'expenses.view', 'suppliers.view', 'budgets.view',
        'utilities.view', 'reports.view', 'audit.view',
        'notifications.view', 'messages.view',
    ],
    'tenant' => [],
];

/**
 * The approved role for a database user row.
 *
 * @param array<string,mixed> $user Row containing role and (optionally) staff_role.
 */
function permission_role_for_user(array $user): string
{
    $staffRole = isset($user['staff_role']) ? (string) $user['staff_role'] : '';
    if ($staffRole !== '' && in_array($staffRole, JPT_STAFF_ROLES, true)) {
        return $staffRole;
    }

    $legacy = isset($user['role']) ? (string) $user['role'] : '';
    if ($legacy === 'tenant') {
        return 'tenant';
    }

    return JPT_LEGACY_STAFF_ROLE_MAP[$legacy] ?? 'unknown';
}

/**
 * A tenant account is never treated as staff, even if a staff_role was set
 * by mistake.
 */
function permission_is_staff(array $user): bool
{
    $accountType = isset($user['account_type']) ? (string) $user['account_type'] : '';
    if ($accountType === 'tenant') {
        return false;
    }
    if (($user['role'] ?? '') === 'tenant') {
        return false;
    }

    return in_array(permission_role_for_user($user), JPT_STAFF_ROLES, true);
}

/**
 * @param array<string,mixed> $user
 */
function permission_can(array $user, string $permission): bool
{
    if (!permission_is_staff($user)) {
        return false;
    }

    $role = permission_role_for_user($user);
    $granted = JPT_ROLE_PERMISSIONS[$role] ?? [];

    return in_array('*', $granted, true) || in_array($permission, $granted, true);
}

/**
 * @param array<string,mixed> $user
 */
function permission_require(array $user, string $permission): void
{
    if (!permission_can($user, $permission)) {
        security_json_response(403, [
            'message' => 'Unauthorized. You do not have permission to perform this action.',
        ]);
    }
}

/**
 * Super Administrator-only access for Control Center (tech/sensitive) features.
 *
 * @param array<string,mixed> $user
 */
function permission_require_super_admin(array $user): void
{
    if (!permission_is_staff($user) || permission_role_for_user($user) !== 'super_administrator') {
        security_json_response(403, [
            'message' => 'Unauthorized. Super Administrator access required.',
        ]);
    }
}

/**
 * Map an approved staff role to the legacy users.role value that the existing
 * endpoint compatibility layer still understands.
 *
 * IMPORTANT: users.role may be a legacy ENUM in some databases (e.g.
 * landlord/agent/tenant/maintenance/superadmin). Always return a value that is
 * valid for that column; canonical authorization uses staff_role.
 */
function permission_legacy_role_for_staff(string $staffRole): string
{
    $map = [
        'super_administrator' => 'superadmin',
        // 'admin' is not present in some legacy role ENUMs; use 'landlord' as a
        // safe, DB-compatible legacy bucket while staff_role remains canonical.
        'administrator' => 'landlord',
        'property_manager' => 'landlord',
        'finance_accountant' => 'landlord',
        'maintenance_manager' => 'landlord',
        'maintenance_technician' => 'maintenance',
        'reception_support' => 'agent',
        'auditor' => 'landlord',
    ];

    return $map[$staffRole] ?? 'landlord';
}

/**
 * Safe user payload for login responses. The `role` field is the approved
 * role so the frontend does not need to know about legacy names.
 *
 * @param array<string,mixed> $user
 * @return array<string,mixed>
 */
function permission_user_payload(array $user): array
{
    $role = permission_role_for_user($user);
    $isStaff = permission_is_staff($user);
    $granted = $isStaff ? (JPT_ROLE_PERMISSIONS[$role] ?? []) : [];

    return [
        'id' => (int) ($user['id'] ?? 0),
        'full_name' => (string) ($user['full_name'] ?? ''),
        'email' => (string) ($user['email'] ?? ''),
        'role' => $role,
        'staff_role' => $isStaff ? $role : null,
        'account_type' => $isStaff ? 'staff' : 'tenant',
        'permissions' => $granted === ['*'] ? ['*'] : array_values($granted),
    ];
}
