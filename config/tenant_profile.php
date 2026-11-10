<?php
// config/tenant_profile.php
// Helpers for tenant profile provisioning.
//
// A tenant who self-registers has a user account but no `tenants` row until a
// landlord links them to a unit. Provisioning that row lazily lets the tenant
// complete their personal/emergency details first; the lease columns
// (owner_id, unit_id, lease_start, lease_end) stay NULL until a unit is
// assigned. See migrations/2026-11-10_tenant_profile.sql.

require_once __DIR__ . '/security.php';

/**
 * Fetch the tenant row that belongs to a user, if it exists.
 */
function tenant_profile_fetch(PDO $conn, int $userId): ?array
{
    $stmt = $conn->prepare(
        "SELECT * FROM tenants WHERE user_id = :user_id ORDER BY id ASC LIMIT 1"
    );
    $stmt->execute([':user_id' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return $row ?: null;
}

/**
 * Return the tenant row for a user, creating an unlinked profile row on first
 * use. Name, email and phone are seeded from the account so the profile is
 * usable before a lease exists.
 *
 * Returns null only when the user account itself is missing or the row could
 * not be created.
 */
function tenant_profile_ensure(PDO $conn, int $userId): ?array
{
    $tenant = tenant_profile_fetch($conn, $userId);
    if ($tenant !== null) {
        return $tenant;
    }

    $stmt = $conn->prepare(
        "SELECT full_name, email, phone FROM users WHERE id = :id LIMIT 1"
    );
    $stmt->execute([':id' => $userId]);
    $account = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$account) {
        return null;
    }

    try {
        // Native prepares reject a reused placeholder, so the guard uses a
        // second name. The NOT EXISTS clause makes the insert idempotent when
        // two requests race on the same account.
        $stmt = $conn->prepare(
            "INSERT INTO tenants (user_id, name, email, phone)
             SELECT :user_id, :name, :email, :phone
             FROM DUAL
             WHERE NOT EXISTS (
                 SELECT 1 FROM tenants WHERE user_id = :user_id_check
             )"
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':name' => security_clean_text($account['full_name'] ?? '', 100),
            ':email' => (string) ($account['email'] ?? ''),
            ':phone' => security_clean_text($account['phone'] ?? '', 20),
            ':user_id_check' => $userId,
        ]);
    } catch (Throwable $e) {
        error_log('Tenant profile provisioning failed: ' . $e->getMessage());
    }

    return tenant_profile_fetch($conn, $userId);
}
