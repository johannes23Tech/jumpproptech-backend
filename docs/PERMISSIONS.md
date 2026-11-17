# JUMP PROPTECH — Roles and Permissions

**Version:** Phase 0 baseline
**Updated:** 17 November 2026
**Status:** Implemented in `config/permissions.php`; endpoint coverage is being migrated incrementally.

This matrix is the server-side contract. Hiding a button is not authorization. Every protected endpoint must call `authenticate()` and then either `permission_require()` or an explicit, documented role check.

## Account types

| Account type | Purpose |
| --- | --- |
| `staff` | Internal JUMP PROPTECH employee |
| `tenant` | Renter, restricted to their own records |

## Staff roles

| Code | Display name |
| --- | --- |
| `super_administrator` | Super Administrator |
| `administrator` | Administrator |
| `property_manager` | Property Manager |
| `finance_accountant` | Finance / Accountant |
| `maintenance_manager` | Maintenance Manager |
| `maintenance_technician` | Maintenance Technician |
| `reception_support` | Reception / Support |
| `auditor` | Auditor (read-only) |

## Capability matrix

Legend: **M** = manage, **V** = view, **A** = assigned/limited, — = no access.

| Capability | Super Admin | Admin | Property Manager | Finance | Maint. Manager | Technician | Reception | Auditor |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Staff accounts | M | M | — | — | — | — | — | — |
| Company settings | M | M | — | — | — | — | — | — |
| Audit log | V | V | — | — | — | — | — | V |
| Properties / units | M | M | M | V | V | V | V | V |
| Tenants | M | M | M | V | V | — | V | V |
| Applications / QR | M | M | M | — | — | — | M | V |
| Leases / deposits | M | M | M | V | — | — | — | V |
| Cash payments | M | M | — | M | — | — | — | V |
| EFT verification / reconciliation | M | M | — | M | — | — | — | V |
| Payment reversal | M | M | — | M | — | — | — | — |
| Arrears / late penalties | M | M | V | M | — | — | — | V |
| Maintenance requests | M | M | M | V | M | A | M | V |
| Expenses | M | M | Submit + view | M + approve | Submit + view | — | — | V |
| Suppliers / budgets | M | M | — | M | — | — | — | V |
| Utilities / meters | M | M | M | V | M | — | V | V |
| Reports / exports | M | M | M | M | M | — | V | V |
| Notifications | M | M | V | V | V | V | V | V |
| Messages | M | M | M | M | M | M | M | V |
| JUMP FLUX | M | M | M | M | M | — | — | V (read) |

## Legacy role mapping

The database still contains legacy `users.role` values. `permission_role_for_user()` maps them until every account is migrated:

| Legacy `role` | Approved staff role |
| --- | --- |
| `superadmin` | `super_administrator` |
| `landlord` | `property_manager` |
| `agent` | `property_manager` |
| `maintenance` | `maintenance_technician` |
| `tenant` | tenant (no staff permissions) |

New staff accounts are created through `POST /api/staff.php` with an explicit `staff_role`. The legacy `role` column is written only for compatibility and must never be used for new authorization decisions.

## Rules

1. **Deny by default.** Unknown roles have no permissions.
2. **Tenant isolation.** A tenant may only read or write records linked to their own `user_id`/tenancy.
3. **Auditor is read-only.** Enforced centrally in `middleware/check_role.php`: any non-GET/HEAD/OPTIONS request returns 403.
4. **Inactive accounts lose access immediately**, even with a valid JWT.
5. **Audit sensitive actions.** Role changes, payment verification, receipt corrections, expense approvals, deposit refunds, exports and QR regeneration must be logged.
6. **No offline privileged actions.** Payment verification, approvals and role changes are online-only.
7. **Least privilege on creation.** Do not create a Super Administrator when an Administrator or Property Manager is sufficient.

## Migration checklist

1. Run `migrations/2026-11-17_phase0_roles_and_company.sql`.
2. Verify backfill:
   ```sql
   SELECT role, staff_role, account_type, COUNT(*)
   FROM users GROUP BY role, staff_role, account_type;
   ```
3. Create the company record through a controlled admin action; do not invent a legal name.
4. Create real staff accounts through `POST /api/staff.php`.
5. Keep `subscription_status` dormant. It no longer gates access.
6. Do not re-enable the public marketplace, landlord sign-up or subscription paywall.

## Open items

- Confirm the final matrix with the owner before enforcing it in production.
- Migrate every remaining legacy endpoint from `$user->role` checks to `permission_require()`.
- Add negative-permission tests for each role after the endpoint migration.
