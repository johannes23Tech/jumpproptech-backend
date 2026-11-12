# JumpPropTech Backend — Penetration Test Report

**Target:** `C:\xampp\htdocs\jumpproptech-backend` (PHP 8.2 / MariaDB / JWT API)
**Test date:** 2026-11-08
**Test types:** White-box SAST, black-box dynamic testing, gray-box authenticated authorization/business-logic testing
**Environment:** isolated local clone + disposable `jumpproptech_pentest` database. No production/Azure data was accessed.

> **Status update — 2026-11-09:** Five critical fixes were applied and re-tested: JWT secret hardening, removal of the backdoor/debug endpoints, rent IDOR, cross-tenant unit/tenant creation, and maintenance IDOR. Message spoofing, login user enumeration, the hard-coded cron secret and the DB credential fallback were also fixed. All 5 targeted re-tests and 21/21 smoke checks pass. A second hardening batch was applied on the same date (login/reset rate limiting, reset-token expiry + single-use, stored-XSS input sanitisation, receipt and expense authorization, CORS allowlist); it passed 18/18 targeted checks and the same 21/21 regression checks. Remaining items are listed in §9.

---

## 1. Executive summary

The API has a solid foundation in a few areas — every SQL statement uses PDO prepared statements, passwords are hashed with bcrypt, and several tenant-scoped queries correctly filter by owner. However, the authentication and object-authorization layers are **not safe to expose to the internet**.

**Result: 5 Critical, 8 High, 10 Medium/Low findings.**

The two most serious issues allow a full compromise without any valid credentials:

1. **The JWT signing secret is hard-coded in source** (`jumpproptech_super_secret_key_2025`). Anyone who can read the repository can mint a `superadmin` token and access every endpoint.
2. **`api/fix_admin.php` is an unauthenticated password-reset backdoor** that resets the superadmin account to `SuperAdmin123`.

Even if those are fixed, a normal landlord account can still mark another landlord's rent as paid, create units inside another landlord's property, resolve other landlords' maintenance tickets, and a tenant can create user accounts — all confirmed by live requests.

**Immediate action:** take the API offline or block external access until CRITICAL items are fixed and secrets are rotated. Assume the JWT secret and the DB fallback password are already compromised.

---

## 2. Scope, rules of engagement and limitations

| Item | Detail |
|---|---|
| In scope | All PHP files under `api/`, `config/`, `middleware/`; `.htaccess`; `Dockerfile`; dependency manifests |
| Out of scope | Production Azure MySQL (`jumpproptech-db.mysql.database.azure.com`), third-party SMTP, Vercel frontend, DoS/load testing |
| Active target | `http://127.0.0.1:8099` — isolated clone, disposable DB `jumpproptech_pentest` |
| Accounts used | Disposable superadmin, two landlords, one tenant, one agent, one maintenance user |
| Safety controls | No production DB contact; no destructive payloads; no real emails sent (SMTP pointed to a closed local port); test data only |
| Harness note | The clone's `config/db.php` was changed **only** to skip the Azure TLS option for the local MariaDB, which has TLS disabled. Application logic was not modified. PHP's built-in server does not read `.htaccess`, so header/dotfile results were additionally validated by source review. |

**Why this matters to an attacker:** this is a multi-tenant SaaS. A single authorization mistake leaks other landlords' tenants, ID numbers, leases, contact details and payment records — high-value PII and financial data in South Africa, with POPIA exposure. Rent records are money, so IDOR here is direct fraud, not just data disclosure.

---

## 3. Test type 1 — White-box static application security testing (SAST)

Full source review of every endpoint, middleware, config and container file. Findings below are source-confirmed.

### 3.1 Critical

#### W-01 — Hard-coded JWT secret / tokens can be forged
**Files:** `api/auth/login.php:7`, `api/auth/register.php:6`, `middleware/check_role.php:9`, `config/jwt.php:6`

```php
define('JWT_SECRET', 'jumpproptech_super_secret_key_2025');
```

`login.php` and `register.php` sign tokens with a constant, not `getenv('JWT_SECRET')`. `check_role.php` verifies with the same constant. The secret is in the repository and (by definition) in every developer's copy and every container image. An attacker can sign:

```json
{"user_id":1,"role":"superadmin","exp":9999999999}
```

and become superadmin. Role is read from the token, not the database, so this grants everything. **Confirmed live in BB-03.**

**Why an attacker does this:** it is the cheapest possible path to full compromise — no password, no brute force, no user interaction. Read public source → sign token → dump data / change rent status / create admin accounts.

#### W-02 — Unauthenticated admin password reset backdoor
**File:** `api/fix_admin.php:1-12`

```php
$email = 'admin@jumpliving.co.za';
$newPassword = 'SuperAdmin123';
...
echo json_encode(["message" => "Admin password updated successfully to SuperAdmin123"]);
```

The file has no authentication, no role check, no method restriction, and returns the new password in the response. **Confirmed live in BB-10** — the test logged in as superadmin immediately afterwards.

**Why an attacker does this:** direct account takeover of the highest-privilege account, with a known password, in one request.

#### W-03 — IDOR on rent payments (financial fraud)
**File:** `api/rent.php:27-34`

```php
UPDATE rent_records SET status='Paid', ... WHERE id = :id
```

There is no `owner_id`/`tenant_id` predicate and no role check. Any authenticated user can mark any rent record paid. **Confirmed live in BB-11:** landlord B changed landlord A's record #1 from `Pending` to `Paid`.

**Why an attacker does this:** erase arrears, falsify receipts, or sabotage another landlord's books. This is direct monetary fraud and destroys the integrity of the platform's core record.

#### W-04 — Secrets/credentials exposed: `.env`, hard-coded DB password, disabled TLS verification
**Files:** `.env` present in webroot; `config/db.php:8-11,19-20`; `.htaccess:1`; `Dockerfile:6`

- `config/db.php` falls back to a real-looking credential pair if env vars are missing:
  ```php
  $username = getenv('DB_USER') ?: 'jumpproptech';
  $password = getenv('DB_PASS') ?: 'Matlola@2026';
  ```
- `PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false` disables server-certificate verification, so a network attacker can MITM the DB connection.
- `.env` sits in the document root. `.htaccess` is supposed to block it, but line 1 is `<?php` — an invalid Apache directive. Apache would return 500 on every request (availability failure), and nginx (the actual `Dockerfile` base) ignores `.htaccess` entirely.
- `Dockerfile: COPY . .` bakes `.env`, `.git` and the whole working tree into the image; there is no `.dockerignore`.
- **Confirmed live in BB-26:** `GET /.env` returned 695 bytes of configuration from the built-in server.

**Why an attacker does this:** database credentials give direct access to all tenant PII, bypassing the API entirely. Source/image exposure gives the JWT secret and mail credentials. TLS verification off turns any network position into a DB eavesdropping position.

#### W-05 — Missing object-level authorization across several resources
**Files:** `api/units.php:36-50`, `api/tenants.php:28-95`, `api/maintenance.php:74-88`, `api/messages.php:72-84`, `api/expenses.php:34-44`

- `units.php` accepts any `property_id`; no check that the property belongs to the caller.
- `tenants.php` has **no role check at all**. A tenant can create a `users` row and a `tenants` row, pointing at any `unit_id`.
- `maintenance.php` updates `WHERE id = :id` with no ownership predicate (both "Resolved" and assign branches).
- `messages.php` inserts any `receiver_id` / `tenant_id`; only the read path checks ownership.
- `expenses.php` accepts any `property_id`.

**Confirmed live:** BB-12 (cross-tenant unit), BB-13 (tenant created users/tenants), BB-14 (cross-tenant ticket resolution), BB-15 (message injection).

**Why an attacker does this:** cross-tenant data poisoning, occupying someone else's unit, closing maintenance tickets to hide problems, injecting messages to phish another landlord's tenants, and polluting financial reports.

### 3.2 High

| ID | Finding | File / evidence | Reason an attacker uses it |
|---|---|---|---|
| W-06 | No rate limiting on login, registration, forgot-password | `api/auth/login.php`, `forgot_password.php` | Credential stuffing, password spraying, email bombing. 12 rapid failures produced no `429` (BB-07). |
| W-07 | User enumeration on login and reset | `login.php:55-57`, `forgot_password.php:18-21` | 404 "User not found" vs 401 "Invalid password" reveals valid accounts, shrinking brute-force space (BB-05, BB-23). |
| W-08 | Password-reset tokens have no expiry and are never single-use | `forgot_password.php:24-28` | Stored plaintext, deleted only on a new request. A DB leak or log leak gives permanent account takeover. |
| W-09 | Stored XSS / HTML injection sinks | `tenant_profile.php:31-61`, `maintenance.php` `photo`, `send_receipt.php:14,23`, `generate_lease.php` | Payloads stored and returned verbatim (BB-22). In the React frontend this can steal JWTs from storage, deface the portal, or phish other tenants. |
| W-10 | Arbitrary email sending + HTML injection via receipts | `api/send_receipt.php` | Any authenticated user can send mail from the platform's domain to any address, with attacker-controlled `receipt_number`. Phishing and reputation damage. |
| W-11 | Hard-coded cron secret in a GET parameter | `api/cron/generate_invoices.php:5-6` (`JumpPropTechCron2026`) | Anyone can trigger mass invoice emails (spam/resource abuse). URLs leak through proxy logs, browser history and referrers. |
| W-12 | Authorization uses stale token claims for 24h; no revocation | `check_role.php:36-54` | A demoted/compromised user keeps old privileges until expiry. **Confirmed BB-21:** a landlord demoted to tenant still reached landlord endpoints. |
| W-13 | Verbose error disclosure and debug endpoints | `register.php:73-76`, `login.php:58-61`, `tenants.php:91-95`, `tenant_profile.php:64-67`, `config/db.php:25-35`, `api/test_db.php` | Leaks SQL/schema/host details and confirms infrastructure state (BB-27). Speeds up targeted attacks. |

### 3.3 Medium / Low

| ID | Finding | File | Reason |
|---|---|---|---|
| W-14 | CORS `*` with `Authorization` allowed | `config/config.php:22-24` | Any website can call the API from a victim's browser if it can obtain the bearer token. Confirmed BB-24. |
| W-15 | Security headers absent / `.htaccess` invalid; nginx ignores it | `.htaccess:1`, `Dockerfile` | No CSP, HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy` (BB-25). Clickjacking, MIME sniffing, no XSS mitigation. |
| W-16 | No password policy | `register.php:10`, `change_password.php:10`, `create_landlord.php:16` | Weak passwords are accepted, making brute force and credential stuffing effective. |
| W-17 | No email verification / weak account lifecycle | `register.php`, `tenants.php` | Fake accounts, spam, unverified contact data. |
| W-18 | Container supply-chain risk | `Dockerfile:1,6` | `richarvey/nginx-php-fpm:latest` is unpinned and runs a large image as root; `COPY . .` includes `.env`/`.git`; no `.dockerignore`. A compromised/updated `latest` is deployed blindly. |
| W-19 | No audit logging / monitoring | entire codebase | Admin actions (password reset, subscription toggle, rent changes) are unattributable, so fraud cannot be investigated. |
| W-20 | Unbounded `longtext` upload fields | `tenant_profile.php` `id_document`, `maintenance.php` `photo` | No type/size validation: DB bloat/DoS, and stored-XSS carrier if rendered. |
| W-21 | Lease PDF HTML injection | `generate_lease.php:55-87` | Tenant-controlled fields are interpolated into HTML before Dompdf renders it. Low RCE risk with current Dompdf defaults, but document forgery/phishing is possible. |
| W-22 | `toggle_sub.php` accepts any status string | `api/admin/toggle_sub.php:15-20` | Superadmin only, but no enum validation weakens the subscription gate. |
| W-23 | `test_db.php` public diagnostic | `api/test_db.php` | Confirms DB connectivity and hosting details; should never ship. |

### 3.4 Positive white-box findings

- **SQL injection:** no dynamic SQL found; all user input is bound through PDO. Basic payloads did not bypass login (BB-08). Keep it that way — never concatenate `ORDER BY`/filters.
- **Password storage:** `password_hash(..., PASSWORD_BCRYPT)` + `password_verify` used correctly.
- **Public registration:** role is forced to `tenant`; a `role=superadmin` injection was ignored (BB-09).
- **Admin routes:** role checks present and effective for non-superadmin tokens (BB-19).
- **Subscription gate:** returns `402` for expired landlords (BB-20).
- **Tenant scoping:** lease download (BB-16), rent list (BB-18) and message read (retested after removing injected data) are correctly scoped.
- **Dependencies:** `composer audit` — no advisories; `npm audit` — no vulnerabilities. PHP lint — all API files clean.

---

## 4. Test type 2 — Black-box dynamic testing (unauthenticated + authenticated HTTP)

**Target:** `http://127.0.0.1:8099` (isolated clone)
**Method:** OWASP WSTG-style manual requests, 27 checks. Raw results: `%TEMP%\opencode\pentest-results.json`.

| ID | Test | Expected | Observed | Verdict |
|---|---|---|---|---|
| BB-01 | `/api/ping.php` | 200 | 200 `{"status":"awake"}` | INFO |
| BB-02 | `/api/admin/stats.php` with no token | 401 | 401 | PASS |
| BB-03 | Admin stats with forged JWT (secret from source) | 401/403 | **200 + full stats** | **CRITICAL** |
| BB-04 | Valid landlord login | 200 | 200, role=landlord | INFO |
| BB-05 | Login unknown email | generic 401 | **404 "User not found"** | HIGH |
| BB-06 | Login wrong password | 401 | 401 | PASS |
| BB-07 | 12 rapid failed logins | eventual 429 | **12 × 401, no 429** | HIGH |
| BB-08 | SQLi `' OR '1'='1` in login | 401/404 | 404 | PASS |
| BB-09 | `role=superadmin` during registration | stored tenant | stored tenant | PASS |
| BB-10 | Unauthenticated `fix_admin.php` | 401/404 | **200, then superadmin login with `SuperAdmin123`** | **CRITICAL** |
| BB-11 | Landlord B marks landlord A's rent #1 paid | 403/404 | **200; DB `Pending → Paid`** | **CRITICAL** |
| BB-12 | Landlord B creates unit in landlord A's property | 403/404 | **201; unit inserted under property #1** | HIGH |
| BB-13 | Tenant creates user + tenant record | 403 | **200; `owner_id=4` (tenant's own id)** | HIGH |
| BB-14 | Landlord B resolves landlord A's ticket | 403/404 | **200; ticket → Resolved** | HIGH |
| BB-15 | Tenant posts message with arbitrary `receiver_id`/`tenant_id` | 403/400 | **200; row written** | MEDIUM |
| BB-16 | Landlord B downloads landlord A's lease (control) | 404 | 404 | PASS |
| BB-17 | Landlord B reads landlord A's thread (control) | empty | empty after removing injected row | PASS |
| BB-18 | Landlord B lists landlord A's rent (control) | no rows | 0 rows | PASS |
| BB-19 | Landlord token on admin stats (control) | 403 | 403 | PASS |
| BB-20 | Expired landlord subscription (control) | 402 | 402 | PASS |
| BB-21 | Role demoted in DB, old token reused | 403 | **200; stale role honoured** | MEDIUM |
| BB-22 | Stored `<script>` in profile returned verbatim | encoded | **raw `<script>` in JSON** | HIGH* |
| BB-23 | Reset known vs unknown email | identical | **500 vs 404** (enumeration) | HIGH |
| BB-24 | CORS preflight from `https://evil.example` | no wildcard | **`ACAO: *`** | MEDIUM |
| BB-25 | Security headers on API | all present | **all 5 missing** | MEDIUM |
| BB-26 | `GET /.env` | 403/404 | **200, 695 bytes config** | **CRITICAL** |
| BB-27 | `GET /api/test_db.php` | 403/404 | **200, DB connectivity confirmed** | LOW |

\* XSS impact depends on how the frontend renders API values; the API itself stores and returns unencoded HTML.

### Reproduce the critical token forgery (authorized test only)

```bash
# 1) Build a token signed with the secret found in the source
node -e '
const c=require("crypto");
const b=s=>Buffer.from(s).toString("base64").replace(/=+$/,"").replace(/\+/g,"-").replace(/\//g,"_");
const h=b(JSON.stringify({typ:"JWT",alg:"HS256"}));
const p=b(JSON.stringify({iss:"jumpproptech",iat:Math.floor(Date.now()/1000),exp:9999999999,user_id:1,role:"superadmin"}));
const s=c.createHmac("sha256","jumpproptech_super_secret_key_2025").update(h+"."+p).digest("base64").replace(/=+$/,"").replace(/\+/g,"-").replace(/\//g,"_");
console.log(h+"."+p+"."+s);'
# 2) Use it
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8099/api/admin/stats.php
```

---

## 5. Test type 3 — Gray-box authenticated authorization & business-logic testing

This phase uses valid tokens for low-privilege accounts and attempts lateral/vertical movement — the most realistic attacker model for a SaaS (a malicious or compromised landlord/tenant).

### 5.1 Authorization matrix (live results)

| Endpoint | Superadmin | Landlord (own data) | Landlord (other's data) | Tenant | Agent | Maintenance |
|---|---|---|---|---|---|---|
| `admin/stats.php` | 200 | 403 | 403 | 403 | 403 | 403 |
| `properties.php` GET | 403 | scoped | n/a | 403 | 200 (bug: filters by agent id, sees none) | 403 |
| `units.php` POST | 403 | own property: 201 | **other property: 201** | 403 | 403 | 403 |
| `tenants.php` POST | 200 | 200 | n/a | **200 (should be 403)** | 403 | 403 |
| `rent.php` POST | 200 | own: 200 | **other's: 200** | **200** | **200** | **200** |
| `maintenance.php` POST | 200 | own: 200 | **other's: 200** | 200 (own) | **other's: 200** | 200 |
| `messages.php` POST | 200 | 200 | **arbitrary ids: 200** | **arbitrary ids: 200** | 200 | 200 |
| `expenses.php` POST | 200 | own: 200 | **other property id: 200** | **200** | **200** | **200** |
| `send_receipt.php` | SMTP attempt | SMTP attempt | **any email** | **any email** | SMTP attempt | SMTP attempt |
| `cron/generate_invoices.php` | **no auth, secret in URL → 200** | 200 | 200 | 200 | 200 | 200 |

### 5.2 Business-logic attack chains (why they matter)

1. **Rent fraud chain:** any account → `POST /api/rent.php {id:<victim record>}` → record becomes `Paid` with a generated receipt. No ownership check, no audit trail. This can hide non-payment or fabricate income for financing/fraud.
2. **Tenant data poisoning chain:** tenant → `POST /api/tenants.php` → creates a new login and a tenant tied to any unit, then `POST /api/maintenance.php` to file tickets in that unit. This breaks tenant isolation and can be used to squat/overwrite occupancy.
3. **Cross-landlord disruption chain:** landlord B → resolve A's maintenance tickets (hides urgent repairs) and create units in A's property (pollutes A's inventory/reports).
4. **Phishing chain:** tenant → `POST /api/messages.php` with an arbitrary `receiver_id`/`tenant_id`, or `POST /api/send_receipt.php` with a victim email and crafted `receipt_number` → credible-looking payment message from the real platform domain.
5. **Persistence chain:** forged superadmin token + `admin/create_landlord.php` → create a durable landlord account, then use `toggle_sub` as needed. The `fix_admin.php` backdoor gives the same outcome without forgery.
6. **Token-theft chain:** stored XSS in profile → frontend reads JWT from storage → attacker uses it from any origin because CORS is `*` and there is no token binding/revocation.

### 5.3 Controls that held up

- `generate_lease.php` correctly rejects cross-tenant access (404).
- `rent.php` GET and `messages.php` GET correctly scope reads by owner.
- Role checks on `/api/admin/*` work when the token is legitimate.
- Subscription expiry is enforced with `402`.
- Public registration cannot self-assign a role.

These should be preserved while fixing the write-path IDORs.

---

## 6. Attack reasons and attacker motivation (summary)

| Goal | Finding used | Attacker payoff |
|---|---|---|
| Full platform takeover | W-01 forged JWT, W-02 admin backdoor | All properties, tenants, ID numbers, leases, payments; ability to create/delete accounts |
| Direct financial fraud | W-03 rent IDOR | Mark rent paid, fabricate receipts, hide arrears |
| Data theft / POPIA breach | W-04 DB creds/.env, IDORs | Bulk PII export (names, phones, emails, ID numbers, emergency contacts, vehicle details) |
| Espionage / stalking | IDORs, message injection | Read another landlord's tenant list, leases, maintenance history |
| Sabotage | W-05, W-12 | Close tickets, occupy units, corrupt reports, keep access after demotion |
| Phishing / reputation damage | W-09, W-10, W-11 | Send credible mail from the platform domain, in-app messages to tenants |
| Account takeover at scale | W-06, W-07, W-08 | Credential stuffing, user enumeration, permanent reset-token replay |
| Reconnaissance | W-13, W-23 | Schema, hostnames, DB state to plan deeper attacks |

---

## 7. Remediation plan

### Immediate (next 24–48 hours)

1. **Rotate the JWT secret** and remove every hard-coded copy. Use only `getenv('JWT_SECRET')`; fail closed if absent. Invalidate all existing tokens by adding a `token_version` claim checked against `users.token_version` (or rotate the secret, which invalidates everything).
   ```php
   // config/jwt.php
   $secret = getenv('JWT_SECRET');
   if (!$secret || strlen($secret) < 32) { http_response_code(500); exit('JWT not configured'); }
   define('JWT_SECRET', $secret);
   ```
   Delete the local `define(...)` lines in `login.php`, `register.php`, `check_role.php`; require `config/jwt.php` instead.
2. **Delete or block `api/fix_admin.php`, `api/test_db.php` and `api/cron/`** from the public webroot. Reset the superadmin password manually and force re-login.
3. **Fix rent IDOR** — every write must include the ownership predicate, e.g.:
   ```php
   UPDATE rent_records r
   JOIN tenants t ON r.tenant_id = t.id
   SET r.status='Paid', ...
   WHERE r.id = :id AND t.owner_id = :user_id
   ```
   Then check `rowCount()` and return `404` when nothing matched.
4. **Purge secrets from the deployment:** remove `.env` from the webroot (store it one level above, or use real environment variables), remove DB fallbacks in `db.php`, turn TLS verification back on (`MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true`), and rotate the DB password.
5. **Move the cron trigger out of HTTP** (CLI or a signed header) and rotate `JumpPropTechCron2026`. Use `hash_equals` and an env secret if HTTP is unavoidable.

### Short term (1–2 weeks)

6. **Add object-level authorization to every write path:** units (property ownership), tenants (role + unit ownership), maintenance (ticket ownership), messages (receiver must belong to the thread/landlord), expenses (property ownership), send_receipt (own tenant/landlord only, recipient from DB, not request).
7. **Restrict `tenants.php` to landlord/agent** and validate `unit_id` belongs to the caller. Validate all enum/foreign-key inputs.
8. **Rate limiting + generic auth responses:** 5–10 attempts/minute per IP+account, exponential backoff, `429`, identical `"Invalid credentials"` for unknown user and wrong password, on login/register/forgot/reset. Add CAPTCHA or proof-of-work if abuse persists.
9. **Password reset hardening:** store only `hash('sha256', $token)` in DB, add `expires_at` (15–30 min), mark used/delete on consumption, rate-limit requests, and do not reveal whether the email exists.
10. **Output encoding / XSS:** treat all stored strings as untrusted. Encode on output in the frontend (`React` already escapes by default — never use `dangerouslySetInnerHTML`), validate `id_document`/`photo` as base64 with a size cap and MIME allowlist, and sanitise anything inserted into emails/PDF (`htmlspecialchars`).
11. **CORS allowlist:** replace `*` with the exact frontend origins, add `Vary: Origin`, and only allow `Authorization` from trusted origins.
12. **Security headers at the web server** (nginx, since `.htaccess` is ignored/ broken): CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`. Delete the invalid `<?php` line from `.htaccess` if Apache is used.
13. **Stop verbose errors:** `APP_ENV=production`, `display_errors=0`, never return `$e->getMessage()`; log with correlation IDs instead.

### Hardening (ongoing)

14. **Password policy:** enforce 8–12 characters, require uppercase + lowercase + number + symbol, block common passwords, and use bcrypt cost ≥ 12. Add MFA for superadmin/landlords.
15. **Session/token lifecycle:** shorter access token (15–60 min) + refresh rotation, `aud`/`jti` validation, server-side revocation (`token_version`), logout invalidation, and re-check current role from DB on sensitive actions.
16. **Audit logging:** append-only log of auth events, admin actions, rent changes, subscription toggles, data exports; alert on anomalies.
17. **Container/deploy:** add `.dockerignore` (`.env`, `.git`, `node_modules`, `vendor` if rebuilt), pin the base image by digest, run as non-root, inject secrets at runtime, scan images (Trivy/Grype) in CI.
18. **CI security gates:** `composer audit`, `npm audit`, `php -l`, Semgrep/Psalm, and `gitleaks` on every push. Add a pre-commit hook to block secrets.
19. **Privacy/POPIA:** because tenant ID numbers, contact details and leases are exposed by IDOR, document a breach assessment if this code was ever public with real data.

---

## 8. Verification checklist after fixes

Re-run the same harness and require:

- [ ] BB-03 returns 401/403 with a forged token.
- [ ] BB-10 returns 404 (file removed).
- [ ] BB-11/12/13/14/15 return 403/404 and the DB is unchanged.
- [ ] BB-05/BB-23 return identical responses for known/unknown users.
- [ ] BB-07 eventually returns 429.
- [ ] BB-21 returns 402/403 immediately after demotion (or after token lifetime ≤ 15 min).
- [ ] BB-22 returns encoded output.
- [ ] BB-24 returns no wildcard ACAO.
- [ ] BB-25 returns all security headers.
- [ ] BB-26 returns 403/404 for `/.env` and `/.git/*`.
- [ ] `composer audit` / `npm audit` clean; no hard-coded secrets (`gitleaks`).

---

## 9. Re-test results — 2026-11-09

### 9.1 Changes applied

| Fix | Files | Result |
|---|---|---|
| JWT secret is now env-only; weak/default secrets rejected; expiry shortened to 1h; role re-read from DB | `config/jwt.php`, `api/auth/login.php`, `api/auth/register.php`, `middleware/check_role.php` | Old forged token rejected; valid admin token still works; forged `role=superadmin` claim denied |
| Backdoor/debug endpoints removed | deleted `api/fix_admin.php`, `api/test_db.php` | Both return 404; app still responds |
| Rent IDOR fixed with ownership check | `api/rent.php` | Cross-tenant update 404, record unchanged; owner update succeeds |
| Units/tenants authorization fixed | `api/units.php`, `api/tenants.php` | Cross-tenant unit 404; tenant account 403; owner flows work; agent-created tenant is assigned to the property owner |
| Maintenance IDOR fixed | `api/maintenance.php` | Cross-tenant resolve 404, ticket unchanged; owner resolve succeeds |
| Message spoofing fixed | `api/messages.php` | Arbitrary receiver/thread 403; legitimate message works |
| Login user enumeration fixed | `api/auth/login.php` | Unknown email now returns the same `401 Invalid credentials` |
| Cron secret no longer hard-coded | `api/cron/generate_invoices.php` | Requires `CRON_SECRET` env + `hash_equals`; no default |
| DB credentials no longer fall back to source | `config/db.php` | Fails closed if env vars are missing; Azure TLS verification enabled |
| Secret/debug files excluded from image; Apache dotfile rules repaired | `.dockerignore`, `.htaccess` | `.env`/`.git` no longer baked into Docker images; Apache blocks dotfiles |

### 9.2 Targeted re-tests (5/5 passed)

| ID | Test | Attack result | Legitimate control |
|---|---|---|---|
| RT-1 | JWT hardening | Old-secret token → **401**; valid-secret token with false `role=superadmin` → **403** | Real superadmin login → **200** |
| RT-2 | Backdoors removed | `fix_admin.php` → **404**, `test_db.php` → **404** | `ping.php` → **200** |
| RT-3 | Rent IDOR | Landlord B on A's record → **404**, DB stayed `Pending` | Landlord A → **200**, DB `Paid` |
| RT-4 | Units/tenants authz | B creates unit in A's property → **404**, 0 rows; tenant creates tenant → **403**, 0 rows | A creates unit → **201**; A creates tenant with `owner_id=2` → **200** |
| RT-5 | Maintenance IDOR | B resolves A's ticket → **404**, stayed `Open` | A resolves → **200**, became `Resolved` |

### 9.3 Regression smoke test (21/21 passed)

Landlord properties/units/tenants/rent/dashboard/expenses/maintenance/messages, tenant data/profile/maintenance/messages, superadmin stats, lease PDF, public registration, new-tenant login, tenant list denial, and post-fix property access all returned the expected results.

### 9.4 Regression found and fixed during re-testing

Enabling `PDO::ATTR_EMULATE_PREPARES => false` broke existing queries that reuse the same named placeholder (e.g. `:user_id` in `dashboard.php`). Native MySQL prepares reject repeated placeholders. Fix: keep emulation enabled for backward compatibility and use distinct placeholders in all newly added authorization queries. Recommended follow-up: rewrite legacy queries to unique placeholders, then disable emulation again.

### 9.5 Remaining priorities after batch 3

| Priority | Item |
|---|---|
| Critical | `.env` is still present in the working tree/webroot. `.dockerignore` and the nginx/Docker configs keep it out of images and block it over HTTP, but remove it from the host and inject runtime env vars. Rotate every secret that was ever in it. |
| High | Enforce MFA for `superadmin` and landlord accounts (the endpoints and migration exist, but accounts must still be enrolled). |
| High | Apply `deploy/nginx-security.conf` and `deploy/php-hardening.ini` in production and verify the controls in `deploy/README.md`. |
| Medium | Run both batch migrations plus `migrations/2026-11-10_mfa.sql` before exposing the API. |
| Medium | Ship auth/admin audit logs to centralised, immutable storage and alert on the events in §7. The DB table is append-only, but it is local to each database. |
| Medium | Backups, restore drills and an incident-response/revocation runbook. |
| Low | Unbounded `longtext` upload fields (base64 documents/photos); add size and MIME limits at the application layer. |
| Low | POPIA data inventory, retention and deletion procedures. |

### 9.6 Required deployment actions

1. Set a new strong `JWT_SECRET` (≥32 bytes) and new `CRON_SECRET` in the production secret manager. Rotating the JWT secret invalidates every existing token.
2. Rotate the production DB password if the old fallback or `.env` was ever exposed.
3. Remove `.env` from the production webroot; inject environment variables at runtime.
4. Run `migrations/2026-11-09_security_hardening.sql` (creates `rate_limits`) and `migrations/2026-11-09_security_hardening_batch3.sql` (adds `users.token_version`, `revoked_tokens`, `audit_logs`, append-only triggers and reset indexes) before deploying. Run `migrations/2026-11-10_mfa.sql` if MFA is enabled and `migrations/2026-11-10_tenant_profile.sql` so self-registered tenants can complete a profile before a unit is assigned. The app can create tables lazily, but dedicated migrations avoid relying on runtime DDL rights.
5. Add the nginx dotfile/header rules before exposing the API (`deploy/nginx-security.conf`) and copy `deploy/php-hardening.ini` into PHP's `conf.d`.
6. Set `CORS_ALLOWED_ORIGINS` (or `ALLOWED_ORIGINS`) to the production frontend origin and `FRONTEND_URL` for password-reset links.
7. Keep `MAIL_ENCRYPTION` at `tls` or `ssl` in production; `none` is only for local capture testing.
8. After the batch-3 migration, every pre-existing JWT is rejected because it lacks `jti`/`ver`. Announce a one-time sign-out; users simply log in again.

---

### 9.7 Second hardening batch (2026-11-09)

| Fix | Files | Verified behaviour |
|---|---|---|
| Login lockout | `config/security.php`, `api/auth/login.php` | 5 failures per email+IP (20 per IP) return 429 + `Retry-After`; the correct password is also refused while locked; a successful login clears the per-account counter |
| Password-reset abuse controls | `api/auth/forgot_password.php` | Identical generic 200 for known and unknown emails; tokens stored as SHA-256 hashes; per-IP and per-email throttling |
| Reset-token expiry + single use | `api/auth/reset_password.php` (new) | 30-minute expiry; token deleted on use; replay 400; expired tokens 400; weak passwords rejected without consuming the token |
| Stored-XSS input sanitisation | `api/tenant_profile.php`, `api/messages.php`, `api/tenants.php` | Tags/control characters stripped; emails validated; `javascript:` ID documents rejected; messages and tenant names cleaned |
| Receipt recipient fixation | `api/send_receipt.php` | Recipient taken from the tenant's DB record, never from the request; only tenant/owner/agent/superadmin may send; unpaid records 400; outbound receipts rate-limited |
| Expense authorization | `api/expenses.php` | Tenant accounts 403; cross-property writes 404; owner write succeeds; amount/date validation |
| CORS allowlist | `config/config.php` | Only `CORS_ALLOWED_ORIGINS` / `ALLOWED_ORIGINS` origins are reflected; unknown origins receive no ACAO header |
| Local mail capture | `config/mailer.php` | `MAIL_ENCRYPTION=none` supports an isolated SMTP capture server; production still defaults to STARTTLS |

**Targeted verification: 18/18 passed.** Scenarios: lockout, correct-password-during-lock, recovery, counter reset; forgot-password non-enumeration and hashed token storage; single-use, expiry, weak-password handling and password restoration; XSS sanitisation and `javascript:` document rejection; cross-tenant receipt denial, DB-derived recipient (captured `RCPT TO` = `tenant.a@test.local` even when the request supplied `email=attacker@evil.local`), unpaid receipt rejection; tenant/cross-property expense denial, owner expense success and date validation; CORS allow/deny.

**New endpoint contract:** `POST /api/auth/reset_password.php` with `{ "token": "...", "password": "..." }`. Reset links point at `FRONTEND_URL` + `/reset-password?token=...`.

**Regression:** the original 21-check smoke suite still passes (21/21).

---

### 9.8 Third hardening batch (2026-11-09)

| Fix | Files | Verified behaviour |
|---|---|---|
| Token revocation + logout | `config/security.php`, `middleware/check_role.php`, `api/auth/login.php`, `api/auth/register.php`, `api/auth/change_password.php`, `api/auth/reset_password.php`, `api/auth/logout.php` (new) | JWTs carry `jti` + `ver`; the middleware compares `ver` with `users.token_version` and rejects deny-listed `jti`. Single logout revokes only the presented token; `{"all":true}` bumps the version and kills every session. Denylist failure falls back to a global logout instead of pretending success. Password change/reset bump the version and invalidate old tokens. |
| Append-only audit trail | `config/audit.php` (new), `migrations/2026-11-09_security_hardening_batch3.sql`, all auth/admin/data-write endpoints | Logs actor, action, entity, outcome, IP, user agent and bounded metadata. DB triggers reject `UPDATE`/`DELETE`, so the trail cannot be edited or cleared by the application. Audit writes fail open to `error_log` rather than blocking a login or payment. |
| Admin/business-logic validation | `api/admin/toggle_sub.php`, `api/admin/create_landlord.php` | Subscription status is restricted to `active`, `expired`, `suspended`, `past_due`; the target must exist and be a landlord; non-superadmin callers get 403. Landlord creation validates email/name/password policy, rate-limits per admin and audits the result. |
| Lease PDF output encoding | `api/generate_lease.php` | Role gate + owner/agent predicate; every DB value is HTML-escaped before interpolation; the download filename is sanitised (no CR/LF or path characters). Owners get a PDF, tenants get 403, non-owners get 404. |
| Native server-side prepares | `config/db.php`, `api/dashboard.php`, `api/messages.php` | `PDO::ATTR_EMULATE_PREPARES => false`. Legacy queries that reused a named placeholder were rewritten to positional or distinct placeholders. |
| Deployment-grade web server controls | `deploy/nginx-security.conf`, `deploy/php-hardening.ini`, `deploy/README.md`, `Dockerfile`, `.htaccess` | nginx denies dotfiles/secrets/dumps, restricts the cron endpoint to localhost, sets HSTS/headers and request limits; PHP disables `expose_php`/`display_errors` and caps uploads. Apache `.htaccess` mirrors the dotfile/header rules. Security headers are also emitted from `config/config.php` as defence in depth. |
| Password hash/policy upgrade | `config/security.php` | 8–12 characters, uppercase + lowercase + number + symbol, common-password blocklist, bcrypt cost 12 with transparent rehash on login. Filename sanitiser shared by PDF output. |

**New schema:** `users.token_version`, `revoked_tokens` (per-token denylist with expiry), `audit_logs` (with append-only triggers) and password-reset lookup indexes.

**Targeted verification: 18/18 passed.** Scenarios: security headers and no `X-Powered-By`; `jti`/`ver` present and matching the DB; single logout revokes only that token while another session survives; global logout invalidates every token and a fresh login works; short/common passwords rejected while a strong one registers; password change invalidates prior tokens and returns a usable fresh token; password reset invalidates prior tokens and is single-use; audit rows recorded with the correct actor; `UPDATE`/`DELETE` on `audit_logs` rejected by the triggers; `toggle_sub` rejects unknown states, non-landlord/missing targets and non-superadmin callers, and accepts valid states; lease PDF succeeds for the owner, is blocked for tenant/non-owner, and has a sanitised filename; dashboard/messages succeed under native prepares.

**Regression:** the original smoke suite passes **21/21** and the second-batch hardening suite passes **18/18** on the same build.

---

### 9.9 Tenant profile completion fix (2026-11-10)

**Reported issue:** a tenant could not complete their profile; the page showed "Failed to load tenant details" and saving returned an error or silently changed nothing.

**Root cause (reproduced as an authenticated user):** public registration creates a `users` row only. It never creates the matching `tenants` row, so a self-registered tenant has no profile record. `api/tenant_profile.php` returned JSON `false` for the GET, `api/tenant_data.php` returned `{"message":"Tenant profile not found."}`, and the profile page requires the `tenant` object before it renders. The POST issued `UPDATE tenants ... WHERE user_id = ?`, which affected **0 rows** and still reported success. Landlord-created tenants were unaffected because `api/tenants.php` inserts both rows.

**Fix**

| Change | File |
|---|---|
| Lazy profile provisioning: fetch the user's tenant row, or create an unlinked row seeded with the account name/email/phone. The insert is idempotent (`NOT EXISTS`) and uses distinct placeholders for native prepares. | `config/tenant_profile.php` (new) |
| `GET` provisions the row before reading; `POST` provisions before updating, so the completed profile persists; updates are audited as `tenant.profile.updated`; the endpoint is now tenant-only (403 for other roles). | `api/tenant_profile.php` |
| `tenant_data.php` provisions and uses `LEFT JOIN` for units/properties, returning a usable unassigned-tenant payload (`unit_id`/`unit_number`/`property_name` null, empty rent/maintenance arrays) instead of "not found". | `api/tenant_data.php` |
| Maintenance tickets now return a clear `400` when a tenant has no unit yet, instead of a database `500`. | `api/maintenance.php` |
| Lease columns made nullable so an unlinked profile row is valid: `owner_id`, `unit_id`, `lease_start`, `lease_end`. NULL `owner_id`/`unit_id` keeps the row out of every landlord-scoped query (those filter on `owner_id` or join `units`). Idempotent migration. | `migrations/2026-11-10_tenant_profile.sql` (new) |

**Targeted verification: 10/10 passed.** A fresh self-registration has no tenant row; `GET /api/tenant_profile.php` provisions and returns the account phone/login email; `GET /api/tenant_data.php` returns an unassigned stub with empty rent/maintenance; a full profile POST persists and round-trips all fields (including a Cloudinary ID URL); only one row is created after repeated reads; the update appears in `audit_logs`; maintenance returns `400` before a unit is assigned; a landlord token gets `403`.

**Regression:** original smoke **21/21**, second-batch hardening **18/18**, third-batch security **18/18** on the same build; 39/39 PHP files pass `php -l`; the migration re-runs cleanly.

**Deployment note:** run `migrations/2026-11-10_tenant_profile.sql` before exposing this build. Existing self-registered accounts are repaired automatically on their next profile load; no data backfill is needed.

---

## 10. Test artifacts

| Artifact | Location |
|---|---|
| Dynamic test harness (Node) | `%TEMP%\opencode\pentest-run.js` |
| Second-batch harness (Node) | `%TEMP%\opencode\hardening-run.js` |
| Second-batch results (JSON) | `%TEMP%\opencode\hardening-results.json` |
| Third-batch harness (Node) | `%TEMP%\opencode\batch3-run.js` |
| Third-batch results (JSON) | `%TEMP%\opencode\batch3-results.json` |
| Tenant-profile harness (Node) | `%TEMP%\opencode\tprofile-run.js` |
| Tenant-profile results (JSON) | `%TEMP%\opencode\tprofile-results.json` |
| Raw results (JSON) | `%TEMP%\opencode\pentest-results.json` |
| Disposable schema/seed | `%TEMP%\opencode\jp_pentest_seed.sql` |
| Test database | `jumpproptech_pentest` (local MariaDB) |
| Isolated app clone | `%TEMP%\opencode\pentest-app` |

**Cleanup:** the test DB and clone can be deleted; no changes were made to the repository source. The local MariaDB instance was started only for this test and can be stopped.
