# JumpPropTech — Security Hardening Guide

> Goal: make the platform expensive to attack, quick to detect, and safe to recover.
> There is no "unhackable". A determined, well-resourced attacker will eventually find a way in; the job is to remove easy paths, limit blast radius, and detect/contain fast.

---

## Implemented controls (2026-11-10)

| Control | Why it matters |
|---|---|
| TOTP two-factor authentication (`config/mfa.php`, `api/auth/mfa_*.php`) | Passwords leak; a stolen password alone no longer grants a session. Codes are replay-protected and recovery codes are single-use bcrypt hashes. |
| JWT `scope` claim | The short-lived MFA challenge token can never be replayed as a session token. |
| Password confirmation for MFA enrolment/removal | A stolen session token cannot attach an attacker's authenticator or silently remove yours. |
| Token version bump on MFA changes | Enabling/disabling a second factor signs out every other session. |
| CI: gitleaks + dependency audits + build/lint | Blocks the three most common regressions: committed secrets, vulnerable dependencies, broken auth code. |
| Dependabot (weekly) | Keeps supply-chain patches flowing without manual chasing. |

Run `migrations/2026-11-10_mfa.sql` once. The application also creates the
columns lazily, so a deployment without the migration keeps working.

---

## 0. The honest threat model

| Attacker | What they do | What stops them |
|---|---|---|
| Automated bots / scanners | Probe `/.env`, `/.git`, default passwords, known CVEs, login brute force | Removing exposed files, patching, rate limits, WAF |
| Skilled individual ("Harvard grad") | Reads your source/JS, maps the API, tests IDOR/business logic, forges tokens, phishes staff | Server-side authorization, secret management, MFA, monitoring, least privilege |
| Organized crime | Credential stuffing, ransomware, data sale | MFA, segmentation, backups, EDR, incident response |
| Insider | Misuses legitimate access | Least privilege, audit logs, separation of duties |

**Key assumption:** assume the source code is public. Security must not depend on the attacker not knowing how the app works.

**Your current position:** the API has critical issues that a single automated scan or a junior attacker can exploit (hardcoded JWT secret, unauthenticated admin reset, rent IDOR, exposed `.env`). Fix those before worrying about advanced attackers.

---

## 1. Do these first (24–48 hours)

These are the findings from `SECURITY_ASSESSMENT.md` that make everything else moot.

1. **Rotate every secret** — JWT secret, DB password, SMTP password, cron key. Assume they are already leaked.
2. **Remove the hardcoded JWT secret.** Use only environment variables and fail closed.
3. **Delete `api/fix_admin.php` and `api/test_db.php`** from the deployed webroot. Remove `api/cron/` from public HTTP.
4. **Fix the rent IDOR** — every update must include the owner predicate.
5. **Remove `.env` from the webroot** and stop `Dockerfile` `COPY . .` from baking it into the image.
6. **Turn DB TLS verification back on** and remove the hardcoded DB fallback password.
7. **Force-reset the superadmin password** and invalidate all existing JWTs.
8. **Take a backup and snapshot the server** before changing anything, so you can restore.

### Current implementation status (2026-11-10)

Implemented and verified in this repository:

- Env-only JWT secret with weak/old values rejected, 1-hour tokens, and the current role re-read from the database on every request.
- Login lockout: 5 failures per email+IP (50 per IP) for 15 minutes, `429` + `Retry-After`, generic `401`, constant-time-ish bcrypt verification for unknown accounts, no user enumeration.
- Token revocation: every JWT carries `jti` + `ver`; `middleware/check_role.php` compares `ver` with `users.token_version` and checks the `revoked_tokens` deny-list. `POST /api/auth/logout.php` revokes one device, or all sessions with `{"all":true}`. Password change/reset bump the version.
- Append-only audit trail: `audit_logs` records actor/action/entity/outcome/IP/user-agent/metadata; database triggers reject `UPDATE`/`DELETE`; writes fail open to `error_log`.
- Password reset: SHA-256 token hashes, 30-minute expiry, single use, per-IP/per-email throttling, generic forgot-password response, and the `POST /api/auth/reset_password.php` endpoint.
- Password policy: 12–72 characters, letter + number, common-password blocklist, bcrypt cost 12 with transparent rehash on login.
- Ownership checks on rent, units, tenants, maintenance, messages and expenses; `send_receipt.php` derives the recipient from the tenant record and never trusts a request-supplied email.
- Admin validation: `toggle_sub.php` accepts only `active`, `expired`, `suspended`, `past_due` and only for an existing landlord; `create_landlord.php` validates input, enforces the password policy, rate-limits and audits.
- Lease PDF: role gate, owner/agent predicate, HTML-escaped values and a sanitised download filename.
- Input sanitisation for tenant profiles, messages and tenant names; `javascript:` document URIs are rejected.
- Tenant self-service profiles: a self-registered tenant has no `tenants` row until a landlord assigns a unit. `config/tenant_profile.php` provisions an unlinked row lazily (seeded from the account) so `GET`/`POST /api/tenant_profile.php` and `GET /api/tenant_data.php` work before a lease exists; maintenance returns a clear `400` until a unit is assigned; the endpoint is tenant-only.
- Native server-side prepares (`PDO::ATTR_EMULATE_PREPARES => false`); legacy duplicate-placeholder queries rewritten.
- CORS allowlist via `CORS_ALLOWED_ORIGINS` / `ALLOWED_ORIGINS`; security headers emitted in PHP and mirrored in nginx/Apache.
- `.dockerignore`, repaired `.htaccess`, `CRON_SECRET`, fail-closed DB configuration, Azure TLS verification.
- Deployment controls: `deploy/nginx-security.conf`, `deploy/php-hardening.ini`, `deploy/README.md`; the `Dockerfile` copies both into the image.
- MFA (TOTP) endpoints, challenge/access scopes and recovery codes (see the 2026-11-10 table above).

Migrations (run in order): `migrations/2026-11-09_security_hardening.sql`, `migrations/2026-11-09_security_hardening_batch3.sql`, `migrations/2026-11-10_mfa.sql`, `migrations/2026-11-10_tenant_profile.sql`.

Still open (details in `SECURITY_ASSESSMENT.md` §9.5): remove `.env` from the host and rotate secrets, enforce MFA enrolment for admin/landlord accounts, deploy and verify the nginx/PHP controls, ship audit logs to immutable central storage with alerts, backups/restore drills, upload size/MIME limits, and POPIA retention/deletion.

---

## 2. Authentication and sessions

### 2.1 JWT done safely

```php
// config/jwt.php
$secret = getenv('JWT_SECRET');
if (!$secret || strlen($secret) < 32) {
    http_response_code(500);
    exit('Server misconfigured');
}
define('JWT_SECRET', $secret);
define('JWT_ALGO', 'HS256');
define('JWT_ACCESS_TTL', 900);        // 15 minutes
define('JWT_REFRESH_TTL', 60 * 60 * 24 * 7);
```

- Remove **all** local `define('JWT_SECRET', ...)` lines from `login.php`, `register.php`, `check_role.php`.
- Validate `iss`, `aud`, `iat`, `nbf`, `exp`.
- Add `token_version` to `users`; put it in the token; compare it against the DB on every request. Increment it on logout/password change/demotion.
- Short access token + rotating refresh token. Store refresh tokens hashed, with device/IP metadata and revocation.
- Never put secrets, roles you cannot re-check, or PII in the token payload.
- Prefer `HttpOnly; Secure; SameSite=Strict` cookies over `localStorage` for the browser. If you must use bearer tokens, keep them out of `localStorage` (XSS steals them).

### 2.2 Roles must come from the database

```php
$decoded = JWT::decode($jwt, new Key(JWT_SECRET, JWT_ALGO));
$stmt = $conn->prepare(
  "SELECT id, role, subscription_status, token_version
   FROM users WHERE id = :id LIMIT 1"
);
$stmt->execute([':id' => $decoded->user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || (int)$decoded->tv !== (int)$user['token_version']) {
    unauthorized('Session revoked');
}
// Use $user['role'], not $decoded->role, for authorization decisions.
```

This kills the stale-role problem (demoted user keeps access for 24h) and gives you instant revocation.

### 2.3 Login hardening

- Rate limit by **IP + account**: 5 failures / 15 min, exponential backoff, `429`.
- Return the **same** response for unknown user and wrong password: `401 {"message":"Invalid credentials"}`.
- Add MFA (TOTP) for `superadmin` and `landlord`; require it for admin actions.
- Log every success/failure with IP, user agent, timestamp, account.
- Alert on: >20 failures for one account, logins from new countries, impossible travel, admin login outside business hours.
- Consider a CAPTCHA after 3 failures, and block breached passwords via the HIBP k-anonymity API.

### 2.4 Password reset

- Store `hash('sha256', $token)`, never the raw token.
- Add `expires_at` (15–30 min) and `used_at`.
- Single use; delete/mark used on consumption.
- Rate limit requests (email bombing) and always return the same message whether the email exists or not.
- Generate with `random_bytes(32)` (already done) and compare with `hash_equals`.

### 2.5 Registration

- Email verification before the account can act.
- Password policy: minimum 12 characters, block common/breached passwords, no maximum below 128.
- Never allow role selection from the request (already correct).
- Add a terms/consent record for POPIA.

---

## 3. Authorization — the biggest remaining risk

Every request must answer three questions **on the server**:

1. **Who** is calling? (verified identity, not just a token claim)
2. **What** object are they touching?
3. **Does this identity own/relate to that object?**

### 3.1 Write a single authorization helper

```php
function assertOwnsProperty(PDO $conn, int $userId, int $propertyId): void {
    $stmt = $conn->prepare("SELECT 1 FROM properties WHERE id=:pid AND landlord_id=:uid");
    $stmt->execute([':pid' => $propertyId, ':uid' => $userId]);
    if (!$stmt->fetchColumn()) {
        http_response_code(404); // 404, not 403: do not confirm existence
        exit(json_encode(['message' => 'Not found']));
    }
}
```

Use it in `units.php`, `expenses.php`, `maintenance.php`, `messages.php`, `send_receipt.php`, and anywhere a foreign key comes from the client.

### 3.2 Ownership-aware SQL

```php
// rent.php — only the owner can mark a record paid
$stmt = $conn->prepare(
  "UPDATE rent_records r
   JOIN tenants t ON r.tenant_id = t.id
   SET r.status='Paid', r.payment_method=:m, r.paid_date=:d, r.receipt_number=:r
   WHERE r.id=:id AND t.owner_id=:uid"
);
$stmt->execute([...]);
if ($stmt->rowCount() === 0) { http_response_code(404); exit; }
```

Apply the same pattern to maintenance updates, unit creation, tenant creation, expenses, and messages.

### 3.3 Role gates

- `tenants.php` → landlord/agent only.
- `rent.php` POST → landlord/agent for their own records; tenant can only pay their own.
- `send_receipt.php` → verify the receipt/tenant belongs to the caller; never accept an arbitrary recipient email.
- `generate_lease.php` → keep the existing owner predicate; add a role check.
- Return `404` for objects the caller cannot see, so IDs cannot be enumerated.

### 3.4 Never trust client-side checks

The frontend hiding a button is UX, not security. Every rule must be enforced again in PHP/SQL.

---

## 4. Input, output and data protection

- **Validate allowlists:** role, status, property type, priority, currency, dates, email, phone. Reject unknown fields.
- **File uploads:** decode base64 server-side, enforce MIME (`finfo`), max size (e.g. 5 MB), store outside the webroot or in object storage, serve via signed URLs, never inline untrusted HTML.
- **Output encoding:** React escapes by default; never use `dangerouslySetInnerHTML` with API data. For emails/PDF, `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')`.
- **SQL:** keep PDO prepared statements; never concatenate `ORDER BY`/filters. Use `PDO::ATTR_EMULATE_PREPARES => false`.
- **Mass assignment:** never bind request JSON directly to a model; map only known fields.
- **Error handling:** log details server-side, return generic messages. Never return `$e->getMessage()` to clients.
- **Data minimisation:** don't store ID numbers/documents unless required; encrypt at rest (DB TDE or application-level), mask in logs and UI, define retention/deletion.
- **POPIA:** document lawful basis, access control, breach notification (72h where applicable), data subject requests, and a register of processing.

---

## 5. Secrets and supply chain

### 5.1 Secrets

- Store secrets in **Azure Key Vault** (you already use Azure MySQL) or the platform's secret manager — never in `.env` in the repo, never in Docker layers.
- Inject at runtime: `DB_PASS`, `JWT_SECRET`, `MAIL_PASSWORD`, cron key.
- Use **different secrets per environment** (dev/staging/prod).
- Rotate on a schedule and after any staff change or suspected leak.
- Scan every push with `gitleaks`/`trufflehog`; block commits containing secrets.
- Remove secrets from git history (`git filter-repo`/BFG) if they were ever committed, then rotate them.

### 5.2 Dependencies and container

- `.dockerignore`: `.env`, `.git`, `node_modules`, `vendor` (rebuild it), `tests`.
- Pin the base image by digest, not `latest`.
- Run as non-root, read-only filesystem, drop Linux capabilities, no shell in production.
- `composer audit`, `npm audit`, Dependabot/Renovate, Trivy/Grype image scans in CI.
- Remove unused packages; every dependency is attack surface.
- Keep PHP, MariaDB, nginx and OpenSSL patched; subscribe to security advisories.

### 5.3 Database least privilege

```sql
CREATE USER 'jump_app'@'10.0.0.%' IDENTIFIED BY '<strong-random>';
GRANT SELECT, INSERT, UPDATE, DELETE ON jumpproptech.* TO 'jump_app'@'10.0.0.%';
-- no DROP, ALTER, CREATE, FILE, GRANT
```

- Separate migration/admin user from the runtime user.
- Do **not** grant `UPDATE` or `DELETE` on `audit_logs`. The batch-3 triggers already reject both, but least privilege is a second lock on the same door. If the runtime account is shared, create a dedicated audit-writer role that only has `INSERT`.
- Azure MySQL: firewall allowlist only the app subnet, private endpoint if possible, TLS required and verified.
- Backups encrypted, offsite, immutable, and **restore-tested**.

---

## 6. Network and platform controls

| Layer | Control |
|---|---|
| Edge | Cloudflare / Azure Front Door WAF, DDoS protection, bot management, geo/rate rules, TLS 1.2+ |
| Web server | Security headers (below), request size limits, timeout limits, hide `Server`/`X-Powered-By`, deny dotfiles |
| API | Rate limits per IP/account/route, JSON schema validation, method allowlists, `429` + `Retry-After` |
| Host | Minimal OS, automatic patches, host firewall, fail2ban, EDR, no public SSH (bastion/VPN only) |
| Network | App/DB in private subnets, no DB port from the internet, egress allowlist |
| Monitoring | Centralised logs, uptime checks, alerts, SIEM (Azure Sentinel / ELK / Grafana Loki) |

### 6.1 Nginx headers (the `Dockerfile` uses nginx, so `.htaccess` is ignored)

The ready-to-include snippet is `deploy/nginx-security.conf`; the `Dockerfile`
copies it to `/etc/nginx/snippets/jumpproptech-security.conf`. Include it inside
the API `server { ... }` block, before `location /`:

```nginx
include /etc/nginx/snippets/jumpproptech-security.conf;
```

It mirrors the following controls:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" always;

location ~ /\.(env|git|htaccess) { deny all; return 404; }
location ~* \.(sql|log|bak|ini|sh)$ { deny all; return 404; }
```

If you use Apache, fix `.htaccess` (line 1 is invalid `<?php`) and set `AllowOverride` deliberately.

### 6.2 CORS

```php
$allowed = ['https://app.jumpproptech.co.za', 'https://jumpproptech-frontend.vercel.app'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Vary: Origin');
}
```

Never `*` together with credentials or sensitive APIs.

---

## 7. Detection and response (assume breach)

Prevention fails eventually; detection limits damage.

**Log and alert on:**
- Auth failures, `401/403/404` spikes per IP/account.
- Admin actions: password resets, role changes, subscription toggles, data exports.
- Rent status changes and new units/tenants.
- Unusual data volume (many rows in a short time).
- New country/device, impossible travel, token reuse.
- WAF blocks, file-integrity changes, new admin users.

**Have ready:**
- An incident response plan with named roles and contact list.
- One-command revocation: rotate JWT secret + increment `token_version` + disable accounts.
- Forensics: retain logs ≥ 90 days, immutable storage, DB audit logs.
- Backups + tested restore (ransomware).
- POPIA breach assessment and notification process.
- Honeytokens/canary records (e.g. a fake admin account, fake tenant) to catch intruders early.

**Do not** hack back or retaliate. Preserve evidence and report to authorities if needed.

---

## 8. Secure development process

- **Threat model** every new endpoint: who calls it, what they can change, what leaks.
- **Code review** mandatory for auth, money, PII, admin.
- **CI gates:** `php -l`, Semgrep, Psalm/PHPStan, `composer audit`, `npm audit`, `gitleaks`, Trivy.
- **Staging** with production-like config; never test on production data.
- **Automated tests** for authorization: tenant A must not read/write tenant B.
- **Annual external pen test** + a private bug bounty or responsible-disclosure policy.
- **Tabletop exercises:** simulate a leaked JWT, a DB dump, a ransomware event.
- **Dependency updates** monthly; emergency patch SLA for critical CVEs (24–72h).

---

## 9. If a skilled attacker targets you specifically

A well-resourced attacker will:

1. Read your public GitHub, JS bundles, error messages and API docs.
2. Enumerate users, subdomains, staging servers and old endpoints.
3. Look for **logic flaws** (IDOR, race conditions, price/rent manipulation) rather than SQLi.
4. Try credential stuffing and phishing staff.
5. Attack the supply chain (dependency, CI/CD, Docker image, DNS).

Defences that actually matter here:

- **No secrets in source or client bundles.**
- **Server-side authorization on every object.**
- **MFA + least privilege** for all admin and CI accounts.
- **Short-lived, revocable sessions.**
- **Immutable audit logs + alerting.**
- **Network segmentation** so a web RCE cannot reach the DB directly.
- **Fast rotation and restore capability.**
- **Remove debug/backdoor endpoints** — these are exactly what a skilled attacker looks for.
- **Don't rely on obscurity** (hidden endpoints, custom headers, minified JS).
- **Minimise data** so a breach is less damaging.

You cannot out-build a determined attacker forever; you can make the cost higher than the payoff and the detection faster than the damage.

---

## 10. 30 / 60 / 90-day roadmap

### Days 1–7
- Rotate secrets, remove backdoors/debug files, fix rent IDOR, remove `.env` from webroot, force admin reset.
- Enable WAF + rate limiting + security headers.
- Turn on auth/admin logging and alerts.

### Days 8–30
- Fix all IDOR/role gaps; add authorization helper and tests.
- Move JWT secret to Key Vault; short-lived tokens + `token_version`.
- Password reset hardening; generic auth errors; MFA for admin.
- DB least-privilege user and private networking; TLS verification on.
- `.dockerignore`, pinned images, CI secret scanning.

### Days 31–60
- Full SAST/DAST/SCA in CI; dependency policy.
- Stored XSS/output encoding fixes; upload validation.
- Centralised logging + SIEM dashboards + on-call alerts.
- Backups, restore drills, incident response plan.
- POPIA data inventory and retention policy.

### Days 61–90
- External penetration test and remediation verification.
- Bug bounty / disclosure policy.
- Tabletop exercise and security training for staff.
- Quarterly access reviews and secret rotation.

---

## 11. Quick checklist

- [ ] No secrets in git, `.env` in webroot, or Docker image
- [ ] JWT secret from vault, ≥32 bytes, rotated, tokens revocable
- [ ] Roles re-checked from DB, not trusted from token
- [ ] Every write has an ownership predicate
- [ ] Admin routes role-gated and MFA-protected
- [ ] Rate limits + generic auth errors on login/reset
- [ ] Reset tokens hashed, expiring, single-use
- [ ] Output encoded; uploads validated; no arbitrary email recipients
- [ ] CORS allowlist, not `*`
- [ ] CSP/HSTS/XFO/nosniff/Referrer-Policy enabled at nginx
- [ ] Debug/test/backdoor endpoints removed
- [ ] DB least privilege + TLS verified + private network
- [ ] WAF, DDoS protection, bot management
- [ ] Centralised logs, alerts, immutable audit trail
- [ ] Backups encrypted and restore-tested
- [ ] Incident response plan and revocation runbook
- [ ] CI: SAST, SCA, secret scan, image scan
- [ ] Annual pen test + disclosure policy

---

*Defensive guidance only. Test only systems you own or are explicitly authorised to test.*
