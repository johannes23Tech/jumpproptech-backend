# JUMP PROPTECH — Master Project Memory & Build Specification

**Document type:** AI project memory / product requirements baseline
**Version:** 3.0 — Realigned to the approved internal product
**Updated:** 17 November 2026
**Owner:** JUMP PROPTECH / JUMP Living
**Status:** Working master baseline for implementation planning
**Primary purpose:** Give any AI assistant or developer a reliable, persistent understanding of the JUMP PROPTECH product, decisions, constraints, current implementation and next steps.

> **Instruction to the AI assistant:** Treat this document as the current source of truth for JUMP PROPTECH. Do not silently change approved decisions, invent business data, credentials, policies, dates, prices, legal terms or completed functionality. If a decision is marked "to confirm", ask before implementing the dependent behaviour. Keep this document updated when the owner approves a change.

---

## 0. Realignment notice — read this first

The project briefly drifted into a **public property marketplace with landlord/agency sign-up and paid subscription plans**. That is **not** the approved product.

The approved product is an **internal property-management platform for company-owned rental stock**. This version realigns the product without throwing away the working foundation.

**What we keep (already built and reviewed):**

- The existing API system: PHP 8 REST endpoints.
- Render for backend/API hosting (Docker, nginx + PHP-FPM).
- Azure Database for MySQL as the relational database.
- Vercel for the React + TypeScript PWA frontend.
- Cloudinary for image/document storage.
- JWT access tokens, TOTP MFA, audit logging, rate limiting, password policy and server-side role checks.
- Existing property, unit, tenant, rent, maintenance, expense and messaging foundations.

**What must be corrected (not necessarily deleted immediately):**

- Public marketplace (`/`, `/explore`) as the product's landing experience.
- Landlord/agency self-service registration.
- R250-style subscription plans, the paywall and the HTTP 402 subscription gate.
- Multi-landlord SaaS tenancy (`landlord_id` as the top-level ownership boundary).
- The five-role model (`superadmin`, `landlord`, `agent`, `tenant`, `maintenance`).

**Change policy:** realignment is **additive where possible**. Existing code is frozen, hidden or repurposed before it is removed. No destructive rewrite, no schema drop, no data loss without explicit owner approval. New work must move the system toward the approved scope in Section 1.

**Stack correction:** earlier versions of this document named Supabase for database, auth and storage. The deployed reality is **Azure Database for MySQL + JWT/TOTP auth + Cloudinary storage**. This document now follows the deployed stack. Supabase must not be introduced.

---

## 1. Project identity and vision

- **Business / product:** JUMP PROPTECH
- **Developed by:** JUMP Living
- **Product type:** Internal property-management platform for the company's own rental property portfolio.
- **Business model:** Internal property management system only. Do not build an external landlord SaaS, third-party landlord portal or subscription platform in the initial scope.
- **Market:** South Africa, initially with operating context in Rustenburg, North West.
- **Currency:** South African Rand (ZAR).
- **Language:** English only for the initial release.
- **Product vision:** A secure, mobile-first, central operating system for managing company-owned residential rental properties, tenants, leases, rental collections, maintenance, expenses, utilities and management reporting.
- **Product principle:** Design the full architecture and data model for the approved scope from the beginning, then implement and release capabilities in controlled phases.

The system must support township/backroom micro-housing as well as conventional residential rental stock. It must be practical for staff and tenants using entry-level Android devices, limited mobile data and intermittent connectivity.

---

## 2. Current technology and hosting decision — AUTHORITATIVE

### 2.1 Confirmed architecture

| Layer | Technology | Responsibility |
| --- | --- | --- |
| Development | Visual Studio Code | Local development, source control and project maintenance |
| Frontend hosting | **Vercel** | Host and deploy the public web/PWA frontend |
| Frontend framework | **React 18 + TypeScript + Vite** | Installable PWA, role-aware UI |
| Backend/API hosting | **Render** | Host the application API and trusted server-side services |
| Backend runtime | **PHP 8 (nginx + PHP-FPM, Docker)** | REST endpoints, business rules, server-side authorization |
| Database | **Azure Database for MySQL** | Main relational database (MySQL, utf8mb4) |
| Authentication | **Application JWT + TOTP MFA** | Staff and tenant identity, sessions, revocation, MFA |
| File storage | **Cloudinary** | Private tenant documents, leases, payment proof, maintenance images |
| Authorization | **Server-side role checks + ownership-scoped queries** | Enforce user/role/property/tenant access at the API |
| PWA | Web app manifest + service worker (to be implemented) | Installable experience on supported Android and iOS browsers |
| Source control | Git (GitHub) | Version control and deployment integration |

### 2.2 Architecture boundary

- Vercel serves the frontend only.
- Render hosts the backend API and trusted business logic.
- Azure MySQL is the only relational database.
- Cloudinary is the only file store.
- Authentication is issued and verified by the API. There is no Supabase project and no external identity provider in the initial release.
- Do not duplicate the database, auth or file storage on another platform unless the owner explicitly approves an architectural change.

### 2.3 Database security without PostgreSQL RLS

Azure MySQL does not provide PostgreSQL row-level security. The compensating controls are mandatory:

1. Every protected endpoint calls `authenticate()` and reads the **current** role from the database — never from the token alone.
2. Every query is scoped by the authenticated user's permitted properties/units/tenants.
3. All writes validate ownership server-side before mutating.
4. A central permission matrix (Section 6) is enforced in code, not only in the UI.
5. Deny-by-default: an endpoint must explicitly allow a role; unknown roles get 403.
6. Sensitive actions write an audit record (Section 20).
7. Tests must include negative permission cases for every role.

### 2.4 Technical decisions still to confirm

- Service worker/offline strategy and which capture workflows are allowed offline.
- Domain names, DNS ownership and production origins.
- Production email and SMS providers.
- E-signature provider and legal review.
- Accounting export format.
- AI provider and data-processing terms for JUMP FLUX.
- Backup/restore, retention and incident-response policy.

Never put database passwords, JWT secrets, SMTP credentials, Cloudinary API secrets, AI keys or provider credentials in frontend code, public environment variables, source control or chat. Keep privileged secrets server-side in Render environment settings. Frontend variables must contain only intentionally public values.

---

## 3. Product objectives

1. Maintain a central register of company properties, buildings, units and utility meters.
2. Support staff-assisted tenant registration and public/QR applications.
3. Provide first-time tenant sign-up through a unique QR code assigned to each unit.
4. Manage tenant records, occupants, leases, contractual rent dates, deposits and tenancy lifecycle.
5. Record and control cash and EFT rental payments.
6. Enforce full rental payment only; no partial rent payments in the initial release.
7. Provide sequential receipts and auditable EFT verification.
8. Track arrears, due dates and management-approved lease-based late penalties.
9. Manage tenant maintenance requests and internal maintenance work orders.
10. Manage company expenses, suppliers, budgets and approval.
11. Record prepaid electricity meter details; tenants purchase their own electricity tokens.
12. Include water in the total rent; do not separately bill tenants for water.
13. Provide tenant and staff communications through in-app messages, email and SMS.
14. Provide management dashboards, reporting and PDF/Excel exports.
15. Provide JUMP FLUX as a permission-aware AI management assistant for Q&A and report summaries.
16. Deliver an installable, responsive PWA for Android, iOS and desktop browsers, with carefully selected offline capture features.

---

## 4. Property portfolio and unit model

### 4.1 Supported property types

**Apartments and flats**
- 1 bedroom + 1 bathroom.
- 2 bedrooms + 1 bathroom.

**Residential houses**
- Number of bedrooms/rooms must be selectable.
- Number of bathrooms must be selectable.
- Do not hard-code only one house configuration.

**Precast rooms**
- 1 room: 3 m × 3 m (9 m²).
- 2 rooms: 6 m × 3 m (18 m²).

### 4.2 Data model concepts

Support:
- Property / site (company-owned).
- Building or structure (where applicable).
- Unit / rentable space.
- Property type and configuration (bedrooms, bathrooms, size).
- Address and location details.
- Unit identifier/number.
- Occupancy status (vacant, occupied, reserved, maintenance/unavailable, archived).
- Rental amount and contractual terms.
- Photos and supporting documents.
- Prepaid electricity meter identifier and notes.
- Property/unit history and audit trail.

A property can contain multiple rentable units. A standalone house or room can be represented without forcing an unnecessary building layer. The data model must avoid duplicating a property record for every room when a parent-child relationship is more appropriate.

**Additive schema direction:** keep the existing `properties` and `units` tables. Add a nullable `buildings` layer, unit configuration fields and archive status. Replace the `landlord_id` ownership boundary with a company/portfolio scope (a single configured company in the initial release).

---

## 5. Ownership and operating model

- Only properties owned by the company are managed in the initial product.
- No third-party landlord registration or external owner dashboard.
- No external SaaS subscriptions or multi-company tenanting in the initial release.
- No public marketplace, listing publication, viewing bookings or agent enquiries.
- Design the schema cleanly so future expansion is possible, but do not implement speculative multi-tenant SaaS features now.

**Migration note:** existing `landlord` and `agent` accounts are staff accounts in the new model. They are reassigned to staff roles (Property Manager, etc.) during migration. Existing `properties.landlord_id` values remain as historical ownership references until the company-scope migration is complete.

---

## 6. Users, roles and access control

### 6.1 Staff roles (eight)

1. Super Administrator
2. Administrator
3. Property Manager
4. Finance / Accountant
5. Maintenance Manager
6. Maintenance Technician
7. Reception / Support
8. Auditor — read-only

Plus one external-facing account type:

9. **Tenant** — restricted to their own profile, tenancy, unit, documents, payments and requests.

### 6.2 Permission matrix (to be completed in `docs/PERMISSIONS.md`)

Use least privilege. A suggested starting matrix:

| Capability | Super Admin | Admin | Property Manager | Finance | Maint. Manager | Technician | Reception | Auditor |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Manage staff & roles | ✔ | ✔ | — | — | — | — | — | — |
| Property/unit register | ✔ | ✔ | ✔ | read | read | read | read | read |
| Tenant records | ✔ | ✔ | ✔ | read | read | — | ✔ | read |
| Applications & QR | ✔ | ✔ | ✔ | — | — | — | ✔ | read |
| Leases & deposits | ✔ | ✔ | ✔ | read | — | — | — | read |
| Record cash payment | ✔ | ✔ | — | ✔ | — | — | — | — |
| Verify EFT / reconcile | ✔ | ✔ | — | ✔ | — | — | — | read |
| Approve expense | ✔ | ✔ | — | ✔ | — | — | — | read |
| Maintenance work orders | ✔ | ✔ | ✔ | read | ✔ | ✔ (assigned) | ✔ (create) | read |
| Reports & exports | ✔ | ✔ | ✔ | ✔ | ✔ | — | — | ✔ |
| JUMP FLUX | ✔ | ✔ | ✔ | ✔ | ✔ | — | — | read |

The matrix is a starting point, not an approved policy. Confirm with the owner before enforcing.

### 6.3 Authentication and security requirements

- Email/password authentication.
- Phone verification / OTP where configured and supported.
- Password recovery.
- Secure session handling.
- Mandatory 2FA for staff.
- Optional 2FA for tenants.
- Passkeys/biometric sign-in only where supported by the chosen browser/device and authentication provider; do not promise universal biometric capability.
- Audit log for sensitive actions and permission changes.
- Tenant access must be restricted to that tenant's own profile, tenancy, unit, documents, payment records and requests.
- Auditor is read-only.
- Administrative actions must be server-authorised and logged.

**Current implementation note:** JWT + TOTP MFA + token versioning + revocation are implemented. Role names must be migrated from the five legacy roles to the nine-role model. Staff MFA enforcement is currently optional; it must become mandatory for staff before production.

---

## 7. Tenant onboarding and QR access

- Staff can register or assist tenants.
- A public application flow is available.
- **Each rentable unit has its own unique QR code.**
- QR code is intended for **first-time sign-up / onboarding only**.
- QR code resolves to a unit-scoped sign-up/application page.
- A QR code must not act as a permanent password or unrestricted access credential.
- Use secure, unguessable, revocable tokens; store token hashes where practical; apply expiry/activation controls and abuse/rate limiting.
- Management approval is required before a tenant account/tenancy becomes active.
- After first-time onboarding, tenants sign in through the normal login flow; they do not need to scan the QR code every time.
- Existing tenant login must not accidentally create a second application or tenancy.
- QR codes can be regenerated/revoked when a unit changes status or a token is compromised.

### 7.1 Tenant application fields

Capture appropriate personal/contact and tenancy-related information, including:
- Full name and identity details as required by approved policy.
- Contact information.
- Emergency contact.
- Number of occupants / occupant details as approved.
- References.
- Requested unit and application information.
- Supporting documents as approved.

**Do not request employment income or salary information.** Employment/income data is explicitly excluded from the tenant application.

**Additive schema direction:** add `onboarding_tokens` (unit_id, token_hash, expires_at, revoked_at, used_at) and `tenant_applications` (unit_id, applicant fields, documents, status: submitted/reviewing/approved/rejected). Do not overload the existing `tenants` table for unapproved applications.

---

## 8. Tenant portal

Tenant portal capabilities in the approved scope:
- Profile and permitted profile updates.
- Allocated property/unit information.
- Lease and tenancy information.
- Rent amount and contractual due date.
- Current balance and payment history.
- Receipts.
- Lease/document access.
- Maintenance request submission, photos and status tracking.
- Tenant-management messages.
- In-app notifications and announcements.
- Supporting documents.
- EFT proof-of-payment submission.
- Relevant prepaid electricity meter identifier/information.

Tenants must not see another tenant's records, internal notes, staff-only communications, approval data or company financial information.

---

## 9. Tenancy, lease and deposit management

Support:
- Tenancy creation and approval.
- Link tenant(s) to a specific unit.
- Lease templates and uploaded lease documents.
- Lease versioning and amendments.
- Lease start/end dates.
- Renewal and expiry reminders.
- Electronic signature integration (provider to be selected and legally reviewed).
- Move-in and move-out workflows.
- Inspection records and supporting photos.
- Deposit status: paid, outstanding, refundable, deductions and refunded.
- Deposit statements and audit history.
- Tenancy termination and unit status updates.

Lease templates and legal wording must be supplied/approved by management and reviewed by a qualified South African legal professional. Do not invent contract clauses.

**Current implementation note:** Phase 2 implements the versioned `leases`, `lease_signatures`, `deposit_transactions`, `inspections` and `inspection_photos` tables plus the tenancy lifecycle fields. Ad-hoc PDF generation is retired; management must supply the approved lease document. A formal e-signature provider is still not integrated.

---

## 10. Rent and payment management

### 10.1 Launch payment methods

- Cash.
- EFT (bank transfer).

**Online payment gateways are paused/disabled for the initial release.** Build the architecture so a future gateway can be added, but do not activate or simulate one now.

### 10.2 Payment rules

- Full rent payment only; no partial rent payments in the initial release.
- Each tenant's rent due date is set according to their individual contract. Management must be able to configure different due dates for different tenants.
- Rent obligations should be generated from the active lease/tenancy terms.
- Overdue status and reminders must follow the approved policy.
- Late penalties can only be applied after management approval and must follow the tenant's lease terms.
- Finance staff verify EFT proof against actual bank receipt before marking EFT as paid.
- Uploading EFT proof is not proof that money has cleared.
- Cash payments are recorded by authorised staff and must generate a sequential receipt.
- Receipts must be traceable and not silently overwritten or renumbered.
- Reversals, corrections and refunds require controlled, auditable workflows.
- Do not invent the company's EFT beneficiary/bank details; obtain them from the owner/finance manager.
- Maintain payment status distinctions: submitted, pending verification, verified/paid, rejected, reversed/refunded.

### 10.3 Reconciliation

Support bank statement CSV/Excel import as an integration workflow, subject to the bank's export format and approval. Matching must not silently mark ambiguous transactions as paid. Record who verified or reconciled each payment and when.

**Implementation status (Phase 3):** `api/rent.php` now uses the Phase 3 state machine. `config/rent.php` owns obligation generation, derived overdue status, arrears aging and the locked receipt service. Receipt numbers come from `receipt_sequences` inside the payment transaction and are never random, reused or renumbered. The previous random-number defect is closed; do not reintroduce formatting-based receipt numbers.

---

## 11. Utilities

### 11.1 Electricity

- Each relevant unit may have a prepaid electricity meter.
- **Tenants purchase their own electricity tokens.**
- JUMP PROPTECH does not purchase electricity tokens on behalf of tenants.
- The platform does not sell electricity or collect a separate electricity payment in the initial release.
- Record prepaid meter identifier and associate it with the correct property/unit.
- Allow authorised staff to maintain meter notes/history where useful.

### 11.2 Water

- Water is included in the total rent amount.
- No separate tenant water billing or tenant water charge calculation.
- Company water costs may be recorded as property/company expenses for management reporting.

---

## 12. Maintenance management

- Tenants submit maintenance requests and optional photographs.
- Staff triage and prioritise requests.
- Maintenance Manager assigns work to internal maintenance staff.
- Maintenance Technician updates status, notes, work performed, photos and completion details.
- Record costs and link them to the relevant property/unit.
- Track request lifecycle (submitted, reviewed, assigned, in progress, awaiting information/parts if needed, completed, closed).
- Tenant can see an appropriate status and response, not internal-only notes.

**Initial exclusion:** No external contractor workforce module, contractor onboarding, contractor quotation workflow or contractor invoice management.

**Current implementation note:** the existing maintenance module assigns external `contractors` and only supports Open / In Progress / Resolved. It must be repurposed for internal staff assignment. Contractor tables can remain dormant; do not build them out.

---

## 13. Company expense management

Include:
- Manual expense capture.
- Expense categories.
- Supplier records.
- Property/unit association where applicable.
- Receipt/invoice/document attachments.
- Budgets and actuals.
- Approval workflow.
- **One authorised manager approval** for expenses.
- Audit trail for submission, approval, rejection and edits.
- Property profitability and company-level financial summaries.

Do not assume the identity of the approving manager or invent approval thresholds. Those are configuration items.

**Current implementation note:** expenses are flat records with no supplier, budget, attachment, status or approver. Add these additively.

---

## 14. Communications and notifications

Approved channels:
- In-app notifications.
- Email.
- SMS.

Approved communication features:
- Tenant-management messaging.
- Announcements.
- Rent reminders and payment-related notifications.
- Lease expiry/renewal reminders.
- Maintenance updates.
- Delivery/status tracking where supported.

**WhatsApp is excluded from the initial release.** Provider selection, message templates, sender identity, consent and pricing must be confirmed before enabling email/SMS production delivery.

**Current implementation note:** email exists only for password reset and receipts. There is no notifications table, no SMS adapter and no in-app notification centre. Add a notifications table and provider adapters.

---

## 15. Reporting and management dashboard

Provide role-appropriate dashboards and reports, including:
- Property and unit register.
- Occupancy and vacancy.
- Tenant and tenancy lists.
- Rent due and collections.
- Arrears and overdue accounts.
- Cash and EFT payment records.
- EFT verification and reconciliation.
- Deposit balances and settlements.
- Maintenance requests and costs.
- Company expenses and budgets.
- Property-level income/expense and profitability.
- Monthly management reports.
- Filters and date comparisons.
- Interactive charts.
- PDF and Excel exports.

Exports must respect the requesting user's permissions and avoid exposing unnecessary personal information.

**Current implementation note:** one aggregate dashboard endpoint exists; charts are basic. PDF exists for leases/receipts. There is no Excel generator, report builder or export audit. Add `PhpSpreadsheet` server-side and audit export actions.

---

## 16. JUMP FLUX AI

**Name:** JUMP FLUX
**Role:** AI assistant for authorised JUMP PROPTECH management users.

### 16.1 Initial approved scope

- Answer management questions using records the logged-in user is authorised to access.
- Summarise reports and operational trends.
- Help locate relevant records and explain dashboard information.
- Provide natural-language assistance for management workflows.

### 16.2 Explicit exclusions initially

- Predictive AI.
- Automated arrears-risk scoring.
- Predictive maintenance.
- Investment/property acquisition recommendations.
- Autonomous financial actions.
- Automatic payment verification, receipt issuance, deposit refunds, expense approvals or lease changes.

### 16.3 AI safety and data rules

- AI must never bypass server-side role checks or query scoping.
- Retrieve only records the requesting user is authorised to view.
- Minimise personal and sensitive information sent to an external AI provider.
- Never expose secrets, full identity documents or unrelated tenant data in prompts.
- AI-generated summaries must be labelled as AI-assisted and users must be able to inspect source records.
- AI cannot approve payments, expenses, refunds, penalties or access changes.
- Do not claim an action was completed unless a trusted application action confirms it.
- AI provider and data-processing terms must be reviewed before activation.

**Current implementation note:** `api/faq_bot.php` is a keyword/regex FAQ responder. It is not JUMP FLUX. Keep it as a labelled help assistant until a real provider adapter is approved.

---

## 17. PWA and offline requirements

- Responsive web application.
- Installable PWA for supported Android and iOS devices.
- Desktop browser access.
- App icon, manifest, service worker and install guidance.
- Mobile-first layouts suitable for entry-level Android devices and limited data.
- Offline support only for specifically approved capture/read workflows.
- Clear queued/synchronising/synced/failed status.
- Retry-safe synchronisation using idempotency keys.
- Conflict handling and audit trail.
- Do not cache sensitive tenant documents or financial data unnecessarily.
- No offline payment verification, expense approval, deposit refund approval, role changes or other privileged financial/security actions.
- Test real devices and supported browsers. PWA installation and background behaviour vary by platform; do not promise identical native-app functionality on Android and iOS.

**Current implementation note:** the manifest and install prompt exist, but there is **no service worker** and no offline queue. A Capacitor Android wrapper and a separate Flutter app exist; neither replaces the PWA requirement. The Flutter app is out of scope unless the owner revives it.

---

## 18. Integrations

Potential integration categories in scope, with providers not yet selected:
- Email delivery.
- SMS delivery.
- E-signature.
- Accounting software.
- Bank statement CSV/Excel imports.
- AI provider for JUMP FLUX.

Build provider adapters so vendors can be changed without rewriting core business logic. Confirm vendor API capability, commercial terms, data processing, security, support and sandbox availability before implementation.

---

## 19. Explicit exclusions / deferred features

Do not include these in the initial launch unless the owner approves a formal scope change:
- External landlord SaaS / third-party owner portal.
- Public property marketplace, listing publication, viewing bookings or agent enquiries.
- Subscription plans and paywalls.
- Online payment gateway activation.
- Partial rent payments.
- Tenant electricity sales or electricity-token purchasing by the company.
- Separate tenant water billing.
- WhatsApp notifications.
- Inventory/stock management.
- External contractor workforce and contractor quotation/invoice workflows.
- Predictive AI.
- Additional languages.
- Multi-currency.
- Multi-company SaaS tenancy.
- Legacy data migration (initial system starts clean).
- Speculative features not in the approved requirements.

**Note on existing marketplace code:** it is **frozen**, not deleted. It must be removed from the default public route and must not be extended. Deletion happens only after the owner confirms, so no working code is lost prematurely.

---

## 20. Security, privacy and compliance

- Design for South African POPIA obligations and obtain qualified legal/privacy advice.
- Apply least privilege, secure sessions, staff MFA and server-side authorization on every request.
- Use private/authenticated Cloudinary assets and short-lived signed URLs where needed.
- Validate file type, size and access on the server.
- Audit sensitive actions: payment verification, receipt correction, lease changes, role changes, expense approval, deposit deductions/refunds, exports and QR token regeneration.
- Rate-limit public application and QR endpoints.
- Protect against CSRF, XSS, injection, IDOR, brute force and insecure direct object references.
- Use server-side validation; never trust client-supplied amounts, roles or ownership.
- Use secure headers, HTTPS and appropriate CORS restrictions.
- Separate development, staging and production environments.
- Maintain backups and test restoration.
- Define retention/deletion and incident response procedures.
- Do not present the application as legally compliant until the actual implementation and organisational practices have been reviewed.

This specification is not legal, tax or accounting advice. Lease enforceability, e-signature validity, VAT, rental legislation, municipal rules and financial reporting must be confirmed by qualified professionals.

---

## 21. Delivery approach and implementation phases

Plan the whole system architecture and database for the approved scope at the start, but implement in controlled phases.

| Phase | Focus | Main outcomes |
| --- | --- | --- |
| 0 | Foundation and architecture | Confirm role model and company scope, environment separation, data model, migrations, auth, permissions matrix, audit, storage, PWA shell |
| 1 | Property and tenant core | Property/building/unit register, unique QR onboarding, applications, staff approval and tenant portal foundation |
| 2 | Tenancies, leases and deposits | Tenancy lifecycle, lease documents/templates, versioning, signatures, deposits, inspections and move-in/out |
| 3 | Rent, cash and EFT | Contractual rent obligations, cash recording, EFT proof/verification, sequential receipts, arrears and reconciliation |
| 4 | Maintenance and expenses | Tenant requests, internal technician workflows, expense capture, suppliers, budgets and manager approval |
| 5 | Utilities, communications and reports | Meter register, in-app/email/SMS, dashboards, PDF/Excel exports and monthly reporting |
| 6 | JUMP FLUX AI, offline and PWA hardening | Permission-aware AI, selected offline capture/sync, Android/iOS/browser tests and security/performance hardening |
| 7 | Production readiness | UAT, privacy/security review, finance verification, backup/restore drill, training, support and go-live approval |

Do not invent delivery dates, budgets or team members. Estimate them after Phase 0 discovery and resource confirmation.

---

## 22. Project management and quality rules

- Maintain a requirements backlog and traceability from requirement to implementation and test.
- Use version control and reviewed changes.
- Use database migrations; do not make undocumented production schema changes.
- Maintain development, staging and production environments.
- Keep a decision log, change log, risk register and issue list.
- Do not silently alter approved requirements.
- Demonstrate working increments and obtain business feedback.
- Test positive and negative permissions for every role.
- Test financial workflows end-to-end.
- No unresolved critical security, privacy or financial-integrity defects at launch.
- Require business UAT and explicit owner/sponsor go-live approval.
- A feature is not complete merely because its screen exists; its permissions, business rules, errors, audit and tests must work.

---

## 23. Open decisions / configuration items

These are not permission to invent values. Ask the owner or authorised business representative when needed.

1. Legal company name, official contact details, logo and branding assets.
2. Company EFT beneficiary and bank details.
3. Exact property portfolio and initial property/unit records.
4. Approved lease templates and legal clauses.
5. Deposit rules, deductions and refund authority.
6. Late-penalty terms and approval authority for each lease.
7. VAT registration status and tax configuration, confirmed by an accountant.
8. Email provider and credentials.
9. SMS provider and credentials.
10. E-signature provider and legal review.
11. Accounting software and import/export format.
12. AI provider and data-processing terms.
13. Domain name and DNS ownership.
14. Named sponsor, Project Manager, Product Owner and Technical Lead.
15. Project budget, resource capacity and delivery schedule.
16. Offline workflows and which roles may use them.
17. Notification templates, timing and consent rules.
18. Backup, retention, support and incident-response policies.

---

## 24. Current implementation status (as-is, 17 November 2026)

### 24.1 Working foundation (keep)

- PHP API on Render with nginx/PHP-FPM Docker image.
- Azure MySQL connection with TLS certificate verification.
- React + TypeScript + Vite frontend on Vercel.
- JWT auth with token versioning, revocation and 1-hour expiry.
- TOTP MFA setup/enable/disable/login.
- Password policy, bcrypt cost 12, reset flow.
- Rate limiting, CORS allowlist, security headers.
- Append-only audit log.
- Property, unit, tenant, rent, maintenance, expense and message endpoints.
- Cloudinary image upload integration in the frontend.
- PWA manifest and install prompt (no service worker yet).

### 24.1a Phase 0 applied (17 November 2026)

- `config/permissions.php` defines the eight staff roles, tenant role, permission matrix and legacy-role mapping.
- `migrations/2026-11-17_phase0_roles_and_company.sql` adds `companies`, `users.company_id`, `users.staff_role`, `users.account_type`, `users.is_active` and `properties.company_id`, and backfills existing accounts.
- `middleware/check_role.php` reads the approved role from the database, rejects inactive accounts, blocks Auditor writes and no longer enforces the subscription gate.
- `api/staff.php` provides permission-gated staff listing, creation and role/active-state updates.
- Login and MFA login return canonical roles, `staff_role`, `account_type` and `permissions`.
- Public tenant registration explicitly creates `account_type = 'tenant'`.
- Frontend `VITE_ENABLE_MARKETPLACE` is retired. The marketplace, onboarding and paywall screens are no longer routed or bundled.
- The app entry is a white animated JUMP PROPTECH logo reveal that leads into staff/tenant sign-in.
- Frontend has a real Staff management screen at `/staff` and role-aware navigation.
- `docs/PERMISSIONS.md` documents the matrix and migration checklist.

**Deployment note:** run the Phase 0 migration before deploying the matching API, or login and authenticated requests will fail on the new columns.

### 24.1b Phase 1 applied (18 November 2026)

- `migrations/2026-11-18_phase1_property_tenant_core.sql` adds `buildings`, `properties.archived_at`, `units.building_id`, `units.prepaid_meter_number`, `units.archived_at`, `onboarding_tokens`, `tenant_applications` and `application_documents`.
- Each unit can have one live QR onboarding token. Only a SHA-256 hash is stored; the raw token and application URL are shown once. Generating a new token revokes the previous unused token, and a token is single-use, expiring and revocable.
- `api/qr_tokens.php` lets authorised staff (`qr.manage`) generate, list and revoke unit QR tokens.
- `api/public/onboarding.php` resolves a QR link and accepts a first-time tenant application. It is rate-limited, never exposes tenant or company data, and captures no employment or income fields.
- `api/applications.php` lets staff with `applications.view` inspect applications and staff with `applications.review` mark them under review, reject them with a reason, or approve them. Approval atomically creates the tenant user, tenancy record, first rent obligation and marks the unit occupied.
- `api/buildings.php` adds the optional building/block layer. `api/properties.php` and `api/units.php` gained archive support, and units gained building, prepaid-meter and QR-status fields.
- The tenant portal now exposes the building name, unit details and the prepaid electricity meter identifier. Water remains included in rent.
- Frontend: public `/apply/:token` onboarding page, staff `/applications` review screen, and QR generation/revocation in the Units screen.

**Deployment note:** run the Phase 1 migration before deploying this API. Both migrations are additive and safe to re-run. Run Phase 0 first.

### 24.1c Phase 2 applied (18 November 2026)

- `migrations/2026-11-18_phase2_leases_deposits.sql` adds tenancy status/move-in/move-out/termination fields to `tenants`, the versioned `leases` table, `lease_signatures`, the append-only `deposit_transactions` ledger, `inspections` and `inspection_photos`.
- A legacy `leases` table without a `version` column is renamed to `leases_legacy` once, preserving any historical rows. The new API never reads the legacy table.
- `api/tenants.php` and application approval now create lease version 1 as a draft so management can attach the approved document and record signatures.
- `api/leases.php` manages versions: edit a draft, record tenant/landlord signatures, activate (which supersedes the previous active version and applies the term dates, rent and deposit), or delete an unsigned draft. Activation requires an uploaded document or at least one recorded signature.
- `api/deposits.php` records received, deduction, refund and adjustment movements. Deductions and refunds cannot exceed the held balance. Every movement is audited.
- `api/inspections.php` records move-in, move-out and routine inspections with Cloudinary photos.
- `api/tenancies.php` drives the lifecycle: move-in, notice, cancel notice, renewal (creates the next draft lease version) and termination (marks the active lease terminated and the unit vacant).
- `api/generate_lease.php` is retired with HTTP 410. The platform no longer generates clause wording; lease templates and legal wording must be supplied and approved by management.
- The tenant portal now returns the current lease document and signature status, the deposit position and ledger, and the tenant's own inspections.
- Frontend: consolidated `/tenancy` staff workspace (tenancies, leases, deposits, inspections) and a data-backed tenant Lease & Docs page.

**Deployment note:** run the Phase 2 migration before deploying this API. The migration is additive and safe to re-run, and preserves a legacy `leases` table.

### 24.1d Phase 3 applied (18 November 2026)

- `migrations/2026-11-18_phase3_rent_cash_eft.sql` adds `tenants.rent_due_day`, `rent_records.due_date/lease_id/updated_at`, expands the rent status enum to `Pending, Overdue, Submitted, PendingVerification, Paid, Rejected, Reversed`, and adds `rent_payments`, `receipts` and `receipt_sequences`.
- `config/rent.php` owns the Phase 3 helpers: contractual due-date clamping, idempotent obligation generation from active lease terms, the locked per-year receipt sequence, receipt issuance, derived overdue status and arrears aging.
- `api/rent.php` implements the cash/EFT state machine. `payments.record_cash` records counted cash; `payments.verify_eft` verifies EFT against the bank; `payments.reverse` reverses a verified payment and voids its receipt. Tenants may only submit Cloudinary proof for their own obligations, and proof submission never marks rent paid.
- Receipts are sequential per year (`RCP-YYYY-NNNNNN`), issued inside the payment transaction. A reversal keeps the rent record and the receipt row, marks both voided/reversed, and never reuses or renumbers the number.
- Overdue is derived at read time from the contractual `due_date`; there is no background job. Arrears aging covers current, 1–30, 31–60, 61–90 and 90+ days, and future obligations are not counted.
- Lease activation generates rent obligations from the lease dates and monthly rent using the tenant's individual `rent_due_day` (default 1, clamped to month length). Existing months are skipped; only a null `due_date` is backfilled.
- `api/tenant_data.php` now returns each obligation's effective status and payment attempts, the tenant's receipts (voided receipts stay visible), and the arrears summary.
- Frontend: `/rent` is a staff register with filters, EFT proof review, verify/reject/reverse and cash recording; the tenant statement gains EFT proof upload, status/rejection display, receipts and arrears.

**Deployment note:** the Phase 3 migration has already been applied to the Azure database. It is additive and safe to re-run.

### 24.2 Drift to retire

| Drift | Location | Action |
| --- | --- | --- |
| Public marketplace landing | `frontend/src/App.tsx`, `src/marketplace/*` | Remove from default route; hide behind a disabled flag; do not extend |
| Landlord/agency sign-up | `Marketplace.tsx` screens, `api/admin/create_landlord.php` | Freeze; no public business-account endpoint |
| Subscription/paywall | `Paywall.tsx`, `api/admin/toggle_sub.php`, 402 gate in `middleware/check_role.php` | Disable the gate; keep columns dormant |
| Multi-landlord boundary | `properties.landlord_id`, scoped queries | Introduce company/portfolio scope; migrate staff accounts |
| External contractors | `contractors` table, `api/maintenance.php` | Replace with internal staff assignment |
| Random receipts | `api/rent.php` | Replace with sequential receipt service |
| Five-role model | schema + API + frontend | Migrate to nine-role model |

### 24.3 Missing capabilities (build in phase order)

- ~~Buildings layer, unit configuration fields, archive status.~~ (Phase 1)
- ~~Company scope and nine-role permission matrix.~~ (Phase 0)
- ~~QR onboarding tokens and tenant applications.~~ (Phase 1)
- ~~Application review/approval workflow.~~ (Phase 1)
- ~~Tenant portal linked to approved applications.~~ (Phase 1 foundation)
- ~~Lease versions, signature records, deposit ledger, inspections.~~ (Phase 2)
- ~~Contractual due dates, arrears/aging, late-penalty approval.~~ (Phase 3 — due dates, obligation generation and aging; penalty approval remains policy-driven)
- ~~Cash/EFT payment records with proof, verification and rejection states.~~ (Phase 3)
- ~~Database-backed sequential receipts and reversal workflow.~~ (Phase 3)
- Bank statement import and reconciliation.
- Internal maintenance work orders, assignment, notes and costs.
- Suppliers, budgets, expense approval and attachments.
- Prepaid meter register.
- Notifications (in-app/email/SMS), templates and adapter layer.
- Reports, Excel export, export permissions and audit.
- JUMP FLUX provider adapter and permission-scoped retrieval.
- Service worker, offline capture queue and sync status.
- Staff MFA enforcement and negative-permission test suite.

---

## 25. Instructions for future AI assistants

When continuing this project:

- Read this file first.
- Treat the current stack as **VS Code + React/Vite PWA on Vercel + PHP 8 API on Render + Azure Database for MySQL + Cloudinary + JWT/TOTP**.
- Never introduce Supabase, Railway or Netlify unless the owner explicitly changes the decision.
- Preserve all confirmed business rules, especially company-owned properties only, unique QR per unit for first-time onboarding, no employment/income application fields, cash and EFT only at launch, no partial rent, individual contractual due dates, tenants buying their own prepaid electricity, water included in rent, internal maintenance staff, one-manager expense approval, JUMP FLUX as a management assistant, and no predictive AI initially.
- Do not resurrect the public marketplace, landlord self-registration or subscription paywall.
- Ask concise questions only when a missing decision blocks safe implementation. Do not repeatedly ask questions already answered in this document.
- Do not create dummy tenants, fake properties, fake transactions, fake receipts, fake testimonials or fabricated financial figures in production data.
- Use clearly labelled development fixtures only when required for automated tests, and keep them out of production.
- Never expose or request secret keys in chat. Use local environment files and hosting secret settings.
- Explain each implementation step in practical VS Code terms.
- Build real working functionality, not just attractive mock screens.
- Test each phase and fix errors before moving forward.
- Update this master memory file when the owner approves a material change.

---

**End of master project memory.**
