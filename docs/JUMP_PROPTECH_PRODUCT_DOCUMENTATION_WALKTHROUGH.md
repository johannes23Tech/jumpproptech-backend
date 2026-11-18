# JUMP PROPTECH — Product Documentation & App Walk-Through

**Product:** JUMP PROPTECH  
**Developer / Owner:** Jump Living  
**Document type:** Product documentation and application walk-through (copy-paste ready for Microsoft Word)  
**Version / build context:** Current internal build (Phases 0–6: core portfolio/tenant/rent/maintenance/expense workflows, Super Admin Control Center, JUMP FLUX AI assistant)  
**Date:** <!-- Add document date -->  
**Prepared by:** <!-- Add author -->  
**Status:** Draft — for review and final Word formatting  

---

## How to use this document in Word

- Copy the content into Word and apply your preferred styles (Heading 1–3, Normal, List, Caption).
- Replace each `[SCREENSHOT: ...]` placeholder with the actual image.
- Keep the **Figure** captions (e.g., `Figure 1 — ...`) directly below each screenshot and update the figure numbers if you add/remove images.
- Complete all `<!-- ... -->` fields (date, owner, version, sign-off).
- Add a Table of Contents and (optionally) a Table of Figures in Word after inserting screenshots.

---

## Table of Contents (suggested)

1. Executive Summary  
2. Product Overview  
3. Roles, Access & Security  
4. Feature Documentation (Module Reference)  
5. Application Walk-Through (User Journeys)  
6. JUMP FLUX AI — Assistant Guide  
7. Super Admin Control Center Guide  
8. Screenshot & Figure Index  
9. Acceptance Criteria / QA Walk-Through Checklist  
10. Known Limitations & Future Enhancements  
11. Deployment & Configuration Notes  
12. Document Control & Sign-Off  

---

## 1. Executive Summary

JUMP PROPTECH is an internal property-management platform for Jump Living, designed to manage a residential property portfolio in South Africa through a single, disciplined operating system. The platform covers the operational lifecycle — properties and units, QR-based tenant onboarding and applications, tenancies/leases and deposits, rent (cash and EFT, full payments only), arrears visibility, maintenance, expenses/budgets/suppliers, staff administration — and includes the **Super Admin Control Center** for sensitive system/security oversight and **JUMP FLUX AI** (“Intelligence in Motion”) for AI-assisted property intelligence.

**Key operating principles (current build)**
- Internal company system (not a public marketplace/subscription product in active scope).
- Unique QR onboarding per unit; unit-scoped public application links.
- Full rent payments only (no partial rent). Cash recorded by authorized staff; EFT submitted with proof and verified against records before being marked paid.
- Receipts issued with sequential numbering (e.g., `RCP-YYYY-NNNNNN`).
- Internal maintenance staff assignment (contractor model not the active workflow).
- Expense workflow with controlled approval and auditable, append-only reversals (corrective entries rather than silent edits).
- Security-first: authenticated access (JWT), optional MFA, role/permission-based authorization, session/device tracking, audit logging, and privacy-aware AI behavior.

---

## 2. Product Overview

### 2.1 Purpose & mission
Provide Jump Living with a reliable, auditable, and user-friendly system to operate its property portfolio, reduce manual tracking, improve payment/maintenance visibility, and enable secure AI-assisted insights and assistance.

### 2.2 Users and operating model
| User / role context | Primary purpose |
|---|---|
| Super Administrator | Sensitive/system controls, security monitoring, account/session/token oversight, audited exports (Control Center). |
| Administrator | Operational administration and portfolio oversight (separate admin dashboard and duties). |
| Property / Operations staff (e.g., Property Manager, Reception/Support) | Properties, units, tenants, applications, tenancies, communications/operations within permissions. |
| Finance / Accountant | Rent/payment recording/verification/reconciliation/reversal, arrears, financial views within permissions. |
| Maintenance Manager / Technician | Maintenance triage, assignment, updates, resolution, related costs within permissions. |
| Auditor (read-only, where applicable) | Read-only visibility within granted scope. |
| Tenant | Tenant portal: own tenancy/rent/payments/maintenance/profile and JUMP FLUX AI assistance (authorized scope). |
| Public applicant (no account) | Unit-scoped onboarding application via a unique QR/token link. |

*Note: Exact permission grants are enforced server-side and may vary by configuration/role mapping.*

### 2.3 Scope (current build)
**In scope**
- Staff console: dashboard, properties, units, tenants, applications, tenancy/leases/deposits/inspections, rent/arrears, maintenance, expenses/budgets/suppliers/utilities (as enabled), staff/security management.
- Tenant-facing portal: tenant dashboard/profile/documents, payments/rent views and submissions (as applicable), maintenance requests, JUMP FLUX AI.
- Public onboarding: `/apply/:token` for unit-scoped applications.
- JUMP FLUX AI: chat interface, persistent conversations, provider-independent server-side AI integration, role-aware data context, setup/error handling, learning/feedback capture.
- Super Admin Control Center: overview, accounts, monitoring/audit, sessions/devices, QR token oversight, access/permissions audit, controlled exports.

**Out of scope / dormant (current build)**
- Public marketplace, external landlord self-signup, and subscription paywall flows (kept dormant; not active product behavior).
- Predictive AI features.
- Bank statement auto-reconciliation without an approved sample import format.
- Autonomous AI actions that change records or send communications without explicit, authorized human confirmation.

### 2.4 Technical context (high level)
| Layer | Summary |
|---|---|
| Frontend | React + Vite (SPA), deployed on Vercel |
| Backend | PHP 8 API, deployed on Render |
| Database | Azure MySQL |
| Authentication | JWT access tokens, optional TOTP MFA, token versioning/revocation, session/device tracking |
| Media/uploads | Cloudinary (where applicable, e.g. proof/document uploads) |
| AI | JUMP FLUX AI — provider-independent server-side integration (configurable model/provider), role-aware context, conversation persistence |

---

## 3. Roles, Access & Security

### 3.1 Authentication
- Users sign in with authorized credentials; successful authentication issues a JWT access token (subject to account status and security controls).
- Optional multi-factor authentication (TOTP) and recovery flows are supported where enabled.
- Password reset and security-related changes follow controlled flows and may invalidate prior sessions/tokens as designed.

**[SCREENSHOT: Login screen]**  
**Figure 1 — Login:** Secure sign-in screen for authorized users.

**[SCREENSHOT: MFA challenge / verification]**  
**Figure 2 — Multi-factor authentication:** MFA challenge/verification during sign-in (if enabled).

**[SCREENSHOT: Forgot password / reset password]**  
**Figure 3 — Password recovery:** Forgot/reset password flow.

### 3.2 Authorization & permissions
- Access is **deny-by-default** and enforced server-side (UI visibility is not authorization).
- Staff permissions are role-based (e.g., view/manage properties/units/tenants/applications/leases, record/verify/reconcile/reverse payments, manage maintenance/expenses, view reports/audit, manage staff/settings) according to the approved role matrix.
- Tenants access only their own authorized information and actions.

### 3.3 Sessions, devices, and auditability
- Issued sessions/devices can be tracked; sensitive actions (e.g., deactivation, MFA reset, role changes, forced logout/token rotation) are auditable.
- Audit/activity logs record security-relevant and administrative events (who/what/when/outcome, with request metadata where applicable).

### 3.4 Public onboarding security
- Unit QR/onboarding tokens are unique, time-bound, single-use (first successful submission/use as designed), and revocable. Public application access does not require an authenticated session.

---

## 4. Feature Documentation (Module Reference)

### 4.1 Dashboard / home
**Purpose:** Provide an at-a-glance operational and financial overview for authorized staff.

**Typical elements**
- Portfolio counts (properties, units, occupied/vacant).
- Financial indicators (e.g., collected/pending rent) where permitted.
- Trends/charts (e.g., rent vs expenses over recent months) where permitted.
- Quick navigation to key modules.

**[SCREENSHOT: Staff dashboard / home]**  
**Figure 4 — Dashboard:** Operational overview with portfolio and financial indicators.

**[SCREENSHOT: Administrator dashboard (if distinct)]**  
**Figure 5 — Administrator dashboard:** Admin-focused operational overview.

### 4.2 Properties
**Purpose:** Create and manage properties in the portfolio.

**Key capabilities**
- Add/edit property details including name/address/location fields (e.g., street, city, province, suburb, postal code) and description.
- Use canonical property types: **Apartment Block**, **House**, **Precast Structure**, **Backroom**.
- View property-level status and related units/tenancy context.

**[SCREENSHOT: Properties list]**  
**Figure 6 — Properties:** Portfolio property listing and management.

**[SCREENSHOT: Add Property modal/form]**  
**Figure 7 — Add Property:** Create a property with canonical type and address fields.

### 4.3 Units
**Purpose:** Manage units within properties, occupancy, and rent parameters.

**Key capabilities**
- Create/manage units (unit number/identifier, status such as Occupied/Vacant, rent amount).
- Track rent due day (per tenant/unit configuration as applicable; default behavior per system rules).
- Generate/manage QR onboarding tokens for unit-scoped applications.

**[SCREENSHOT: Units list / unit details]**  
**Figure 8 — Units:** Unit management, occupancy, and rent configuration.

**[SCREENSHOT: QR onboarding token generation for a unit]**  
**Figure 9 — Unit QR onboarding:** Generate a unique onboarding link/QR for a specific unit.

### 4.4 Public onboarding (QR / apply link)
**Purpose:** Allow a prospective tenant to submit a unit-scoped application without signing in.

**Key capabilities**
- Public route: `/apply/:token` (unique, expiring, single-use/revocable token).
- Collect required application information and supporting documents (as configured).
- Submission creates/updates application records for staff review.

**Important:** If a scanned QR link does not load the application page, confirm the deployed frontend serves the deep link and that the token is valid/active (not expired, used, or revoked); regenerate the QR token if required.

**[SCREENSHOT: Public onboarding / apply page]**  
**Figure 10 — Public application:** Unit-scoped tenant application via QR/token link.

### 4.5 Applications & approvals
**Purpose:** Review and process tenant applications.

**Key capabilities**
- View application queue/details (authorized staff).
- Approve/reject applications according to policy and permissions.
- On approval (as implemented), create/link tenant and tenancy/lease/rent records required to operationalize occupancy.

**[SCREENSHOT: Applications list/review]**  
**Figure 11 — Applications:** Review and manage incoming tenant applications.

**[SCREENSHOT: Application approval action/result]**  
**Figure 12 — Application approval:** Approve an application and trigger downstream tenant/lease/rent setup.

### 4.6 Tenancy, leases, deposits & inspections
**Purpose:** Manage the tenant lifecycle and contractual/condition records.

**Key capabilities**
- Lease management (active status, start/end dates, monthly rent, terms as applicable).
- Deposit tracking/transactions (as implemented).
- Inspections and related records/photos (as implemented).

**[SCREENSHOT: Tenancy / leases view]**  
**Figure 13 — Tenancy & leases:** Lease and tenancy management.

**[SCREENSHOT: Deposits / inspections view]**  
**Figure 14 — Deposits & inspections:** Deposit and inspection records.

### 4.7 Rent, payments & receipts
**Purpose:** Manage rent obligations and record/verify payments accurately and audibly.

**Key capabilities**
- Generate/manage rent obligations from active lease terms and due-day rules.
- **Full payments only** (no partial rent).
- **Cash:** recorded by authorized staff.
- **EFT:** tenant/staff submits proof of payment; authorized staff verifies against actual proof/records before marking paid. Proof upload alone does not equal payment.
- Payment states (as implemented): e.g., submitted → pending verification → verified/paid, or rejected / reversed-refunded.
- Sequential receipt issuance (e.g., `RCP-YYYY-NNNNNN`).
- Reversal is controlled, reasoned, and auditable (append-only; corrective handling rather than silent deletion).

**[SCREENSHOT: Rent records / register]**  
**Figure 15 — Rent management:** Rent obligations, statuses, and actions.

**[SCREENSHOT: Record cash payment / verify EFT proof]**  
**Figure 16 — Payment processing:** Record cash or verify EFT proof of payment.

**[SCREENSHOT: Receipt / payment confirmation]**  
**Figure 17 — Receipt:** Issued receipt and payment confirmation details.

### 4.8 Arrears
**Purpose:** Provide visibility into outstanding rent and ageing.

**Key capabilities**
- Derive arrears from obligations and payment status.
- View outstanding amounts/ageing summaries (authorized users).
- Support follow-up prioritization (and AI-assisted summaries/draft reminders where enabled and confirmed).

**[SCREENSHOT: Arrears / ageing view]**  
**Figure 18 — Arrears:** Outstanding rent and ageing visibility.

### 4.9 Maintenance
**Purpose:** Track and resolve maintenance issues efficiently.

**Key capabilities**
- Tenants submit maintenance requests (description, category/priority, photo/evidence as applicable).
- Staff triage, assign internal technicians, update status/costs/notes, and resolve tickets.
- Visibility into unresolved/urgent cases and maintenance history.

**[SCREENSHOT: Maintenance list / queue]**  
**Figure 19 — Maintenance:** Maintenance requests and work-order tracking.

**[SCREENSHOT: Maintenance ticket detail / assignment]**  
**Figure 20 — Maintenance workflow:** Assign, update, and resolve a maintenance ticket.

### 4.10 Expenses, budgets & suppliers
**Purpose:** Control and track property-related spending.

**Key capabilities**
- Submit expenses with supporting details.
- Approval workflow (controlled/authorized approval).
- Reversal/adjustment handling is auditable and append-only (with required reason); reversed items excluded from approved spend as designed.
- Budgets and supplier records/utilities management where enabled.

**[SCREENSHOT: Expenses list / submission]**  
**Figure 21 — Expenses:** Expense submission and tracking.

**[SCREENSHOT: Expense approval / reversal]**  
**Figure 22 — Expense controls:** Approve or reverse an expense with an auditable reason.

### 4.11 Tenant portal (authenticated)
**Purpose:** Give tenants access to their own information and self-service actions.

**Key capabilities (as applicable)**
- View tenancy/lease/documents and profile details.
- View/submit rent-related information and proof (subject to rules) and view receipts/history.
- Submit and track maintenance requests.
- Access JUMP FLUX AI for authorized assistance.

**[SCREENSHOT: Tenant dashboard / home]**  
**Figure 23 — Tenant portal:** Tenant home and key self-service areas.

**[SCREENSHOT: Tenant payments / documents / maintenance view]**  
**Figure 24 — Tenant self-service:** Payments, documents, or maintenance within the tenant portal.

### 4.12 Staff & security administration
**Purpose:** Manage staff access and account security.

**Key capabilities**
- Create/manage staff accounts and roles (authorized administrators).
- Security settings including MFA management (where applicable).
- Session and access controls aligned with auditability.

**[SCREENSHOT: Staff management]**  
**Figure 25 — Staff management:** Manage staff accounts and roles.

**[SCREENSHOT: Security settings / MFA setup]**  
**Figure 26 — Security settings:** Account security and MFA configuration.

---

## 5. Application Walk-Through (User Journeys)

### 5.1 Journey A — Staff sign-in and daily operations
1. **Open the application** and navigate to the login screen.  
   - *See Figure 1.*
2. **Sign in** with authorized credentials; complete **MFA** if prompted.  
   - *See Figure 2.*
3. **Land on the appropriate home screen** (Dashboard / Administrator / Control Center depending on role).  
   - *See Figures 4–5, 34.*
4. **Review portfolio status** (properties, units, occupancy, rent/arrears indicators).  
   - *See Figure 4.*
5. **Navigate to required modules** (Properties, Units, Applications, Rent, Maintenance, Expenses, etc.) using the main navigation.

### 5.2 Journey B — Add a property and prepare a unit for onboarding
1. Go to **Properties** and select **Add Property**.  
   - *See Figures 6–7.*
2. Enter property details and select the correct **property type** and address fields; save.
3. Go to **Units** and create/configure the unit (status, rent amount, due-day details as applicable).  
   - *See Figure 8.*
4. Generate a **QR/onboarding token** for the unit to produce a unique application link.  
   - *See Figure 9.*
5. Share the QR/link with the prospective tenant.

### 5.3 Journey C — Public application to approved tenancy
1. Applicant scans/opens the **`/apply/:token`** link (no login required).  
   - *See Figure 10.*
2. Applicant completes and submits the **unit-scoped application** with required information/documents.
3. Authorized staff review the application in **Applications**.  
   - *See Figure 11.*
4. Staff **approve** (or reject) the application per policy and permissions.  
   - *See Figure 12.*
5. On approval, the system provisions/links the relevant tenant/tenancy/lease/rent records as implemented; the tenant can proceed to authenticated access when credentials are issued/activated.

### 5.4 Journey D — Rent processing (cash and EFT)
1. Go to **Rent** to view obligations/records and statuses.  
   - *See Figure 15.*
2. **Cash payment:** authorized staff record the full cash payment and issue/confirm the receipt.  
   - *See Figures 16–17.*
3. **EFT payment:** proof of payment is submitted/uploaded; authorized staff **verify** the proof against actual records/bank confirmation before marking paid (upload alone is not payment).  
   - *See Figures 16–17.*
4. If required and authorized, perform a **reversal** with a documented reason (auditable; receipt/payment handling per system rules).

### 5.5 Journey E — Maintenance request to resolution
1. **Tenant/staff logs a maintenance request** with details (and photo/evidence if provided).  
   - *See Figure 19.*
2. Staff **triage** the ticket and assign an **internal technician** (where applicable).  
   - *See Figure 20.*
3. Technician/staff **update** progress, costs, and notes.
4. Staff **resolve/close** the ticket when work is complete and recorded.

### 5.6 Journey F — Expense submission and approval
1. Submit an **expense** with required details/supporting information.  
   - *See Figure 21.*
2. Authorized manager reviews and **approves** (or rejects) the expense.  
   - *See Figure 22.*
3. If a correction is needed, perform an auditable **reversal/adjustment** with a required reason (no silent edits to approved history).

### 5.7 Journey G — Tenant self-service
1. Tenant signs in and completes MFA if required.  
   - *See Figures 1–2.*
2. Tenant accesses **home/profile/documents**, **payments/rent**, and **maintenance** areas as available.  
   - *See Figures 23–24.*
3. Tenant submits maintenance requests or payment proof/actions permitted by policy.
4. Tenant uses **JUMP FLUX AI** for authorized questions and guidance.  
   - *See Figures 27–29.*

---

## 6. JUMP FLUX AI — Assistant Guide

### 6.1 Overview
**JUMP FLUX AI** (“Intelligence in Motion”) is the AI assistant integrated into the Messages experience of JUMP PROPTECH. It provides a conversational interface for property-management questions, summaries, and guided assistance using **authorized** system context and a configurable, provider-independent AI backend.

**[SCREENSHOT: JUMP FLUX AI — main chat interface]**  
**Figure 27 — JUMP FLUX AI interface:** Chat experience with branded visual design, message history, and input composer.

**[SCREENSHOT: JUMP FLUX AI — conversation history/sidebar]**  
**Figure 28 — Conversation management:** Create, select, rename, and delete conversations.

**[SCREENSHOT: JUMP FLUX AI — suggested prompts / response actions]**  
**Figure 29 — Prompts & actions:** Suggested questions and response actions (e.g., copy, ask again, flag for review).

### 6.2 What JUMP FLUX AI can assist with (within permissions)
- **Portfolio/property intelligence:** occupancy/vacancy summaries, property/unit overviews, performance-oriented questions (based on available authorized data).
- **Tenant/tenancy intelligence:** tenancy/lease summaries, expiring leases, relevant tenant context (authorized scope only).
- **Financial intelligence:** rent collected, outstanding/arrears indicators, payment/expense summaries, and transparent calculations from available records.
- **Arrears intelligence:** identify outstanding rent patterns and help draft professional follow-up/reminder text **for review** (no automatic enforcement actions).
- **Maintenance intelligence:** summarize requests, highlight unresolved/urgent items, and suggest possible next steps (as guidance).
- **General assistance:** explain app workflows/processes and help users find the right area/action.

### 6.3 How it works (high level)
- Conversations and messages are persisted per user.
- The backend builds **role-aware, authorized context** from Jump PropTech data and combines it with the assistant’s system guidance and the configured AI model/provider (server-side).
- The assistant distinguishes **actual (database) information**, **calculated results**, **AI suggestions**, and **unavailable** information, and must not invent records or completed actions.

### 6.4 Actions, confirmations, and safety
- For any action that would change financial/tenant/lease/payment records or send external communications, JUMP FLUX AI must **prepare details, show them, request explicit confirmation, and proceed only after authorized approval** (with audit logging). It must not claim completion without confirmed execution.
- South African property/legal/tax topics are provided as **general information only** (not legal/tax advice).
- Sensitive data is minimized; secrets and unnecessary personal/ID data must not be exposed.

### 6.5 Setup and availability states
- If the AI provider is **not configured or unavailable**, the interface remains usable and displays a clear setup/unavailable message (no fabricated “live” responses).
- Administrators configure provider credentials/models server-side via environment variables (see **Section 11**).

### 6.6 Learning from feedback (human-in-the-loop)
- Users can flag problematic/unhelpful responses for review; the system may also capture likely unanswered cases.
- Captured items are queued for **review and approval** before being promoted into approved knowledge/guidance (no autonomous self-modification of core rules or permissions).

---

## 7. Super Admin Control Center Guide

### 7.1 Purpose
The **Control Center** provides Super Administrators with centralized visibility and control over sensitive system, security, account, session/device, token, and access-audit concerns — separate from day-to-day operational workflows.

**[SCREENSHOT: Control Center — Overview]**  
**Figure 30 — Control Center overview:** System counts, security/auth signals, and recent events.

### 7.2 Key areas
| Area | Purpose |
|---|---|
| Overview | High-level system and security indicators, recent security/admin events. |
| Accounts | Searchable registry of accounts (staff/tenants) with safe metadata; audited sensitive actions (e.g., activate/deactivate, force logout, MFA reset, role changes, password reset triggers) as permitted. |
| Monitoring / Audit | View and filter audit/activity and auth/security events (who/what/when/outcome, metadata). |
| Sessions & Devices | View tracked sessions/devices and revoke sessions where supported. |
| QR Tokens | Oversight of onboarding tokens (status, unit/property context, revoke/manage as permitted). |
| Access Audit / Permissions | Review role/permission posture and related access signals. |
| Data & Exports | Controlled, audited exports (e.g., accounts/audit) in supported formats. |

**[SCREENSHOT: Control Center — Accounts]**  
**Figure 31 — Accounts management:** Account registry and audited administrative actions.

**[SCREENSHOT: Control Center — Monitoring/Audit]**  
**Figure 32 — Monitoring & audit:** Audit and security event visibility with filters.

**[SCREENSHOT: Control Center — Sessions & Devices / QR Tokens]**  
**Figure 33 — Sessions, devices & tokens:** Session/device tracking and QR token oversight.

**[SCREENSHOT: Control Center — Access audit / Exports]**  
**Figure 34 — Access audit & exports:** Permission visibility and controlled data exports.

*Note: Sensitive secrets (passwords, MFA secrets/recovery codes, raw tokens) are not exposed. Sensitive actions are audited and may rotate/revoke sessions as designed.*

---

## 8. Screenshot & Figure Index

Use this index to track required screenshots. Update figure numbers in Word if they change.

| Figure | Suggested screenshot | Where in app (typical) |
|---|---|---|
| 1 | Login screen | `/login` |
| 2 | MFA challenge/verification | Login/MFA flow |
| 3 | Forgot/reset password | Password recovery flow |
| 4 | Staff dashboard/home | `/manage` or role home |
| 5 | Administrator dashboard | `/administrator` (if applicable) |
| 6 | Properties list | Properties module |
| 7 | Add Property form/modal | Properties → Add |
| 8 | Units list/details | Units module |
| 9 | QR onboarding token generation | Units → QR onboarding |
| 10 | Public application page | `/apply/:token` |
| 11 | Applications list/review | Applications module |
| 12 | Application approval | Applications → approve |
| 13 | Tenancy/leases | Tenancy/leases module |
| 14 | Deposits/inspections | Deposits/inspections module |
| 15 | Rent records/register | Rent module |
| 16 | Record cash / verify EFT | Rent → payment actions |
| 17 | Receipt/payment confirmation | Rent/receipt view |
| 18 | Arrears/ageing | Arrears/rent views |
| 19 | Maintenance queue/list | Maintenance module |
| 20 | Maintenance ticket detail/assignment | Maintenance → ticket |
| 21 | Expenses list/submission | Expenses/budgets module |
| 22 | Expense approval/reversal | Expenses → actions |
| 23 | Tenant portal home | Tenant dashboard |
| 24 | Tenant self-service (payments/docs/maintenance) | Tenant portal sections |
| 25 | Staff management | Staff module |
| 26 | Security/MFA settings | Security settings |
| 27 | JUMP FLUX AI chat interface | `/messages` (JUMP FLUX AI) |
| 28 | JUMP FLUX AI conversations/sidebar | `/messages` sidebar |
| 29 | JUMP FLUX AI prompts/actions | `/messages` chat actions |
| 30 | Control Center overview | `/control-center` |
| 31 | Control Center accounts | Control Center → Accounts |
| 32 | Control Center monitoring/audit | Control Center → Monitoring |
| 33 | Control Center sessions/tokens | Control Center → Sessions/Tokens |
| 34 | Control Center access audit/exports | Control Center → Access/Exports |
| 35 | Mobile view — key screen (optional) | Responsive/mobile layout |
| 36 | Mobile view — JUMP FLUX AI (optional) | Responsive/mobile layout |

**Additional figure placeholders (optional)**
- **Figure 35 — Mobile navigation/layout:** Key screen on a mobile viewport.  
  `[SCREENSHOT: Mobile responsive view]`
- **Figure 36 — Mobile JUMP FLUX AI:** Assistant experience on a mobile viewport.  
  `[SCREENSHOT: Mobile JUMP FLUX AI view]`

---

## 9. Acceptance Criteria / QA Walk-Through Checklist

Use this checklist during review/testing. Mark Pass/Fail/N/A and capture evidence (screenshots/notes).

### 9.1 Access & security
- [ ] Authorized user can sign in successfully (valid credentials).  
- [ ] Invalid credentials are rejected with an appropriate message.  
- [ ] MFA challenge/verification works when enabled (and recovery path behaves as expected).  
- [ ] Password reset flow works end-to-end.  
- [ ] Unauthorized access to protected routes/APIs is denied.  
- [ ] Role-based navigation and permissions match the signed-in role.

### 9.2 Properties & units
- [ ] Property can be created/edited with required fields and canonical property type.  
- [ ] Unit can be created/updated (status/rent/due-day as applicable).  
- [ ] Unit QR/onboarding token can be generated and is unique/revocable as designed.

### 9.3 Public onboarding & applications
- [ ] `/apply/:token` loads for a valid, active token (no login required).  
- [ ] Invalid/expired/used/revoked token is handled with a clear message.  
- [ ] Application submission succeeds and appears for authorized review.  
- [ ] Application approval/rejection behaves as expected and triggers downstream records on approval (as implemented).

### 9.4 Rent & payments
- [ ] Rent obligations/records display correctly for authorized users.  
- [ ] Cash payment (authorized staff) is recorded as a full payment with receipt issuance.  
- [ ] EFT proof submission and staff verification flow works; proof upload alone does not mark rent paid.  
- [ ] Payment states transition correctly (submitted/pending verification/paid/rejected/reversed as applicable).  
- [ ] Reversal requires reason and is auditable (no silent deletion).

### 9.5 Maintenance & expenses
- [ ] Maintenance request can be created and viewed in context.  
- [ ] Staff can triage/assign/update/resolve tickets per permissions.  
- [ ] Expense submission and approval workflow works per permissions.  
- [ ] Expense reversal/adjustment is controlled, reasoned, and auditable.

### 9.6 JUMP FLUX AI
- [ ] Messages/JUMP FLUX AI screen loads for authenticated users.  
- [ ] Conversation create/select/rename/delete/clear works; history persists across refresh/session (when backend available).  
- [ ] When AI is configured, assistant returns relevant responses using authorized context (no invented records).  
- [ ] When AI is not configured/unavailable, a clear setup/unavailable message is shown (no fabricated live response).  
- [ ] Flag/feedback capture works (queued for review).  
- [ ] Role/permission boundaries are respected (tenant vs staff scope).

### 9.7 Super Admin Control Center
- [ ] Super Admin can access Control Center; non-super-admins are restricted appropriately.  
- [ ] Overview/accounts/monitoring/sessions/tokens/permissions/exports views load and display expected data.  
- [ ] Sensitive actions (where performed) are confirmed and audited; session/token effects behave as designed.  
- [ ] Exports (if used) complete successfully and are logged.

### 9.8 Cross-cutting
- [ ] Responsive layout works on desktop and mobile for key screens.  
- [ ] Error states and loading states are clear and non-breaking.  
- [ ] Audit logs capture key security/admin/AI events as applicable.

---

## 10. Known Limitations & Future Enhancements

### 10.1 Known limitations (current build)
- **AI provider dependency:** Live, model-generated responses require server-side provider configuration; without it, JUMP FLUX AI operates in a setup/unavailable state (by design).
- **Action execution depth:** Some AI-assisted actions may be limited to guidance/drafting; actions that change records or send communications require explicit confirmation and authorized execution flows (expand per domain as implemented).
- **Data/context coverage:** AI context is best-effort and scoped to available, authorized records/queries; deeper analytics and broader entity coverage can be expanded.
- **Learning loop:** Feedback/unanswered captures are queued for human review; promotion into approved knowledge is a managed process (no autonomous self-learning).
- **Bank statement reconciliation:** Automated reconciliation depends on an approved sample bank export/import format.
- **Legacy flows:** Some legacy messaging/marketplace components may remain dormant or unused in favor of current workflows.

### 10.2 Future enhancements (planned/possible)
- Expanded, tool-backed action drafts with in-app confirmation steps across more domains (reminders, reports, maintenance drafts, etc.).
- Streaming responses and richer conversation UX (where supported).
- Admin review/promote workflow for learning captures and curated knowledge base management.
- Broader analytics (yield, performance ranking, deeper arrears/expense insights) with validated formulas.
- Additional South African language support and curated, approved knowledge entries.
- Further mobile/PWA refinements and offline-friendly behaviors where appropriate.

*Update this section to reflect the latest agreed roadmap and release notes.*

---

## 11. Deployment & Configuration Notes

### 11.1 Environments (typical)
- **Frontend:** Vercel deployment serving the SPA (ensure deep-link rewrites, e.g. `/apply/:token`, are correctly routed to the app).
- **Backend API:** Render-hosted PHP API.
- **Database:** Azure MySQL (apply required migrations in order for enabled features).

### 11.2 JUMP FLUX AI configuration (server-side)
Configure on the backend environment (never in frontend code):
- `FLUX_AI_PROVIDER` (`openai` | `openai_compatible` | `azure_openai` | `none`)
- `FLUX_AI_API_KEY` (secret)
- `FLUX_AI_MODEL` (model/deployment name)
- `FLUX_AI_BASE_URL` (as required for compatible/Azure endpoints)
- `FLUX_AI_API_VERSION` (Azure, as required)
- Optional tuning: `FLUX_AI_MAX_TOKENS`, `FLUX_AI_TEMPERATURE`, `FLUX_AI_TIMEOUT`, `FLUX_AI_RATE_LIMIT_PER_MINUTE`

After configuration changes, redeploy/restart the backend and verify `/messages` shows the assistant as ready.

### 11.3 Database migrations
- Apply additive/idempotent migrations for the enabled phases/features (including JUMP FLUX AI tables when used).
- Verify required tables/columns exist in the target environment before release.

### 11.4 Operational checks
- Confirm `FRONTEND_URL` / allowed origins/CORS settings align with the deployed frontend.
- Smoke-test deep links (`/apply/:token`), authentication/MFA, core CRUD flows, rent state transitions, and JUMP FLUX AI status/chat.

---

## 12. Document Control & Sign-Off

### 12.1 Version history
| Version | Date | Author | Summary of changes |
|---|---|---|---|
| 0.1 (Draft) | <!-- YYYY-MM-DD --> | <!-- Name --> | Initial draft: product documentation and app walk-through with screenshot placeholders. |
|  |  |  |  |

### 12.2 Review & approval
| Role | Name | Signature | Date |
|---|---|---|---|
| Product Owner |  |  |  |
| Operations / Property Lead |  |  |  |
| Technical Lead |  |  |  |
| QA / Reviewer |  |  |  |

### 12.3 Distribution & notes
- **Intended audience:** Internal stakeholders, operations, administrators, and implementation/support teams.
- **Confidentiality:** Internal use. Do not include secrets, credentials, or unnecessary personal data in shared copies.
- **Related materials:** Master Memory Guide / AI knowledge references, migration notes, environment configuration records, and release notes (maintain separately as applicable).

---

*End of document.*