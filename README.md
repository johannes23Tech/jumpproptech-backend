# JumpPropTech Backend API

A modern PHP REST API for property management built with PDO, JWT authentication, and PSR-4 autoloading support.

## Features

- JWT-based authentication
- Role-based access control (Super Admin, Landlord, Agent, Tenant, Maintenance)
- Property, Unit, Tenant, and Rent management
- Expense tracking
- Maintenance request system
- Automated invoice generation
- Email notifications via PHPMailer
- PDF generation via DomPDF
- Subscription management

## Requirements

- PHP 8.0+
- MySQL 5.7+ / MariaDB 10.3+
- Composer
- Apache/Nginx

## Installation

1. Clone the repository
```bash
git clone <repo-url>
cd jumpproptech-backend
```

2. Install dependencies
```bash
composer install
```

3. Configure environment variables
```bash
cp .env.example .env
```
Edit `.env` with your database, mail, and JWT credentials.

4. Import database schema (if available)
5. Start your server

## Environment Variables

See `.env.example` for all available configuration options.

## API Endpoints

### Authentication
- `POST /api/auth/login.php` - User login (returns `mfa_required` + `mfa_token` when 2FA is on)
- `POST /api/auth/mfa_login.php` - Complete login with a TOTP or recovery code
- `GET /api/auth/mfa_status.php` - Is 2FA enabled for the current account?
- `POST /api/auth/mfa_setup.php` - Start 2FA enrolment (requires your password)
- `POST /api/auth/mfa_enable.php` - Confirm a TOTP code and receive recovery codes
- `POST /api/auth/mfa_disable.php` - Disable 2FA (requires password + code)
- `POST /api/auth/register.php` - Tenant registration
- `POST /api/auth/forgot_password.php` - Password reset request
- `POST /api/auth/change_password.php` - Change password

### Properties
- `GET /api/properties.php` - List properties
- `POST /api/properties.php` - Create property (super admins must include the target `landlord_id`)

### Units
- `GET /api/units.php` - List units
- `POST /api/units.php` - Create unit

### Tenants
- `GET /api/tenants.php` - List tenants
- `POST /api/tenants.php` - Create tenant

### Rent
- `GET /api/rent.php` - List rent records
- `POST /api/rent.php` - Record payment

### Dashboard
- `GET /api/dashboard.php` - Dashboard statistics

### FAQ Assistant
- `GET /api/faq_bot.php` - Get suggested FAQ questions (requires authentication)
- `POST /api/faq_bot.php` - Get a rule-based FAQ answer; send JSON such as `{"question":"How do I report maintenance?"}` (requires authentication)

### Admin
- `POST /api/admin/create_landlord.php` - Create landlord (Super Admin only)
- `POST /api/admin/toggle_sub.php` - Toggle subscription (Super Admin only)
- `GET /api/admin/stats.php` - System stats (Super Admin only)

## Security

- All passwords are hashed using `password_hash()` with BCRYPT (cost 12)
- JWT access tokens with `scope`, `jti` and `ver` claims (single-device and global revocation)
- TOTP two-factor authentication (RFC 6238) with single-use, hashed recovery codes
- Role-based access control enforced server-side on every request
- CORS allowlist; strict security headers and `no-store` on every API response
- SQL prepared statements and input sanitisation
- Environment variables for sensitive data; `.env` is never committed
- CI runs secret scanning, dependency audits and PHP/TypeScript builds

## Deployment notes

- Copy `.env.example` to `.env` and fill in real values. `.env` is never
  committed or baked into the image.
- The container serves nginx, so `.htaccess` is **not** used. Hardening lives in
  `deploy/nginx-security.conf` and is loaded through
  `conf/nginx/nginx-site.conf` (the base image copies that file over
  `sites-available/default.conf` on start). Keep both files in the image.
- The invoice cron at `/api/cron/generate_invoices.php` reads `CRON_SECRET` from
  the `X-Cron-Secret` header (or `Authorization: Bearer <CRON_SECRET>`). The old
  `?key=` form is disabled unless `CRON_ALLOW_QUERY_SECRET=1` is set temporarily
  during a scheduler migration. Point the scheduler at a private address; nginx
  only allows loopback by default.
- Rotate `JWT_SECRET`, `CRON_SECRET`, database and SMTP credentials if they were
  ever committed to git history, then redeploy.

## License

Proprietary
