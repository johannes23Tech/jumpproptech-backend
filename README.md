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
- `POST /api/auth/login.php` - User login
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

- All passwords are hashed using `password_hash()` with BCRYPT
- JWT tokens for authentication
- Role-based access control
- CORS configured
- SQL prepared statements
- Environment variables for sensitive data

## License

Proprietary
