<?php
/**
 * JumpPropTech backend - QA database setup and seed.
 *
 * Creates the disposable `jumpproptech_qa` database, a dedicated least-
 * privilege test user, seeds deterministic test data, and keeps production /
 * development data untouched.
 *
 * Usage: php tests/setup_database.php
 */

declare(strict_types=1);

const QA_DB = 'jumpproptech_qa';
const QA_DB_USER = 'jpt_qa';
const QA_DB_PASS = 'QaDbPass!2026';
const QA_PASSWORD = 'QaTest!2026';

function out(string $message): void
{
    fwrite(STDOUT, $message . PHP_EOL);
}

function fail(string $message): void
{
    fwrite(STDERR, "SETUP FAILED: {$message}" . PHP_EOL);
    exit(1);
}

function rootPdo(string $db = ''): PDO
{
    $dsn = 'mysql:host=127.0.0.1;charset=utf8mb4' . ($db !== '' ? ';dbname=' . $db : '');
    return new PDO($dsn, 'root', '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

out('Creating database and app user...');
$root = rootPdo();
$root->exec('DROP DATABASE IF EXISTS `' . QA_DB . '`');
$root->exec('CREATE DATABASE `' . QA_DB . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci');

foreach (['127.0.0.1', 'localhost'] as $host) {
    $root->exec("CREATE USER IF NOT EXISTS '" . QA_DB_USER . "'@'" . $host . "' IDENTIFIED BY '" . QA_DB_PASS . "'");
    $root->exec("ALTER USER '" . QA_DB_USER . "'@'" . $host . "' IDENTIFIED BY '" . QA_DB_PASS . "'");
    $root->exec("GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES, TRIGGER ON `" . QA_DB . "`.* TO '" . QA_DB_USER . "'@'" . $host . "'");
}
$root->exec('FLUSH PRIVILEGES');

out('Cloning schema from the existing local test database...');
$source = 'jumpproptech_pentest';
$tables = $root->query(
    'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ' . $root->quote($source) . ' AND TABLE_TYPE = "BASE TABLE" ORDER BY TABLE_NAME'
)->fetchAll(PDO::FETCH_COLUMN);

if ($tables === []) {
    fail("Source schema `{$source}` not found or empty. Create it first or adapt the seed script.");
}

$qa = rootPdo(QA_DB);
$qa->exec('SET FOREIGN_KEY_CHECKS=0');

foreach ($tables as $table) {
    $row = $root->query('SHOW CREATE TABLE `' . $source . '`.`' . $table . '`')->fetch(PDO::FETCH_NUM);
    $qa->exec($row[1]);
}
$qa->exec('SET FOREIGN_KEY_CHECKS=1');

// Recreate the append-only triggers from the migration on the cloned table.
$qa->exec('DROP TRIGGER IF EXISTS audit_logs_no_update');
$qa->exec('DROP TRIGGER IF EXISTS audit_logs_no_delete');
$qa->exec(
    "CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW
     SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only'"
);
$qa->exec(
    "CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW
     SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only'"
);

out('Seeding deterministic fixtures...');
$qa->exec('SET FOREIGN_KEY_CHECKS=0');
foreach ($tables as $table) {
    $qa->exec('TRUNCATE TABLE `' . $table . '`');
}
$qa->exec('SET FOREIGN_KEY_CHECKS=1');

$hash = password_hash(QA_PASSWORD, PASSWORD_BCRYPT, ['cost' => 12]);

$users = [
    [1, 'QA Super Admin', 'superadmin@qa.local', 'superadmin', 'active'],
    [2, 'QA Landlord A', 'landlord.a@qa.local', 'landlord', 'active'],
    [3, 'QA Landlord B', 'landlord.b@qa.local', 'landlord', 'active'],
    [4, 'QA Agent A', 'agent.a@qa.local', 'agent', 'active'],
    [5, 'QA Tenant A', 'tenant.a@qa.local', 'tenant', 'active'],
    [6, 'QA Tenant B', 'tenant.b@qa.local', 'tenant', 'active'],
    [7, 'QA Maintenance', 'maintenance@qa.local', 'maintenance', 'active'],
    [8, 'QA Expired Landlord', 'landlord.expired@qa.local', 'landlord', 'expired'],
    [9, 'QA Self Tenant', 'tenant.self@qa.local', 'tenant', 'active'],
    [10, 'QA MFA Landlord', 'mfa.landlord@qa.local', 'landlord', 'active'],
    [11, 'QA Password User', 'password.user@qa.local', 'landlord', 'active'],
    [12, 'QA Logout User', 'logout.user@qa.local', 'landlord', 'active'],
    [13, 'QA Reset User', 'reset.user@qa.local', 'landlord', 'active'],
    [14, 'QA Extra Landlord', 'extra.landlord@qa.local', 'landlord', 'active'],
];
$insertUser = $qa->prepare(
    'INSERT INTO users (id, full_name, email, password_hash, phone, role, subscription_status, token_version)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0)'
);
foreach ($users as $u) {
    $insertUser->execute([$u[0], $u[1], $u[2], $hash, '0710000000', $u[3], $u[4]]);
}

$qa->exec("INSERT INTO properties (id, landlord_id, agent_id, name, address, property_type) VALUES
    (1, 2, 4, 'Prop A', '1 QA Street', 'House'),
    (2, 3, NULL, 'Prop B', '2 QA Street', 'Apartment Block')");

$qa->exec("INSERT INTO units (id, property_id, unit_number, size_dimensions, is_furnished, included_items, monthly_rent, status) VALUES
    (1, 1, 'A1', '50sqm', 0, 'Nothing', 5000.00, 'Occupied'),
    (2, 1, 'A2', '45sqm', 0, 'Nothing', 6000.00, 'Vacant'),
    (3, 2, 'B1', '60sqm', 1, 'Fridge', 7000.00, 'Occupied')");

$today = new DateTimeImmutable('now');
$leaseStart = $today->modify('-6 months')->format('Y-m-01');
$leaseEnd = $today->modify('+6 months')->format('Y-m-t');
$month = $today->format('Y-m-01');
$prevMonth = $today->modify('-1 month')->format('Y-m-01');

$insertTenant = $qa->prepare(
    'INSERT INTO tenants (id, owner_id, unit_id, user_id, name, phone, email, lease_start, lease_end, deposit, monthly_rent)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
);
$insertTenant->execute([5, 2, 1, 5, 'QA Tenant A', '0711111111', 'tenant.a@qa.local', $leaseStart, $leaseEnd, 5000.00, 5000.00]);
$insertTenant->execute([6, 3, 3, 6, 'QA Tenant B', '0722222222', 'tenant.b@qa.local', $leaseStart, $leaseEnd, 7000.00, 7000.00]);

$insertRent = $qa->prepare(
    'INSERT INTO rent_records (id, tenant_id, unit_id, month_for, amount, status, payment_method, paid_date, receipt_number)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
);
$insertRent->execute([1, 5, 1, $month, 5000.00, 'Pending', null, null, null]);
$insertRent->execute([2, 6, 3, $month, 7000.00, 'Pending', null, null, null]);
$insertRent->execute([3, 5, 1, $prevMonth, 5000.00, 'Paid', 'EFT', $prevMonth, 'RCP-SEED-0001']);

$qa->exec("INSERT INTO maintenance (id, unit_id, tenant_id, description, priority, status, category) VALUES
    (1, 1, 5, 'Seeded leaking tap', 'Medium', 'Open', 'Plumbing')");

$qa->exec("INSERT INTO contractors (id, name, trade, phone, owner_id) VALUES
    (1, 'QA Plumber', 'Plumbing', '0733333333', 2)");

$qa->exec("INSERT INTO expenses (id, owner_id, property_id, category, amount, expense_date, description) VALUES
    (1, 2, 1, 'Repairs', 1250.00, CURDATE(), 'Seeded expense')");

$qa->exec("INSERT INTO leases (id, tenant_id, unit_id, lease_start, lease_end, deposit_amount, status) VALUES
    (1, 5, 1, '{$leaseStart}', '{$leaseEnd}', 5000.00, 'Active')");

out('Database ready: ' . QA_DB . ' (' . count($tables) . ' tables, ' . count($users) . ' users).');
out('App credentials: ' . QA_DB_USER . ' / ' . QA_DB_PASS);
out('Fixture password: ' . QA_PASSWORD);
