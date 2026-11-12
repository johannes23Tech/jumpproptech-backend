<?php
/**
 * Structural tests: source layout, syntax, configuration invariants, schema,
 * secret hygiene, container/web-server hardening and dependency manifests.
 */

declare(strict_types=1);

function qa_php_files(string $dir): array
{
    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
            $files[] = $file->getPathname();
        }
    }
    sort($files);
    return $files;
}

function qa_source(string $relative): string
{
    $path = QA_ROOT . '/' . $relative;
    Assert::ok(is_file($path), "missing file: {$relative}");
    $source = file_get_contents($path);
    Assert::ok($source !== false, "could not read: {$relative}");
    return $source;
}

function qa_run(array $command): array
{
    $output = [];
    $code = 1;
    @exec(implode(' ', array_map('escapeshellarg', $command)) . ' 2>&1', $output, $code);
    return [$code, implode(PHP_EOL, $output)];
}

function run_structural(Reporter $reporter): void
{
    $reporter->section('Structural — runtime and layout');

    $reporter->test('PHP runtime is supported (>= 8.0)', function (): void {
        Assert::ok(version_compare(PHP_VERSION, '8.0.0', '>='), 'PHP ' . PHP_VERSION . ' is too old');
    });

    $reporter->test('Required PHP extensions are loaded', function (): void {
        foreach (['pdo', 'pdo_mysql', 'json', 'openssl', 'mbstring', 'curl', 'dom', 'filter', 'hash'] as $extension) {
            Assert::ok(extension_loaded($extension), "missing PHP extension: {$extension}");
        }
    });

    $reporter->test('Composer autoloader and declared libraries are installed', function (): void {
        Assert::ok(is_file(QA_ROOT . '/vendor/autoload.php'), 'vendor/autoload.php is missing');
        foreach (['Firebase\\JWT\\JWT', 'PHPMailer\\PHPMailer\\PHPMailer', 'Dompdf\\Dompdf'] as $class) {
            Assert::ok(class_exists($class), "autoloadable class missing: {$class}");
        }
    });

    $reporter->test('All application PHP files pass php -l', function (): void {
        $files = array_merge(
            qa_php_files(QA_ROOT . '/api'),
            qa_php_files(QA_ROOT . '/config'),
            qa_php_files(QA_ROOT . '/middleware'),
            qa_php_files(QA_ROOT . '/migrations')
        );
        Assert::ok(count($files) >= 30, 'expected at least 30 application PHP files, found ' . count($files));

        $broken = [];
        foreach ($files as $file) {
            [$code, $output] = qa_run([PHP_BINARY, '-l', $file]);
            if ($code !== 0) {
                $broken[] = basename($file) . ': ' . trim($output);
            }
        }
        Assert::same([], $broken, 'syntax errors found');
    });

    $reporter->test('No debug/backdoor endpoints remain', function (): void {
        foreach (['api/fix_admin.php', 'api/test_db.php', 'api/debug.php', 'api/phpinfo.php'] as $dangerous) {
            Assert::false(is_file(QA_ROOT . '/' . $dangerous), "unsafe endpoint present: {$dangerous}");
        }
    });

    $reporter->test('API sources contain no debug output calls', function (): void {
        $offenders = [];
        foreach (qa_php_files(QA_ROOT . '/api') as $file) {
            $source = file_get_contents($file) ?: '';
            foreach (['var_dump(', 'print_r(', 'phpinfo(', 'var_export('] as $needle) {
                if (strpos($source, $needle) !== false) {
                    $offenders[] = basename($file) . ':' . $needle;
                }
            }
        }
        Assert::same([], $offenders, 'debug output left in API code');
    });

    $reporter->test('Internal directories are never served (Apache and nginx)', function (): void {
        $htaccess = qa_source('.htaccess');
        foreach (['config', 'middleware', 'migrations', 'vendor', 'deploy'] as $dir) {
            Assert::contains($dir, $htaccess, ".htaccess does not deny {$dir}");
        }
        Assert::contains('\.(?!well-known/)', $htaccess, '.htaccess does not block dotfiles');

        $nginx = qa_source('deploy/nginx-security.conf');
        foreach (['/config/', '/middleware/', '/migrations/', '/vendor/', '/deploy/', '/conf/'] as $dir) {
            Assert::contains($dir, $nginx, "nginx does not deny {$dir}");
        }
        Assert::contains('location ~ /\\.(?!well-known)', $nginx, 'nginx does not block dotfiles');
        Assert::contains('location ~* \\.(env|sql|log|bak|ini|sh|swp|dist|md|pem|crt|key)$', $nginx, 'nginx does not block secret/artifact extensions');
    });

    $reporter->test('Container ignores secrets and local state', function (): void {
        $dockerignore = qa_source('.dockerignore');
        foreach (['.env', '.git', 'tests', 'vendor'] as $entry) {
            Assert::contains($entry, $dockerignore, ".dockerignore does not exclude {$entry}");
        }
    });

    $reporter->test('Git ignores environment files', function (): void {
        $gitignore = qa_source('.gitignore');
        Assert::contains('.env', $gitignore);

        [$code, $tracked] = qa_run(['git', 'ls-files', '.env']);
        if ($code === 0) {
            Assert::same('', trim($tracked), '.env is tracked by git');
        }
    });

    $reporter->test('.env.example documents every required secret without values', function (): void {
        $example = qa_source('.env.example');
        foreach (['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS', 'JWT_SECRET', 'CRON_SECRET', 'FRONTEND_URL'] as $key) {
            Assert::contains($key . '=', $example, "missing env key: {$key}");
        }
        // config.php accepts either spelling; the documented example uses the shorter one.
        Assert::ok(
            preg_match('/^(CORS_ALLOWED_ORIGINS|ALLOWED_ORIGINS)=/m', $example) === 1,
            'missing env key: CORS_ALLOWED_ORIGINS (or ALLOWED_ORIGINS)'
        );
        Assert::ok(
            preg_match('/^JWT_SECRET=\s*$/m', $example) === 1,
            'JWT_SECRET must be blank in .env.example'
        );
        Assert::ok(
            preg_match('/^CRON_SECRET=\s*$/m', $example) === 1,
            'CRON_SECRET must be blank in .env.example'
        );
    });

    $reporter->test('No known hard-coded secrets appear in tracked source', function (): void {
        $needles = [
            // Legitimate only as a denylist entry inside jwt.php, never as a usable fallback.
            'jumpproptech_super_secret_key_2025' => ['config/jwt.php'],
            'JumpPropTechCron2026' => [],
            'SuperAdmin123' => [],
            'Matlola@2026' => [],
            "define('JWT_SECRET', '" => [],
            'define("JWT_SECRET", "' => [],
        ];
        $offenders = [];
        foreach (array_merge(
            qa_php_files(QA_ROOT . '/api'),
            qa_php_files(QA_ROOT . '/config'),
            qa_php_files(QA_ROOT . '/middleware')
        ) as $file) {
            $source = file_get_contents($file) ?: '';
            $relative = str_replace('\\', '/', substr($file, strlen(QA_ROOT) + 1));
            foreach ($needles as $needle => $allowedFiles) {
                if (strpos($source, $needle) === false) {
                    continue;
                }
                if (in_array($relative, $allowedFiles, true)) {
                    continue;
                }
                $offenders[] = basename($file) . ':' . $needle;
            }
        }
        Assert::same([], $offenders, 'hard-coded secret material found');
    });

    $reporter->test('Database credentials are env-only and fail closed', function (): void {
        $db = qa_source('config/db.php');
        foreach (['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS'] as $key) {
            Assert::contains("getenv('{$key}')", $db, "db.php does not read {$key} from the environment");
        }
        Assert::notContains("?: 'jumpproptech'", $db, 'db.php still has a credential fallback');
        Assert::contains('ATTR_EMULATE_PREPARES => false', $db, 'native server-side prepares are not enabled');
        Assert::contains('MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true', $db, 'DB TLS verification is not enforced');
    });

    $reporter->test('JWT configuration fails closed on weak secrets', function (): void {
        $jwt = qa_source('config/jwt.php');
        Assert::contains("getenv('JWT_SECRET')", $jwt);
        Assert::contains('strlen($secret) < 32', $jwt, 'JWT secret length check missing');
        Assert::contains('Server configuration error', $jwt);
        Assert::contains("'scope' => 'access'", $jwt, 'access token scope missing');
        Assert::contains("'jti'", $jwt, 'jti claim missing');
        Assert::contains("'ver'", $jwt, 'token version claim missing');
    });

    $reporter->test('Middleware re-reads role, version and denylist from the DB', function (): void {
        $middleware = qa_source('middleware/check_role.php');
        Assert::contains('SELECT role, subscription_status, token_version', $middleware);
        Assert::contains('decoded->ver !== (int) $currentUser', $middleware);
        Assert::contains('security_token_is_revoked', $middleware);
        Assert::contains("decoded->scope !== 'access'", $middleware);
        Assert::contains("security_json_response(402", $middleware, 'expired subscriptions are not blocked');
    });

    $reporter->test('Login uses generic errors, rate limits and constant-time-ish hashing', function (): void {
        $login = qa_source('api/auth/login.php');
        Assert::contains('LOGIN_MAX_ATTEMPTS', $login);
        Assert::contains('LOGIN_MAX_IP_ATTEMPTS', $login);
        Assert::contains('LOGIN_DUMMY_HASH', $login);
        Assert::contains('password_verify($data->password, $user[\'password_hash\'] ?? LOGIN_DUMMY_HASH)', $login);
        Assert::contains('Invalid credentials', $login);
        Assert::notContains('User not found', $login, 'login enumerates accounts');
        Assert::contains('security_rate_limit_retry', $login);
    });

    $reporter->test('Cron endpoint authenticates with a header and hash_equals', function (): void {
        $cron = qa_source('api/cron/generate_invoices.php');
        Assert::contains('HTTP_X_CRON_SECRET', $cron);
        Assert::contains('hash_equals', $cron);
        Assert::contains("CRON_ALLOW_QUERY_SECRET') === '1'", $cron, 'legacy query secret is not gated');
        Assert::notContains('JumpPropTechCron2026', $cron);
    });

    $reporter->test('CORS is an allowlist, never a wildcard', function (): void {
        $config = qa_source('config/config.php');
        Assert::notContains('Access-Control-Allow-Origin: *', $config);
        Assert::contains('CORS_ALLOWED_ORIGINS', $config);
        Assert::contains('Vary: Origin', $config);
        Assert::contains('Origin not allowed.', $config);
    });

    $reporter->test('Security headers are emitted by the application', function (): void {
        $config = qa_source('config/config.php');
        foreach ([
            'X-Content-Type-Options: nosniff',
            'X-Frame-Options: DENY',
            'Referrer-Policy: strict-origin-when-cross-origin',
            'Permissions-Policy:',
            'Content-Security-Policy:',
            'Cache-Control: no-store',
            'Strict-Transport-Security:',
        ] as $header) {
            Assert::contains($header, $config, "missing header: {$header}");
        }
        Assert::contains("header_remove('X-Powered-By')", $config);
        Assert::contains("ini_set('display_errors', 0)", $config, 'production error display is not disabled');
    });

    $reporter->test('PHP runtime hardening file is present', function (): void {
        $ini = qa_source('deploy/php-hardening.ini');
        foreach (['expose_php = Off', 'display_errors = Off', 'allow_url_include = Off'] as $setting) {
            Assert::contains($setting, $ini, "missing: {$setting}");
        }
    });

    $reporter->test('nginx restricts the cron endpoint to loopback', function (): void {
        $nginx = qa_source('deploy/nginx-security.conf');
        Assert::contains('location = /api/cron/generate_invoices.php', $nginx);
        Assert::contains('allow 127.0.0.1', $nginx);
        Assert::contains('deny all', $nginx);
        Assert::contains('client_max_body_size', $nginx);
    });

    $reporter->test('Migrations create the security tables and columns', function (): void {
        $batch3 = qa_source('migrations/2026-11-09_security_hardening_batch3.sql');
        foreach (['token_version', 'revoked_tokens', 'audit_logs', 'audit_logs_no_update', 'audit_logs_no_delete'] as $token) {
            Assert::contains($token, $batch3, "migration missing {$token}");
        }
        $rate = qa_source('migrations/2026-11-09_security_hardening.sql');
        Assert::contains('rate_limits', $rate);
        $mfa = qa_source('migrations/2026-11-10_mfa.sql');
        foreach (['mfa_secret', 'mfa_enabled', 'mfa_recovery_codes', 'mfa_last_step'] as $column) {
            Assert::contains($column, $mfa, "MFA migration missing {$column}");
        }
        $profile = qa_source('migrations/2026-11-10_tenant_profile.sql');
        foreach (['id_number', 'occupants', 'alt_email', 'id_document'] as $column) {
            Assert::contains($column, $profile, "profile migration missing {$column}");
        }
    });

    $reporter->section('Structural — live schema');

    $reporter->test('Disposable QA schema has every table the API uses', function (): void {
        $tables = qa_query('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()');
        $names = array_column($tables, 'TABLE_NAME');
        foreach (['users', 'properties', 'units', 'tenants', 'rent_records', 'expenses', 'maintenance', 'messages', 'contractors', 'leases', 'password_resets', 'rate_limits', 'revoked_tokens', 'audit_logs'] as $table) {
            Assert::ok(in_array($table, $names, true), "missing table: {$table}");
        }
    });

    $reporter->test('users schema supports auth, MFA and revocation', function (): void {
        $columns = array_column(
            qa_query('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = "users"'),
            'COLUMN_NAME'
        );
        foreach (['id', 'full_name', 'email', 'password_hash', 'role', 'subscription_status', 'token_version', 'mfa_secret', 'mfa_enabled', 'mfa_recovery_codes', 'mfa_last_step'] as $column) {
            Assert::ok(in_array($column, $columns, true), "users missing column: {$column}");
        }
    });

    $reporter->test('audit_logs is append-only at the database layer', function (): void {
        $triggers = array_column(
            qa_query('SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = "audit_logs"'),
            'TRIGGER_NAME'
        );
        Assert::ok(in_array('audit_logs_no_update', $triggers, true), 'missing UPDATE trigger');
        Assert::ok(in_array('audit_logs_no_delete', $triggers, true), 'missing DELETE trigger');

        $inserted = qa_exec(
            "INSERT INTO audit_logs (actor_user_id, action, outcome) VALUES (NULL, 'qa.structural', 'success')"
        );
        Assert::same(1, $inserted);

        $blocked = false;
        try {
            qa_pdo()->exec("UPDATE audit_logs SET action = 'tampered' WHERE action = 'qa.structural'");
        } catch (Throwable $e) {
            $blocked = true;
        }
        Assert::true($blocked, 'audit_logs UPDATE was not rejected');

        $blocked = false;
        try {
            qa_pdo()->exec("DELETE FROM audit_logs WHERE action = 'qa.structural'");
        } catch (Throwable $e) {
            $blocked = true;
        }
        Assert::true($blocked, 'audit_logs DELETE was not rejected');
    });

    $reporter->test('maintenance.tenant_id references the tenants table', function (): void {
        $rows = qa_query(
            'SELECT REFERENCED_TABLE_NAME FROM information_schema.KEY_COLUMN_USAGE
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = "maintenance" AND COLUMN_NAME = "tenant_id"'
        );
        Assert::ok(count($rows) > 0, 'maintenance.tenant_id has no foreign key');
        Assert::same(
            'tenants',
            $rows[0]['REFERENCED_TABLE_NAME'],
            'maintenance.tenant_id must reference tenants(id); the API inserts tenants.id'
        );
    });

    $reporter->test('Password reset lookups are indexed', function (): void {
        $indexes = array_column(
            qa_query('SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = "password_resets"'),
            'INDEX_NAME'
        );
        Assert::ok(in_array('idx_password_resets_token', $indexes, true), 'token lookup index missing');
        Assert::ok(in_array('idx_password_resets_email', $indexes, true), 'email lookup index missing');
    });

    $reporter->test('No dynamic SQL interpolation of request data', function (): void {
        $offenders = [];
        foreach (qa_php_files(QA_ROOT . '/api') as $file) {
            $source = file_get_contents($file) ?: '';
            if (preg_match('/->query\s*\(\s*["\'][^"\']*\$_(GET|POST|REQUEST|SERVER)/', $source)) {
                $offenders[] = basename($file);
            }
        }
        Assert::same([], $offenders, 'request data interpolated into SQL');
    });
}
