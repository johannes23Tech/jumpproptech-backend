<?php
/**
 * JumpPropTech backend QA runner.
 *
 * Usage:
 *   php tests/setup_database.php     # (re)create and seed the disposable DB
 *   php tests/run.php [suite]        # suite: all|structural|unit|functional|nonfunctional
 *
 * The runner never touches the real `jumpproptech` database. It only talks to
 * the disposable `jumpproptech_qa` schema and local PHP servers bound to
 * 127.0.0.1.
 */

declare(strict_types=1);

require_once __DIR__ . '/Support.php';

$only = $argv[1] ?? 'all';
$valid = ['all', 'structural', 'unit', 'functional', 'nonfunctional'];
if (!in_array($only, $valid, true)) {
    fwrite(STDERR, 'Unknown suite "' . $only . '". Use one of: ' . implode(', ', $valid) . PHP_EOL);
    exit(2);
}

// Configuration for the test process itself (JWT/MFA helpers read these).
foreach ([
    'APP_ENV' => 'development',
    'APP_TIMEZONE' => 'Africa/Johannesburg',
    'DB_HOST' => '127.0.0.1',
    'DB_NAME' => QA_DB,
    'DB_USER' => QA_DB_USER,
    'DB_PASS' => QA_DB_PASS,
    'JWT_SECRET' => QA_JWT_SECRET,
    'JWT_EXPIRY' => '3600',
    'JWT_ISSUER' => 'jumpproptech',
    'CRON_SECRET' => QA_CRON_SECRET,
    'CORS_ALLOWED_ORIGINS' => QA_FRONTEND . ',' . QA_DEV_ORIGIN,
    'ALLOWED_ORIGINS' => QA_FRONTEND . ',' . QA_DEV_ORIGIN,
    'FRONTEND_URL' => QA_FRONTEND,
    'MAIL_HOST' => '127.0.0.1',
    'MAIL_PORT' => '1',
    'MAIL_USERNAME' => '',
    'MAIL_PASSWORD' => '',
    'MAIL_ENCRYPTION' => 'none',
    'MAIL_FROM' => 'qa@example.test',
    'MAIL_FROM_NAME' => 'Jump PropTech QA',
    'TRUSTED_PROXIES' => '127.0.0.1,::1,10.0.0.0/8',
] as $key => $value) {
    putenv($key . '=' . $value);
    $_ENV[$key] = $value;
}

require_once __DIR__ . '/suites/structural.php';
require_once __DIR__ . '/suites/unit.php';
require_once __DIR__ . '/suites/functional.php';
require_once __DIR__ . '/suites/nonfunctional.php';

try {
    qa_pdo()->query('SELECT 1');
} catch (Throwable $e) {
    fwrite(STDERR, 'The disposable QA database is not reachable: ' . $e->getMessage() . PHP_EOL);
    fwrite(STDERR, 'Run `php tests/setup_database.php` first (and make sure MySQL/MariaDB is running).' . PHP_EOL);
    exit(2);
}

$reporter = new Reporter();

echo 'JumpPropTech backend QA' . PHP_EOL;
echo 'PHP ' . PHP_VERSION . ' on ' . PHP_OS_FAMILY . PHP_EOL;
echo 'Database: ' . QA_DB . ' (disposable) | Suite: ' . $only . PHP_EOL;

$server = null;
try {
    if ($only === 'all' || $only === 'structural') {
        run_structural($reporter);
    }
    if ($only === 'all' || $only === 'unit') {
        run_unit($reporter);
    }

    if ($only === 'all' || $only === 'functional' || $only === 'nonfunctional') {
        $server = qa_start_server(8099);
        echo PHP_EOL . 'Test server: http://127.0.0.1:8099' . PHP_EOL;

        if ($only === 'all' || $only === 'functional') {
            run_functional($reporter, 8099);
        }
        if ($only === 'all' || $only === 'nonfunctional') {
            run_nonfunctional($reporter, 8099);
        }
    }
} catch (Throwable $e) {
    fwrite(STDERR, PHP_EOL . 'Harness error: ' . get_class($e) . ': ' . $e->getMessage() . PHP_EOL);
    $reporter->test('Harness completed without an uncaught error', function () use ($e): void {
        throw $e;
    });
} finally {
    if ($server !== null) {
        qa_stop_server($server);
    }
}

exit($reporter->summary());
