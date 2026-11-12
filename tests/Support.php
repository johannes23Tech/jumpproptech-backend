<?php
/**
 * Shared test harness for the JumpPropTech backend QA suite.
 *
 * No external test framework is required: this file provides assertions,
 * a tiny reporting layer, a cURL client, a PHP built-in server controller and
 * database helpers. Every test talks to the disposable `jumpproptech_qa`
 * database and a local server bound to 127.0.0.1.
 */

declare(strict_types=1);

const QA_ROOT = __DIR__ . '/..';
const QA_DB = 'jumpproptech_qa';
const QA_DB_USER = 'jpt_qa';
const QA_DB_PASS = 'QaDbPass!2026';
const QA_PASSWORD = 'QaTest!2026';
const QA_JWT_SECRET = 'qa-only-jwt-secret-0123456789abcdef0123456789abcdef';
const QA_CRON_SECRET = 'qa-only-cron-secret-0123456789abcdef';
const QA_FRONTEND = 'https://jumpproptech-frontend.vercel.app';
const QA_DEV_ORIGIN = 'http://localhost:5173';
const QA_EVIL_ORIGIN = 'https://evil.example';

final class TestFailure extends RuntimeException
{
}

final class Assert
{
    public static function ok(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new TestFailure($message);
        }
    }

    public static function same($expected, $actual, string $message = ''): void
    {
        if ($expected !== $actual) {
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . 'expected ' . self::export($expected) . ', got ' . self::export($actual)
            );
        }
    }

    public static function equals($expected, $actual, string $message = ''): void
    {
        if ($expected != $actual) {
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . 'expected ' . self::export($expected) . ', got ' . self::export($actual)
            );
        }
    }

    public static function true($actual, string $message = ''): void
    {
        self::same(true, $actual, $message);
    }

    public static function false($actual, string $message = ''): void
    {
        self::same(false, $actual, $message);
    }

    public static function contains(string $needle, string $haystack, string $message = ''): void
    {
        if (strpos($haystack, $needle) === false) {
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . "expected to contain \"{$needle}\", got " . self::export($haystack)
            );
        }
    }

    public static function notContains(string $needle, string $haystack, string $message = ''): void
    {
        if (strpos($haystack, $needle) !== false) {
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . "expected NOT to contain \"{$needle}\""
            );
        }
    }

    public static function matches(string $pattern, string $value, string $message = ''): void
    {
        if (!preg_match($pattern, $value)) {
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . "expected to match {$pattern}, got " . self::export($value)
            );
        }
    }

    public static function between($value, $min, $max, string $message = ''): void
    {
        if ($value < $min || $value > $max) {
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . "expected between {$min} and {$max}, got " . self::export($value)
            );
        }
    }

    public static function status(int $expected, array $response, string $message = ''): void
    {
        if ($response['status'] !== $expected) {
            $body = substr((string) $response['body'], 0, 400);
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . "expected HTTP {$expected}, got {$response['status']} body: {$body}"
            );
        }
    }

    public static function json($response, string $message = ''): void
    {
        if (!is_array($response['json'])) {
            throw new TestFailure(
                ($message !== '' ? $message . ' — ' : '')
                . 'expected a JSON body, got: ' . substr((string) $response['body'], 0, 400)
            );
        }
    }

    private static function export($value): string
    {
        if (is_string($value)) {
            return '"' . (strlen($value) > 200 ? substr($value, 0, 200) . '…' : $value) . '"';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        if (is_array($value)) {
            $json = json_encode($value);
            return strlen($json) > 300 ? substr($json, 0, 300) . '…' : $json;
        }
        return (string) $value;
    }
}

final class Reporter
{
    public int $passed = 0;
    public int $failed = 0;
    public int $skipped = 0;
    /** @var array<int, array{suite:string,name:string,status:string,detail:string,ms:float}> */
    public array $results = [];
    private string $currentSuite = 'General';

    public function section(string $suite): void
    {
        $this->currentSuite = $suite;
        echo PHP_EOL . "== {$suite} ==" . PHP_EOL;
    }

    public function test(string $name, callable $fn): void
    {
        $start = microtime(true);
        try {
            $fn();
            $this->passed++;
            $this->results[] = [
                'suite' => $this->currentSuite,
                'name' => $name,
                'status' => 'PASS',
                'detail' => '',
                'ms' => round((microtime(true) - $start) * 1000, 1),
            ];
            echo "  PASS  {$name}" . PHP_EOL;
        } catch (TestFailure $e) {
            $this->failed++;
            $this->results[] = [
                'suite' => $this->currentSuite,
                'name' => $name,
                'status' => 'FAIL',
                'detail' => $e->getMessage(),
                'ms' => round((microtime(true) - $start) * 1000, 1),
            ];
            echo "  FAIL  {$name}" . PHP_EOL . "        " . $e->getMessage() . PHP_EOL;
        } catch (Throwable $e) {
            $this->failed++;
            $this->results[] = [
                'suite' => $this->currentSuite,
                'name' => $name,
                'status' => 'ERROR',
                'detail' => get_class($e) . ': ' . $e->getMessage(),
                'ms' => round((microtime(true) - $start) * 1000, 1),
            ];
            echo "  ERROR {$name}" . PHP_EOL . "        " . get_class($e) . ': ' . $e->getMessage() . PHP_EOL;
        }
    }

    public function skip(string $name, string $reason): void
    {
        $this->skipped++;
        $this->results[] = [
            'suite' => $this->currentSuite,
            'name' => $name,
            'status' => 'SKIP',
            'detail' => $reason,
            'ms' => 0.0,
        ];
        echo "  SKIP  {$name} ({$reason})" . PHP_EOL;
    }

    public function note(string $message): void
    {
        echo "  note  {$message}" . PHP_EOL;
    }

    public function summary(): int
    {
        $total = $this->passed + $this->failed + $this->skipped;
        echo PHP_EOL . str_repeat('-', 72) . PHP_EOL;
        echo "TOTAL {$total}  PASS {$this->passed}  FAIL {$this->failed}  SKIP {$this->skipped}" . PHP_EOL;

        if ($this->failed > 0) {
            echo PHP_EOL . 'Failed checks:' . PHP_EOL;
            foreach ($this->results as $result) {
                if ($result['status'] !== 'PASS' && $result['status'] !== 'SKIP') {
                    echo "  - [{$result['suite']}] {$result['name']}: {$result['detail']}" . PHP_EOL;
                }
            }
        }

        $artifact = sys_get_temp_dir() . '/opencode/jpt-qa-results.json';
        if (!is_dir(dirname($artifact))) {
            @mkdir(dirname($artifact), 0777, true);
        }
        @file_put_contents($artifact, json_encode([
            'generated_at' => date('c'),
            'php' => PHP_VERSION,
            'os' => PHP_OS_FAMILY,
            'passed' => $this->passed,
            'failed' => $this->failed,
            'skipped' => $this->skipped,
            'results' => $this->results,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        echo 'Artifact: ' . $artifact . PHP_EOL;

        return $this->failed === 0 ? 0 : 1;
    }
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

function qa_pdo(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO(
            'mysql:host=127.0.0.1;dbname=' . QA_DB . ';charset=utf8mb4',
            QA_DB_USER,
            QA_DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]
        );
    }
    return $pdo;
}

function qa_query(string $sql, array $params = []): array
{
    $stmt = qa_pdo()->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function qa_value(string $sql, array $params = [])
{
    $stmt = qa_pdo()->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchColumn();
}

function qa_exec(string $sql, array $params = []): int
{
    $stmt = qa_pdo()->prepare($sql);
    $stmt->execute($params);
    return $stmt->rowCount();
}

function qa_reset_rate_limits(): void
{
    qa_pdo()->exec('DELETE FROM rate_limits');
}

// ---------------------------------------------------------------------------
// PHP built-in server controller
// ---------------------------------------------------------------------------

/** @var array<int, array{proc:resource,pid:int,log:string}> */
$GLOBALS['qa_servers'] = [];

function qa_base_env(array $overrides = []): array
{
    $env = getenv();
    if (!is_array($env)) {
        $env = [];
    }

    return array_merge($env, [
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
    ], $overrides);
}

function qa_start_server(int $port, array $overrides = []): array
{
    $probe = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.3);
    if ($probe) {
        fclose($probe);
        throw new RuntimeException("Port {$port} is already in use");
    }

    $log = sys_get_temp_dir() . '/opencode/jpt-qa-server-' . $port . '.log';
    if (!is_dir(dirname($log))) {
        @mkdir(dirname($log), 0777, true);
    }
    @file_put_contents($log, '');

    $command = [PHP_BINARY, '-d', 'display_errors=0', '-d', 'log_errors=1', '-S', '127.0.0.1:' . $port, '-t', realpath(QA_ROOT)];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['file', $log, 'a'],
        2 => ['file', $log, 'a'],
    ];

    $proc = proc_open($command, $descriptors, $pipes, realpath(QA_ROOT), qa_base_env($overrides));
    if (!is_resource($proc)) {
        throw new RuntimeException("Could not start PHP server on port {$port}");
    }
    if (isset($pipes[0]) && is_resource($pipes[0])) {
        fclose($pipes[0]);
    }

    $status = proc_get_status($proc);
    $pid = (int) ($status['pid'] ?? 0);

    for ($i = 0; $i < 100; $i++) {
        $probe = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
        if ($probe) {
            fclose($probe);
            $server = ['proc' => $proc, 'pid' => $pid, 'log' => $log, 'port' => $port];
            $GLOBALS['qa_servers'][$port] = $server;
            return $server;
        }
        usleep(100000);
    }

    throw new RuntimeException("PHP server did not start on port {$port}. Log: " . qa_tail($log));
}

function qa_stop_server(array $server): void
{
    if (!is_resource($server['proc'])) {
        return;
    }

    if (PHP_OS_FAMILY === 'Windows') {
        @exec('taskkill /F /T /PID ' . (int) $server['pid'] . ' 2>NUL');
    } else {
        @proc_terminate($server['proc'], 9);
    }
    @proc_close($server['proc']);
    unset($GLOBALS['qa_servers'][$server['port']]);
}

function qa_stop_all_servers(): void
{
    foreach ($GLOBALS['qa_servers'] as $server) {
        qa_stop_server($server);
    }
}

function qa_tail(string $file, int $lines = 40): string
{
    if (!is_file($file)) {
        return '(no log)';
    }
    $all = file($file, FILE_IGNORE_NEW_LINES);
    return implode(PHP_EOL, array_slice($all ?: [], -$lines));
}

function qa_server_log(array $server): string
{
    return qa_tail($server['log']);
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

/**
 * Perform an HTTP request against a local server.
 *
 * @param array{
 *   json?:mixed, body?:string, headers?:array<string,string>, origin?:string,
 *   timeout?:int
 * } $options
 * @return array{status:int,headers:array<string,string>,body:string,json:mixed,ms:float,error:?string}
 */
function qa_http(string $method, int $port, string $path, array $options = []): array
{
    $url = 'http://127.0.0.1:' . $port . $path;
    $headers = [];

    foreach (($options['headers'] ?? []) as $name => $value) {
        $headers[] = $name . ': ' . $value;
    }
    if (isset($options['origin'])) {
        $headers[] = 'Origin: ' . $options['origin'];
    }

    $body = $options['body'] ?? null;
    if (array_key_exists('json', $options)) {
        $body = json_encode($options['json']);
        $headers[] = 'Content-Type: application/json';
    }

    $responseHeaders = [];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => (int) ($options['timeout'] ?? 30),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders): int {
            $length = strlen($line);
            if (preg_match('#^HTTP/\S+\s+\d+#', $line)) {
                $responseHeaders = [];
            } elseif (strpos($line, ':') !== false) {
                [$name, $value] = explode(':', $line, 2);
                $responseHeaders[strtolower(trim($name))] = trim($value);
            }
            return $length;
        },
    ]);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }

    $start = microtime(true);
    $raw = curl_exec($ch);
    $ms = (microtime(true) - $start) * 1000;
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $error = $raw === false ? curl_error($ch) : null;
    curl_close($ch);

    $text = $raw === false ? '' : (string) $raw;
    $json = null;
    if ($text !== '') {
        $decoded = json_decode($text, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            $json = $decoded;
        }
    }

    return [
        'status' => $status,
        'headers' => $responseHeaders,
        'body' => $text,
        'json' => $json,
        'ms' => $ms,
        'error' => $error,
    ];
}

function qa_request(string $method, int $port, string $path, array $options = []): array
{
    return qa_http($method, $port, $path, $options);
}

function qa_login(int $port, string $email, ?string $password = null, ?string $origin = null): array
{
    $options = ['json' => ['email' => $email, 'password' => $password ?? QA_PASSWORD]];
    if ($origin !== null) {
        $options['origin'] = $origin;
    }
    return qa_http('POST', $port, '/api/auth/login.php', $options);
}

function qa_token(int $port, string $email, ?string $password = null): string
{
    $response = qa_login($port, $email, $password);
    Assert::status(200, $response, 'login for ' . $email);
    Assert::json($response);
    Assert::ok(isset($response['json']['token']) && is_string($response['json']['token']), 'login did not return a token');
    return $response['json']['token'];
}

function qa_auth(string $token, array $extra = []): array
{
    return ['headers' => array_merge(['Authorization' => 'Bearer ' . $token], $extra['headers'] ?? [])];
}

function qa_auth_request(string $method, int $port, string $path, string $token, array $options = []): array
{
    $options['headers'] = array_merge($options['headers'] ?? [], ['Authorization' => 'Bearer ' . $token]);
    return qa_http($method, $port, $path, $options);
}

function qa_header(array $response, string $name): ?string
{
    return $response['headers'][strtolower($name)] ?? null;
}

function qa_assert_no_php_errors(array $response, string $context = ''): void
{
    foreach (['Fatal error', 'Parse error', 'Warning:', 'Notice:', 'Deprecated:', 'Stack trace', 'Uncaught'] as $needle) {
        Assert::notContains($needle, $response['body'], $context . ' leaked PHP diagnostics');
    }
}

function qa_now(): string
{
    return date('Y-m-d H:i:s');
}

register_shutdown_function('qa_stop_all_servers');
