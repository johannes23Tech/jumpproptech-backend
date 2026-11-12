<?php
/**
 * Non-functional tests: latency, throughput, concurrency, resource limits,
 * rate-limit isolation, security headers under production configuration and
 * cross-environment behaviour (development, production, weak secrets and a
 * broken database).
 */

declare(strict_types=1);

require_once QA_ROOT . '/vendor/autoload.php';

if (!function_exists('qa_functional_tokens')) {
    require_once __DIR__ . '/functional.php';
}

function qa_percentile(array $values, float $percentile): float
{
    if ($values === []) {
        return 0.0;
    }
    sort($values);
    $index = (int) ceil(($percentile / 100) * count($values)) - 1;
    $index = max(0, min($index, count($values) - 1));
    return (float) $values[$index];
}

/**
 * Run HTTP requests in parallel against several local server instances.
 *
 * @param array<int, array{method:string,port:int,path:string,options?:array}> $requests
 * @return array<int, array{status:int,body:string,json:mixed,error:?string}>
 */
function qa_parallel(array $requests, int $timeout = 60): array
{
    $multi = curl_multi_init();
    $handles = [];

    foreach ($requests as $index => $request) {
        $options = $request['options'] ?? [];
        $url = 'http://127.0.0.1:' . $request['port'] . $request['path'];
        $headers = [];
        foreach (($options['headers'] ?? []) as $name => $value) {
            $headers[] = $name . ': ' . $value;
        }
        if (isset($options['origin'])) {
            $headers[] = 'Origin: ' . $options['origin'];
        }

        $body = null;
        if (array_key_exists('json', $options)) {
            $body = json_encode($options['json']);
            $headers[] = 'Content-Type: application/json';
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => strtoupper($request['method']),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        curl_multi_add_handle($multi, $ch);
        $handles[$index] = $ch;
    }

    $running = null;
    do {
        $status = curl_multi_exec($multi, $running);
        if ($running > 0) {
            curl_multi_select($multi, 0.2);
        }
    } while ($running > 0 && $status === CURLM_OK);

    $results = [];
    foreach ($handles as $index => $ch) {
        $raw = curl_multi_getcontent($ch);
        $text = $raw === false ? '' : (string) $raw;
        $results[$index] = [
            'status' => (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
            'body' => $text,
            'json' => json_decode($text, true),
            'error' => $raw === false ? curl_error($ch) : null,
        ];
        curl_multi_remove_handle($multi, $ch);
        curl_close($ch);
    }
    curl_multi_close($multi);

    return $results;
}

function run_nonfunctional(Reporter $reporter, int $port): void
{
    $extra = [];
    $servers = [
        'primary' => ['port' => $port],
        'secondary' => ['port' => 8101],
        'tertiary' => ['port' => 8102],
        'production' => ['port' => 8103, 'overrides' => [
            'APP_ENV' => 'production',
            'CORS_ALLOWED_ORIGINS' => QA_FRONTEND,
            'ALLOWED_ORIGINS' => QA_FRONTEND,
        ]],
        'weak_jwt' => ['port' => 8104, 'overrides' => [
            'APP_ENV' => 'production',
            'JWT_SECRET' => str_repeat('a', 31),
        ]],
        'bad_db' => ['port' => 8105, 'overrides' => [
            'APP_ENV' => 'production',
            'DB_PASS' => 'DefinitelyNotTheQaPassword!1',
        ]],
    ];

    try {
        foreach ($servers as $name => $server) {
            if ($name === 'primary') {
                continue;
            }
            $extra[$name] = qa_start_server((int) $server['port'], $server['overrides'] ?? []);
        }

        $tokens = qa_functional_tokens($port);

        // -------------------------------------------------------------------
        $reporter->section('Non-functional — latency and throughput');

        $reporter->test('Ping latency p95 stays under 300 ms over 30 requests', function () use ($port): void {
            $samples = [];
            for ($i = 0; $i < 30; $i++) {
                $response = qa_http('GET', $port, '/api/ping.php');
                Assert::status(200, $response);
                Assert::same(null, $response['error']);
                $samples[] = $response['ms'];
            }
            $p95 = qa_percentile($samples, 95);
            Assert::ok($p95 < 300, 'ping p95 latency is ' . round($p95, 1) . ' ms (limit 300 ms)');
        });

        $reporter->test('Authenticated reads sustain 40 sequential requests under 15 s', function () use ($port, $tokens): void {
            $samples = [];
            $start = microtime(true);
            for ($i = 0; $i < 40; $i++) {
                $response = qa_auth_request('GET', $port, '/api/properties.php', $tokens['landlord.a']);
                Assert::status(200, $response);
                $samples[] = $response['ms'];
            }
            $elapsed = microtime(true) - $start;
            $p95 = qa_percentile($samples, 95);
            Assert::ok($elapsed < 15, '40 reads took ' . round($elapsed, 2) . ' s (limit 15 s)');
            Assert::ok($p95 < 500, 'authenticated read p95 is ' . round($p95, 1) . ' ms (limit 500 ms)');
        });

        $reporter->test('Password hashing uses bcrypt cost 12 and stays within a sane budget', function (): void {
            $samples = [];
            for ($i = 0; $i < 3; $i++) {
                $start = microtime(true);
                $hash = password_hash('PerfTest!2026', PASSWORD_BCRYPT, ['cost' => 12]);
                $samples[] = (microtime(true) - $start) * 1000;
                Assert::matches('/^\$2y\$12\$/', $hash);
                Assert::true(password_verify('PerfTest!2026', $hash));
            }
            $average = array_sum($samples) / count($samples);
            Assert::between($average, 40, 1500, 'bcrypt cost 12 average is ' . round($average, 1) . ' ms');
        });

        $reporter->test('TOTP generation has negligible CPU cost', function (): void {
            $secret = mfa_generate_secret();
            $step = (int) floor(time() / MFA_PERIOD);
            $start = microtime(true);
            for ($i = 0; $i < 1000; $i++) {
                mfa_totp_at($secret, $step + $i);
            }
            $elapsed = microtime(true) - $start;
            Assert::ok($elapsed < 3, '1000 TOTP codes took ' . round($elapsed, 2) . ' s (limit 3 s)');
        });

        $reporter->test('Rate-limit bookkeeping stays fast under repeated hits', function () use ($port): void {
            qa_reset_rate_limits();
            $conn = qa_pdo();
            $bucket = 'qa_perf_' . bin2hex(random_bytes(4));
            $start = microtime(true);
            for ($i = 0; $i < 200; $i++) {
                security_rate_limit_hit($conn, $bucket, 'perf@example.test|198.51.100.1', 1000, 900, 900);
            }
            $elapsed = microtime(true) - $start;
            Assert::ok($elapsed < 10, '200 rate-limit hits took ' . round($elapsed, 2) . ' s (limit 10 s)');
            Assert::same(1, (int) qa_value('SELECT COUNT(*) FROM rate_limits WHERE bucket = ?', [$bucket]));
            qa_reset_rate_limits();
        });

        // -------------------------------------------------------------------
        $reporter->section('Non-functional — concurrency');

        $reporter->test('30 concurrent reads across three servers all succeed', function () use ($servers, $tokens): void {
            $requests = [];
            $ports = [$servers['primary']['port'], $servers['secondary']['port'], $servers['tertiary']['port']];
            for ($i = 0; $i < 30; $i++) {
                $requests[] = [
                    'method' => 'GET',
                    'port' => $ports[$i % 3],
                    'path' => '/api/properties.php',
                    'options' => ['headers' => ['Authorization' => 'Bearer ' . $tokens['landlord.a']]],
                ];
            }

            $start = microtime(true);
            $results = qa_parallel($requests);
            $elapsed = microtime(true) - $start;

            Assert::same(30, count($results));
            foreach ($results as $index => $result) {
                Assert::same(null, $result['error'], "request {$index} failed at the transport layer");
                Assert::same(200, $result['status'], "concurrent request {$index} returned {$result['status']}");
                Assert::ok(is_array($result['json']), "concurrent request {$index} was not JSON");
            }
            Assert::ok($elapsed < 20, '30 concurrent reads took ' . round($elapsed, 2) . ' s (limit 20 s)');
        });

        $reporter->test('12 concurrent logins are not mistaken for a brute-force attack', function () use ($servers): void {
            $requests = [];
            $ports = [$servers['primary']['port'], $servers['secondary']['port'], $servers['tertiary']['port']];
            for ($i = 0; $i < 12; $i++) {
                $requests[] = [
                    'method' => 'POST',
                    'port' => $ports[$i % 3],
                    'path' => '/api/auth/login.php',
                    'options' => ['json' => ['email' => 'landlord.a@qa.local', 'password' => QA_PASSWORD]],
                ];
            }

            $results = qa_parallel($requests);
            Assert::same(12, count($results));
            foreach ($results as $index => $result) {
                Assert::same(200, $result['status'], "concurrent login {$index} returned {$result['status']}: " . substr($result['body'], 0, 200));
                Assert::ok(!empty($result['json']['token']), "concurrent login {$index} returned no token");
            }
        });

        $reporter->test('9 concurrent writes all commit exactly once', function () use ($port, $servers, $tokens): void {
            $ports = [$servers['primary']['port'], $servers['secondary']['port'], $servers['tertiary']['port']];
            $marker = 'Concurrent-' . bin2hex(random_bytes(4));
            $requests = [];
            for ($i = 0; $i < 9; $i++) {
                $requests[] = [
                    'method' => 'POST',
                    'port' => $ports[$i % 3],
                    'path' => '/api/properties.php',
                    'options' => [
                        'headers' => ['Authorization' => 'Bearer ' . $tokens['landlord.a']],
                        'json' => [
                            'name' => $marker . '-' . $i,
                            'address' => $i . ' Concurrency Street',
                            'property_type' => 'House',
                        ],
                    ],
                ];
            }

            $results = qa_parallel($requests);
            Assert::same(9, count($results));
            foreach ($results as $index => $result) {
                Assert::same(201, $result['status'], "concurrent write {$index} returned {$result['status']}: " . substr($result['body'], 0, 200));
            }

            Assert::same(
                9,
                (int) qa_value('SELECT COUNT(*) FROM properties WHERE name LIKE ?', [$marker . '%']),
                'concurrent writes were lost or duplicated'
            );
            qa_exec('DELETE FROM properties WHERE name LIKE ?', [$marker . '%']);
        });

        // -------------------------------------------------------------------
        $reporter->section('Non-functional — resilience and input bounds');

        $reporter->test('A mixed read workload produces no 5xx or PHP diagnostics', function () use ($port, $tokens): void {
            $plan = [
                ['GET', '/api/properties.php', 'landlord.a'],
                ['GET', '/api/units.php', 'landlord.a'],
                ['GET', '/api/tenants.php', 'landlord.a'],
                ['GET', '/api/rent.php', 'landlord.a'],
                ['GET', '/api/maintenance.php', 'landlord.a'],
                ['GET', '/api/messages.php', 'landlord.a'],
                ['GET', '/api/expenses.php', 'landlord.a'],
                ['GET', '/api/dashboard.php', 'landlord.a'],
                ['GET', '/api/auth/mfa_status.php', 'landlord.a'],
                ['GET', '/api/tenant_data.php', 'tenant.a'],
                ['GET', '/api/tenant_profile.php', 'tenant.a'],
                ['GET', '/api/maintenance.php', 'maintenance'],
                ['GET', '/api/admin/stats.php', 'superadmin'],
                ['GET', '/api/properties.php', 'superadmin'],
            ];

            $checked = 0;
            for ($round = 0; $round < 3; $round++) {
                foreach ($plan as [$method, $path, $role]) {
                    $response = qa_auth_request($method, $port, $path, $tokens[$role]);
                    Assert::ok($response['status'] < 500, "{$path} ({$role}) returned {$response['status']}");
                    qa_assert_no_php_errors($response, "{$path} ({$role})");
                    $checked++;
                }
            }
            Assert::same(42, $checked);
        });

        $reporter->test('Oversized message bodies are truncated, not stored unbounded', function () use ($port, $tokens): void {
            $response = qa_auth_request('POST', $port, '/api/messages.php', $tokens['tenant.a'], [
                'json' => ['tenant_id' => 5, 'receiver_id' => 2, 'message' => str_repeat('A', 100000)],
            ]);
            Assert::status(200, $response);
            $max = (int) qa_value('SELECT MAX(CHAR_LENGTH(message)) FROM messages WHERE tenant_id = 5');
            Assert::ok($max <= 5000, "stored message length is {$max} (limit 5000)");
        });

        $reporter->test('A 200 KB malformed body is rejected without crashing the server', function () use ($port): void {
            $response = qa_http('POST', $port, '/api/auth/login.php', [
                'body' => str_repeat('{invalid', 25000),
                'timeout' => 30,
            ]);
            Assert::ok($response['status'] >= 400 && $response['status'] < 500, 'malformed body returned ' . $response['status']);
            qa_assert_no_php_errors($response);

            $healthy = qa_http('GET', $port, '/api/ping.php');
            Assert::status(200, $healthy, 'server did not recover after malformed input');
        });

        $reporter->test('SQL injection attempts fail safely with generic credentials errors', function () use ($port): void {
            foreach (["' OR '1'='1", "admin@qa.local' --", "' UNION SELECT 1,2,3 --"] as $payload) {
                $response = qa_login($port, $payload, 'anything');
                Assert::ok($response['status'] === 401 || $response['status'] === 429, 'injection probe returned ' . $response['status']);
                qa_assert_no_php_errors($response);
                Assert::notContains('SQLSTATE', $response['body']);
            }
            qa_reset_rate_limits();
        });

        $reporter->test('Rate limits are isolated per client IP', function () use ($port): void {
            qa_reset_rate_limits();
            $email = 'ip.scope@qa.local';
            $last = null;
            for ($i = 0; $i < 5; $i++) {
                $last = qa_http('POST', $port, '/api/auth/login.php', [
                    'headers' => ['X-Forwarded-For' => '198.51.100.10'],
                    'json' => ['email' => $email, 'password' => 'Wrong' . $i . '!'],
                ]);
            }
            Assert::status(429, $last, 'per-account lock was not enforced');

            $sameIp = qa_http('POST', $port, '/api/auth/login.php', [
                'headers' => ['X-Forwarded-For' => '198.51.100.10'],
                'json' => ['email' => $email, 'password' => 'Wrong!'],
            ]);
            Assert::status(429, $sameIp, 'locked IP was allowed through');

            $otherIp = qa_http('POST', $port, '/api/auth/login.php', [
                'headers' => ['X-Forwarded-For' => '198.51.100.11'],
                'json' => ['email' => $email, 'password' => 'Wrong!'],
            ]);
            Assert::status(401, $otherIp, 'a different IP inherited the lock (status ' . $otherIp['status'] . ')');
            qa_reset_rate_limits();
        });

        // -------------------------------------------------------------------
        $reporter->section('Non-functional — production configuration');

        $reporter->test('Production responses keep the full security header set', function () use ($servers): void {
            // ping.php does not include config.php, so probe a real API endpoint.
            $login = qa_http('POST', (int) $servers['production']['port'], '/api/auth/login.php', [
                'json' => ['email' => 'landlord.a@qa.local', 'password' => QA_PASSWORD],
            ]);
            Assert::status(200, $login);
            Assert::same(null, qa_header($login, 'X-Powered-By'));
            Assert::same('nosniff', qa_header($login, 'X-Content-Type-Options'));
            Assert::same('DENY', qa_header($login, 'X-Frame-Options'));
            Assert::contains('no-store', (string) qa_header($login, 'Cache-Control'));
            Assert::contains("default-src 'none'", (string) qa_header($login, 'Content-Security-Policy'));
            Assert::same(null, qa_header($login, 'Strict-Transport-Security'));
        });

        $reporter->test('Production CORS rejects development origins and allows the frontend', function () use ($servers): void {
            $prod = (int) $servers['production']['port'];

            $dev = qa_http('OPTIONS', $prod, '/api/auth/login.php', ['origin' => QA_DEV_ORIGIN]);
            Assert::status(403, $dev);
            Assert::same(null, qa_header($dev, 'Access-Control-Allow-Origin'));

            $frontend = qa_http('OPTIONS', $prod, '/api/auth/login.php', ['origin' => QA_FRONTEND]);
            Assert::status(200, $frontend);
            Assert::same(QA_FRONTEND, qa_header($frontend, 'Access-Control-Allow-Origin'));

            $evil = qa_http('POST', $prod, '/api/auth/login.php', [
                'origin' => QA_EVIL_ORIGIN,
                'json' => ['email' => 'landlord.a@qa.local', 'password' => QA_PASSWORD],
            ]);
            Assert::status(403, $evil);
        });

        $reporter->test('Production errors do not leak paths, stack traces or SQL state', function () use ($servers): void {
            $prod = (int) $servers['production']['port'];

            $wrong = qa_http('POST', $prod, '/api/auth/login.php', [
                'json' => ['email' => 'landlord.a@qa.local', 'password' => 'Wrong!1234'],
            ]);
            Assert::status(401, $wrong);

            $malformed = qa_http('POST', $prod, '/api/auth/login.php', ['body' => '{oops']);
            Assert::status(400, $malformed);

            $array = qa_http('POST', $prod, '/api/auth/login.php', ['json' => ['email' => [], 'password' => []]]);
            Assert::status(400, $array);

            foreach ([$wrong, $malformed, $array] as $response) {
                foreach (['C:\\', '/config/', '.php', 'SQLSTATE', 'Stack trace', 'Uncaught', 'Fatal error'] as $needle) {
                    Assert::notContains($needle, $response['body'], 'production response leaked internal detail');
                }
            }
        });

        $reporter->test('A weak JWT secret fails closed on login', function () use ($servers): void {
            $response = qa_http('POST', (int) $servers['weak_jwt']['port'], '/api/auth/login.php', [
                'json' => ['email' => 'landlord.a@qa.local', 'password' => QA_PASSWORD],
            ]);
            Assert::status(500, $response);
            Assert::contains('Server configuration error', $response['body']);
            Assert::notContains('token', $response['body']);
            Assert::notContains(str_repeat('a', 31), $response['body']);
        });

        $reporter->test('A broken database fails closed without exposing credentials', function () use ($servers): void {
            $response = qa_login((int) $servers['bad_db']['port'], 'landlord.a@qa.local');
            Assert::status(500, $response);
            foreach ([QA_DB_PASS, 'DefinitelyNotTheQaPassword', 'jpt_qa', 'SQLSTATE', 'mysql:host'] as $needle) {
                Assert::notContains($needle, $response['body'], 'database error response leaked internals');
            }
            qa_assert_no_php_errors($response);
        });

        $reporter->note('Environment matrix exercised: development, production, weak JWT secret, invalid DB credentials.');

        // -------------------------------------------------------------------
        $reporter->section('Non-functional — server stability');

        $reporter->test('The development server survives a burst of invalid requests', function () use ($port): void {
            for ($i = 0; $i < 25; $i++) {
                $response = qa_http('POST', $port, '/api/auth/login.php', ['body' => 'garbage-' . $i]);
                Assert::ok($response['status'] >= 400 && $response['status'] < 500, 'invalid request returned ' . $response['status']);
            }
            $healthy = qa_http('GET', $port, '/api/ping.php');
            Assert::status(200, $healthy);
            Assert::same('awake', $healthy['json']['status'] ?? null);
        });
    } finally {
        foreach ($extra as $server) {
            qa_stop_server($server);
        }
    }
}
