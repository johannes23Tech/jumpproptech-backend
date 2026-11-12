<?php
/**
 * Functional tests: exercise the real HTTP endpoints against the disposable
 * QA database. Every test drives the API exactly like the frontend would
 * (JSON over HTTP + bearer tokens) and verifies both the response contract and
 * the resulting database state.
 */

declare(strict_types=1);

require_once QA_ROOT . '/vendor/autoload.php';
require_once QA_ROOT . '/config/mfa.php';

use Firebase\JWT\JWT;

/** @var array<string,string>|null */
$GLOBALS['qa_functional_tokens'] = null;
$GLOBALS['qa_functional_mfa'] = [];

function qa_functional_tokens(int $port): array
{
    if (is_array($GLOBALS['qa_functional_tokens'])) {
        return $GLOBALS['qa_functional_tokens'];
    }

    $tokens = [];
    foreach ([
        'superadmin' => 'superadmin@qa.local',
        'landlord.a' => 'landlord.a@qa.local',
        'landlord.b' => 'landlord.b@qa.local',
        'agent.a' => 'agent.a@qa.local',
        'tenant.a' => 'tenant.a@qa.local',
        'tenant.b' => 'tenant.b@qa.local',
        'maintenance' => 'maintenance@qa.local',
        'landlord.expired' => 'landlord.expired@qa.local',
        'tenant.self' => 'tenant.self@qa.local',
    ] as $key => $email) {
        $tokens[$key] = qa_token($port, $email);
    }

    $GLOBALS['qa_functional_tokens'] = $tokens;
    return $tokens;
}

function qa_functional_request(int $port, string $method, string $path, string $tokenKey, array $options = []): array
{
    $tokens = qa_functional_tokens($port);
    Assert::ok(isset($tokens[$tokenKey]), "unknown token key {$tokenKey}");
    return qa_auth_request($method, $port, $path, $tokens[$tokenKey], $options);
}

function qa_functional_json(array $response, string $label = ''): array
{
    Assert::json($response, $label);
    return is_array($response['json']) ? $response['json'] : [];
}

function qa_functional_ids(array $rows, string $key = 'id'): array
{
    $ids = array_map('intval', array_column($rows, $key));
    sort($ids);
    return $ids;
}

function qa_functional_forge(array $overrides = [], string $secret = QA_JWT_SECRET): string
{
    $now = time();
    $payload = array_merge([
        'iss' => 'jumpproptech',
        'iat' => $now,
        'exp' => $now + 3600,
        'jti' => bin2hex(random_bytes(16)),
        'scope' => 'access',
        'ver' => 0,
        'user_id' => 2,
        'role' => 'landlord',
    ], $overrides);

    return JWT::encode($payload, $secret, 'HS256');
}

function qa_functional_login_json(int $port, string $email, ?string $password = null): array
{
    $response = qa_login($port, $email, $password);
    Assert::json($response, 'login for ' . $email);
    return $response['json'];
}

function run_functional(Reporter $reporter, int $port): void
{
    $tokens = qa_functional_tokens($port);

    // -----------------------------------------------------------------------
    $reporter->section('Functional — transport, CORS and headers');

    $reporter->test('GET /api/ping.php reports healthy without leaking internals', function () use ($port): void {
        $response = qa_http('GET', $port, '/api/ping.php');
        Assert::status(200, $response);
        $body = qa_functional_json($response);
        Assert::same('awake', $body['status'] ?? null);
        qa_assert_no_php_errors($response);
    });

    $reporter->test('API responses carry the hardened security header set', function () use ($port, $tokens): void {
        $response = qa_auth_request('GET', $port, '/api/properties.php', $tokens['landlord.a']);
        Assert::status(200, $response);
        Assert::same(null, qa_header($response, 'X-Powered-By'), 'X-Powered-By must be removed');
        Assert::same('nosniff', qa_header($response, 'X-Content-Type-Options'));
        Assert::same('DENY', qa_header($response, 'X-Frame-Options'));
        Assert::same('strict-origin-when-cross-origin', qa_header($response, 'Referrer-Policy'));
        Assert::contains("default-src 'none'", (string) qa_header($response, 'Content-Security-Policy'));
        Assert::contains('geolocation=()', (string) qa_header($response, 'Permissions-Policy'));
        Assert::contains('no-store', (string) qa_header($response, 'Cache-Control'));
        Assert::same('Origin', qa_header($response, 'Vary'));
        Assert::same(null, qa_header($response, 'Strict-Transport-Security'), 'HSTS must not be sent over plain HTTP');
    });

    $reporter->test('HSTS is emitted when the request arrives over HTTPS', function () use ($port, $tokens): void {
        $response = qa_auth_request('GET', $port, '/api/properties.php', $tokens['landlord.a'], [
            'headers' => ['X-Forwarded-Proto' => 'https'],
        ]);
        Assert::status(200, $response);
        $hsts = (string) qa_header($response, 'Strict-Transport-Security');
        Assert::contains('max-age=31536000', $hsts);
        Assert::contains('includeSubDomains', $hsts);
    });

    $reporter->test('CORS allowlist echoes known origins and blocks unknown ones', function () use ($port): void {
        $allowed = qa_http('OPTIONS', $port, '/api/auth/login.php', ['origin' => QA_DEV_ORIGIN]);
        Assert::status(200, $allowed);
        Assert::same(QA_DEV_ORIGIN, qa_header($allowed, 'Access-Control-Allow-Origin'));
        Assert::same('Origin', qa_header($allowed, 'Vary'));
        Assert::contains('POST', (string) qa_header($allowed, 'Access-Control-Allow-Methods'));
        Assert::contains('Authorization', (string) qa_header($allowed, 'Access-Control-Allow-Headers'));
        Assert::same('600', qa_header($allowed, 'Access-Control-Max-Age'));

        $evil = qa_http('OPTIONS', $port, '/api/auth/login.php', ['origin' => QA_EVIL_ORIGIN]);
        Assert::status(403, $evil);
        Assert::same(null, qa_header($evil, 'Access-Control-Allow-Origin'));
        Assert::contains('Origin not allowed', $evil['body']);

        $anonymous = qa_http('GET', $port, '/api/ping.php');
        Assert::status(200, $anonymous);

        $productionOrigin = qa_http('POST', $port, '/api/auth/login.php', [
            'origin' => QA_FRONTEND,
            'json' => ['email' => 'landlord.a@qa.local', 'password' => QA_PASSWORD],
        ]);
        Assert::status(200, $productionOrigin);
        Assert::same(QA_FRONTEND, qa_header($productionOrigin, 'Access-Control-Allow-Origin'));
    });

    $reporter->test('Unsupported HTTP methods are rejected with 405', function () use ($port, $tokens): void {
        $response = qa_auth_request('PUT', $port, '/api/properties.php', $tokens['landlord.a'], [
            'json' => ['name' => 'Method probe'],
        ]);
        Assert::same(
            405,
            $response['status'],
            'PUT /api/properties.php returned ' . $response['status'] . ' (empty body: ' . var_export($response['body'], true) . ')'
        );
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — authentication');

    $reporter->test('Valid credentials return a scoped access token and the user profile', function () use ($port): void {
        $response = qa_login($port, 'landlord.a@qa.local');
        Assert::status(200, $response);
        $body = qa_functional_json($response);
        Assert::matches('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', (string) ($body['token'] ?? ''));
        Assert::same(2, (int) ($body['user']['id'] ?? 0));
        Assert::same('landlord', $body['user']['role'] ?? null);

        $decoded = JWT::decode($body['token'], new \Firebase\JWT\Key(QA_JWT_SECRET, 'HS256'));
        Assert::same('access', $decoded->scope);
        Assert::same('jumpproptech', $decoded->iss);
        Assert::matches('/^[a-f0-9]{32}$/', $decoded->jti);
    });

    $reporter->test('Wrong passwords and unknown accounts get the same generic 401', function () use ($port): void {
        $wrong = qa_login($port, 'landlord.a@qa.local', 'DefinitelyWrong!1');
        Assert::status(401, $wrong);
        Assert::contains('Invalid credentials', $wrong['body']);
        qa_assert_no_php_errors($wrong);

        $unknown = qa_login($port, 'nobody@qa.local', 'DefinitelyWrong!1');
        Assert::status(401, $unknown);
        Assert::same($wrong['body'], $unknown['body'], 'responses must not reveal account existence');
    });

    $reporter->test('Malformed login payloads are rejected cleanly', function () use ($port): void {
        $missing = qa_http('POST', $port, '/api/auth/login.php', ['json' => ['email' => 'landlord.a@qa.local']]);
        Assert::status(400, $missing);
        Assert::contains('Email and password are required', $missing['body']);

        $invalid = qa_http('POST', $port, '/api/auth/login.php', ['body' => '{not-json']);
        Assert::status(400, $invalid);

        $array = qa_http('POST', $port, '/api/auth/login.php', ['json' => ['email' => ['x'], 'password' => ['y']]]);
        Assert::status(400, $array);
    });

    $reporter->test('Protected endpoints reject missing, malformed and untrusted tokens', function () use ($port): void {
        $missing = qa_http('GET', $port, '/api/properties.php');
        Assert::status(401, $missing);
        Assert::contains('No token provided', $missing['body']);

        $malformed = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer not-a-jwt']]);
        Assert::status(401, $malformed);

        $foreign = qa_functional_forge([], str_repeat('z', 64));
        $wrongSecret = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $foreign]]);
        Assert::status(401, $wrongSecret);

        $now = time();
        $expired = qa_functional_forge(['iat' => $now - 7200, 'exp' => $now - 3600]);
        $expiredResponse = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $expired]]);
        Assert::status(401, $expiredResponse);

        $noJti = JWT::encode(['iss' => 'jumpproptech', 'iat' => $now, 'exp' => $now + 60, 'scope' => 'access', 'ver' => 0, 'user_id' => 2, 'role' => 'landlord'], QA_JWT_SECRET, 'HS256');
        $noJtiResponse = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $noJti]]);
        Assert::status(401, $noJtiResponse);

        $mfaScope = qa_functional_forge(['scope' => 'mfa']);
        $mfaResponse = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $mfaScope]]);
        Assert::status(401, $mfaResponse);
    });

    $reporter->test('Token role claims cannot escalate privileges', function () use ($port): void {
        $forged = qa_functional_forge(['user_id' => 5, 'role' => 'superadmin']);
        $response = qa_http('GET', $port, '/api/admin/stats.php', ['headers' => ['Authorization' => 'Bearer ' . $forged]]);
        Assert::status(403, $response, 'the role in the token must never be trusted');
    });

    $reporter->test('Bumping token_version invalidates previously issued tokens', function () use ($port): void {
        $token = qa_token($port, 'extra.landlord@qa.local');
        $before = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $token]]);
        Assert::status(200, $before);

        qa_exec('UPDATE users SET token_version = token_version + 1 WHERE id = 14');

        $after = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $token]]);
        Assert::status(401, $after);
        Assert::contains('Session expired', $after['body']);
    });

    $reporter->test('Expired subscriptions are blocked with 402 (login still succeeds)', function () use ($port): void {
        $login = qa_login($port, 'landlord.expired@qa.local');
        Assert::status(200, $login);
        $token = (string) (qa_functional_json($login)['token'] ?? '');
        Assert::ok($token !== '', 'expired landlord could not log in');

        $blocked = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $token]]);
        Assert::status(402, $blocked);
        Assert::contains('subscription has expired', $blocked['body']);
    });

    $reporter->test('Tenant and maintenance roles bypass the SaaS subscription gate', function () use ($port): void {
        $tenant = qa_functional_request($port, 'GET', '/api/tenant_data.php', 'tenant.a');
        Assert::same(200, $tenant['status'], 'tenant was blocked by the subscription gate');

        $maintenance = qa_functional_request($port, 'GET', '/api/maintenance.php', 'maintenance');
        Assert::same(200, $maintenance['status'], 'maintenance was blocked by the subscription gate');
    });

    $reporter->test('Login is rate limited after repeated failures', function () use ($port): void {
        qa_reset_rate_limits();
        $email = 'bruteforce@qa.local';
        $last = null;
        for ($i = 0; $i < 6; $i++) {
            $last = qa_login($port, $email, 'WrongPass!' . $i);
        }
        Assert::status(429, $last);
        Assert::contains('Too many login attempts', $last['body']);
        $retry = qa_header($last, 'Retry-After');
        Assert::ok($retry !== null && ctype_digit((string) $retry), 'Retry-After header missing or malformed');
        Assert::ok((int) $retry > 0, 'Retry-After must be positive');
        qa_reset_rate_limits();
    });

    $reporter->test('Public registration creates tenant-only accounts', function () use ($port): void {
        $email = 'registered.tenant@qa.local';
        $response = qa_http('POST', $port, '/api/auth/register.php', ['json' => [
            'full_name' => 'Registered Tenant',
            'email' => $email,
            'password' => QA_PASSWORD,
            'phone' => '0744444444',
            'role' => 'superadmin',
        ]]);
        Assert::status(201, $response);
        $body = qa_functional_json($response);
        Assert::same('tenant', $body['user']['role'] ?? null);
        Assert::ok(!empty($body['token']), 'registration did not auto-login');

        $role = qa_value('SELECT role FROM users WHERE email = ?', [$email]);
        Assert::same('tenant', $role, 'mass assignment must not change the role');

        $duplicate = qa_http('POST', $port, '/api/auth/register.php', ['json' => [
            'full_name' => 'Registered Tenant',
            'email' => $email,
            'password' => QA_PASSWORD,
        ]]);
        Assert::status(400, $duplicate);
        Assert::contains('Email already exists', $duplicate['body']);

        $weak = qa_http('POST', $port, '/api/auth/register.php', ['json' => [
            'full_name' => 'Weak User',
            'email' => 'weak.user@qa.local',
            'password' => 'weak',
        ]]);
        Assert::status(400, $weak);
        qa_reset_rate_limits();
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — properties and units');

    $reporter->test('Landlords only list their own properties', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/properties.php', 'landlord.a');
        Assert::status(200, $response);
        Assert::same([1], qa_functional_ids(qa_functional_json($response)));

        $other = qa_functional_request($port, 'GET', '/api/properties.php', 'landlord.b');
        Assert::status(200, $other);
        $ids = qa_functional_ids(qa_functional_json($other));
        Assert::ok(in_array(2, $ids, true), 'landlord B cannot see own property');
        Assert::ok(!in_array(1, $ids, true), 'landlord B can see landlord A property');
    });

    $reporter->test('Superadmin sees every property', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/properties.php', 'superadmin');
        Assert::status(200, $response);
        $ids = qa_functional_ids(qa_functional_json($response));
        Assert::ok(in_array(1, $ids, true) && in_array(2, $ids, true), 'superadmin does not see all properties');
    });

    $reporter->test('Superadmin must target a real landlord when creating a property', function () use ($port): void {
        $missing = qa_functional_request($port, 'POST', '/api/properties.php', 'superadmin', [
            'json' => ['name' => 'No owner', 'address' => '1 Nowhere', 'property_type' => 'House'],
        ]);
        Assert::status(400, $missing);

        $nonLandlord = qa_functional_request($port, 'POST', '/api/properties.php', 'superadmin', [
            'json' => ['landlord_id' => 5, 'name' => 'Tenant owned', 'address' => '1 Nowhere', 'property_type' => 'House'],
        ]);
        Assert::status(404, $nonLandlord);
    });

    $reporter->test('Property creation sanitizes input and ignores client ownership', function () use ($port): void {
        $response = qa_functional_request($port, 'POST', '/api/properties.php', 'landlord.a', [
            'json' => [
                'landlord_id' => 3,
                'name' => '<script>alert(1)</script>QA Villa ' . str_repeat('x', 200),
                'address' => '42 QA Avenue',
                'property_type' => 'House',
            ],
        ]);
        Assert::status(201, $response);
        $id = (int) (qa_functional_json($response)['id'] ?? 0);
        Assert::ok($id > 0, 'no property id returned');

        $row = qa_query('SELECT * FROM properties WHERE id = ?', [$id]);
        Assert::same(1, count($row));
        Assert::same(2, (int) $row[0]['landlord_id'], 'payload landlord_id must be ignored for landlords');
        Assert::notContains('<', $row[0]['name'], 'markup was stored in the property name');
        Assert::ok(mb_strlen($row[0]['name']) <= 100, 'property name is not length limited');

        $listed = qa_functional_request($port, 'GET', '/api/properties.php', 'landlord.a');
        Assert::ok(in_array($id, qa_functional_ids(qa_functional_json($listed)), true), 'created property is not listed');

        $invalid = qa_functional_request($port, 'POST', '/api/properties.php', 'landlord.a', [
            'json' => ['name' => 'Bad type', 'address' => '1 QA', 'property_type' => 'Skyscraper'],
        ]);
        Assert::status(400, $invalid);
    });

    $reporter->test('Units are scoped to the landlord and validate their payload', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/units.php', 'landlord.a');
        Assert::status(200, $response);
        $ids = qa_functional_ids(qa_functional_json($response));
        Assert::ok(in_array(1, $ids, true) && in_array(2, $ids, true), 'landlord A cannot see own units');
        Assert::ok(!in_array(3, $ids, true), 'landlord A can see landlord B unit');

        $created = qa_functional_request($port, 'POST', '/api/units.php', 'landlord.a', [
            'json' => ['property_id' => 1, 'unit_number' => 'A3', 'size_dimensions' => '40sqm', 'monthly_rent' => 4500, 'status' => 'Vacant'],
        ]);
        Assert::status(201, $created);
        Assert::ok((int) (qa_functional_json($created)['id'] ?? 0) > 0);

        $badStatus = qa_functional_request($port, 'POST', '/api/units.php', 'landlord.a', [
            'json' => ['property_id' => 1, 'unit_number' => 'A4', 'size_dimensions' => '40sqm', 'monthly_rent' => 4500, 'status' => 'Haunted'],
        ]);
        Assert::status(400, $badStatus);

        $foreignProperty = qa_functional_request($port, 'POST', '/api/units.php', 'landlord.a', [
            'json' => ['property_id' => 2, 'unit_number' => 'B9', 'size_dimensions' => '40sqm', 'monthly_rent' => 4500],
        ]);
        Assert::status(404, $foreignProperty);

        $tenant = qa_functional_request($port, 'GET', '/api/units.php', 'tenant.a');
        Assert::status(403, $tenant);
    });

    $reporter->test('Agents can act on assigned properties and see the data they manage', function () use ($port): void {
        $agentEmail = 'agent.tenant@qa.local';
        $issues = [];

        $unit = qa_functional_request($port, 'POST', '/api/units.php', 'agent.a', [
            'json' => ['property_id' => 1, 'unit_number' => 'AG1', 'size_dimensions' => '30sqm', 'monthly_rent' => 4000, 'status' => 'Vacant'],
        ]);
        if ($unit['status'] !== 201) {
            $issues[] = 'agent could not create a unit on the assigned property (HTTP ' . $unit['status'] . ')';
            $unitId = 0;
        } else {
            $unitId = (int) (qa_functional_json($unit)['id'] ?? 0);
        }

        if ($unitId > 0) {
            $start = date('Y-m-d', strtotime('+1 month'));
            $end = date('Y-m-d', strtotime('+7 months'));
            $tenant = qa_functional_request($port, 'POST', '/api/tenants.php', 'agent.a', [
                'json' => [
                    'name' => 'Agent Created Tenant',
                    'email' => $agentEmail,
                    'password' => QA_PASSWORD,
                    'unit_id' => $unitId,
                    'lease_start' => $start,
                    'lease_end' => $end,
                    'deposit' => 4000,
                    'monthly_rent' => 4000,
                ],
            ]);
            if ($tenant['status'] !== 200) {
                $issues[] = 'agent could not create a tenant on the assigned property (HTTP ' . $tenant['status'] . ')';
            }
        }

        $properties = qa_functional_request($port, 'GET', '/api/properties.php', 'agent.a');
        $propertyIds = qa_functional_json($properties);
        if (!in_array(1, qa_functional_ids($propertyIds), true)) {
            $issues[] = 'GET /properties.php omits property 1 even though agent_id = 4 (query filters landlord_id only)';
        }

        $units = qa_functional_request($port, 'GET', '/api/units.php', 'agent.a');
        $unitIds = qa_functional_ids(qa_functional_json($units));
        if (!in_array(1, $unitIds, true)) {
            $issues[] = 'GET /units.php omits units of the assigned property (query filters properties.landlord_id)';
        }

        $tenants = qa_functional_request($port, 'GET', '/api/tenants.php', 'agent.a');
        $tenantRows = qa_functional_json($tenants);
        if (!in_array($agentEmail, array_column($tenantRows, 'email'), true)) {
            $issues[] = 'GET /tenants.php omits the tenant the agent just created (owner_id is set to the landlord)';
        }

        $rent = qa_functional_request($port, 'GET', '/api/rent.php', 'agent.a');
        $rentRows = qa_functional_json($rent);
        $tenantId = (int) qa_value('SELECT id FROM tenants WHERE email = ? LIMIT 1', [$agentEmail]);
        if ($tenantId > 0 && !in_array($tenantId, array_map('intval', array_column($rentRows, 'tenant_id')), true)) {
            $issues[] = 'GET /rent.php omits rent records for the tenant the agent manages';
        }

        Assert::same([], $issues, 'agent scoping is inconsistent: ' . implode('; ', $issues));
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — tenants and rent');

    $reporter->test('Tenants are scoped to their owner and never expose credentials', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/tenants.php', 'landlord.a');
        Assert::status(200, $response);
        $rows = qa_functional_json($response);
        Assert::ok(count($rows) >= 1, 'landlord A sees no tenants');
        foreach ($rows as $row) {
            Assert::ok(!array_key_exists('password_hash', $row), 'tenant payload leaks password_hash');
        }
        $emails = array_column($rows, 'email');
        Assert::ok(in_array('tenant.a@qa.local', $emails, true), 'landlord A cannot see tenant A');
        Assert::ok(!in_array('tenant.b@qa.local', $emails, true), 'landlord A can see landlord B tenant');
    });

    $reporter->test('Creating a tenant provisions a user, tenant row, rent record and unit status', function () use ($port): void {
        $email = 'new.tenant@qa.local';
        $response = qa_functional_request($port, 'POST', '/api/tenants.php', 'landlord.a', [
            'json' => [
                'name' => 'New Tenant',
                'email' => $email,
                'password' => QA_PASSWORD,
                'phone' => '0755555555',
                'unit_id' => 2,
                'lease_start' => date('Y-m-01'),
                'lease_end' => date('Y-m-t', strtotime('+11 months')),
                'deposit' => 6000,
                'monthly_rent' => 6000,
            ],
        ]);
        Assert::status(200, $response);

        $userId = (int) qa_value('SELECT id FROM users WHERE email = ? LIMIT 1', [$email]);
        Assert::ok($userId > 0, 'tenant user account was not created');
        Assert::same('tenant', qa_value('SELECT role FROM users WHERE id = ?', [$userId]));
        Assert::same('active', qa_value('SELECT subscription_status FROM users WHERE id = ?', [$userId]));

        $tenantId = (int) qa_value('SELECT id FROM tenants WHERE user_id = ? LIMIT 1', [$userId]);
        Assert::ok($tenantId > 0, 'tenant row was not created');
        Assert::same(2, (int) qa_value('SELECT owner_id FROM tenants WHERE id = ?', [$tenantId]));
        Assert::same(2, (int) qa_value('SELECT unit_id FROM tenants WHERE id = ?', [$tenantId]));

        Assert::same('Occupied', qa_value('SELECT status FROM units WHERE id = 2'));
        Assert::same(1, (int) qa_value("SELECT COUNT(*) FROM rent_records WHERE tenant_id = ? AND status = 'Pending'", [$tenantId]));

        $login = qa_login($port, $email);
        Assert::status(200, $login);
        Assert::same('tenant', qa_functional_json($login)['user']['role'] ?? null);
    });

    $reporter->test('Tenant creation rejects duplicates, weak passwords, bad dates and foreign units', function () use ($port): void {
        $duplicate = qa_functional_request($port, 'POST', '/api/tenants.php', 'landlord.a', [
            'json' => [
                'name' => 'Duplicate', 'email' => 'tenant.a@qa.local', 'password' => QA_PASSWORD, 'unit_id' => 2,
                'lease_start' => date('Y-m-01'), 'lease_end' => date('Y-m-t'),
            ],
        ]);
        Assert::status(400, $duplicate);
        Assert::contains('already registered', $duplicate['body']);

        $weak = qa_functional_request($port, 'POST', '/api/tenants.php', 'landlord.a', [
            'json' => [
                'name' => 'Weak', 'email' => 'weak.tenant@qa.local', 'password' => 'weak', 'unit_id' => 2,
                'lease_start' => date('Y-m-01'), 'lease_end' => date('Y-m-t'),
            ],
        ]);
        Assert::status(400, $weak);

        $badDates = qa_functional_request($port, 'POST', '/api/tenants.php', 'landlord.a', [
            'json' => [
                'name' => 'Bad dates', 'email' => 'bad.dates@qa.local', 'password' => QA_PASSWORD, 'unit_id' => 2,
                'lease_start' => '2026-12-31', 'lease_end' => '2026-01-01',
            ],
        ]);
        Assert::status(400, $badDates);

        $foreign = qa_functional_request($port, 'POST', '/api/tenants.php', 'landlord.a', [
            'json' => [
                'name' => 'Foreign', 'email' => 'foreign.tenant@qa.local', 'password' => QA_PASSWORD, 'unit_id' => 3,
                'lease_start' => date('Y-m-01'), 'lease_end' => date('Y-m-t'),
            ],
        ]);
        Assert::status(404, $foreign);

        $tenant = qa_functional_request($port, 'GET', '/api/tenants.php', 'tenant.a');
        Assert::status(403, $tenant);
    });

    $reporter->test('Rent records are scoped and payment is atomic and single-use', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/rent.php', 'landlord.a');
        Assert::status(200, $response);
        $rows = qa_functional_json($response);
        $tenantIds = array_map('intval', array_column($rows, 'tenant_id'));
        Assert::ok($tenantIds !== [], 'landlord A sees no rent records');
        Assert::ok(!in_array(6, $tenantIds, true), 'landlord A can see landlord B rent');

        $pay = qa_functional_request($port, 'POST', '/api/rent.php', 'landlord.a', [
            'json' => ['id' => 1, 'method' => 'EFT'],
        ]);
        Assert::status(200, $pay);
        $receipt = (string) (qa_functional_json($pay)['receipt_number'] ?? '');
        Assert::matches('/^RCP-\d{4}-[A-F0-9]{5}$/', $receipt);

        $row = qa_query('SELECT * FROM rent_records WHERE id = 1');
        Assert::same('Paid', $row[0]['status']);
        Assert::same($receipt, $row[0]['receipt_number']);
        Assert::same(1, (int) qa_value("SELECT COUNT(*) FROM audit_logs WHERE action = 'rent.payment_recorded' AND entity_id = 1"));

        $again = qa_functional_request($port, 'POST', '/api/rent.php', 'landlord.a', ['json' => ['id' => 1]]);
        Assert::status(409, $again);

        $foreign = qa_functional_request($port, 'POST', '/api/rent.php', 'landlord.a', ['json' => ['id' => 2]]);
        Assert::status(404, $foreign);

        $missing = qa_functional_request($port, 'POST', '/api/rent.php', 'landlord.a', ['json' => []]);
        Assert::status(400, $missing);

        $invalid = qa_functional_request($port, 'POST', '/api/rent.php', 'landlord.a', ['json' => ['id' => 'nope']]);
        Assert::status(400, $invalid);
    });

    $reporter->test('Tenants can only pay their own rent records', function () use ($port): void {
        qa_exec(
            "INSERT INTO rent_records (id, tenant_id, unit_id, month_for, amount, status) VALUES
             (100, 5, 1, ?, 5000.00, 'Pending'), (101, 6, 3, ?, 7000.00, 'Pending')",
            [date('Y-m-01'), date('Y-m-01')]
        );

        $own = qa_functional_request($port, 'POST', '/api/rent.php', 'tenant.a', ['json' => ['id' => 100, 'method' => 'Cash']]);
        Assert::status(200, $own);
        Assert::same('Paid', qa_value('SELECT status FROM rent_records WHERE id = 100'));

        $other = qa_functional_request($port, 'POST', '/api/rent.php', 'tenant.a', ['json' => ['id' => 101]]);
        Assert::status(404, $other);

        $maintenance = qa_functional_request($port, 'POST', '/api/rent.php', 'maintenance', ['json' => ['id' => 101]]);
        Assert::status(403, $maintenance);
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — maintenance');

    $reporter->test('Landlords and tenants get a scoped maintenance payload', function () use ($port): void {
        $landlord = qa_functional_request($port, 'GET', '/api/maintenance.php', 'landlord.a');
        Assert::status(200, $landlord);
        $body = qa_functional_json($landlord);
        Assert::ok(isset($body['tickets'], $body['contractors']), 'landlord payload is missing tickets/contractors');
        $ticketIds = qa_functional_ids($body['tickets']);
        Assert::ok(in_array(1, $ticketIds, true), 'seeded ticket is not visible to its landlord');

        $tenant = qa_functional_request($port, 'GET', '/api/maintenance.php', 'tenant.a');
        Assert::status(200, $tenant);
        $tenantBody = qa_functional_json($tenant);
        Assert::ok(isset($tenantBody['tickets']), 'tenant payload is missing tickets');
        foreach ($tenantBody['tickets'] as $ticket) {
            Assert::same(5, (int) $ticket['tenant_id'], 'tenant can see another tenant ticket');
        }
    });

    $reporter->test('Contractor creation is landlord-only', function () use ($port): void {
        $created = qa_functional_request($port, 'POST', '/api/maintenance.php', 'landlord.a', [
            'json' => ['action' => 'add_contractor', 'name' => 'QA Electrician', 'trade' => 'Electrical', 'phone' => '0766666666'],
        ]);
        Assert::status(200, $created);
        Assert::same(1, (int) qa_value("SELECT COUNT(*) FROM contractors WHERE name = 'QA Electrician' AND owner_id = 2"));

        $denied = qa_functional_request($port, 'POST', '/api/maintenance.php', 'tenant.a', [
            'json' => ['action' => 'add_contractor', 'name' => 'Rogue', 'trade' => 'X', 'phone' => '0'],
        ]);
        Assert::status(403, $denied);
    });

    $reporter->test('Tenants can open sanitized tickets and landlords can assign/resolve them', function () use ($port): void {
        $created = qa_functional_request($port, 'POST', '/api/maintenance.php', 'tenant.a', [
            'json' => [
                'description' => '<script>alert(1)</script>Kitchen sink is blocked',
                'category' => 'Plumbing',
                'priority' => 'High',
                'photo' => 'data:image/png;base64,iVBORw0KGgo=',
            ],
        ]);
        Assert::status(200, $created);

        $ticket = qa_query("SELECT * FROM maintenance WHERE description LIKE '%Kitchen sink%' ORDER BY id DESC LIMIT 1");
        Assert::same(1, count($ticket));
        Assert::same(5, (int) $ticket[0]['tenant_id']);
        Assert::same(1, (int) $ticket[0]['unit_id']);
        Assert::notContains('<', $ticket[0]['description'], 'markup was stored in the ticket description');
        $ticketId = (int) $ticket[0]['id'];

        $empty = qa_functional_request($port, 'POST', '/api/maintenance.php', 'tenant.a', ['json' => ['description' => '<script></script>']]);
        Assert::status(400, $empty);

        $assign = qa_functional_request($port, 'POST', '/api/maintenance.php', 'landlord.a', [
            'json' => ['ticket_id' => $ticketId, 'contractor_id' => 1, 'severity' => 'Urgent'],
        ]);
        Assert::status(200, $assign);
        $row = qa_query('SELECT * FROM maintenance WHERE id = ?', [$ticketId]);
        Assert::same('In Progress', $row[0]['status']);
        Assert::same(1, (int) $row[0]['contractor_id']);

        $resolve = qa_functional_request($port, 'POST', '/api/maintenance.php', 'landlord.a', [
            'json' => ['ticket_id' => 1, 'status' => 'Resolved'],
        ]);
        Assert::status(200, $resolve);
        Assert::same('Resolved', qa_value('SELECT status FROM maintenance WHERE id = 1'));

        $foreign = qa_functional_request($port, 'POST', '/api/maintenance.php', 'landlord.b', [
            'json' => ['ticket_id' => $ticketId, 'status' => 'Resolved'],
        ]);
        Assert::status(404, $foreign);

        $agent = qa_functional_request($port, 'POST', '/api/maintenance.php', 'agent.a', [
            'json' => ['ticket_id' => 1, 'status' => 'Resolved'],
        ]);
        Assert::status(200, $agent, 'agents must be able to manage tickets on assigned properties');
    });

    $reporter->test('Self-registered tenants without a unit get a clear 400', function () use ($port): void {
        qa_exec(
            "INSERT INTO tenants (user_id, name, email) SELECT 9, 'QA Self Tenant', 'tenant.self@qa.local' FROM DUAL
             WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE user_id = 9)"
        );

        $response = qa_functional_request($port, 'POST', '/api/maintenance.php', 'tenant.self', [
            'json' => ['description' => 'No unit yet'],
        ]);
        Assert::status(400, $response);
        Assert::contains('No unit has been assigned', $response['body']);
    });

    $reporter->test('Unknown roles cannot fall through to an empty 200 response', function () use ($port): void {
        $response = qa_functional_request($port, 'POST', '/api/maintenance.php', 'maintenance', [
            'json' => ['action' => 'not-a-real-action'],
        ]);
        Assert::same(
            403,
            $response['status'],
            'maintenance POST fell through to an empty ' . $response['status'] . ' response instead of rejecting the role'
        );
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — messaging');

    $reporter->test('Landlord inbox and thread are scoped to owned tenants', function () use ($port): void {
        $inbox = qa_functional_request($port, 'GET', '/api/messages.php', 'landlord.a');
        Assert::status(200, $inbox);
        $body = qa_functional_json($inbox);
        Assert::ok(isset($body['inbox']), 'inbox key missing');
        $emails = array_column($body['inbox'], 'id');
        Assert::ok(in_array(5, array_map('intval', $emails), true), 'tenant A missing from inbox');

        $thread = qa_functional_request($port, 'GET', '/api/messages.php?tenant_id=5', 'landlord.a');
        Assert::status(200, $thread);
        $threadBody = qa_functional_json($thread);
        Assert::same(2, (int) ($threadBody['my_id'] ?? 0));
        Assert::same(5, (int) ($threadBody['other_id'] ?? 0));
        Assert::same(5, (int) ($threadBody['tenant_id'] ?? 0));

        $foreign = qa_functional_request($port, 'GET', '/api/messages.php?tenant_id=6', 'landlord.a');
        Assert::status(200, $foreign);
        $foreignBody = qa_functional_json($foreign);
        Assert::same(0, (int) ($foreignBody['tenant_id'] ?? -1), 'landlord A can open landlord B thread');
    });

    $reporter->test('Landlords and tenants can exchange messages only inside their thread', function () use ($port): void {
        $send = qa_functional_request($port, 'POST', '/api/messages.php', 'landlord.a', [
            'json' => ['tenant_id' => 5, 'receiver_id' => 5, 'message' => '<b>Hello</b> tenant'],
        ]);
        Assert::status(200, $send);
        Assert::same(1, (int) qa_value("SELECT COUNT(*) FROM messages WHERE tenant_id = 5 AND sender_id = 2 AND message = 'Hello tenant'"));

        $reply = qa_functional_request($port, 'POST', '/api/messages.php', 'tenant.a', [
            'json' => ['tenant_id' => 5, 'receiver_id' => 2, 'message' => 'Hello landlord'],
        ]);
        Assert::status(200, $reply);

        $thread = qa_functional_request($port, 'GET', '/api/messages.php', 'tenant.a');
        Assert::status(200, $thread);
        $body = qa_functional_json($thread);
        $bodies = array_column($body['messages'] ?? [], 'message');
        Assert::ok(in_array('Hello tenant', $bodies, true), 'tenant cannot read the landlord message');
        Assert::ok(in_array('Hello landlord', $bodies, true), 'tenant cannot read its own reply');

        $spoofTenant = qa_functional_request($port, 'POST', '/api/messages.php', 'tenant.a', [
            'json' => ['tenant_id' => 6, 'receiver_id' => 2, 'message' => 'Spoof'],
        ]);
        Assert::status(403, $spoofTenant);

        $wrongReceiver = qa_functional_request($port, 'POST', '/api/messages.php', 'tenant.a', [
            'json' => ['tenant_id' => 5, 'receiver_id' => 1, 'message' => 'Wrong receiver'],
        ]);
        Assert::status(403, $wrongReceiver);

        $foreignThread = qa_functional_request($port, 'POST', '/api/messages.php', 'landlord.a', [
            'json' => ['tenant_id' => 6, 'receiver_id' => 6, 'message' => 'Cross tenant'],
        ]);
        Assert::status(403, $foreignThread);

        $empty = qa_functional_request($port, 'POST', '/api/messages.php', 'tenant.a', [
            'json' => ['tenant_id' => 5, 'receiver_id' => 2, 'message' => '<script></script>'],
        ]);
        Assert::status(400, $empty);

        $maintenance = qa_functional_request($port, 'POST', '/api/messages.php', 'maintenance', [
            'json' => ['tenant_id' => 5, 'receiver_id' => 2, 'message' => 'Nope'],
        ]);
        Assert::status(403, $maintenance);
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — expenses and dashboard');

    $reporter->test('Expenses are scoped, validated and audited', function () use ($port): void {
        $list = qa_functional_request($port, 'GET', '/api/expenses.php', 'landlord.a');
        Assert::status(200, $list);
        $body = qa_functional_json($list);
        Assert::ok(isset($body['expenses'], $body['total_rent']), 'expense payload is incomplete');

        $created = qa_functional_request($port, 'POST', '/api/expenses.php', 'landlord.a', [
            'json' => ['property_id' => 1, 'category' => 'Plumbing', 'amount' => 999.5, 'expense_date' => date('Y-m-d'), 'description' => 'QA repair'],
        ]);
        Assert::status(200, $created);
        $row = qa_query("SELECT * FROM expenses WHERE description = 'QA repair' ORDER BY id DESC LIMIT 1");
        Assert::same(1, count($row));
        Assert::same(2, (int) $row[0]['owner_id']);
        Assert::same(1, (int) $row[0]['property_id']);

        $foreign = qa_functional_request($port, 'POST', '/api/expenses.php', 'landlord.a', [
            'json' => ['property_id' => 2, 'category' => 'X', 'amount' => 1, 'expense_date' => date('Y-m-d')],
        ]);
        Assert::status(404, $foreign);

        $badDate = qa_functional_request($port, 'POST', '/api/expenses.php', 'landlord.a', [
            'json' => ['property_id' => 1, 'category' => 'X', 'amount' => 1, 'expense_date' => '2026-02-30'],
        ]);
        Assert::status(400, $badDate);

        $tenant = qa_functional_request($port, 'POST', '/api/expenses.php', 'tenant.a', [
            'json' => ['property_id' => 1, 'category' => 'X', 'amount' => 1, 'expense_date' => date('Y-m-d')],
        ]);
        Assert::status(403, $tenant);

        $admin = qa_functional_request($port, 'POST', '/api/expenses.php', 'superadmin', [
            'json' => ['property_id' => 2, 'category' => 'Admin', 'amount' => 10, 'expense_date' => date('Y-m-d')],
        ]);
        Assert::status(200, $admin);
        $adminRow = qa_query('SELECT owner_id FROM expenses WHERE property_id = 2 AND amount = 10 ORDER BY id DESC LIMIT 1');
        Assert::same(1, count($adminRow));
        Assert::same(3, (int) $adminRow[0]['owner_id'], 'admin expense must be attributed to the property owner');
    });

    $reporter->test('Dashboard figures agree with the database', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/dashboard.php', 'landlord.a');
        Assert::status(200, $response);
        $body = qa_functional_json($response);

        $properties = (int) qa_value('SELECT COUNT(*) FROM properties WHERE landlord_id = 2');
        $units = (int) qa_value('SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = 2');
        $occupied = (int) qa_value("SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = 2 AND u.status = 'Occupied'");
        $vacant = (int) qa_value("SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = 2 AND u.status = 'Vacant'");

        Assert::same($properties, (int) $body['total_properties']);
        Assert::same($units, (int) $body['total_units']);
        Assert::same($occupied, (int) $body['occupied']);
        Assert::same($vacant, (int) $body['vacant']);
        Assert::same(6, count($body['chart_data'] ?? []), 'chart must contain six months');
        foreach ($body['chart_data'] as $month) {
            Assert::ok(isset($month['month'], $month['income'], $month['expense']), 'chart row is incomplete');
        }
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — tenant profile');

    $reporter->test('Tenant profile loads and updates with sanitized values', function () use ($port): void {
        $profile = qa_functional_request($port, 'GET', '/api/tenant_profile.php', 'tenant.a');
        Assert::status(200, $profile);
        $body = qa_functional_json($profile);
        Assert::same('tenant.a@qa.local', $body['login_email'] ?? null);

        $update = qa_functional_request($port, 'POST', '/api/tenant_profile.php', 'tenant.a', [
            'json' => [
                'phone' => '0777777777',
                'id_number' => '9001015009087',
                'occupants' => 3,
                'second_occupant_name' => '<script>alert(1)</script>Second Person',
                'vehicle_type' => 'Car',
                'vehicle_details' => 'Blue hatchback',
                'emergency_contact_name' => 'Emergency Contact',
                'emergency_contact_phone' => '0788888888',
                'emergency_relationship' => 'Sibling',
                'emergency_contact_email' => 'emergency@qa.local',
                'alt_email' => 'alt@qa.local',
            ],
        ]);
        Assert::status(200, $update);

        $row = qa_query('SELECT * FROM tenants WHERE user_id = 5');
        Assert::same('0777777777', $row[0]['phone']);
        Assert::same(3, (int) $row[0]['occupants']);
        Assert::same('alt@qa.local', $row[0]['alt_email']);
        Assert::notContains('<', $row[0]['second_occupant_name'], 'markup was stored in the profile');

        foreach ([
            ['occupants' => 0],
            ['alt_email' => 'not-an-email'],
            ['id_document' => 'javascript:alert(1)'],
        ] as $invalid) {
            $response = qa_functional_request($port, 'POST', '/api/tenant_profile.php', 'tenant.a', ['json' => $invalid]);
            Assert::status(400, $response);
        }

        $landlord = qa_functional_request($port, 'GET', '/api/tenant_profile.php', 'landlord.a');
        Assert::status(403, $landlord);
    });

    $reporter->test('Tenant data returns rent and maintenance history', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/tenant_data.php', 'tenant.a');
        Assert::status(200, $response);
        $body = qa_functional_json($response);
        Assert::ok(isset($body['tenant'], $body['rent'], $body['maintenance']), 'tenant data payload is incomplete');
        Assert::same(5, (int) $body['tenant']['id']);
        Assert::ok(count($body['rent']) >= 2, 'rent history is incomplete');
        Assert::ok(count($body['maintenance']) >= 1, 'maintenance history is incomplete');
    });

    $reporter->test('Tenant data provisions a usable profile for unlinked tenants', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/tenant_data.php', 'tenant.self');
        Assert::status(200, $response);
        $body = qa_functional_json($response);
        Assert::same(9, (int) $body['tenant']['user_id']);
        Assert::same(null, $body['tenant']['unit_id']);
        Assert::same([], $body['rent']);
    });

    $reporter->test('Tenant-only endpoints reject non-tenant roles', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/tenant_data.php', 'landlord.a');
        $provisioned = (int) qa_value('SELECT COUNT(*) FROM tenants WHERE user_id = 2');
        Assert::same(
            403,
            $response['status'],
            'GET /tenant_data.php is tenant-only but returned ' . $response['status']
            . " for a landlord (tenant rows provisioned for user 2: {$provisioned})"
        );
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — admin');

    $reporter->test('Admin stats are superadmin-only and accurate', function () use ($port): void {
        $response = qa_functional_request($port, 'GET', '/api/admin/stats.php', 'superadmin');
        Assert::status(200, $response);
        $body = qa_functional_json($response);
        foreach (['total_landlords', 'total_properties', 'total_units', 'total_rent_processed', 'recent_signups'] as $key) {
            Assert::ok(array_key_exists($key, $body), "admin stats missing {$key}");
        }
        Assert::same(
            (int) qa_value("SELECT COUNT(*) FROM users WHERE role = 'landlord'"),
            (int) $body['total_landlords']
        );
        Assert::same(
            (int) qa_value('SELECT COUNT(*) FROM properties'),
            (int) $body['total_properties']
        );
        foreach ($body['recent_signups'] as $signup) {
            Assert::same('landlord', $signup['role'] ?? null);
        }

        $denied = qa_functional_request($port, 'GET', '/api/admin/stats.php', 'landlord.a');
        Assert::status(403, $denied);
    });

    $reporter->test('Superadmin can create landlords but weak or duplicate input is rejected', function () use ($port): void {
        $email = 'created.landlord@qa.local';
        $created = qa_functional_request($port, 'POST', '/api/admin/create_landlord.php', 'superadmin', [
            'json' => ['full_name' => 'Created Landlord', 'email' => $email, 'password' => QA_PASSWORD, 'phone' => '0799999999'],
        ]);
        Assert::status(201, $created);
        Assert::same('landlord', qa_value('SELECT role FROM users WHERE email = ?', [$email]));

        $login = qa_login($port, $email);
        Assert::status(200, $login);
        Assert::same('landlord', qa_functional_json($login)['user']['role'] ?? null);

        $duplicate = qa_functional_request($port, 'POST', '/api/admin/create_landlord.php', 'superadmin', [
            'json' => ['full_name' => 'Created Landlord', 'email' => $email, 'password' => QA_PASSWORD],
        ]);
        Assert::status(400, $duplicate);

        $weak = qa_functional_request($port, 'POST', '/api/admin/create_landlord.php', 'superadmin', [
            'json' => ['full_name' => 'Weak Landlord', 'email' => 'weak.landlord@qa.local', 'password' => 'weak'],
        ]);
        Assert::status(400, $weak);

        $denied = qa_functional_request($port, 'POST', '/api/admin/create_landlord.php', 'landlord.a', [
            'json' => ['full_name' => 'Nope', 'email' => 'nope@qa.local', 'password' => QA_PASSWORD],
        ]);
        Assert::status(403, $denied);
    });

    $reporter->test('Subscription toggling validates the target and status', function () use ($port): void {
        $updated = qa_functional_request($port, 'POST', '/api/admin/toggle_sub.php', 'superadmin', [
            'json' => ['landlord_id' => 14, 'status' => 'SUSPENDED'],
        ]);
        Assert::status(200, $updated);
        Assert::same('suspended', qa_value('SELECT subscription_status FROM users WHERE id = 14'));

        $restored = qa_functional_request($port, 'POST', '/api/admin/toggle_sub.php', 'superadmin', [
            'json' => ['landlord_id' => 14, 'status' => 'active'],
        ]);
        Assert::status(200, $restored);

        $badStatus = qa_functional_request($port, 'POST', '/api/admin/toggle_sub.php', 'superadmin', [
            'json' => ['landlord_id' => 14, 'status' => 'vip'],
        ]);
        Assert::status(400, $badStatus);

        $notLandlord = qa_functional_request($port, 'POST', '/api/admin/toggle_sub.php', 'superadmin', [
            'json' => ['landlord_id' => 5, 'status' => 'expired'],
        ]);
        Assert::status(404, $notLandlord);
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — logout, password lifecycle and cron');

    $reporter->test('Single-device logout deny-lists only that token', function () use ($port): void {
        $first = qa_token($port, 'logout.user@qa.local');
        $second = qa_token($port, 'logout.user@qa.local');

        $before = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $first]]);
        Assert::status(200, $before);

        $logout = qa_http('POST', $port, '/api/auth/logout.php', ['headers' => ['Authorization' => 'Bearer ' . $first]]);
        Assert::status(200, $logout);

        $revoked = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $first]]);
        Assert::status(401, $revoked);
        $other = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $second]]);
        Assert::status(200, $other, 'logout must not revoke other devices');

        $denied = qa_http('POST', $port, '/api/auth/logout.php');
        Assert::status(401, $denied);
    });

    $reporter->test('Logout-all invalidates every session for the account', function () use ($port): void {
        $token = qa_token($port, 'logout.user@qa.local');
        $logout = qa_http('POST', $port, '/api/auth/logout.php', [
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'json' => ['all' => true],
        ]);
        Assert::status(200, $logout);
        Assert::contains('all devices', $logout['body']);

        $revoked = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $token]]);
        Assert::status(401, $revoked);

        $fresh = qa_token($port, 'logout.user@qa.local');
        $works = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $fresh]]);
        Assert::status(200, $works);
    });

    $reporter->test('Password change verifies the old password and invalidates old sessions', function () use ($port): void {
        $email = 'password.user@qa.local';
        $old = qa_token($port, $email);

        $missing = qa_http('POST', $port, '/api/auth/change_password.php', [
            'headers' => ['Authorization' => 'Bearer ' . $old],
            'json' => ['currentPassword' => QA_PASSWORD],
        ]);
        Assert::status(400, $missing);

        $wrong = qa_http('POST', $port, '/api/auth/change_password.php', [
            'headers' => ['Authorization' => 'Bearer ' . $old],
            'json' => ['currentPassword' => 'Nope!1234', 'newPassword' => 'NewQaPass!2026'],
        ]);
        Assert::status(401, $wrong);

        $weak = qa_http('POST', $port, '/api/auth/change_password.php', [
            'headers' => ['Authorization' => 'Bearer ' . $old],
            'json' => ['currentPassword' => QA_PASSWORD, 'newPassword' => 'weak'],
        ]);
        Assert::status(400, $weak);

        $changed = qa_http('POST', $port, '/api/auth/change_password.php', [
            'headers' => ['Authorization' => 'Bearer ' . $old],
            'json' => ['currentPassword' => QA_PASSWORD, 'newPassword' => 'NewQaPass!2026'],
        ]);
        Assert::status(200, $changed);
        $newToken = (string) (qa_functional_json($changed)['token'] ?? '');
        Assert::ok($newToken !== '', 'no replacement token returned');

        $oldNowInvalid = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $old]]);
        Assert::status(401, $oldNowInvalid);
        $newWorks = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $newToken]]);
        Assert::status(200, $newWorks);

        $loginNew = qa_login($port, $email, 'NewQaPass!2026');
        Assert::status(200, $loginNew);
        $loginOld = qa_login($port, $email, QA_PASSWORD);
        Assert::status(401, $loginOld);
    });

    $reporter->test('Forgot-password never reveals whether an account exists', function () use ($port): void {
        qa_reset_rate_limits();
        $existing = qa_http('POST', $port, '/api/auth/forgot_password.php', ['json' => ['email' => 'reset.user@qa.local']]);
        Assert::status(200, $existing);

        $unknown = qa_http('POST', $port, '/api/auth/forgot_password.php', ['json' => ['email' => 'ghost@qa.local']]);
        Assert::status(200, $unknown);
        Assert::same($existing['body'], $unknown['body']);

        $invalid = qa_http('POST', $port, '/api/auth/forgot_password.php', ['json' => ['email' => 'not-an-email']]);
        Assert::status(200, $invalid);
        Assert::same($existing['body'], $invalid['body']);

        Assert::same(1, (int) qa_value('SELECT COUNT(*) FROM password_resets WHERE email = ?', ['reset.user@qa.local']));
        $stored = (string) qa_value('SELECT token FROM password_resets WHERE email = ? LIMIT 1', ['reset.user@qa.local']);
        Assert::matches('/^[a-f0-9]{64}$/', $stored, 'reset token must be stored as a SHA-256 hash');
    });

    $reporter->test('Password reset is single-use, policy-checked and invalidates sessions', function () use ($port): void {
        $email = 'reset.user@qa.local';
        $oldToken = qa_token($port, $email);

        $token = bin2hex(random_bytes(32));
        qa_exec('DELETE FROM password_resets WHERE email = ?', [$email]);
        qa_exec('INSERT INTO password_resets (email, token, created_at) VALUES (?, ?, NOW())', [$email, hash('sha256', $token)]);

        $short = qa_http('POST', $port, '/api/auth/reset_password.php', ['json' => ['token' => 'short', 'password' => 'ResetQa!2026']]);
        Assert::status(400, $short);

        $bogus = qa_http('POST', $port, '/api/auth/reset_password.php', [
            'json' => ['token' => str_repeat('a', 64), 'password' => 'ResetQa!2026'],
        ]);
        Assert::status(400, $bogus);

        $weak = qa_http('POST', $port, '/api/auth/reset_password.php', ['json' => ['token' => $token, 'password' => 'weak']]);
        Assert::status(400, $weak);

        $reset = qa_http('POST', $port, '/api/auth/reset_password.php', ['json' => ['token' => $token, 'password' => 'ResetQa!2026']]);
        Assert::status(200, $reset);

        $oldSession = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $oldToken]]);
        Assert::status(401, $oldSession, 'reset must invalidate existing sessions');

        $login = qa_login($port, $email, 'ResetQa!2026');
        Assert::status(200, $login);

        $reuse = qa_http('POST', $port, '/api/auth/reset_password.php', ['json' => ['token' => $token, 'password' => 'Another!2026']]);
        Assert::status(400, $reuse);
        Assert::same(0, (int) qa_value('SELECT COUNT(*) FROM password_resets WHERE email = ?', [$email]));
    });

    $reporter->test('Cron endpoint requires a header secret and cannot be triggered with the query string', function () use ($port): void {
        $anonymous = qa_http('GET', $port, '/api/cron/generate_invoices.php');
        Assert::status(403, $anonymous);
        Assert::contains('Unauthorized', $anonymous['body']);

        $wrong = qa_http('GET', $port, '/api/cron/generate_invoices.php', [
            'headers' => ['X-Cron-Secret' => 'wrong-secret'],
        ]);
        Assert::status(403, $wrong);

        $query = qa_http('GET', $port, '/api/cron/generate_invoices.php?key=' . QA_CRON_SECRET);
        Assert::status(403, $query, 'the legacy query secret must be disabled by default');

        $accepted = qa_http('GET', $port, '/api/cron/generate_invoices.php', [
            'headers' => ['X-Cron-Secret' => QA_CRON_SECRET],
            'timeout' => 60,
        ]);
        Assert::status(200, $accepted);
        $body = qa_functional_json($accepted);
        Assert::same('Invoices sent', $body['message'] ?? null);
        Assert::ok(array_key_exists('count', $body) && array_key_exists('failed', $body), 'cron result is incomplete');
        Assert::same(1, (int) qa_value("SELECT COUNT(*) FROM audit_logs WHERE action = 'system.invoices.sent'"));
    });

    // -----------------------------------------------------------------------
    $reporter->section('Functional — multi-factor authentication');

    $reporter->test('MFA setup requires the password and only activates after a valid code', function () use ($port): void {
        $email = 'mfa.landlord@qa.local';
        $login = qa_login($port, $email);
        Assert::status(200, $login);
        $loginBody = qa_functional_json($login);
        $token = (string) ($loginBody['token'] ?? '');
        Assert::ok($token !== '', 'MFA user could not log in before enrolment');

        $status = qa_http('GET', $port, '/api/auth/mfa_status.php', ['headers' => ['Authorization' => 'Bearer ' . $token]]);
        Assert::status(200, $status);
        Assert::false((bool) (qa_functional_json($status)['enabled'] ?? true));

        $wrong = qa_http('POST', $port, '/api/auth/mfa_setup.php', [
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'json' => ['password' => 'WrongPassword!1'],
        ]);
        Assert::status(401, $wrong);

        $setup = qa_http('POST', $port, '/api/auth/mfa_setup.php', [
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'json' => ['password' => QA_PASSWORD],
        ]);
        Assert::status(200, $setup);
        $setupBody = qa_functional_json($setup);
        $secret = (string) ($setupBody['secret'] ?? '');
        Assert::matches('/^[A-Z2-7]{32,}$/', $secret);
        Assert::contains('otpauth://totp/', (string) ($setupBody['otpauth_uri'] ?? ''));
        Assert::same($secret, qa_value('SELECT mfa_secret FROM users WHERE id = 10'));
        Assert::same(0, (int) qa_value('SELECT mfa_enabled FROM users WHERE id = 10'));

        $invalidCode = qa_http('POST', $port, '/api/auth/mfa_enable.php', [
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'json' => ['code' => '12345'],
        ]);
        Assert::status(400, $invalidCode);

        $step = (int) floor(time() / MFA_PERIOD);
        $code = mfa_totp_at($secret, $step);
        $enable = qa_http('POST', $port, '/api/auth/mfa_enable.php', [
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'json' => ['code' => $code],
        ]);
        Assert::status(200, $enable);
        $enableBody = qa_functional_json($enable);
        Assert::true((bool) ($enableBody['enabled'] ?? false));
        Assert::same(10, count($enableBody['recovery_codes'] ?? []));
        Assert::ok(!empty($enableBody['token']), 'MFA enable did not return a replacement token');
        Assert::same(1, (int) qa_value('SELECT mfa_enabled FROM users WHERE id = 10'));

        $GLOBALS['qa_functional_mfa'] = [
            'secret' => $secret,
            'code' => $code,
            'recovery' => $enableBody['recovery_codes'],
            'token' => $enableBody['token'],
        ];
    });

    $reporter->test('MFA login requires the second factor and refuses replay', function () use ($port): void {
        Assert::ok(isset($GLOBALS['qa_functional_mfa']['secret']), 'MFA setup did not complete');
        $secret = (string) $GLOBALS['qa_functional_mfa']['secret'];
        $recovery = $GLOBALS['qa_functional_mfa']['recovery'];

        // Clear the step consumed during enrolment so this test starts clean.
        qa_exec('UPDATE users SET mfa_last_step = NULL WHERE id = 10');

        $challenge = qa_login($port, 'mfa.landlord@qa.local');
        Assert::status(200, $challenge);
        $challengeBody = qa_functional_json($challenge);
        Assert::true((bool) ($challengeBody['mfa_required'] ?? false));
        Assert::ok(empty($challengeBody['token']), 'password-only login returned a full token');
        $challengeToken = (string) ($challengeBody['mfa_token'] ?? '');
        Assert::ok($challengeToken !== '', 'no MFA challenge token returned');

        $wrong = qa_http('POST', $port, '/api/auth/mfa_login.php', [
            'json' => ['mfa_token' => $challengeToken, 'code' => 'AAAAA-AAAAA'],
        ]);
        Assert::status(401, $wrong);

        $step = (int) floor(time() / MFA_PERIOD);
        $code = mfa_totp_at($secret, $step);
        $GLOBALS['qa_functional_mfa']['code'] = $code;

        $freshChallenge = qa_login($port, 'mfa.landlord@qa.local');
        $freshBody = qa_functional_json($freshChallenge);
        $freshToken = (string) ($freshBody['mfa_token'] ?? '');
        Assert::ok($freshToken !== '', 'no challenge token for the second attempt');

        $login = qa_http('POST', $port, '/api/auth/mfa_login.php', [
            'json' => ['mfa_token' => $freshToken, 'code' => $code],
        ]);
        Assert::status(200, $login);
        $accessToken = (string) (qa_functional_json($login)['token'] ?? '');
        Assert::ok($accessToken !== '', 'MFA login did not return an access token');

        $protected = qa_http('GET', $port, '/api/properties.php', ['headers' => ['Authorization' => 'Bearer ' . $accessToken]]);
        Assert::status(200, $protected);

        $reuseChallenge = qa_http('POST', $port, '/api/auth/mfa_login.php', [
            'json' => ['mfa_token' => $freshToken, 'code' => $code],
        ]);
        Assert::status(401, $reuseChallenge, 'a challenge token must be single-use');

        $nextChallenge = qa_functional_json(qa_login($port, 'mfa.landlord@qa.local'));
        $replay = qa_http('POST', $port, '/api/auth/mfa_login.php', [
            'json' => ['mfa_token' => (string) ($nextChallenge['mfa_token'] ?? ''), 'code' => $code],
        ]);
        Assert::status(401, $replay);
        Assert::contains('already been used', $replay['body']);

        Assert::ok(count($recovery) === 10, 'recovery codes were not returned');
    });

    $reporter->test('Recovery codes complete login exactly once', function () use ($port): void {
        Assert::ok(isset($GLOBALS['qa_functional_mfa']['recovery']), 'MFA setup did not complete');
        $code = (string) $GLOBALS['qa_functional_mfa']['recovery'][0];

        $challenge = qa_functional_json(qa_login($port, 'mfa.landlord@qa.local'));
        $login = qa_http('POST', $port, '/api/auth/mfa_login.php', [
            'json' => ['mfa_token' => (string) ($challenge['mfa_token'] ?? ''), 'code' => $code],
        ]);
        Assert::status(200, $login);
        Assert::ok(!empty(qa_functional_json($login)['token']), 'recovery login returned no token');

        $challenge2 = qa_functional_json(qa_login($port, 'mfa.landlord@qa.local'));
        $replay = qa_http('POST', $port, '/api/auth/mfa_login.php', [
            'json' => ['mfa_token' => (string) ($challenge2['mfa_token'] ?? ''), 'code' => $code],
        ]);
        Assert::status(401, $replay, 'recovery codes must be single-use');

        $remaining = json_decode((string) qa_value('SELECT mfa_recovery_codes FROM users WHERE id = 10'), true);
        Assert::same(9, is_array($remaining) ? count($remaining) : -1);
    });

    $reporter->test('MFA can be disabled with the password and a current recovery code', function () use ($port): void {
        Assert::ok(isset($GLOBALS['qa_functional_mfa']['recovery'][1]), 'no spare recovery code');
        $code = (string) $GLOBALS['qa_functional_mfa']['recovery'][1];
        // A password-only token is impossible while MFA is on, so sign in
        // through the challenge before testing the disable endpoint.
        $challenge = qa_functional_json(qa_login($port, 'mfa.landlord@qa.local'));
        $login = qa_http('POST', $port, '/api/auth/mfa_login.php', [
            'json' => ['mfa_token' => (string) ($challenge['mfa_token'] ?? ''), 'code' => $code],
        ]);
        Assert::status(200, $login);
        $token = (string) (qa_functional_json($login)['token'] ?? '');
        Assert::ok($token !== '', 'could not obtain an MFA session');

        $wrong = qa_http('POST', $port, '/api/auth/mfa_disable.php', [
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'json' => ['password' => 'WrongPassword!1', 'code' => $code],
        ]);
        Assert::status(401, $wrong);

        $disableCode = (string) $GLOBALS['qa_functional_mfa']['recovery'][2];
        $disable = qa_http('POST', $port, '/api/auth/mfa_disable.php', [
            'headers' => ['Authorization' => 'Bearer ' . $token],
            'json' => ['password' => QA_PASSWORD, 'code' => $disableCode],
        ]);
        Assert::status(200, $disable);
        $disabled = qa_functional_json($disable);
        Assert::false((bool) ($disabled['enabled'] ?? true));
        Assert::ok(!empty($disabled['token']), 'disable did not return a replacement token');

        Assert::same(0, (int) qa_value('SELECT mfa_enabled FROM users WHERE id = 10'));
        Assert::same(null, qa_value('SELECT mfa_secret FROM users WHERE id = 10'));

        $passwordOnly = qa_login($port, 'mfa.landlord@qa.local');
        Assert::status(200, $passwordOnly);
        $body = qa_functional_json($passwordOnly);
        Assert::ok(!empty($body['token']), 'password-only login failed after disabling MFA');
        Assert::ok(empty($body['mfa_required']), 'MFA is still required after disabling');

        $status = qa_http('GET', $port, '/api/auth/mfa_status.php', [
            'headers' => ['Authorization' => 'Bearer ' . $disabled['token']],
        ]);
        Assert::status(200, $status);
        Assert::false((bool) (qa_functional_json($status)['enabled'] ?? true));
    });

    $reporter->test('Authentication events are written to the append-only audit log', function (): void {
        foreach ([
            'auth.login.success',
            'auth.login.failure',
            'auth.mfa.challenge',
            'auth.mfa.enabled',
            'auth.logout',
            'auth.password.changed',
            'auth.password.reset',
        ] as $action) {
            Assert::ok(
                (int) qa_value('SELECT COUNT(*) FROM audit_logs WHERE action = ?', [$action]) > 0,
                "missing audit event: {$action}"
            );
        }
    });
}
