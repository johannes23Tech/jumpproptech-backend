<?php
/**
 * Functional unit tests for the shared helpers: input hygiene, password
 * policy, IP/CIDR handling, rate limiting, token revocation, audit logging,
 * TOTP/MFA and JWT issuance.
 */

declare(strict_types=1);

require_once QA_ROOT . '/vendor/autoload.php';
require_once QA_ROOT . '/config/security.php';
require_once QA_ROOT . '/config/mfa.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function run_unit(Reporter $reporter): void
{
    $conn = qa_pdo();

    $reporter->section('Unit — input hygiene');

    $reporter->test('security_clean_text strips tags, control characters and markup', function (): void {
        Assert::same('alert(1)Hello', security_clean_text('<script>alert(1)</script>Hello'));
        Assert::same('HelloWorld', security_clean_text("Hel\0lo\x07World"));
        Assert::same('', security_clean_text(['not', 'scalar']));
        Assert::same('', security_clean_text(null));
        Assert::same('Hello', security_clean_text('  Hello  '));
        Assert::same('12345', security_clean_text('1234567890', 5));
        Assert::same('ééééé', security_clean_text(str_repeat('é', 10), 5));
    });

    $reporter->test('security_is_email accepts only valid addresses', function (): void {
        Assert::true(security_is_email('user@example.com'));
        Assert::true(security_is_email('first.last+tag@sub.example.co.za'));
        Assert::false(security_is_email('not-an-email'));
        Assert::false(security_is_email('a@b'));
        Assert::false(security_is_email('a b@example.com'));
        Assert::false(security_is_email(['user@example.com']));
    });

    $reporter->test('security_clean_document allows images/https and blocks script URIs', function (): void {
        Assert::same(
            'data:image/png;base64,iVBORw0KGgo=',
            security_clean_document('data:image/png;base64,iVBORw0KGgo=')
        );
        Assert::same(
            'https://res.cloudinary.com/demo/image/upload/id.jpg',
            security_clean_document('https://res.cloudinary.com/demo/image/upload/id.jpg')
        );
        Assert::same(null, security_clean_document('javascript:alert(1)'));
        Assert::same(null, security_clean_document('data:text/html;base64,PHNjcmlwdD4='));
        Assert::same(null, security_clean_document('http://example.com/id.jpg'));
        Assert::same(null, security_clean_document(str_repeat('a', 5000001)));
        Assert::same(null, security_clean_document(['x']));
        Assert::same(null, security_clean_document(''));
    });

    $reporter->test('security_sanitize_filename removes paths and control characters', function (): void {
        Assert::same('etc_passwd', security_sanitize_filename('../../etc/passwd'));
        Assert::same('a__b.pdf', security_sanitize_filename("a\r\nb.pdf"));
        Assert::same('download', security_sanitize_filename('...'));
        Assert::same('invoice_2026', security_sanitize_filename('invoice 2026'));
        Assert::ok(strlen(security_sanitize_filename(str_repeat('a', 200))) <= 80);
    });

    $reporter->section('Unit — password policy');

    $reporter->test('security_validate_password accepts a strong 8-12 character password', function (): void {
        Assert::same(null, security_validate_password('QaTest!2026'));
        Assert::same(null, security_validate_password('Abcdef1!'));
        Assert::same(null, security_validate_password('Abcdefghij1!'));
    });

    $reporter->test('security_validate_password rejects length and class violations', function (): void {
        Assert::contains('at least 8', (string) security_validate_password('Ab1!'));
        Assert::contains('at most 12', (string) security_validate_password('Abcdefghij1!x'));
        Assert::contains('uppercase', (string) security_validate_password('abcdefg1!'));
        Assert::contains('uppercase', (string) security_validate_password('ABCDEFG1!'));
        Assert::contains('number', (string) security_validate_password('Abcdefgh!'));
        Assert::contains('symbol', (string) security_validate_password('Abcdefgh1'));
        Assert::contains('space', (string) security_validate_password(' Abcdefg1! '));
    });

    $reporter->test('security_validate_password rejects common passwords', function (): void {
        Assert::contains('too common', (string) security_validate_password('Password1!'));
        Assert::contains('too common', (string) security_validate_password('P@ssw0rd'));
    });

    $reporter->test('bcrypt hashes use cost 12 and verify correctly', function (): void {
        $hash = security_hash_password('QaTest!2026');
        Assert::matches('/^\$2y\$12\$/', $hash);
        Assert::true(password_verify('QaTest!2026', $hash));
        Assert::false(password_verify('wrong', $hash));
        Assert::false(security_password_needs_rehash($hash));
        Assert::true(security_password_needs_rehash(password_hash('QaTest!2026', PASSWORD_BCRYPT, ['cost' => 10])));
    });

    $reporter->section('Unit — IP handling');

    $reporter->test('security_ip_matches handles IPv4, IPv6 and CIDR boundaries', function (): void {
        Assert::true(security_ip_matches('192.168.1.5', '192.168.0.0/16'));
        Assert::false(security_ip_matches('192.169.0.1', '192.168.0.0/16'));
        Assert::true(security_ip_matches('10.0.0.1', '10.0.0.1'));
        Assert::false(security_ip_matches('10.0.0.2', '10.0.0.1'));
        Assert::true(security_ip_matches('2001:db8::1', '2001:db8::/32'));
        Assert::false(security_ip_matches('2001:db9::1', '2001:db8::/32'));
        Assert::false(security_ip_matches('192.168.1.1', '192.168.0.0/33'));
        Assert::false(security_ip_matches('192.168.1.1', '2001:db8::/32'));
        Assert::false(security_ip_matches('not-an-ip', '10.0.0.0/8'));
    });

    $reporter->test('security_client_ip ignores forged X-Forwarded-For from untrusted peers', function (): void {
        $oldServer = $_SERVER;
        $oldTrusted = getenv('TRUSTED_PROXIES');
        try {
            putenv('TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8');

            $_SERVER['REMOTE_ADDR'] = '203.0.113.9';
            $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7';
            Assert::same('203.0.113.9', security_client_ip(), 'untrusted peer must be used directly');

            $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
            $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7, 10.0.0.5';
            Assert::same('198.51.100.7', security_client_ip(), 'rightmost untrusted hop expected');

            $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
            unset($_SERVER['HTTP_X_FORWARDED_FOR']);
            Assert::same('127.0.0.1', security_client_ip());

            $_SERVER['REMOTE_ADDR'] = 'garbage';
            Assert::same('0.0.0.0', security_client_ip());
        } finally {
            $_SERVER = $oldServer;
            putenv($oldTrusted === false ? 'TRUSTED_PROXIES' : 'TRUSTED_PROXIES=' . $oldTrusted);
        }
    });

    $reporter->section('Unit — rate limiting and revocation (live DB)');

    $reporter->test('rate limiter locks, reports retry-after and clears', function () use ($conn): void {
        qa_reset_rate_limits();
        $bucket = 'qa_unit_' . bin2hex(random_bytes(4));
        $identifier = 'qa-user@example.test|203.0.113.10';

        Assert::same(0, security_rate_limit_retry($conn, $bucket, $identifier));
        Assert::same(0, security_rate_limit_hit($conn, $bucket, $identifier, 3, 900, 30));
        Assert::same(0, security_rate_limit_hit($conn, $bucket, $identifier, 3, 900, 30));
        $lock = security_rate_limit_hit($conn, $bucket, $identifier, 3, 900, 30);
        Assert::same(30, $lock);
        Assert::ok(security_rate_limit_retry($conn, $bucket, $identifier) > 0);

        $stored = qa_value('SELECT COUNT(*) FROM rate_limits WHERE bucket = ? AND identifier = ?', [
            $bucket,
            hash('sha256', $identifier),
        ]);
        Assert::same(1, (int) $stored, 'identifier must be stored hashed');
        Assert::false(
            (bool) qa_value('SELECT COUNT(*) FROM rate_limits WHERE identifier = ?', [$identifier]),
            'raw identifier must never be stored'
        );

        security_rate_limit_clear($conn, $bucket, $identifier);
        Assert::same(0, security_rate_limit_retry($conn, $bucket, $identifier));
    });

    $reporter->test('revoked-token denylist honours expiry and unknown tokens', function () use ($conn): void {
        $jti = bin2hex(random_bytes(16));
        Assert::true(security_revoke_token($conn, $jti, time() + 300));
        Assert::true(security_token_is_revoked($conn, $jti));
        Assert::false(security_token_is_revoked($conn, bin2hex(random_bytes(16))));
        Assert::true(security_token_is_revoked($conn, ''), 'empty jti must fail closed');

        $expiredJti = bin2hex(random_bytes(16));
        qa_exec('INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, DATE_SUB(NOW(), INTERVAL 1 MINUTE))', [$expiredJti]);
        Assert::false(security_token_is_revoked($conn, $expiredJti), 'expired denylist row must not match');

        qa_exec('DELETE FROM revoked_tokens WHERE jti IN (?, ?)', [$jti, $expiredJti]);
    });

    $reporter->test('audit_log writes bounded, structured rows', function () use ($conn): void {
        $action = 'qa.unit.' . bin2hex(random_bytes(4));
        audit_log($conn, 2, $action, [
            'actor_email' => 'landlord.a@qa.local',
            'entity_type' => 'qa',
            'entity_id' => 42,
            'outcome' => 'success',
            'meta' => ['answer' => 42, 'text' => str_repeat('x', 5000)],
        ]);

        $row = qa_query('SELECT * FROM audit_logs WHERE action = ? ORDER BY id DESC LIMIT 1', [$action]);
        Assert::same(1, count($row));
        Assert::same(2, (int) $row[0]['actor_user_id']);
        Assert::same('landlord.a@qa.local', $row[0]['actor_email']);
        Assert::same('qa', $row[0]['entity_type']);
        Assert::same(42, (int) $row[0]['entity_id']);
        Assert::same('success', $row[0]['outcome']);
        Assert::ok(strlen((string) $row[0]['meta']) <= 4000, 'audit meta must be bounded');
    });

    $reporter->section('Unit — MFA / TOTP');

    $reporter->test('base32 encode/decode round-trips', function (): void {
        $raw = random_bytes(20);
        $encoded = mfa_base32_encode($raw);
        Assert::matches('/^[A-Z2-7]{32}$/', $encoded);
        Assert::same(bin2hex($raw), bin2hex((string) mfa_base32_decode($encoded)));
        Assert::same(null, mfa_base32_decode('***'));
        Assert::same('', (string) mfa_base32_decode(''));
    });

    $reporter->test('TOTP matches the RFC 6238 SHA-1 reference vector', function (): void {
        // Secret "12345678901234567890", T=59 (counter 1) => 94287082.
        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        Assert::same('287082', mfa_totp_at($secret, 1));
        Assert::matches('/^\d{6}$/', mfa_totp_at($secret, 2));
        Assert::same('', mfa_totp_at('', 1));
    });

    $reporter->test('mfa_verify_code accepts the current step and rejects bad input', function (): void {
        $secret = mfa_generate_secret();
        $step = (int) floor(time() / MFA_PERIOD);
        $code = mfa_totp_at($secret, $step);
        Assert::matches('/^\d{6}$/', $code);

        $used = null;
        Assert::true(mfa_verify_code($secret, $code, $used));
        Assert::same($step, $used);
        Assert::false(mfa_verify_code($secret, 'abcdef', $used));
        Assert::false(mfa_verify_code($secret, '12345', $used));
        Assert::false(mfa_verify_code(mfa_generate_secret(), $code, $used));
    });

    $reporter->test('MFA secrets and otpauth URIs are well formed', function (): void {
        $secret = mfa_generate_secret();
        Assert::ok(strlen($secret) >= 32, 'secret must be at least 32 base32 characters');
        Assert::matches('/^[A-Z2-7]+$/', $secret);

        $uri = mfa_otpauth_uri($secret, 'tenant.a@qa.local');
        Assert::contains('otpauth://totp/', $uri);
        Assert::contains('secret=' . $secret, $uri);
        Assert::contains('issuer=Jump+PropTech', $uri);
        Assert::contains('digits=6', $uri);
        Assert::contains('period=30', $uri);
    });

    $reporter->test('Recovery codes are unique, well formed and single-use', function () use ($conn): void {
        $codes = mfa_generate_recovery_codes(10);
        Assert::same(10, count($codes));
        Assert::same(10, count(array_unique($codes)));
        foreach ($codes as $code) {
            Assert::matches('/^[A-F0-9]{5}-[A-F0-9]{5}$/', $code);
        }
        Assert::same('ABCDE12345', mfa_normalize_recovery_code('abcde-12345'));

        $hashes = mfa_hash_recovery_codes($codes);
        $decoded = json_decode($hashes, true);
        Assert::same(10, count($decoded));
        Assert::true(password_verify(mfa_normalize_recovery_code($codes[0]), $decoded[0]));

        qa_exec('UPDATE users SET mfa_recovery_codes = ? WHERE id = 14', [$hashes]);
        Assert::true(mfa_consume_recovery_code($conn, 14, $codes[0]));
        Assert::false(mfa_consume_recovery_code($conn, 14, $codes[0]), 'recovery code must be single-use');
        Assert::true(mfa_consume_recovery_code($conn, 14, $codes[1]));
        qa_exec('UPDATE users SET mfa_recovery_codes = NULL WHERE id = 14');
    });

    $reporter->test('TOTP steps are consumed atomically and replay is refused', function () use ($conn): void {
        qa_exec('UPDATE users SET mfa_last_step = NULL WHERE id = 14');
        Assert::true(mfa_consume_totp_step($conn, 14, 200));
        Assert::false(mfa_consume_totp_step($conn, 14, 200), 'same step must be rejected');
        Assert::false(mfa_consume_totp_step($conn, 14, 199), 'older step must be rejected');
        Assert::true(mfa_consume_totp_step($conn, 14, 201));
        qa_exec('UPDATE users SET mfa_last_step = NULL WHERE id = 14');
    });

    $reporter->section('Unit — JWT');

    $reporter->test('Access tokens carry issuer, scope, version, jti and expiry', function (): void {
        $token = jwt_issue_access_token(['id' => 2, 'role' => 'landlord', 'token_version' => 3]);
        $decoded = JWT::decode($token, new Key(JWT_SECRET, JWT_ALGO));

        Assert::same('jumpproptech', $decoded->iss);
        Assert::same(2, $decoded->user_id);
        Assert::same('landlord', $decoded->role);
        Assert::same(3, $decoded->ver);
        Assert::same('access', $decoded->scope);
        Assert::matches('/^[a-f0-9]{32}$/', $decoded->jti);
        Assert::between($decoded->exp - $decoded->iat, 3500, 3700);
    });

    $reporter->test('Tokens signed with a different secret are rejected', function (): void {
        $token = jwt_issue_access_token(['id' => 2, 'role' => 'landlord', 'token_version' => 3]);
        $rejected = false;
        try {
            JWT::decode($token, new Key(str_repeat('z', 64), 'HS256'));
        } catch (Throwable $e) {
            $rejected = true;
        }
        Assert::true($rejected, 'foreign signature was accepted');
    });
}
