<?php
// config/mfa.php
// Time-based one-time password (RFC 6238 / TOTP) multi-factor authentication.
//
// Design choices:
//  - No third-party dependency: TOTP is ~30 lines of base32 + HMAC-SHA1. Every
//    extra auth dependency is another supply-chain risk.
//  - The shared secret is generated server-side from random_bytes(), never
//    derived from the password, and is stored in the users table.
//  - A successful TOTP step is recorded so the same 6-digit code cannot be
//    replayed (TOTP is valid for 30 seconds and is otherwise reusable).
//  - Recovery codes are stored as bcrypt hashes and are single-use.
//  - MFA is optional per account and can be enabled/disabled by the user.

require_once __DIR__ . '/jwt.php';
require_once __DIR__ . '/security.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

const MFA_ISSUER = 'Jump PropTech';
const MFA_PERIOD = 30;
const MFA_DIGITS = 6;
const MFA_CHALLENGE_TTL = 300; // 5 minutes to enter the code
const MFA_RECOVERY_CODES = 10;

/**
 * Tri-state schema check:
 *   true  = all MFA columns exist
 *   false = columns are definitely absent (no account can have MFA configured)
 *   null  = unknown (the database could not be queried)
 *
 * Callers must treat null as an error, never as "MFA is off". A transient DB
 * failure must not downgrade an MFA-protected account to password-only login.
 */
function mfa_schema_status(PDO $conn): ?bool
{
    static $status = null;
    if ($status !== null) {
        return $status;
    }

    $required = ['mfa_secret', 'mfa_enabled', 'mfa_recovery_codes', 'mfa_last_step'];
    $fetch = static function (PDO $conn) use ($required): ?array {
        try {
            $stmt = $conn->prepare(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
                   AND COLUMN_NAME IN ('mfa_secret', 'mfa_enabled', 'mfa_recovery_codes', 'mfa_last_step')"
            );
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_COLUMN) ?: [];
        } catch (Throwable $e) {
            error_log('MFA schema read failed: ' . $e->getMessage());
            return null;
        }
    };

    $present = $fetch($conn);
    if ($present === null) {
        return null;
    }

    if (count(array_intersect($required, $present)) === count($required)) {
        $status = true;
        return true;
    }

    // Attempt to add the missing columns. The migration is the supported path;
    // this keeps a fresh deployment working when the DB user may ALTER.
    $columns = [
        'mfa_secret' => "ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64) NULL",
        'mfa_enabled' => "ALTER TABLE users ADD COLUMN mfa_enabled TINYINT(1) NOT NULL DEFAULT 0",
        'mfa_recovery_codes' => "ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT NULL",
        'mfa_last_step' => "ALTER TABLE users ADD COLUMN mfa_last_step BIGINT NULL",
    ];

    try {
        foreach ($columns as $name => $sql) {
            if (!in_array($name, $present, true)) {
                $conn->exec($sql);
            }
        }
    } catch (Throwable $e) {
        // Duplicate column (another request won the race) is harmless; the
        // re-read below decides the real state.
        error_log('MFA schema create failed: ' . $e->getMessage());
    }

    $present = $fetch($conn);
    if ($present === null) {
        return null;
    }

    $status = count(array_intersect($required, $present)) === count($required);
    return $status;
}

function mfa_ensure_schema(PDO $conn): bool
{
    return mfa_schema_status($conn) === true;
}

/**
 * Current MFA state for a user.
 *
 * Returns null when the state cannot be determined (DB error, unknown user).
 * Callers MUST fail closed (503/401), never fall through to password-only
 * login. When the columns are definitively absent, returns `enabled=false`
 * because no account can have MFA configured in that schema.
 */
function mfa_user_state(PDO $conn, int $userId): ?array
{
    $empty = [
        'enabled' => false,
        'secret' => null,
        'last_step' => 0,
        'recovery_codes' => [],
    ];

    if ($userId < 1) {
        return null;
    }

    $schema = mfa_schema_status($conn);
    if ($schema === null) {
        return null;
    }
    if ($schema === false) {
        return $empty;
    }

    try {
        $stmt = $conn->prepare(
            "SELECT mfa_enabled, mfa_secret, mfa_last_step, mfa_recovery_codes
             FROM users WHERE id = :id LIMIT 1"
        );
        $stmt->execute([':id' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return null;
        }

        $codes = json_decode((string) ($row['mfa_recovery_codes'] ?? ''), true);

        return [
            'enabled' => (int) ($row['mfa_enabled'] ?? 0) === 1,
            'secret' => $row['mfa_secret'] ?? null,
            'last_step' => (int) ($row['mfa_last_step'] ?? 0),
            'recovery_codes' => is_array($codes) ? $codes : [],
        ];
    } catch (Throwable $e) {
        error_log('MFA state read failed: ' . $e->getMessage());
        return null;
    }
}

// ---------------------------------------------------------------------------
// Base32 / TOTP
// ---------------------------------------------------------------------------

function mfa_base32_encode(string $bytes): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = 0;
    $value = 0;
    $out = '';

    foreach (str_split($bytes) as $byte) {
        $value = ($value << 8) | ord($byte);
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $out .= $alphabet[($value >> $bits) & 0x1F];
        }
    }

    if ($bits > 0) {
        $out .= $alphabet[($value << (5 - $bits)) & 0x1F];
    }

    return $out;
}

function mfa_base32_decode(string $value): ?string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $value = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $value) ?? '');
    if ($value === '') {
        return null;
    }

    $map = array_flip(str_split($alphabet));
    $bits = 0;
    $buffer = 0;
    $out = '';

    foreach (str_split($value) as $char) {
        if (!isset($map[$char])) {
            return null;
        }
        $buffer = ($buffer << 5) | $map[$char];
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $out .= chr(($buffer >> $bits) & 0xFF);
        }
    }

    return $out;
}

function mfa_generate_secret(int $bytes = 20): string
{
    $secret = mfa_base32_encode(random_bytes($bytes));

    // 20 random bytes encode to 32 base32 characters; guarantee at least 32.
    while (strlen($secret) < 32) {
        $secret .= mfa_base32_encode(random_bytes(1));
    }

    return $secret;
}

function mfa_totp_at(string $secret, int $timeSlice): string
{
    $key = mfa_base32_decode($secret);
    if ($key === null || $key === '') {
        return '';
    }

    $hash = hash_hmac('sha1', pack('N*', 0) . pack('N*', $timeSlice), $key, true);
    $offset = ord($hash[19]) & 0x0F;
    $code = ((ord($hash[$offset]) & 0x7F) << 24)
        | ((ord($hash[$offset + 1]) & 0xFF) << 16)
        | ((ord($hash[$offset + 2]) & 0xFF) << 8)
        | (ord($hash[$offset + 3]) & 0xFF);

    return str_pad((string) ($code % (10 ** MFA_DIGITS)), MFA_DIGITS, '0', STR_PAD_LEFT);
}

/**
 * Verify a 6-digit code, allowing +-1 time step for clock drift.
 * When valid, $usedStep receives the matched counter so the caller can record
 * it and refuse replays.
 */
function mfa_verify_code(string $secret, string $code, ?int &$usedStep = null, int $window = 1): bool
{
    $code = preg_replace('/\s+/', '', $code) ?? '';
    if (!preg_match('/^\d{' . MFA_DIGITS . '}$/', $code)) {
        return false;
    }

    $current = (int) floor(time() / MFA_PERIOD);
    for ($i = -$window; $i <= $window; $i++) {
        $step = $current + $i;
        if (hash_equals(mfa_totp_at($secret, $step), $code)) {
            $usedStep = $step;
            return true;
        }
    }

    return false;
}

function mfa_otpauth_uri(string $secret, string $account): string
{
    $label = rawurlencode(MFA_ISSUER . ':' . $account);
    $query = http_build_query([
        'secret' => $secret,
        'issuer' => MFA_ISSUER,
        'algorithm' => 'SHA1',
        'digits' => MFA_DIGITS,
        'period' => MFA_PERIOD,
    ]);

    return 'otpauth://totp/' . $label . '?' . $query;
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

function mfa_normalize_recovery_code(string $code): string
{
    return strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code) ?? '');
}

/** Human-readable single-use codes, e.g. "A1B2C-3D4E5". */
function mfa_generate_recovery_codes(int $count = MFA_RECOVERY_CODES): array
{
    $codes = [];
    for ($i = 0; $i < $count; $i++) {
        $raw = strtoupper(bin2hex(random_bytes(5)));
        $codes[] = substr($raw, 0, 5) . '-' . substr($raw, 5, 5);
    }
    return $codes;
}

function mfa_hash_recovery_codes(array $codes): string
{
    $hashes = [];
    foreach ($codes as $code) {
        // Cost 10 keeps 10 hashes per enrolment fast enough while remaining
        // expensive to brute force (10^10 possible codes anyway).
        $hashes[] = password_hash(
            mfa_normalize_recovery_code($code),
            PASSWORD_BCRYPT,
            ['cost' => 10]
        );
    }
    return json_encode($hashes) ?: '[]';
}

/**
 * Consume a recovery code. The row is locked so two concurrent requests
 * cannot reuse the same code.
 */
function mfa_consume_recovery_code(PDO $conn, int $userId, string $code): bool
{
    $candidate = mfa_normalize_recovery_code($code);
    if ($candidate === '' || !mfa_ensure_schema($conn)) {
        return false;
    }

    try {
        $conn->beginTransaction();

        $stmt = $conn->prepare(
            "SELECT mfa_recovery_codes FROM users WHERE id = :id LIMIT 1 FOR UPDATE"
        );
        $stmt->execute([':id' => $userId]);
        $hashes = json_decode((string) $stmt->fetchColumn(), true);

        if (!is_array($hashes)) {
            $conn->rollBack();
            return false;
        }

        $matchedIndex = null;
        foreach ($hashes as $index => $hash) {
            if (is_string($hash) && password_verify($candidate, $hash)) {
                $matchedIndex = $index;
                break;
            }
        }

        if ($matchedIndex === null) {
            $conn->rollBack();
            return false;
        }

        unset($hashes[$matchedIndex]);
        $update = $conn->prepare(
            "UPDATE users SET mfa_recovery_codes = :codes WHERE id = :id"
        );
        $update->execute([
            ':codes' => json_encode(array_values($hashes)) ?: '[]',
            ':id' => $userId,
        ]);

        $conn->commit();
        return true;
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Recovery code consume failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * Record the TOTP step atomically. Returns false when the step was already
 * used (replay) or the row changed underneath us.
 */
function mfa_consume_totp_step(PDO $conn, int $userId, int $step): bool
{
    try {
        $stmt = $conn->prepare(
            "UPDATE users SET mfa_last_step = :step
             WHERE id = :id AND (mfa_last_step IS NULL OR mfa_last_step < :step)"
        );
        $stmt->execute([':step' => $step, ':id' => $userId]);
        return $stmt->rowCount() > 0;
    } catch (Throwable $e) {
        error_log('TOTP replay check failed: ' . $e->getMessage());
        return false;
    }
}

// ---------------------------------------------------------------------------
// MFA challenge token (password verified, second factor still required)
// ---------------------------------------------------------------------------

function mfa_issue_challenge_token(int $userId, int $tokenVersion): string
{
    $issuedAt = time();

    return JWT::encode([
        'iss' => JWT_ISSUER,
        'iat' => $issuedAt,
        'exp' => $issuedAt + MFA_CHALLENGE_TTL,
        'jti' => bin2hex(random_bytes(16)),
        'scope' => 'mfa',
        'ver' => $tokenVersion,
        'user_id' => $userId,
    ], JWT_SECRET, JWT_ALGO);
}

/**
 * Decode a challenge token and reject anything that has already been spent.
 * The denylist check is what actually makes the token single-use; without it
 * a stolen `mfa_token` could be replayed for its full lifetime.
 */
function mfa_decode_challenge_token(PDO $conn, string $token): ?object
{
    try {
        $decoded = JWT::decode($token, new Key(JWT_SECRET, JWT_ALGO));
    } catch (Throwable $e) {
        return null;
    }

    if (!isset($decoded->user_id, $decoded->ver, $decoded->jti)
        || ($decoded->scope ?? '') !== 'mfa') {
        return null;
    }

    if (security_token_is_revoked($conn, (string) $decoded->jti)) {
        return null;
    }

    return $decoded;
}
