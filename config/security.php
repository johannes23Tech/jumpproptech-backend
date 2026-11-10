<?php
// config/security.php
// Shared defensive helpers: JSON responses, input cleaning, password policy
// and DB-backed rate limiting. Requires an open PDO connection for the
// rate-limit helpers (the caller passes its existing $conn).

/**
 * Emit a JSON response and stop. Sets headers that make it harder for a
 * browser to misinterpret or sniff the response.
 */
function security_json_response(int $status, array $payload, array $headers = []): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    foreach ($headers as $name => $value) {
        header($name . ': ' . $value);
    }
    echo json_encode($payload);
    exit();
}

/**
 * Addresses whose X-Forwarded-For header we trust. Loopback and RFC1918/ULA
 * ranges cover the common "app server behind a local reverse proxy" setup.
 * Add public proxy ranges (Render, Cloudflare, ALB) via TRUSTED_PROXIES.
 */
function security_trusted_proxies(): array
{
    $defaults = [
        '127.0.0.1', '::1',
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        'fc00::/7',
    ];

    $configured = getenv('TRUSTED_PROXIES');
    if ($configured === false || trim($configured) === '') {
        return $defaults;
    }

    return array_values(array_filter(array_map('trim', explode(',', $configured))));
}

function security_ip_matches(string $ip, string $entry): bool
{
    if (strpos($entry, '/') === false) {
        return $ip === $entry;
    }

    [$subnet, $bits] = explode('/', $entry, 2);
    $bits = (int) $bits;
    $ipBin = @inet_pton($ip);
    $netBin = @inet_pton($subnet);

    if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
        return false;
    }
    if ($bits < 0 || $bits > strlen($ipBin) * 8) {
        return false;
    }

    $wholeBytes = intdiv($bits, 8);
    if ($wholeBytes > 0 && substr($ipBin, 0, $wholeBytes) !== substr($netBin, 0, $wholeBytes)) {
        return false;
    }

    $remainder = $bits % 8;
    if ($remainder === 0) {
        return true;
    }

    $mask = (0xFF << (8 - $remainder)) & 0xFF;
    return (ord($ipBin[$wholeBytes]) & $mask) === (ord($netBin[$wholeBytes]) & $mask);
}

function security_ip_in_list(string $ip, array $list): bool
{
    foreach ($list as $entry) {
        if (security_ip_matches($ip, $entry)) {
            return true;
        }
    }
    return false;
}

/**
 * Best-effort client IP.
 *
 * X-Forwarded-For is only honoured when the immediate peer is a trusted proxy.
 * Otherwise any client could forge the header and dodge per-IP rate limits.
 * When the chain is present we return the closest untrusted hop from the right,
 * which is the real client address behind Render/nginx/Cloudflare.
 */
function security_client_ip(): string
{
    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    if ($remote === '' || !filter_var($remote, FILTER_VALIDATE_IP)) {
        $remote = '0.0.0.0';
    }

    $trusted = security_trusted_proxies();
    if (!security_ip_in_list($remote, $trusted)) {
        return $remote;
    }

    $forwarded = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
    if ($forwarded === '') {
        return $remote;
    }

    $chain = array_filter(array_map('trim', explode(',', $forwarded)));
    for ($i = count($chain) - 1; $i >= 0; $i--) {
        if (!filter_var($chain[$i], FILTER_VALIDATE_IP)) {
            continue;
        }
        if (!security_ip_in_list($chain[$i], $trusted)) {
            return $chain[$i];
        }
    }

    return $remote;
}

/**
 * Remove control characters, HTML tags and angle brackets from free text.
 * This stops stored XSS payloads from being persisted in the first place.
 * Output encoding on the client remains the primary defence.
 */
function security_clean_text($value, int $maxLength = 255): string
{
    if (!is_scalar($value)) {
        return '';
    }

    $value = (string) $value;
    $value = str_replace(["\0"], '', $value);
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
    if ($value === null) {
        $value = '';
    }
    $value = strip_tags($value);
    $value = str_replace(['<', '>'], '', $value);
    $value = trim($value);

    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, $maxLength);
    }
    return substr($value, 0, $maxLength);
}

function security_is_email($value): bool
{
    return is_string($value) && filter_var(trim($value), FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate an uploaded identity document. Accepts an image data URI or an
 * https URL so the value cannot be used as a javascript: URI.
 */
function security_clean_document($value, int $maxLength = 5000000): ?string
{
    if ($value === null || $value === '') {
        return null;
    }
    if (!is_string($value) || strlen($value) > $maxLength) {
        return null;
    }

    $allowed = '#^(data:image/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=\r\n]+|https://[^\s<>"\']+)$#i';
    if (!preg_match($allowed, $value)) {
        return null;
    }
    return $value;
}

// Bcrypt truncates at 72 bytes, so rejecting longer input avoids silent
// truncation. Cost 12 is a deliberate step up from PHP's default of 10.
const SECURITY_BCRYPT_COST = 12;
const SECURITY_PASSWORD_MIN = 12;
const SECURITY_PASSWORD_MAX = 72;

function security_hash_password(string $password): string
{
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => SECURITY_BCRYPT_COST]);
}

function security_password_needs_rehash(string $hash): bool
{
    return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => SECURITY_BCRYPT_COST]);
}

function security_validate_password(string $password): ?string
{
    $length = strlen($password);

    if ($length < SECURITY_PASSWORD_MIN) {
        return 'Password must be at least ' . SECURITY_PASSWORD_MIN . ' characters long.';
    }
    if ($length > SECURITY_PASSWORD_MAX) {
        return 'Password must be at most ' . SECURITY_PASSWORD_MAX . ' characters long.';
    }
    if (!preg_match('/[A-Za-z]/', $password) || !preg_match('/[0-9]/', $password)) {
        return 'Password must include at least one letter and one number.';
    }

    $common = [
        'password1234', 'password12345', 'password123456', '123456789012',
        '12345678901', 'qwertyuiop12', 'qwerty123456', 'letmein123456',
        'admin123456', 'welcome12345', 'iloveyou1234', 'monkey123456',
        'dragon123456', 'football1234', 'baseball1234', 'sunshine1234',
    ];
    if (in_array(strtolower($password), $common, true)) {
        return 'Password is too common. Choose a stronger password.';
    }

    // Reject a single repeated character (e.g. aaaaaaaaaaaa1).
    if (preg_match('/^(.)\1+[0-9]$/', $password) || preg_match('/^(.)\1+$/', $password)) {
        return 'Password is too predictable. Choose a stronger password.';
    }

    return null;
}

/**
 * Make a value safe to use as a download filename.
 */
function security_sanitize_filename(string $value, int $maxLength = 80): string
{
    $value = preg_replace('/[^A-Za-z0-9 _.-]/', '_', $value);
    $value = preg_replace('/\s+/', '_', (string) $value);
    $value = trim((string) $value, '._-');

    if ($value === '') {
        $value = 'download';
    }

    return substr($value, 0, $maxLength);
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/**
 * Create the rate_limits table on first use. If the database user cannot
 * create tables, the limiter fails open (log only) so logins stay available.
 */
function security_rate_limits_table(PDO $conn): bool
{
    static $ready = null;
    if ($ready !== null) {
        return $ready;
    }

    try {
        $conn->exec(
            "CREATE TABLE IF NOT EXISTS rate_limits (
                bucket VARCHAR(50) NOT NULL,
                identifier CHAR(64) NOT NULL,
                attempts INT NOT NULL DEFAULT 0,
                window_start DATETIME NOT NULL,
                locked_until DATETIME NULL,
                PRIMARY KEY (bucket, identifier)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        $ready = true;
    } catch (Throwable $e) {
        error_log('Rate limit table unavailable: ' . $e->getMessage());
        $ready = false;
    }

    return $ready;
}

function security_rate_key(string $identifier): string
{
    return hash('sha256', $identifier);
}

/**
 * Seconds until the identifier may try again, or 0 if it is not locked.
 */
function security_rate_limit_retry(PDO $conn, string $bucket, string $identifier): int
{
    if (!security_rate_limits_table($conn)) {
        return 0;
    }

    try {
        $stmt = $conn->prepare(
            "SELECT TIMESTAMPDIFF(SECOND, NOW(), locked_until) AS retry_after
             FROM rate_limits WHERE bucket = :bucket AND identifier = :identifier LIMIT 1"
        );
        $stmt->execute([
            ':bucket' => $bucket,
            ':identifier' => security_rate_key($identifier),
        ]);
        $retry = $stmt->fetchColumn();

        return ($retry !== false && $retry !== null && (int) $retry > 0) ? (int) $retry : 0;
    } catch (Throwable $e) {
        error_log('Rate limit read failed: ' . $e->getMessage());
        return 0;
    }
}

/**
 * Record one failed attempt. Returns the number of seconds the identifier is
 * now locked for, or 0 when it is still under the limit.
 */
function security_rate_limit_hit(
    PDO $conn,
    string $bucket,
    string $identifier,
    int $maxAttempts,
    int $windowSeconds,
    int $lockSeconds
): int {
    if (!security_rate_limits_table($conn)) {
        return 0;
    }

    $key = security_rate_key($identifier);
    $lockSeconds = max(1, $lockSeconds);

    try {
        $conn->beginTransaction();

        $stmt = $conn->prepare(
            "SELECT attempts, TIMESTAMPDIFF(SECOND, window_start, NOW()) AS age
             FROM rate_limits WHERE bucket = :bucket AND identifier = :identifier FOR UPDATE"
        );
        $stmt->execute([':bucket' => $bucket, ':identifier' => $key]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row || (int) $row['age'] >= $windowSeconds) {
            // First failure in a fresh window.
            $stmt = $conn->prepare(
                "INSERT INTO rate_limits (bucket, identifier, attempts, window_start, locked_until)
                 VALUES (:bucket, :identifier, 1, NOW(), NULL)
                 ON DUPLICATE KEY UPDATE attempts = 1, window_start = NOW(), locked_until = NULL"
            );
            $stmt->execute([':bucket' => $bucket, ':identifier' => $key]);
            $conn->commit();
            return 0;
        }

        $attempts = (int) $row['attempts'] + 1;

        if ($attempts >= $maxAttempts) {
            $stmt = $conn->prepare(
                "UPDATE rate_limits
                 SET attempts = :attempts, locked_until = DATE_ADD(NOW(), INTERVAL {$lockSeconds} SECOND)
                 WHERE bucket = :bucket AND identifier = :identifier"
            );
            $stmt->execute([
                ':attempts' => $attempts,
                ':bucket' => $bucket,
                ':identifier' => $key,
            ]);
            $conn->commit();
            return $lockSeconds;
        }

        $stmt = $conn->prepare(
            "UPDATE rate_limits SET attempts = :attempts
             WHERE bucket = :bucket AND identifier = :identifier"
        );
        $stmt->execute([
            ':attempts' => $attempts,
            ':bucket' => $bucket,
            ':identifier' => $key,
        ]);
        $conn->commit();
        return 0;
    } catch (Throwable $e) {
        if ($conn->inTransaction()) {
            $conn->rollBack();
        }
        error_log('Rate limit update failed: ' . $e->getMessage());
        return 0;
    }
}

function security_rate_limit_clear(PDO $conn, string $bucket, string $identifier): void
{
    if (!security_rate_limits_table($conn)) {
        return;
    }

    try {
        $stmt = $conn->prepare(
            "DELETE FROM rate_limits WHERE bucket = :bucket AND identifier = :identifier"
        );
        $stmt->execute([
            ':bucket' => $bucket,
            ':identifier' => security_rate_key($identifier),
        ]);
    } catch (Throwable $e) {
        error_log('Rate limit clear failed: ' . $e->getMessage());
    }
}

// ---------------------------------------------------------------------------
// Token revocation
// ---------------------------------------------------------------------------

/**
 * Create the per-token denylist table on first use. Used by logout so a single
 * device can be signed out without invalidating every other session.
 */
function security_revoked_tokens_table(PDO $conn): bool
{
    static $ready = null;
    if ($ready !== null) {
        return $ready;
    }

    try {
        $conn->exec(
            "CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti CHAR(32) NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (jti),
                KEY idx_revoked_tokens_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        $ready = true;
    } catch (Throwable $e) {
        error_log('Revoked-token table unavailable: ' . $e->getMessage());
        $ready = false;
    }

    return $ready;
}

function security_revoke_token(PDO $conn, string $jti, int $expiresAt): bool
{
    if ($jti === '' || !security_revoked_tokens_table($conn)) {
        return false;
    }

    try {
        // Housekeeping: expired deny-list rows can never match again.
        $conn->exec("DELETE FROM revoked_tokens WHERE expires_at < NOW()");

        $stmt = $conn->prepare(
            "INSERT INTO revoked_tokens (jti, expires_at) VALUES (:jti, :expires_at)
             ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)"
        );
        $stmt->execute([
            ':jti' => $jti,
            ':expires_at' => date('Y-m-d H:i:s', $expiresAt),
        ]);
        return true;
    } catch (Throwable $e) {
        error_log('Token revocation failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * True when the token has been explicitly revoked. Fails open only if the
 * denylist table is unavailable; `token_version` remains the primary control.
 */
function security_token_is_revoked(PDO $conn, string $jti): bool
{
    if ($jti === '') {
        return true;
    }

    try {
        $stmt = $conn->prepare(
            "SELECT 1 FROM revoked_tokens WHERE jti = :jti AND expires_at > NOW() LIMIT 1"
        );
        $stmt->execute([':jti' => $jti]);
        return (bool) $stmt->fetchColumn();
    } catch (Throwable $e) {
        error_log('Token denylist read failed: ' . $e->getMessage());
        return false;
    }
}
