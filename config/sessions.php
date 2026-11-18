<?php
// config/sessions.php
//
// Session issuance tracking for the Super Admin Control Center. Records issued
// access tokens (by jti hash) so active sessions/devices can be listed and
// revoked. Best-effort: failures must never break authentication.

require_once __DIR__ . '/security.php';

function session_table(PDO $conn): bool
{
    static $ready = null;
    if ($ready !== null) {
        return $ready;
    }

    try {
        $conn->exec(
            "CREATE TABLE IF NOT EXISTS user_sessions (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                user_id INT NOT NULL,
                jti_hash CHAR(64) NOT NULL,
                ip VARCHAR(45) NULL,
                user_agent VARCHAR(255) NULL,
                issued_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                last_seen_at DATETIME NULL,
                revoked_at DATETIME NULL,
                revoke_reason VARCHAR(100) NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE KEY uq_user_sessions_jti_hash (jti_hash),
                KEY idx_user_sessions_user (user_id, revoked_at, expires_at),
                KEY idx_user_sessions_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        $ready = true;
    } catch (Throwable $e) {
        error_log('Session table unavailable: ' . $e->getMessage());
        $ready = false;
    }

    return $ready;
}

function session_jti_hash(string $jti): string
{
    return hash('sha256', $jti);
}

/**
 * Record an issued access token/session.
 *
 * @param array $mint {jti, iat, exp, user_id}
 */
function session_record(PDO $conn, array $mint): void
{
    if (!session_table($conn)) {
        return;
    }

    $jti = (string) ($mint['jti'] ?? '');
    if ($jti === '') {
        return;
    }

    $ip = security_client_ip();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
    $ua = $ua === null ? null : substr((string) $ua, 0, 255);

    try {
        $stmt = $conn->prepare(
            "INSERT INTO user_sessions (user_id, jti_hash, ip, user_agent, issued_at, expires_at, last_seen_at)
             VALUES (:user_id, :jti_hash, :ip, :user_agent, :issued_at, :expires_at, :last_seen_at)
             ON DUPLICATE KEY UPDATE last_seen_at = VALUES(last_seen_at)"
        );
        $stmt->execute([
            ':user_id' => (int) ($mint['user_id'] ?? 0),
            ':jti_hash' => session_jti_hash($jti),
            ':ip' => $ip,
            ':user_agent' => $ua,
            ':issued_at' => gmdate('Y-m-d H:i:s', (int) ($mint['iat'] ?? time())),
            ':expires_at' => gmdate('Y-m-d H:i:s', (int) ($mint['exp'] ?? time())),
            ':last_seen_at' => gmdate('Y-m-d H:i:s'),
        ]);
    } catch (Throwable $e) {
        error_log('Session record failed: ' . $e->getMessage());
    }
}

/**
 * Mark a session revoked (by jti) in the issuance log.
 */
function session_mark_revoked(PDO $conn, string $jti, string $reason = 'revoked'): void
{
    if ($jti === '' || !session_table($conn)) {
        return;
    }

    try {
        $stmt = $conn->prepare(
            "UPDATE user_sessions
             SET revoked_at = NOW(), revoke_reason = :reason
             WHERE jti_hash = :jti_hash AND revoked_at IS NULL"
        );
        $stmt->execute([
            ':jti_hash' => session_jti_hash($jti),
            ':reason' => substr($reason, 0, 100),
        ]);
    } catch (Throwable $e) {
        error_log('Session revoke mark failed: ' . $e->getMessage());
    }
}

/**
 * Mark all sessions for a user as revoked in the issuance log (e.g. token_version bump).
 */
function session_revoke_all_for_user(PDO $conn, int $userId, string $reason = 'all_sessions_revoked'): void
{
    if ($userId < 1 || !session_table($conn)) {
        return;
    }

    try {
        $stmt = $conn->prepare(
            "UPDATE user_sessions
             SET revoked_at = NOW(), revoke_reason = :reason
             WHERE user_id = :user_id AND revoked_at IS NULL"
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':reason' => substr($reason, 0, 100),
        ]);
    } catch (Throwable $e) {
        error_log('Session revoke-all mark failed: ' . $e->getMessage());
    }
}
