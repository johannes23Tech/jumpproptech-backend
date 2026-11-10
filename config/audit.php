<?php
// config/audit.php
// Append-only security audit trail. Writes are best-effort: an audit failure
// must never break a login or a payment, but it is always written to the PHP
// error log so monitoring can catch it.
//
// The migration (migrations/2026-11-09_security_hardening_batch3.sql) creates
// the table and triggers that reject UPDATE/DELETE. This file also creates the
// table lazily so a fresh deployment can log before the migration is run.

function audit_table(PDO $conn): bool
{
    static $ready = null;
    if ($ready !== null) {
        return $ready;
    }

    try {
        $conn->exec(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                actor_user_id INT NULL,
                actor_email VARCHAR(150) NULL,
                action VARCHAR(60) NOT NULL,
                entity_type VARCHAR(40) NULL,
                entity_id INT NULL,
                outcome ENUM('success', 'failure', 'denied') NOT NULL DEFAULT 'success',
                ip VARCHAR(45) NULL,
                user_agent VARCHAR(255) NULL,
                meta LONGTEXT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY idx_audit_logs_action (action, created_at),
                KEY idx_audit_logs_actor (actor_user_id, created_at),
                KEY idx_audit_logs_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
        $ready = true;
    } catch (Throwable $e) {
        error_log('Audit table unavailable: ' . $e->getMessage());
        $ready = false;
    }

    return $ready;
}

/**
 * Record one security-relevant event.
 *
 * @param PDO        $conn      Open connection.
 * @param int|null   $actorId   Authenticated user id, or null for anonymous.
 * @param string     $action    Dotted action name, e.g. auth.login.success.
 * @param array      $options    actor_email, entity_type, entity_id, outcome,
 *                               meta (array|string), ip, user_agent.
 */
function audit_log(PDO $conn, ?int $actorId, string $action, array $options = []): void
{
    if (!audit_table($conn)) {
        return;
    }

    $outcome = $options['outcome'] ?? 'success';
    if (!in_array($outcome, ['success', 'failure', 'denied'], true)) {
        $outcome = 'success';
    }

    $actorEmail = $options['actor_email'] ?? null;
    $actorEmail = $actorEmail === null ? null : substr((string) $actorEmail, 0, 150);

    $entityType = $options['entity_type'] ?? null;
    $entityType = $entityType === null ? null : substr((string) $entityType, 0, 40);

    $entityId = $options['entity_id'] ?? null;
    $entityId = $entityId === null ? null : (int) $entityId;

    $meta = $options['meta'] ?? null;
    if (is_array($meta) || is_object($meta)) {
        $meta = json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } elseif ($meta !== null) {
        $meta = (string) $meta;
    }
    if (is_string($meta) && strlen($meta) > 4000) {
        $meta = substr($meta, 0, 4000);
    }

    $ip = $options['ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? null);
    $ip = $ip === null ? null : substr((string) $ip, 0, 45);

    $userAgent = $options['user_agent'] ?? ($_SERVER['HTTP_USER_AGENT'] ?? null);
    $userAgent = $userAgent === null ? null : substr((string) $userAgent, 0, 255);

    try {
        $stmt = $conn->prepare(
            "INSERT INTO audit_logs
                (actor_user_id, actor_email, action, entity_type, entity_id, outcome, ip, user_agent, meta)
             VALUES
                (:actor_id, :actor_email, :action, :entity_type, :entity_id, :outcome, :ip, :user_agent, :meta)"
        );
        $stmt->execute([
            ':actor_id' => $actorId,
            ':actor_email' => $actorEmail,
            ':action' => substr($action, 0, 60),
            ':entity_type' => $entityType,
            ':entity_id' => $entityId,
            ':outcome' => $outcome,
            ':ip' => $ip,
            ':user_agent' => $userAgent,
            ':meta' => $meta,
        ]);
    } catch (Throwable $e) {
        error_log('Audit log write failed: ' . $e->getMessage());
    }
}
