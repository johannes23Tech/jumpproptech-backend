-- Phase 6: JUMP FLUX AI — conversations, messages, usage and learning captures.
-- Additive / idempotent. Safe to run multiple times.

CREATE TABLE IF NOT EXISTS flux_conversations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    title VARCHAR(120) NOT NULL DEFAULT 'New conversation',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_flux_conversations_user_updated (user_id, updated_at),
    CONSTRAINT fk_flux_conversations_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS flux_messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    conversation_id BIGINT UNSIGNED NOT NULL,
    user_id INT NOT NULL,
    role ENUM('user', 'assistant', 'system') NOT NULL,
    content MEDIUMTEXT NOT NULL,
    meta LONGTEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_flux_messages_conversation_created (conversation_id, created_at),
    KEY idx_flux_messages_user (user_id, created_at),
    CONSTRAINT fk_flux_messages_conversation FOREIGN KEY (conversation_id) REFERENCES flux_conversations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS flux_usage_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT NULL,
    conversation_id BIGINT UNSIGNED NULL,
    provider VARCHAR(40) NULL,
    model VARCHAR(80) NULL,
    prompt_tokens INT UNSIGNED NULL,
    completion_tokens INT UNSIGNED NULL,
    total_tokens INT UNSIGNED NULL,
    latency_ms INT UNSIGNED NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'success',
    error_message VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_flux_usage_user_created (user_id, created_at),
    KEY idx_flux_usage_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- "Learn from past mistakes" / unanswered-question capture (human-in-the-loop).
CREATE TABLE IF NOT EXISTS flux_learning_captures (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT NULL,
    conversation_id BIGINT UNSIGNED NULL,
    message_id BIGINT UNSIGNED NULL,
    question TEXT NULL,
    assistant_response MEDIUMTEXT NULL,
    capture_type VARCHAR(40) NOT NULL DEFAULT 'unanswered', -- unanswered|correction|feedback|mistake
    detail TEXT NULL,
    status ENUM('pending_review', 'promoted', 'rejected') NOT NULL DEFAULT 'pending_review',
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    review_note TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_flux_learning_status_created (status, created_at),
    KEY idx_flux_learning_user (user_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
