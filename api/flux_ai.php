<?php
// api/flux_ai.php
// JUMP FLUX AI: conversations, chat (provider-independent), and learning captures.
// Secure, role-aware, server-side.

require_once '../config/db.php';
require_once '../config/security.php';
require_once '../config/audit.php';
require_once '../config/permissions.php';
require_once '../config/flux_ai.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$actor = (array) $user;
$userId = (int) $user->user_id;
$method = $_SERVER['REQUEST_METHOD'];

function flux_json(int $status, array $payload, array $headers = []): void
{
    security_json_response($status, $payload, $headers);
}

function flux_actor_array($user): array
{
    $a = (array) $user;
    // normalize keys expected by permission helpers
    if (!isset($a['id']) && isset($a['user_id'])) $a['id'] = $a['user_id'];
    if (!isset($a['role']) && isset($a['legacy_role'])) $a['role'] = $a['legacy_role'];
    return $a;
}

$actor = flux_actor_array($user);

function flux_get_conversation(PDO $conn, int $id, int $userId): ?array
{
    $stmt = $conn->prepare('SELECT id, user_id, title, created_at, updated_at FROM flux_conversations WHERE id = :id AND user_id = :uid LIMIT 1');
    $stmt->execute([':id' => $id, ':uid' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function flux_conversation_payload(array $row): array
{
    return [
        'id' => (int) $row['id'],
        'title' => (string) $row['title'],
        'created_at' => (string) $row['created_at'],
        'updated_at' => (string) $row['updated_at'],
    ];
}

function flux_message_payload(array $row): array
{
    $meta = null;
    if (isset($row['meta']) && $row['meta'] !== null && $row['meta'] !== '') {
        $decoded = json_decode((string) $row['meta'], true);
        $meta = is_array($decoded) ? $decoded : null;
    }
    return [
        'id' => (int) $row['id'],
        'role' => (string) $row['role'],
        'content' => (string) $row['content'],
        'created_at' => (string) $row['created_at'],
        'meta' => $meta,
    ];
}

function flux_log_usage(PDO $conn, ?int $userId, ?int $conversationId, array $cfg, array $result, string $status, ?string $error = null): void
{
    try {
        $usage = is_array($result['usage'] ?? null) ? $result['usage'] : [];
        $stmt = $conn->prepare(
            "INSERT INTO flux_usage_logs
                (user_id, conversation_id, provider, model, prompt_tokens, completion_tokens, total_tokens, latency_ms, status, error_message)
             VALUES
                (:user_id, :conversation_id, :provider, :model, :prompt_tokens, :completion_tokens, :total_tokens, :latency_ms, :status, :error_message)"
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':conversation_id' => $conversationId,
            ':provider' => $cfg['provider'] ?? null,
            ':model' => $cfg['model'] ?? null,
            ':prompt_tokens' => $usage['prompt_tokens'] ?? null,
            ':completion_tokens' => $usage['completion_tokens'] ?? null,
            ':total_tokens' => $usage['total_tokens'] ?? null,
            ':latency_ms' => isset($result['latency_ms']) ? (int) $result['latency_ms'] : null,
            ':status' => substr($status, 0, 20),
            ':error_message' => $error !== null ? substr($error, 0, 255) : null,
        ]);
    } catch (Throwable $e) {
        error_log('FLUX usage log failed: ' . $e->getMessage());
    }
}

function flux_is_unanswered_like(string $content): bool
{
    $c = mb_strtolower($content);
    $markers = [
        'i do not have', "i don't have", 'not available', 'unavailable',
        'cannot access', "can't access", 'no specific database records',
        'no records were retrieved', 'missing', 'not configured', 'connect the ai service',
    ];
    foreach ($markers as $m) {
        if (mb_strpos($c, $m) !== false) return true;
    }
    return false;
}

$cfg = flux_ai_config();

if ($method === 'GET') {
    $action = isset($_GET['action']) ? strtolower(trim((string) $_GET['action'])) : 'status';

    if ($action === 'status' || $action === '') {
        $configured = flux_ai_is_configured($cfg);
        flux_json(200, [
            'configured' => $configured,
            'provider' => $cfg['provider'],
            'model' => $configured ? $cfg['model'] : null,
            'message' => $configured
                ? 'JUMP FLUX AI is ready.'
                : 'JUMP FLUX AI is not configured. Set FLUX_AI_PROVIDER, FLUX_AI_API_KEY, and FLUX_AI_MODEL to enable live, data-aware responses.',
        ]);
    }

    if ($action === 'conversations') {
        $stmt = $conn->prepare('SELECT id, title, created_at, updated_at FROM flux_conversations WHERE user_id = :uid ORDER BY updated_at DESC, id DESC LIMIT 100');
        $stmt->execute([':uid' => $userId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        flux_json(200, ['conversations' => array_map('flux_conversation_payload', $rows)]);
    }

    if ($action === 'conversation') {
        $id = filter_var($_GET['id'] ?? 0, FILTER_VALIDATE_INT);
        if ($id === false || $id < 1) flux_json(400, ['message' => 'A valid conversation id is required.']);
        $conv = flux_get_conversation($conn, (int) $id, $userId);
        if (!$conv) flux_json(404, ['message' => 'Conversation not found.']);

        $m = $conn->prepare('SELECT id, role, content, meta, created_at FROM flux_messages WHERE conversation_id = :cid AND user_id = :uid ORDER BY id ASC');
        $m->execute([':cid' => (int) $id, ':uid' => $userId]);
        $msgs = $m->fetchAll(PDO::FETCH_ASSOC);

        flux_json(200, [
            'conversation' => flux_conversation_payload($conv),
            'messages' => array_map('flux_message_payload', $msgs),
        ]);
    }

    if ($action === 'suggestions') {
        flux_json(200, [
            'suggestions' => [
                'How much rent did we collect this month?',
                'Which tenants are behind on rent?',
                'Which properties have vacancies?',
                'What are our total monthly expenses?',
                'Which property generates the highest rental income?',
                'How many leases expire next month?',
                'What maintenance cases remain unresolved?',
                'How is the overall portfolio performing?',
            ],
        ]);
    }

    flux_json(400, ['message' => 'Unsupported action.']);
}

if ($method !== 'POST') {
    flux_json(405, ['message' => 'Method not allowed.'], ['Allow' => 'GET, POST']);
}

$data = json_decode(file_get_contents('php://input'));
if (!is_object($data)) {
    flux_json(400, ['message' => 'Invalid request body.']);
}

$action = isset($data->action) ? strtolower(trim((string) $data->action)) : '';

if ($action === 'conversation_create') {
    $title = isset($data->title) ? security_clean_text((string) $data->title, 120) : 'New conversation';
    if ($title === '') $title = 'New conversation';

    $stmt = $conn->prepare('INSERT INTO flux_conversations (user_id, title) VALUES (:uid, :title)');
    $stmt->execute([':uid' => $userId, ':title' => $title]);
    $id = (int) $conn->lastInsertId();
    $conv = flux_get_conversation($conn, $id, $userId);

    audit_log($conn, $userId, 'flux.conversation_created', ['entity_type' => 'flux_conversation', 'entity_id' => $id]);
    flux_json(201, ['conversation' => flux_conversation_payload($conv)]);
}

if ($action === 'conversation_update') {
    $id = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    $title = isset($data->title) ? security_clean_text((string) $data->title, 120) : '';
    if ($id === false || $id < 1 || $title === '') flux_json(400, ['message' => 'A valid id and title are required.']);
    $conv = flux_get_conversation($conn, (int) $id, $userId);
    if (!$conv) flux_json(404, ['message' => 'Conversation not found.']);

    $stmt = $conn->prepare('UPDATE flux_conversations SET title = :title WHERE id = :id AND user_id = :uid');
    $stmt->execute([':title' => $title, ':id' => (int) $id, ':uid' => $userId]);
    $conv = flux_get_conversation($conn, (int) $id, $userId);
    audit_log($conn, $userId, 'flux.conversation_renamed', ['entity_type' => 'flux_conversation', 'entity_id' => (int) $id]);
    flux_json(200, ['conversation' => flux_conversation_payload($conv)]);
}

if ($action === 'conversation_delete') {
    $id = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($id === false || $id < 1) flux_json(400, ['message' => 'A valid conversation id is required.']);
    $conv = flux_get_conversation($conn, (int) $id, $userId);
    if (!$conv) flux_json(404, ['message' => 'Conversation not found.']);

    $stmt = $conn->prepare('DELETE FROM flux_conversations WHERE id = :id AND user_id = :uid');
    $stmt->execute([':id' => (int) $id, ':uid' => $userId]);
    audit_log($conn, $userId, 'flux.conversation_deleted', ['entity_type' => 'flux_conversation', 'entity_id' => (int) $id]);
    flux_json(200, ['message' => 'Conversation deleted.']);
}

if ($action === 'conversation_clear') {
    $id = filter_var($data->id ?? 0, FILTER_VALIDATE_INT);
    if ($id === false || $id < 1) flux_json(400, ['message' => 'A valid conversation id is required.']);
    $conv = flux_get_conversation($conn, (int) $id, $userId);
    if (!$conv) flux_json(404, ['message' => 'Conversation not found.']);

    $stmt = $conn->prepare('DELETE FROM flux_messages WHERE conversation_id = :cid AND user_id = :uid');
    $stmt->execute([':cid' => (int) $id, ':uid' => $userId]);
    $conn->prepare('UPDATE flux_conversations SET updated_at = NOW() WHERE id = :id AND user_id = :uid')->execute([':id' => (int) $id, ':uid' => $userId]);
    audit_log($conn, $userId, 'flux.conversation_cleared', ['entity_type' => 'flux_conversation', 'entity_id' => (int) $id]);
    flux_json(200, ['message' => 'Conversation cleared.']);
}

if ($action === 'chat') {
    $message = isset($data->message) ? trim((string) $data->message) : '';
    if ($message === '') flux_json(400, ['message' => 'A message is required.']);
    $message = security_clean_text($message, 4000);
    if ($message === '') flux_json(400, ['message' => 'A message is required.']);

    // Rate limit (per user)
    $bucket = 'flux_chat';
    $ident = 'user:' . $userId . ':ip:' . security_client_ip();
    $retry = security_rate_limit_retry($conn, $bucket, $ident);
    if ($retry > 0) {
        flux_json(429, ['message' => 'Too many requests. Please try again shortly.', 'retry_after' => $retry], ['Retry-After' => (string) $retry]);
    }
    $lock = security_rate_limit_hit($conn, $bucket, $ident, max(1, (int) $cfg['rate_limit_per_minute']), 60, 60);
    if ($lock > 0) {
        flux_json(429, ['message' => 'Too many requests. Please try again shortly.', 'retry_after' => $lock], ['Retry-After' => (string) $lock]);
    }

    // Resolve/create conversation
    $conversationId = filter_var($data->conversation_id ?? 0, FILTER_VALIDATE_INT);
    $conv = null;
    if ($conversationId !== false && $conversationId > 0) {
        $conv = flux_get_conversation($conn, (int) $conversationId, $userId);
        if (!$conv) flux_json(404, ['message' => 'Conversation not found.']);
    } else {
        $title = mb_substr($message, 0, 42) . (mb_strlen($message) > 42 ? '…' : '');
        $stmt = $conn->prepare('INSERT INTO flux_conversations (user_id, title) VALUES (:uid, :title)');
        $stmt->execute([':uid' => $userId, ':title' => $title !== '' ? $title : 'New conversation']);
        $conversationId = (int) $conn->lastInsertId();
        $conv = flux_get_conversation($conn, $conversationId, $userId);
    }

    // Persist user message
    $ins = $conn->prepare('INSERT INTO flux_messages (conversation_id, user_id, role, content) VALUES (:cid, :uid, :role, :content)');
    $ins->execute([':cid' => (int) $conversationId, ':uid' => $userId, ':role' => 'user', ':content' => $message]);
    $userMessageId = (int) $conn->lastInsertId();

    // If title is default and this is first meaningful message, update title
    if ($conv && ($conv['title'] === 'New conversation')) {
        $title = mb_substr($message, 0, 42) . (mb_strlen($message) > 42 ? '…' : '');
        $conn->prepare('UPDATE flux_conversations SET title = :title, updated_at = NOW() WHERE id = :id AND user_id = :uid')
            ->execute([':title' => $title, ':id' => (int) $conversationId, ':uid' => $userId]);
        $conv['title'] = $title;
    } else {
        $conn->prepare('UPDATE flux_conversations SET updated_at = NOW() WHERE id = :id AND user_id = :uid')
            ->execute([':id' => (int) $conversationId, ':uid' => $userId]);
    }

    // Not configured: return clear setup message (do NOT simulate real AI response).
    if (!flux_ai_is_configured($cfg)) {
        $setup = "JUMP FLUX AI is not configured yet.\n\n"
            . "To enable live, data-aware responses, a server administrator must configure the AI provider (FLUX_AI_PROVIDER, FLUX_AI_API_KEY, FLUX_AI_MODEL, and FLUX_AI_BASE_URL/FLUX_AI_API_VERSION if required) in the server environment, then reload the service.\n\n"
            . "Your conversation is saved. Once configured, I’ll be able to answer using authorized Jump PropTech data within your role permissions.";

        $insA = $conn->prepare('INSERT INTO flux_messages (conversation_id, user_id, role, content, meta) VALUES (:cid, :uid, :role, :content, :meta)');
        $insA->execute([
            ':cid' => (int) $conversationId,
            ':uid' => $userId,
            ':role' => 'assistant',
            ':content' => $setup,
            ':meta' => json_encode(['type' => 'setup_required'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
        $assistantMessageId = (int) $conn->lastInsertId();

        audit_log($conn, $userId, 'flux.chat_unconfigured', ['entity_type' => 'flux_conversation', 'entity_id' => (int) $conversationId]);

        flux_json(200, [
            'conversation' => flux_conversation_payload(flux_get_conversation($conn, (int) $conversationId, $userId) ?: $conv),
            'user_message' => ['id' => $userMessageId, 'role' => 'user', 'content' => $message, 'created_at' => date('c')],
            'assistant_message' => ['id' => $assistantMessageId, 'role' => 'assistant', 'content' => $setup, 'created_at' => date('c'), 'meta' => ['type' => 'setup_required']],
            'configured' => false,
        ]);
    }

    // Build context and call model
    $context = flux_ai_build_context($conn, $actor, $message);
    $system = flux_ai_system_prompt($actor, $context);

    // Recent history (last ~12 messages) for continuity
    $histStmt = $conn->prepare(
        "SELECT role, content FROM flux_messages
         WHERE conversation_id = :cid AND user_id = :uid AND id < :before
         ORDER BY id DESC LIMIT 12"
    );
    $histStmt->execute([':cid' => (int) $conversationId, ':uid' => $userId, ':before' => $userMessageId]);
    $history = array_reverse($histStmt->fetchAll(PDO::FETCH_ASSOC));

    $messages = [['role' => 'system', 'content' => $system]];
    foreach ($history as $h) {
        $r = $h['role'];
        if (!in_array($r, ['user', 'assistant'], true)) continue;
        $messages[] = ['role' => $r, 'content' => (string) $h['content']];
    }
    $messages[] = ['role' => 'user', 'content' => $message];

    $result = flux_ai_call($messages, $cfg);

    if (!($result['ok'] ?? false)) {
        $errCode = (string) ($result['error'] ?? 'provider_error');
        $friendly = "I couldn’t complete that request right now because the AI service is unavailable. Please try again in a moment. If the issue continues, an administrator may need to check the AI provider configuration.";
        if ($errCode === 'not_configured') {
            $friendly = "JUMP FLUX AI is not configured yet. A server administrator must configure the AI provider to enable live responses.";
        }

        $insA = $conn->prepare('INSERT INTO flux_messages (conversation_id, user_id, role, content, meta) VALUES (:cid, :uid, :role, :content, :meta)');
        $insA->execute([
            ':cid' => (int) $conversationId,
            ':uid' => $userId,
            ':role' => 'assistant',
            ':content' => $friendly,
            ':meta' => json_encode(['type' => 'error', 'error' => $errCode], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
        $assistantMessageId = (int) $conn->lastInsertId();

        flux_log_usage($conn, $userId, (int) $conversationId, $cfg, $result, 'error', $errCode);
        audit_log($conn, $userId, 'flux.chat_error', ['entity_type' => 'flux_conversation', 'entity_id' => (int) $conversationId, 'outcome' => 'failure', 'meta' => ['error' => $errCode]]);

        // Capture as potential learning signal (service/answer issue)
        try {
            $cap = $conn->prepare('INSERT INTO flux_learning_captures (user_id, conversation_id, message_id, question, assistant_response, capture_type, detail, status) VALUES (:uid,:cid,:mid,:q,:a,:t,:d,:s)');
            $cap->execute([
                ':uid' => $userId,
                ':cid' => (int) $conversationId,
                ':mid' => $assistantMessageId,
                ':q' => $message,
                ':a' => $friendly,
                ':t' => 'unanswered',
                ':d' => 'provider_error:' . $errCode,
                ':s' => 'pending_review',
            ]);
        } catch (Throwable $e) { /* best effort */ }

        flux_json(200, [
            'conversation' => flux_conversation_payload(flux_get_conversation($conn, (int) $conversationId, $userId) ?: $conv),
            'user_message' => ['id' => $userMessageId, 'role' => 'user', 'content' => $message, 'created_at' => date('c')],
            'assistant_message' => ['id' => $assistantMessageId, 'role' => 'assistant', 'content' => $friendly, 'created_at' => date('c'), 'meta' => ['type' => 'error', 'error' => $errCode]],
            'configured' => true,
            'error' => $errCode,
        ]);
    }

    $answer = (string) $result['content'];
    $insA = $conn->prepare('INSERT INTO flux_messages (conversation_id, user_id, role, content, meta) VALUES (:cid, :uid, :role, :content, :meta)');
    $insA->execute([
        ':cid' => (int) $conversationId,
        ':uid' => $userId,
        ':role' => 'assistant',
        ':content' => $answer,
        ':meta' => json_encode(['type' => 'answer'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    ]);
    $assistantMessageId = (int) $conn->lastInsertId();

    flux_log_usage($conn, $userId, (int) $conversationId, $cfg, $result, 'success', null);
    audit_log($conn, $userId, 'flux.chat', ['entity_type' => 'flux_conversation', 'entity_id' => (int) $conversationId, 'meta' => ['provider' => $cfg['provider'], 'model' => $cfg['model']]]);

    // "Learn from past mistakes": capture likely-unanswered responses for review.
    if (flux_is_unanswered_like($answer)) {
        try {
            $cap = $conn->prepare('INSERT INTO flux_learning_captures (user_id, conversation_id, message_id, question, assistant_response, capture_type, detail, status) VALUES (:uid,:cid,:mid,:q,:a,:t,:d,:s)');
            $cap->execute([
                ':uid' => $userId,
                ':cid' => (int) $conversationId,
                ':mid' => $assistantMessageId,
                ':q' => $message,
                ':a' => $answer,
                ':t' => 'unanswered',
                ':d' => 'auto_detected_unavailable_or_unanswered',
                ':s' => 'pending_review',
            ]);
        } catch (Throwable $e) { /* best effort */ }
    }

    flux_json(200, [
        'conversation' => flux_conversation_payload(flux_get_conversation($conn, (int) $conversationId, $userId) ?: $conv),
        'user_message' => ['id' => $userMessageId, 'role' => 'user', 'content' => $message, 'created_at' => date('c')],
        'assistant_message' => ['id' => $assistantMessageId, 'role' => 'assistant', 'content' => $answer, 'created_at' => date('c'), 'meta' => ['type' => 'answer']],
        'configured' => true,
    ]);
}

if ($action === 'capture' || $action === 'feedback') {
    $conversationId = filter_var($data->conversation_id ?? 0, FILTER_VALIDATE_INT);
    $messageId = filter_var($data->message_id ?? 0, FILTER_VALIDATE_INT);
    $question = isset($data->question) ? security_clean_text((string) $data->question, 2000) : null;
    $assistantResponse = isset($data->assistant_response) ? security_clean_text((string) $data->assistant_response, 8000) : null;
    $captureType = isset($data->capture_type) ? security_clean_text((string) $data->capture_type, 40) : 'feedback';
    $detail = isset($data->detail) ? security_clean_text((string) $data->detail, 2000) : null;

    $allowedTypes = ['unanswered', 'correction', 'feedback', 'mistake'];
    if (!in_array($captureType, $allowedTypes, true)) $captureType = 'feedback';

    // If conversation provided, ensure ownership
    if ($conversationId !== false && $conversationId > 0) {
        $conv = flux_get_conversation($conn, (int) $conversationId, $userId);
        if (!$conv) flux_json(404, ['message' => 'Conversation not found.']);
    } else {
        $conversationId = null;
    }
    if ($messageId === false || $messageId < 1) $messageId = null;

    try {
        $stmt = $conn->prepare(
            'INSERT INTO flux_learning_captures (user_id, conversation_id, message_id, question, assistant_response, capture_type, detail, status)
             VALUES (:uid, :cid, :mid, :q, :a, :t, :d, :s)'
        );
        $stmt->execute([
            ':uid' => $userId,
            ':cid' => $conversationId,
            ':mid' => $messageId,
            ':q' => $question !== '' ? $question : null,
            ':a' => $assistantResponse !== '' ? $assistantResponse : null,
            ':t' => $captureType,
            ':d' => $detail !== '' ? $detail : null,
            ':s' => 'pending_review',
        ]);
        $id = (int) $conn->lastInsertId();
        audit_log($conn, $userId, 'flux.learning_captured', ['entity_type' => 'flux_learning_capture', 'entity_id' => $id, 'meta' => ['type' => $captureType]]);
        flux_json(201, ['message' => 'Feedback captured for review.', 'id' => $id]);
    } catch (Throwable $e) {
        error_log('FLUX capture failed: ' . $e->getMessage());
        flux_json(500, ['message' => 'Could not capture feedback right now.']);
    }
}

flux_json(400, ['message' => 'Unsupported action.']);
