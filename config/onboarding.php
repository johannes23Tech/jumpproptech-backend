<?php
// config/onboarding.php
//
// Shared helpers for unit-scoped QR onboarding. A QR link is only ever a
// first-time application entry point; it is not a password and it cannot be
// used to log in. Raw tokens are never stored: only the SHA-256 hash is kept.

require_once __DIR__ . '/security.php';

const ONBOARDING_TOKEN_DEFAULT_DAYS = 14;
const ONBOARDING_TOKEN_MAX_DAYS = 90;

/**
 * Create a new unguessable onboarding token. The raw value is returned once,
 * encoded in the QR/application link, and is never persisted.
 */
function onboarding_generate_token(): string
{
    return bin2hex(random_bytes(32));
}

function onboarding_token_hash(string $token): string
{
    return hash('sha256', $token);
}

/**
 * Public URL that a unit QR code points at. Uses FRONTEND_URL so the QR is
 * tied to the deployed PWA rather than the API host.
 */
function onboarding_application_url(string $token): string
{
    $base = trim((string) getenv('FRONTEND_URL'));
    if ($base === '') {
        $base = 'https://jumpproptech.vercel.app';
    }

    return rtrim($base, '/') . '/apply/' . rawurlencode($token);
}

/**
 * Load a currently usable token joined to its unit and property.
 *
 * @return array<string,mixed>|null
 */
function onboarding_find_active_token(PDO $conn, string $token): ?array
{
    if ($token === '' || !preg_match('/^[a-f0-9]{64}$/i', $token)) {
        return null;
    }

    $stmt = $conn->prepare(
        "SELECT ot.id AS token_id, ot.unit_id, ot.expires_at,
                u.unit_number, u.monthly_rent, u.archived_at AS unit_archived_at,
                p.name AS property_name, p.address AS property_address,
                b.name AS building_name
         FROM onboarding_tokens ot
         JOIN units u ON ot.unit_id = u.id
         JOIN properties p ON u.property_id = p.id
         LEFT JOIN buildings b ON u.building_id = b.id
         WHERE ot.token_hash = :hash
           AND ot.revoked_at IS NULL
           AND ot.used_at IS NULL
           AND ot.expires_at > NOW()
         LIMIT 1"
    );
    $stmt->execute([':hash' => onboarding_token_hash($token)]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || !empty($row['unit_archived_at'])) {
        return null;
    }

    return $row;
}

/**
 * Validate and normalise the optional application documents payload.
 *
 * @param mixed $documents
 * @return array<int,array{type:string,url:string}>
 */
function onboarding_clean_documents($documents): array
{
    if (!is_array($documents)) {
        return [];
    }

    $allowedTypes = ['id_document', 'proof_of_address', 'other'];
    $clean = [];

    foreach (array_slice($documents, 0, 5) as $document) {
        if (!is_object($document) && !is_array($document)) {
            continue;
        }
        $document = (array) $document;

        $type = isset($document['type']) && is_string($document['type'])
            ? strtolower(trim($document['type']))
            : 'other';
        if (!in_array($type, $allowedTypes, true)) {
            $type = 'other';
        }

        $url = isset($document['url']) && is_string($document['url'])
            ? trim($document['url'])
            : '';
        if (strlen($url) > 500 || strpos($url, 'https://res.cloudinary.com/') !== 0) {
            continue;
        }

        $clean[] = ['type' => $type, 'url' => $url];
    }

    return $clean;
}
