<?php
require_once '../config/db.php';
require_once '../config/security.php';
require_once '../middleware/check_role.php';

authenticate();

$faqs = [
    [
        'id' => 'rent',
        'question' => 'How do I check or pay my rent?',
        'pattern' => '/\b(rent|rental|payment|paid|pay)\b/i',
        'answer' => 'Your rent amount and due date are set by your lease. Check the Rent section or your lease for details. If you have a payment issue, message your landlord or property manager.',
    ],
    [
        'id' => 'maintenance',
        'question' => 'How do I report a maintenance problem?',
        'pattern' => '/\b(maintenance|repair|broken|leak|damage)\b/i',
        'answer' => 'Submit a maintenance request in the Maintenance section and include a clear description of the problem. For urgent issues, contact your landlord or property manager directly.',
    ],
    [
        'id' => 'lease',
        'question' => 'Where can I find my lease?',
        'pattern' => '/\b(lease|contract|agreement)\b/i',
        'answer' => 'Check the lease or documents area in your account. If your lease is not available there, message your landlord or property manager.',
    ],
    [
        'id' => 'messages',
        'question' => 'How do I contact my landlord or property manager?',
        'pattern' => '/\b(message|messages|contact|landlord|manager|property\s+manager)\b/i',
        'answer' => 'Use the Messages section to contact your landlord or property manager.',
    ],
    [
        'id' => 'password',
        'question' => 'How do I change or reset my password?',
        'pattern' => '/\b(password|login|sign\s+in|account)\b/i',
        'answer' => 'If you can sign in, use the Change Password option in your account. If you cannot sign in, use Forgot Password on the login screen.',
    ],
    [
        'id' => 'property',
        'question' => 'Where can I see my property or unit details?',
        'pattern' => '/\b(property|properties|unit|units|address)\b/i',
        'answer' => 'Your available property and unit information is shown in your account. If details are missing or incorrect, message your landlord or property manager.',
    ],
];

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'GET') {
    $questions = array_map(static function (array $faq): array {
        return ['id' => $faq['id'], 'question' => $faq['question']];
    }, $faqs);
    security_json_response(200, ['faqs' => $questions]);
}

if ($method !== 'POST') {
    security_json_response(405, ['message' => 'Method not allowed.'], ['Allow' => 'GET, POST']);
}

$data = json_decode(file_get_contents('php://input'));
if (!is_object($data) || !isset($data->question) || !is_string($data->question)) {
    security_json_response(400, ['message' => 'A question is required.']);
}

$question = security_clean_text($data->question, 500);
if ($question === '') {
    security_json_response(400, ['message' => 'A question is required.']);
}

foreach ($faqs as $faq) {
    if (preg_match($faq['pattern'], $question)) {
        security_json_response(200, [
            'faq_id' => $faq['id'],
            'answer' => $faq['answer'],
        ]);
    }
}

security_json_response(200, [
    'faq_id' => null,
    'answer' => 'I can help with rent, maintenance, leases, contacting your property manager, passwords, and property or unit details. Please choose a suggested question or contact your landlord or property manager for help with something specific.',
]);
