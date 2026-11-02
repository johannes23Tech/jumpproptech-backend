<?php
require_once '../../config/db.php';

$data = json_decode(file_get_contents("php://input"));

if (empty($data->email)) {
    http_response_code(400);
    echo json_encode(["message" => "Email is required."]);
    exit();
}

$email = $data->email;

// 1. Check if user exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
$stmt->execute([':email' => $email]);

if ($stmt->rowCount() === 0) {
    // For security, don't reveal if email exists or not, but we will for this demo
    http_response_code(404);
    echo json_encode(["message" => "No account found with that email address."]);
    exit();
}

// 2. Generate a secure token
$token = bin2hex(random_bytes(32));

// 3. Save the token (delete old ones for this email first)
$conn->prepare("DELETE FROM password_resets WHERE email = :email")->execute([':email' => $email]);
$insert = $conn->prepare("INSERT INTO password_resets (email, token) VALUES (:email, :token)");
$insert->execute([':email' => $email, ':token' => $token]);

// 4. In Phase 3, we will email this link using PHPMailer.
// For now, we return it in the JSON so we can test the flow!
$resetLink = "https://jumpproptech-frontend.vercel.app/reset-password?token=" . $token;

http_response_code(200);
echo json_encode([
    "message" => "Reset link generated.",
    "debug_link" => $resetLink // <-- We will remove this in Phase 3
]);
?>