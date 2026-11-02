<?php
require_once '../../config/db.php';
require_once '../../config/mailer.php'; // Import the mailer

$data = json_decode(file_get_contents("php://input"));

if (empty($data->email)) {
    http_response_code(400);
    echo json_encode(["message" => "Email is required."]);
    exit();
}

$email = $data->email;

$stmt = $conn->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
$stmt->execute([':email' => $email]);

if ($stmt->rowCount() === 0) {
    http_response_code(404);
    echo json_encode(["message" => "No account found with that email address."]);
    exit();
}

$token = bin2hex(random_bytes(32));

$conn->prepare("DELETE FROM password_resets WHERE email = :email")->execute([':email' => $email]);
$insert = $conn->prepare("INSERT INTO password_resets (email, token) VALUES (:email, :token)");
$insert->execute([':email' => $email, ':token' => $token]);

// Create the reset link
$resetLink = "https://jumpproptech-frontend.vercel.app/reset-password?token=" . $token;

// Professional HTML Email Body
$emailBody = "
    <div style='font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #E5DDCD; border-radius: 8px;'>
        <h2 style='color: #C5A059;'>Jump PropTech Password Reset</h2>
        <p>Hello,</p>
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        <div style='text-align: center; margin: 30px 0;'>
            <a href='{$resetLink}' style='display: inline-block; padding: 14px 28px; background-color: #C5A059; color: #000; text-decoration: none; font-weight: bold; border-radius: 6px;'>Reset Password</a>
        </div>
        <p>If you didn't request this change, you can safely ignore this email.</p>
        <br>
        <p style='font-size: 12px; color: #888; text-align: center;'>Smarter Property Management. Stronger Communities.</p>
    </div>
";

// Send the email
$emailSent = sendEmail($email, "Reset Your Jump PropTech Password", $emailBody);

if ($emailSent) {
    http_response_code(200);
    echo json_encode(["message" => "Password reset link sent to your email. Please check your inbox."]);
} else {
    http_response_code(500);
    echo json_encode(["message" => "Failed to send email. Please try again later."]);
}
?>