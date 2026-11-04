<?php
require_once '../../config/db.php';
require_once '../../middleware/check_role.php';

// Authenticate the user (requires a valid JWT token)
$user = authenticate();

$data = json_decode(file_get_contents("php://input"));

if (empty($data->currentPassword) || empty($data->newPassword)) {
    http_response_code(400);
    echo json_encode(["message" => "Both current and new passwords are required."]);
    exit();
}

try {
    // 1. Fetch the current user's password hash
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = :user_id LIMIT 1");
    $stmt->execute([':user_id' => $user->user_id]);
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$userData) {
        http_response_code(404);
        echo json_encode(["message" => "User not found."]);
        exit();
    }

    // 2. Verify the current password
    if (!password_verify($data->currentPassword, $userData['password_hash'])) {
        http_response_code(401);
        echo json_encode(["message" => "Incorrect current password."]);
        exit();
    }

    // 3. Hash the new password
    $newHash = password_hash($data->newPassword, PASSWORD_BCRYPT);

    // 4. Update the password
    $update = $conn->prepare("UPDATE users SET password_hash = :hash WHERE id = :user_id");
    $update->execute([':hash' => $newHash, ':user_id' => $user->user_id]);

    http_response_code(200);
    echo json_encode(["message" => "Password updated successfully."]);
} catch (Exception $e) {
    error_log("Password change failed: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["message" => "Failed to update password. Please try again."]);
}
?>