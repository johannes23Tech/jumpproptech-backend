<?php
require_once '../config/db.php';

$email = 'admin@jumpliving.co.za';
$newPassword = 'SuperAdmin123';
$hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);

$stmt = $conn->prepare("UPDATE users SET password_hash = :hash WHERE email = :email");
$stmt->execute([':hash' => $hashedPassword, ':email' => $email]);

echo json_encode(["message" => "Admin password updated successfully to SuperAdmin123"]);
?>