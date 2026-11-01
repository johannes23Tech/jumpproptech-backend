<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$data = json_decode(file_get_contents("php://input"));

// Simulate sending email
// In reality, you would use PHPMailer here to send an actual PDF attachment.

http_response_code(200);
echo json_encode(["message" => "Receipt successfully emailed to " . $data->email]);
?>