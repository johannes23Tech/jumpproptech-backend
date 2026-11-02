<?php
require_once '../config/db.php';
require_once '../config/mailer.php';
require_once '../middleware/check_role.php';

$user = authenticate();
$data = json_decode(file_get_contents("php://input"));

$emailBody = "
    <div style='font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #E5DDCD; border-radius: 8px;'>
        <h2 style='color: #C5A059;'>Jump PropTech Payment Receipt</h2>
        <p>Thank you for your payment. Your receipt details are below:</p>
        <div style='background: #FAF7F2; padding: 20px; border-radius: 8px; margin: 20px 0;'>
            <p style='margin: 5px 0;'><strong>Receipt Number:</strong> {$data->receipt_number}</p>
            <p style='margin: 5px 0;'><strong>Status:</strong> <span style='color: #2E7D32; font-weight: bold;'>PAID</span></p>
        </div>
        <p>You can log in to your tenant portal to download the official PDF copy of this receipt.</p>
        <br>
        <p style='font-size: 12px; color: #888; text-align: center;'>Smarter Property Management. Stronger Communities.</p>
    </div>
";

$emailSent = sendEmail($data->email, "Payment Receipt - {$data->receipt_number}", $emailBody);

if ($emailSent) {
    http_response_code(200);
    echo json_encode(["message" => "Receipt emailed successfully!"]);
} else {
    http_response_code(500);
    echo json_encode(["message" => "Failed to send email."]);
}
?>