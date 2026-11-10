<?php
// config/mailer.php - Modern mailer configuration

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/config.php';

function sendEmail($to, $subject, $body, $altBody = '') {
    $mail = new PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = getenv('MAIL_HOST') ?: 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        
        $mail->Username   = getenv('MAIL_USERNAME');
        $mail->Password   = getenv('MAIL_PASSWORD');

        // MAIL_ENCRYPTION: "ssl" (implicit TLS), "tls" (STARTTLS, default),
        // or "none" for a local capture server. Production must use ssl/tls.
        $encryption = strtolower((string) getenv('MAIL_ENCRYPTION'));
        if ($encryption === 'ssl') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        } elseif ($encryption === 'none') {
            $mail->SMTPSecure = '';
            $mail->SMTPAutoTLS = false;
        } else {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        }

        $mail->Port       = intval(getenv('MAIL_PORT')) ?: 587;

        // Recipients
        $mail->setFrom(getenv('MAIL_FROM') ?: getenv('MAIL_USERNAME'), getenv('MAIL_FROM_NAME') ?: 'Jump PropTech');
        $mail->addAddress($to);

        // Content
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $body;
        if ($altBody) {
            $mail->AltBody = $altBody;
        }

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Message could not be sent. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
}
