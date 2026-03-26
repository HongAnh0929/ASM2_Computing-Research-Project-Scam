<?php
// send_otp.php
// Full code gửi OTP cho login và register

session_start();

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require '../vendor/autoload.php'; // PHPMailer autoload
require '../Database/database.php'; // nếu cần truy vấn DB

/* ================== OTP SEND FUNCTIONS ================== */

/**
 * Gửi OTP cho đăng nhập
 */
function sendOTPLogin($email, $username, $otp){
    return sendOTP($email, $username, $otp);
}

/**
 * Gửi OTP cho đăng ký
 */
function sendOTPRegister($email, $username, $otp){
    return sendOTP($email, $username, $otp);
}

/**
 * Hàm chính gửi email OTP
 */
function sendOTP($email, $username, $otp){
    $mail = new PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = your.gmail.com;
        $mail->SMTPAuth   = true;
        $mail->Username   = yourgmail.gmail.com; // Gmail gửi
        $mail->Password   = your_app_password;       // App Password Gmail
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = your_port;

        // Recipients
        $mail->setFrom( yourgmail.gmail.com, your_from_name);
        $mail->addAddress($email, $username);

        // Content
        $mail->isHTML(true);
        $mail->Subject = "[SCAM BTEC] OTP verification code - {$otp}";
        $mail->Body    = "<div style='font-family:Arial,sans-serif;line-height:1.6'>
                            <p>Dear {$username},</p>
                            <p>Your OTP is:</p>
                            <h2 style='color:red;'>{$otp}</h2>
                            <p>SCAM BTEC System<br>Building a Safe Digital World</p>
                          </div>";
        $mail->AltBody = "Dear {$username}, Your OTP is: {$otp}";

        $mail->send();

        // Log OTP for testing
        error_log("OTP sent to {$email}: {$otp}");
        return true;

    } catch (Exception $e) {
        error_log("OTP send failed to {$email}: {$mail->ErrorInfo}");
        return false;
    }
}

/* ================== CLI TEST ================== */
if (php_sapi_name() === 'cli') {
    $test_email =  yourgmail.gmail.com; // Thay bằng email test
    $test_user = 'TestUser';
    $test_otp = random_int(100000, 999999);

    if (sendOTPLogin($test_email, $test_user, $test_otp)) {
        echo "✅ OTP sent successfully to {$test_email}\n";
    } else {
        echo "❌ Failed to send OTP. Check send_otp.php or email settings.\n";
    }
}
?>