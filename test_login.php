<?php
/* test_login.php - Full test login with OTP */

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

/* ====== Load required files ====== */
require 'send_otp.php';  // chứa các hàm sendOTPLogin/sendOTPRegister
require '../Database/database.php'; // DB connection nếu muốn lưu user (tùy bạn)

/* ====== Test data ====== */
$test_user = [
    'id' => 1,
    'username' => 'TestUser',
    'email' => 'youremail@gmail.com', // Thay email test của bạn
    'role' => 'user'
];

/* ====== Simulate pending login session ====== */
$_SESSION['pending_user'] = $test_user;

/* ====== Send OTP ====== */
$otp = random_int(100000, 999999);
$_SESSION['otp'] = password_hash($otp, PASSWORD_DEFAULT);
$_SESSION['otp_time'] = time();
$_SESSION['otp_attempts'] = 0;
$_SESSION['otp_locked'] = false;

echo "Sending OTP...\n";
$sent = sendOTPLogin($test_user['email'], $test_user['username'], $otp);

if ($sent) {
    echo "✅ OTP sent successfully to {$test_user['email']}. OTP is: {$otp} (for testing)\n";
} else {
    echo "❌ Failed to send OTP. Check send_otp.php or email settings.\n";
    exit;
}

/* ====== Verify OTP simulation ====== */
echo "Enter OTP to verify: ";
$handle = fopen("php://stdin", "r");
$input_otp = trim(fgets($handle));

if (password_verify($input_otp, $_SESSION['otp'])) {
    echo "✅ OTP verified successfully!\n";
    // Simulate login session creation
    $_SESSION['user_id'] = $_SESSION['pending_user']['id'];
    $_SESSION['user_name'] = $_SESSION['pending_user']['username'];
    $_SESSION['role'] = $_SESSION['pending_user']['role'];
    unset($_SESSION['pending_user'], $_SESSION['otp'], $_SESSION['otp_time'], $_SESSION['otp_attempts'], $_SESSION['otp_locked']);
    echo "User logged in as {$_SESSION['user_name']}\n";
} else {
    echo "❌ Wrong OTP!\n";
}
fclose($handle);