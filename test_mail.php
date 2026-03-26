<?php
require 'send_otp.php';

$email = 'youremail@gmail.com';  // email nhận thử
$username = 'TestUser';
$otp = rand(100000,999999);

if(sendOTPLogin($email, $username, $otp)){
    echo "OTP sent successfully!";
} else {
    echo "Failed to send OTP.";
}