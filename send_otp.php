<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/../vendor/autoload.php';

/* ================= LOAD ENV ================= */
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

/* ================= ESCAPE HTML ================= */
function e($string){
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/* ================= CHECK ENV ================= */
if (
    empty($_ENV['MAIL_HOST']) ||
    empty($_ENV['MAIL_USERNAME']) ||
    empty($_ENV['MAIL_PASSWORD']) ||
    empty($_ENV['MAIL_PORT'])
){
    die('Mail config not set in .env');
}

/* ================= MAIL CONFIG ================= */
function getMailer(){

    $mail = new PHPMailer(true);

    try {

        $mail->isSMTP();
        $mail->Host = $_ENV['MAIL_HOST'];
        $mail->SMTPAuth = true;

        $mail->Username = $_ENV['MAIL_USERNAME'];
        $mail->Password = $_ENV['MAIL_PASSWORD'];

        /* SMTP Encryption */
        $mail->SMTPSecure =
            $_ENV['MAIL_ENCRYPTION'] === 'ssl'
            ? PHPMailer::ENCRYPTION_SMTPS
            : PHPMailer::ENCRYPTION_STARTTLS;

        $mail->Port = $_ENV['MAIL_PORT'];

        $mail->CharSet = 'UTF-8';
        $mail->Encoding = 'base64';

        $mail->setFrom(
            $_ENV['MAIL_FROM_EMAIL'],
            $_ENV['MAIL_FROM_NAME']
        );

        /* Timeout */
        $mail->Timeout = 10;

        /* Debug */
        $mail->SMTPDebug = 0;

        return $mail;

    } catch (Exception $e) {

        error_log("Mailer Config Error: ".$e->getMessage());
        return null;
    }
}

/* ================= SEND MAIL CORE ================= */
function sendMail($to, $subject, $body, $altBody = ''){

    $mail = getMailer();

    if(!$mail){
        return false;
    }

    try {

        $mail->addAddress($to);

        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $body;
        $mail->AltBody = $altBody ?: strip_tags($body);

        if(!$mail->send()){
echo "Mailer Error: " . $mail->ErrorInfo;
return false;
}

        return true;

    } catch (Exception $e) {

        error_log(
            date('Y-m-d H:i:s')
            ." Mail Error: "
            .$mail->ErrorInfo
            ."\n",
            3,
            __DIR__.'/mail_error.log'
        );

        return false;
    }
}

/* ================= EMAIL TEMPLATE ================= */
function buildTemplate($content){

    return "
    <div style='
        font-family:Arial,sans-serif;
        line-height:1.6;
        max-width:600px;
        margin:auto;
        padding:10px'>

        $content

        <hr>

        <p style='font-size:12px;color:gray'>
            SCAM BTEC System<br>
            Building a Safer Digital World
        </p>

    </div>
    ";
}

/* ================= OTP REGISTER ================= */
function sendOTPRegister($email, $username, $otp){
    $safeOTP = e($otp);
    $safeUsername = e($username);
    $subject = "[SCAM BTEC] OTP verification code - $safeOTP";

    $content = "
    <div>
        <p>Dear $safeUsername,</p>

        <p>We have received a request to confirm your personal information on the SCAM BTEC system. 
        To complete this process, please use the OTP code below:</p>

        <h2 style='color:red;'>$safeOTP</h2>

        <p>(This code is valid for 3 minutes and can only be used once)</p>

        <p><b>Security Notice:</b></p>
        <ul>
            <li>DO NOT share this code with anyone, including SCAM BTEC staff.</li>
            <li>If you did not make this request, please ignore this email or contact support immediately.</li>
        </ul>

        <p>Best regards,<br>
        SCAM BTEC Development Team</p>
    </div>
    ";
    return sendMail($email,$subject,buildTemplate($content),"Your OTP is: $safeOTP");
}

/* ================= OTP LOGIN ================= */
function sendOTPLogin($email, $username, $otp){
    $safeOTP = e($otp);
    $safeUsername = e($username);
    $subject = "[SCAM BTEC] OTP verification code - $safeOTP";

    $content = "
    <div>
        <p>Dear $safeUsername,</p>

        <p>The SCAM BTEC system has received a login request for your account. 
        To ensure security and verify ownership, please use the OTP code below to complete the login process:</p>

        <h2 style='color:red;'>$safeOTP</h2>

        <p>(This code is valid for 3 minutes and can only be used once)</p>

        <p><b>Security Warning:</b></p>
        <ul>
            <li>DO NOT share this code with anyone, including support staff.</li>
            <li>If you did not request this login, please ignore this email or change your password immediately.</li>
        </ul>

        <p>Our system is committed to protecting your data and privacy under strict security standards.</p>

        <p>Best regards,<br>
        SCAM BTEC Technical Team<br>
        Building a Safer Digital World</p>
    </div>
    ";
    return sendMail($email,$subject,buildTemplate($content),"Your OTP is: $safeOTP");
}

/* ================= SUCCESS EMAIL ================= */
function sendSuccessEmail($email, $username){
    $safeUsername = e($username);
    $subject = "[SCAM BTEC] Account activation successful";

    $content = "
    <div>
        <p>🎉 Dear $safeUsername,</p>

        <p>We are pleased to inform you that your account has been successfully created and activated on the SCAM BTEC system.</p>

        <p>Your participation plays an important role in strengthening the digital security network that we are building.</p>

        <p>From now on, all risk analysis features and warning databases are available for you.</p>

        <p>Our system operates under strict security standards to ensure transparency and maximum safety.</p>

        <p>If you have any questions, our technical team is always ready to assist you.</p>

        <p>Welcome to the SCAM BTEC community – Building a Safer Digital World.</p>

        <p>Best regards,<br>
        SCAM BTEC Management Board</p>
    </div>
    ";
    return sendMail($email,$subject,buildTemplate($content));
}

/* ================= OTP RESET PASSWORD ================= */
function sendOTPReset($email, $username, $otp){
    $safeOTP = e($otp);
    $safeUsername = e($username);
    $subject = "[SCAM BTEC] Password Reset Request - $safeOTP";

    $content = "
    <div>
        <p>Dear $safeUsername,</p>

        <p>The SCAM BTEC system has received a request to reset the password for the account associated with this email address. 
        To continue the verification process and set a new password, please enter the OTP code below:</p>

        <h2 style='color:red;'>$safeOTP</h2>

        <p>(This OTP is valid for 5 minutes and will automatically expire after a single use)</p>

        <p><b>Security Advice:</b></p>
        <ul>
            <li>Do NOT share this OTP with anyone, including SCAM BTEC staff.</li>
            <li>If you did not request a password reset, please ignore this email. Your account remains secure.</li>
            <li>If you suspect unauthorized access, please check your account security or contact our support team immediately.</li>
        </ul>

        <p>We are committed to applying the strictest security standards to protect your digital identity.</p>

        <p>Best regards,<br>
        SCAM BTEC Management Board<br>
        Building a Safer Digital World</p>
    </div>
    ";
    return sendMail($email,$subject,buildTemplate($content),"Your OTP is: $safeOTP");
}
?>