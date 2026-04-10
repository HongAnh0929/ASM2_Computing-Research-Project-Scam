<?php
session_start();
ob_start();

require '../Database/database.php';
require_once '../vendor/autoload.php';
require_once 'send_otp.php';
require_once 'functions/translate.php';

use Dotenv\Dotenv;

/* ===== ENV ===== */
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'];

/* ===== CSRF ===== */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ===== DEFAULT VALUES (FIX BUG UNDEFINED VARIABLE) ===== */
$lang = $_SESSION['lang'] ?? 'en';
$message = "";

$username = "";
$email = "";

/* ===== POST ===== */
if (isset($_POST['check_user'])) {

    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("CSRF error");
    }

    $username = trim($_POST['username']);
    $email    = strtolower(trim($_POST['email']));

    /* ===== HASH ===== */
    $username_hash = hash_hmac('sha256', $username, $secret_key);
    $email_hash    = hash_hmac('sha256', $email, $secret_key);

    /* ===== QUERY ===== */
    $stmt = $conn->prepare("
        SELECT id, email_encrypted 
        FROM users 
        WHERE username_hash=? AND email_hash=?
        LIMIT 1
    ");
    $stmt->bind_param("ss", $username_hash, $email_hash);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {

        $user = $result->fetch_assoc();

        /* ===== DECRYPT EMAIL ===== */
        $data = base64_decode($user['email_encrypted']);
        $iv = substr($data, 0, 16);
        $enc = substr($data, 16);

        $email_real = openssl_decrypt(
            $enc,
            'aes-256-cbc',
            $secret_key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if (!$email_real) {
            $message = "Cannot decrypt email";
        } else {

            /* ===== OTP ===== */
            $otp = random_int(100000, 999999);

            $_SESSION['otp_hash']   = password_hash($otp, PASSWORD_DEFAULT);
            $_SESSION['otp_time']   = time();
            $_SESSION['otp_email']  = $email_real;
            $_SESSION['reset_user'] = $user['id'];

            /* ===== SEND OTP ===== */
            $sent = sendOTPReset($email_real, $username, $otp);

            if ($sent) {

                $_SESSION['otp_message'] = "OTP sent";

                header("Location: verify_otp.php");
                exit;

            } else {
                $message = "Send OTP failed";
            }
        }

    } else {
        $message = "Invalid account";
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo t("Forgot Password"); ?></title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">

    <style>
    body {
        background: url("img/background.png") center/cover;
        margin: 0;
    }

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
    }

    .form-box {
        max-width: 450px;
        width: 100%;
        background: rgba(0, 0, 0, 0.6);
        padding: 30px;
        border-radius: 10px;
    }

    .lang-btn {
        display: flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        text-decoration: none;
        transition: all 0.3s ease;
        background: #f8f9fa;
        color: #334155;
        border: 1px solid #e2e8f0;
    }

    .lang-btn.active {
        background: #0ea5e9;
        color: white;
        border-color: #0ea5e9;
        box-shadow: 0 0 10px rgba(14, 165, 233, 0.4);
    }

    .flag-img {
        width: 20px;
        height: 15px;
        object-fit: cover;
        border-radius: 2px;
    }

    .lang-btn:hover:not(.active) {
        background: #e2e8f0;
    }
    </style>
</head>

<body>
<div class="overlay">

    <!-- LANGUAGE -->
    <div class="lang-switch position-absolute top-0 end-0 m-3 d-flex gap-2">
        <a href="?lang=en" class="lang-btn <?php echo $lang == 'en' ? 'active' : ''; ?>">
            <img src="https://flagcdn.com/w40/gb.png" class="flag-img">
            <span class="ms-1">EN</span>
        </a>

        <a href="?lang=vi" class="lang-btn <?php echo $lang == 'vi' ? 'active' : ''; ?>">
            <img src="https://flagcdn.com/w40/vn.png" class="flag-img">
            <span class="ms-1">VI</span>
        </a>
    </div>

    <!-- FORM -->
    <div class="form-box">
        <h3 class="mb-4 text-center"><?php echo t("Forgot Password"); ?></h3>

        <?php if ($message != "") { ?>
            <div class="alert alert-info">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php } ?>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <input type="text" name="username" class="form-control mb-3"
                placeholder="<?php echo t('Enter username'); ?>"
                value="<?php echo htmlspecialchars($username ?? ''); ?>"
                required>

            <input type="email" name="email" class="form-control mb-3"
                placeholder="<?php echo t('Enter Gmail address'); ?>"
                value="<?php echo htmlspecialchars($email ?? ''); ?>"
                required>

            <button type="submit" name="check_user" class="btn btn-primary w-100 mb-3">
                <i class="bi bi-send"></i> <?php echo t("Send OTP"); ?>
            </button>
        </form>
    </div>

</div>
</body>
</html>