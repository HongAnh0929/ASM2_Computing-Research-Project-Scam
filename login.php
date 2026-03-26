<?php
session_start();
ob_start();
require_once '../Database/database.php';
require_once 'send_otp.php';
require_once '../vendor/autoload.php';
require_once 'functions/translate.php';


$lang = $_SESSION['lang'] ?? 'en';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

$errors = [];

// Xử lý thay đổi ngôn ngữ
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {

    $_SESSION['lang'] = $_GET['lang'];

    // Lấy đúng trang hiện tại (không bị quay về index)
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');

    header("Location: $currentPage");
    exit;
}

/* ===== CSRF ===== */
if(empty($_SESSION['csrf_token'])){
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

/* ===== LOGIN ===== */
if($_SERVER['REQUEST_METHOD'] === 'POST'){

    if(!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])){
        die("CSRF error");
    }

    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $username_hash = hash_hmac('sha256', $username, $secret_key);

    $stmt = $conn->prepare("SELECT * FROM users WHERE username_hash=? LIMIT 1");
    $stmt->bind_param("s", $username_hash);
    $stmt->execute();
    $result = $stmt->get_result();

    if($result->num_rows === 0){
        $errors['general'] = "User not found";
    } else {

        $user = $result->fetch_assoc();

        if($user['is_locked']){
            $errors['general'] = "Account is locked";
        }

        elseif(password_verify($password, $user['password'])){

            /* RESET FAIL */
            $conn->query("UPDATE users SET failed_attempts=0 WHERE id=".$user['id']);

            /* ===== DECRYPT EMAIL ===== */
            $data = base64_decode($user['email_encrypted']);
            $iv = substr($data,0,16);
            $enc = substr($data,16);

            $email = openssl_decrypt($enc,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);

            if(!$email){
                $errors['general'] = "Cannot decrypt email";
            } else {

                /* ===== OTP ===== */
                $otp = random_int(100000,999999);

                $_SESSION['otp'] = password_hash($otp,PASSWORD_DEFAULT);
                $_SESSION['otp_time'] = time();
                $_SESSION['resend_count'] = 0;
                $_SESSION['otp_attempts'] = 0;

                $_SESSION['login_temp'] = [
                    'user_id' => $user['id'],
                    'username' => $username,
                    'role' => $user['role'],
                    'email' => $email
                ];

                sendOTPLogin($email,$username,$otp);

                $_SESSION['otp_message'] = "OTP has been sent to your email.";

                header("Location: verify_otp_login.php");
                exit;
            }

        } else {

            $attempts = $user['failed_attempts'] + 1;

            if($attempts >= 5){
                $conn->query("UPDATE users SET failed_attempts=$attempts, is_locked=1 WHERE id=".$user['id']);
                $errors['general'] = "Account locked (too many attempts)";
            } else {
                $conn->query("UPDATE users SET failed_attempts=$attempts WHERE id=".$user['id']);
                $errors['general'] = "Wrong password ($attempts/5)";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .overlay {
        position: absolute;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        justify-content: center;
        align-items: center;
        color: white;
    }

    /* Nút ngôn ngữ tổng thể */
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
        /* Màu mặc định light */
        color: #334155;
        border: 1px solid #e2e8f0;
    }

    /* Hiệu ứng khi nút đang được chọn (Active) */
    .lang-btn.active {
        background: #0ea5e9;
        /* Màu xanh Primary hiện đại */
        color: white;
        border-color: #0ea5e9;
        box-shadow: 0 0 10px rgba(14, 165, 233, 0.4);
    }

    /* Chỉnh sửa kích thước và hình dáng lá cờ */
    .flag-img {
        width: 20px;
        height: 15px;
        object-fit: cover;
        border-radius: 2px;
        /* Bo góc nhẹ cho lá cờ */
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }

    .lang-btn:hover:not(.active) {
        background: #e2e8f0;
        transform: translateY(-1px);
    }

    .login-box {
        width: 500px;
        background: rgba(0, 0, 0, 0.6);
        padding: 35px;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
    }

    .links {
        display: flex;
        justify-content: space-between;
        margin-top: 15px;
        font-size: 14px;
    }
    </style>
</head>

<body>

    <div class="overlay">
        <?php $lang = $_SESSION['lang'] ?? 'en'; ?>
        <div class="lang-switch position-absolute top-0 end-0 m-3 d-flex gap-2">
            <a href="?lang=en" class="lang-btn <?php echo $lang=='en' ? 'active' : ''; ?>">
                <img src="https://flagcdn.com/w40/gb.png" class="flag-img">
                EN
            </a>

            <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
                <img src="https://flagcdn.com/w40/vn.png" class="flag-img">
                VI
            </a>
        </div>
        <div class="login-box">

            <h3 class="text-center mb-4"><?php echo t("Login");?></h3>

            <?php if(!empty($errors['general'])): ?>
            <div class="alert alert-danger text-center"><?php echo $errors['general']; ?></div>
            <?php endif; ?>

            <form method="POST">

                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="mb-3">

                    <label class="form-label"><?php echo t("Username");?></label>

                    <input type="text" class="form-control" name="username" required>

                </div>

                <div class="mb-3">

                    <label class="form-label"><?php echo t("Password");?></label>

                    <div class="input-group">

                        <input type="password" class="form-control" id="password" name="password" required>

                        <span class="input-group-text" onclick="togglePassword('password',this)">
                            <i class="bi bi-eye"></i>
                        </span>

                    </div>

                </div>

                <div class="d-flex justify-content-between mt-3">

                    <button type="submit" class="btn btn-primary">
                        <?php echo t("Login");?>
                    </button>

                    <a href="index.php" class="btn btn-secondary">
                        <?php echo t("← Back");?>
                    </a>

                </div>

            </form>

            <div class="links">

                <a href="register.php"><?php echo t("Don't have an account? Register here");?></a>

                <a href="forgot_password.php"><?php echo t("Forgot Password?");?></a>

            </div>

        </div>

    </div>

    <script>
    function togglePassword(fieldId, icon) {

        let input = document.getElementById(fieldId);
        let iconTag = icon.querySelector("i");

        if (input.type === "password") {

            input.type = "text";
            iconTag.classList.remove("bi-eye");
            iconTag.classList.add("bi-eye-slash");

        } else {

            input.type = "password";
            iconTag.classList.remove("bi-eye-slash");
            iconTag.classList.add("bi-eye");

        }
    }
    </script>

</body>

</html>