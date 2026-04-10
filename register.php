<?php
session_start();

require_once '../Database/database.php';
require_once '../vendor/autoload.php';
require_once 'send_otp.php';
require_once 'functions/translate.php';

use Dotenv\Dotenv;

/* ===== LOAD ENV ===== */
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

if(empty($_ENV['SECRET_KEY'])) die("SECRET_KEY missing");

$HASH_KEY = $_ENV['SECRET_KEY'];
$ENC_KEY  = $_ENV['SECRET_KEY'];

/* ===== LANG ===== */
// Xử lý thay đổi ngôn ngữ
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {

    $_SESSION['lang'] = $_GET['lang'];

    // Lấy đúng trang hiện tại (không bị quay về index)
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');

    header("Location: $currentPage");
    exit;
}

$lang = $_SESSION['lang'] ?? 'en';
$lang = ($lang === 'vi') ? 'vi' : 'en';

/* ===== ENCRYPT ===== */
function encryptData($data) {
    global $ENC_KEY;
    $iv = random_bytes(16);
    $enc = openssl_encrypt($data, 'aes-256-cbc', $ENC_KEY, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $enc);
}

/* ===== CSRF ===== */
if(!isset($_SESSION['csrf_token'])){
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

/* ===== INIT ===== */
$errors = [];
$username = $email = $phone = $dob = $gender = "";

/* ===== HELPER ===== */
function normalizePhone($phone){
    $phone = preg_replace('/\D/', '', $phone);
    if(substr($phone,0,1) == '0'){
        $phone = '84'.substr($phone,1);
    }
    return $phone;
}

/* ===================== HANDLE POST ===================== */
if($_SERVER['REQUEST_METHOD'] === 'POST'){

    /* ===== CSRF ===== */
    if(empty($_POST['csrf_token']) || 
       !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])){
        die("CSRF error");
    }

    /* ===== DATA ===== */
    $username = trim($_POST['username'] ?? '');
    $email    = strtolower(trim($_POST['email'] ?? ''));
    $phoneRaw = $_POST['phone'] ?? '';
    $phone    = normalizePhone($phoneRaw);
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm_password'] ?? '';
    $dob      = $_POST['dob'] ?? '';
    $gender   = $_POST['gender'] ?? '';

    /* ===== CAPTCHA CHECK (FIXED) ===== */
    $captcha_secret   = $_ENV['CAPTCHA_KEY'] ?? '';
    $captcha_response = $_POST['g-recaptcha-response'] ?? '';

    if(empty($captcha_response)){
        $errors['captcha'] = "Please complete the CAPTCHA.";
    } else {

        $verify = file_get_contents(
            "https://www.google.com/recaptcha/api/siteverify?secret=$captcha_secret&response=$captcha_response"
        );

        $captcha_data = json_decode($verify, true);

        if(empty($captcha_data['success'])){
            $errors['captcha'] = "CAPTCHA verification failed.";
        }
    }

    /* ===== VALIDATION ===== */
    if(!preg_match('/^[A-Za-z0-9_]{6,20}$/',$username)){
        $errors['username'] = "Username must be 6-20 characters";
    }

    if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
        $errors['email'] = "Invalid email";
    }

    if(!preg_match('/^[0-9]{10}$/',$phoneRaw)){
        $errors['phone'] = "Phone must be 10 digits";
    }

    if(!$dob || $dob > date('Y-m-d')){
        $errors['dob'] = "Invalid date of birth";
    }

    if(!$gender){
        $errors['gender'] = "Select gender";
    }

    if(!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,20}$/',$password)){
        $errors['password'] = "Weak password";
    }

    if($password !== $confirm){
        $errors['confirm'] = "Password mismatch";
    }

    /* ===== IF OK → SEND OTP ===== */
    if(empty($errors)){

        $_SESSION['register_data'] = [
            'username_encrypted' => encryptData($username),
            'email_encrypted'    => encryptData($email),
            'phone_encrypted'    => encryptData($phone),
            'dob_encrypted'      => encryptData($dob),
            'gender_encrypted'   => encryptData($gender),

            'username_hash' => hash_hmac('sha256',$username,$HASH_KEY),
            'email_hash'    => hash_hmac('sha256',$email,$HASH_KEY),
            'phone_hash'    => hash_hmac('sha256',$phone,$HASH_KEY),

            'password' => password_hash($password,PASSWORD_DEFAULT)
        ];

        $otp = random_int(100000,999999);

        $_SESSION['otp'] = password_hash($otp,PASSWORD_DEFAULT);
        $_SESSION['otp_time'] = time();

        if(sendOTPRegister($email,$username,$otp)){
            $_SESSION['otp_message'] = "OTP sent successfully.";
            header("Location: verify_otp_register.php");
            exit;
        } else {
            $errors['general'] = "Send OTP failed";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title><?php echo t("Register"); ?></title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <script src="https://www.google.com/recaptcha/api.js?hl=<?php echo $lang; ?>" async defer></script>
    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 40px 0;
    }

    .overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.6);
        z-index: -1;
    }

    .register-box {
        position: relative;
        width: 100%;
        max-width: 550px;
        /* nhỏ ngang hơn */
        background: rgba(0, 0, 0, 0.6);
        padding: 25px 20px;
        /* giảm chiều cao */
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
        z-index: 1;
        color: white;
    }

    .register-box h3 {
        font-weight: 700;
    }

    /* Nút chuyển ngôn ngữ cố định trên cùng bên phải */
    .lang-switcher-top {
        position: fixed;
        top: 10px;
        right: 20px;
        z-index: 9999;
        display: flex;
        gap: 8px;
    }

    /* Các nút ngôn ngữ */
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
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }

    .lang-btn:hover:not(.active) {
        background: #e2e8f0;
        transform: translateY(-1px);
    }

    .form-control {
        border-radius: 8px;
    }

    .form-control:focus {
        box-shadow: 0 0 5px rgba(13, 110, 253, .5);
    }

    .error {
        color: red;
        font-size: 13px;
    }

    .strength {
        font-size: 13px;
        margin-top: 3px;
    }

    .btn-primary {
        border-radius: 8px;
        width: 120px;
    }

    .btn-secondary {
        border-radius: 8px;
        width: 120px;
    }

    .rule {
        display: flex;
        align-items: center;
        gap: 6px;
        opacity: 0.4;
        transition: 0.3s;
    }

    .rule i {
        color: gray;
    }

    .rule.valid {
        opacity: 1;
        color: #4ade80;
    }

    .rule.valid i {
        color: #4ade80;
    }

    .links {
        display: flex;
        justify-content: space-between;
        margin-top: 15px;
    }
    </style>
</head>

<body>

    <div class="overlay"></div>

    <!-- LANG -->
    <?php $lang = $_SESSION['lang'] ?? 'en'; ?>
    <div class="lang-switcher-top">
        <a href="?lang=en" class="lang-btn <?php echo $lang=='en' ? 'active' : ''; ?>">
            <img src="https://flagcdn.com/w40/gb.png" class="flag-img" alt="English">
            <span class="ms-1">EN</span>
        </a>

        <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
            <img src="https://flagcdn.com/w40/vn.png" class="flag-img" alt="Vietnamese">
            <span class="ms-1">VI</span>
        </a>
    </div>

    <div class="register-box">

        <h3 class="text-center mb-4"><?php echo t("Register"); ?></h3>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

            <!-- Username -->
            <div class="mb-3">
                <label class="form-label"><?php echo t("Username"); ?></label>
                <input type="text" class="form-control" name="username" placeholder="<?php echo t("Enter username"); ?>"
                    value="<?php echo htmlspecialchars($username); ?>" required>
            </div>
            <div class="error">
                <?php echo $errors['username'] ?? '' ?>
            </div>

            <!-- Email -->
            <div class="mb-3">
                <label class="form-label"><?php echo t("Email"); ?></label>
                <input type="email" class="form-control" name="email" placeholder="<?php echo t("Enter email"); ?>"
                    value="<?php echo htmlspecialchars($email); ?>" required>
            </div>
            <div class="error">
                <?php echo $errors['email'] ?? '' ?>
            </div>

            <!-- Phone -->
            <div class="mb-3">
                <label class="form-label"><?php echo t("Phone"); ?></label>
                <input type="text" class="form-control" name="phone" placeholder="<?php echo t("Enter phone"); ?>"
                    value="<?php echo htmlspecialchars($phone); ?>"
                    oninput="this.value=this.value.replace(/[^0-9]/g,'')" pattern="[0-9]+" maxlength="11" required>
            </div>
            <div class="error">
                <?php echo $errors['phone'] ?? '' ?>
            </div>

            <!-- DOB -->
            <div class="mb-3">
                <label><?php echo t("Date of Birth"); ?></label>
                <input type="date" class="form-control" name="dob" max="<?php echo date('Y-m-d'); ?>"
                    value="<?php echo htmlspecialchars($dob); ?>" required>
            </div>

            <!-- Gender -->
            <div class="mb-3">
                <label><?php echo t("Gender"); ?></label>
                <select class="form-control" name="gender" required>
                    <option value="">Select gender</option>
                    <option value="Male" <?php echo ($gender=="Male")?"selected":""; ?>>Male</option>
                    <option value="Female" <?php echo ($gender=="Female")?"selected":""; ?>>Female</option>
                </select>
            </div>
            <!-- Password -->
            <div class="mb-3">
                <label class="form-label"><?php echo t("Password"); ?></label>

                <div class="input-group">
                    <input type="password" class="form-control" id="password" name="password"
                        placeholder="<?php echo t("Enter password"); ?>" onkeyup="checkStrength()" required>

                    <span class="input-group-text" onclick="togglePassword('password',this)">
                        <i class="bi bi-eye"></i>
                    </span>
                </div>

                <div id="strength" class="strength"></div>
                <div class="error"><?php echo $errors['password'] ?? '' ?></div>
            </div>

            <!-- PASSWORD RULE -->
            <div id="password-rules" style="font-size:13px; margin-top:8px;">
                <div class="rule" id="rule-length">
                    <i class="bi bi-check-circle"></i> 8-20 characters
                </div>

                <div class="rule" id="rule-upper">
                    <i class="bi bi-check-circle"></i> Uppercase letter
                </div>

                <div class="rule" id="rule-lower">
                    <i class="bi bi-check-circle"></i> Lowercase letter
                </div>

                <div class="rule" id="rule-number">
                    <i class="bi bi-check-circle"></i> Number
                </div>

                <div class="rule" id="rule-special">
                    <i class="bi bi-check-circle"></i> Special character (!@#$%^&*)
                </div>
            </div>
            <!-- Confirm Password -->
            <div class="mb-3">
                <label class="form-label"><?php echo t("Confirm Password"); ?></label>

                <div class="input-group">
                    <input type="password" class="form-control" id="confirm" name="confirm_password"
                        placeholder="<?php echo t("Confirm password"); ?>" onkeyup="checkStrength()" required>

                    <span class="input-group-text" onclick="togglePassword('confirm',this)">
                        <i class="bi bi-eye"></i>
                    </span>
                </div>

                <div id="confirm-error" class="error">
                    <?php echo $errors['confirm'] ?? '' ?>
                </div>
            </div>

            <!-- CAPTCHA -->
            <div class="mb-3">
                <div class="g-recaptcha" data-sitekey="6LdKbrAsAAAAAJBaGDJVPCrwjcSt9mnsyLGp_Iii"></div>
                <div class="error"><?php echo $errors['captcha'] ?? ''; ?></div>
            </div>

            <div class="d-flex justify-content-between mt-4">

                <button type="submit" class="btn btn-primary">
                    <?php echo t("Register");?>
                </button>

                <a href="login.php" class="btn btn-secondary">
                    <?php echo t("← Back");?>
                </a>

            </div>

            <div class="links">

                <a href="login.php"><?php echo t("You already have an account. Login here");?></a>

            </div>

        </form>
    </div>

    <script>
    function togglePassword(id, el) {
        let input = document.getElementById(id);
        let icon = el.querySelector("i");

        if (input.type === "password") {
            input.type = "text";
            icon.classList.replace("bi-eye", "bi-eye-slash");
        } else {
            input.type = "password";
            icon.classList.replace("bi-eye-slash", "bi-eye");
        }
    }

    function checkStrength() {

        let pass = document.getElementById("password").value;
        let confirm = document.getElementById("confirm").value;
        let strength = document.getElementById("strength");

        let rules = {
            length: pass.length >= 8 && pass.length <= 20,
            upper: /[A-Z]/.test(pass),
            lower: /[a-z]/.test(pass),
            number: /[0-9]/.test(pass),
            special: /[!@#$%^&*]/.test(pass)
        };

        // Highlight rules
        Object.keys(rules).forEach(key => {
            let el = document.getElementById("rule-" + key);
            let icon = el.querySelector("i");

            if (rules[key]) {
                el.classList.add("valid");
                icon.classList.replace("bi-check-circle", "bi-check-circle-fill");
            } else {
                el.classList.remove("valid");
                icon.classList.replace("bi-check-circle-fill", "bi-check-circle");
            }
        });

        let isValid = Object.values(rules).every(v => v === true);

        // Strength text
        if (!pass) {
            strength.innerHTML = "";
        } else if (isValid) {
            strength.innerHTML = "Strong password";
            strength.style.color = "lightgreen";
        } else {
            strength.innerHTML = "Password not strong enough";
            strength.style.color = "red";
        }

        // Confirm check
        let confirmError = document.getElementById("confirm-error");
        if (confirm && pass !== confirm) {
            confirmError.innerHTML = "Password mismatch";
        } else {
            confirmError.innerHTML = "";
        }

        // RULE highlight
        document.getElementById("rule-length").classList.toggle("valid", pass.length >= 8 && pass.length <= 20);
        document.getElementById("rule-upper").classList.toggle("valid", /[A-Z]/.test(pass));
        document.getElementById("rule-lower").classList.toggle("valid", /[a-z]/.test(pass));
        document.getElementById("rule-number").classList.toggle("valid", /[0-9]/.test(pass));
        document.getElementById("rule-special").classList.toggle("valid", /[!@#$%^&*]/.test(pass));
    }
    </script>

</body>

</html>