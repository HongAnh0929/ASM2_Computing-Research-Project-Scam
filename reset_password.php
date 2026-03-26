<?php
session_start();
require '../Database/database.php';
require_once 'functions/translate.php';

/* ================== CHECK OTP VERIFIED ================== */
if(!isset($_SESSION['reset_user'], $_SESSION['otp_verified']) || $_SESSION['otp_verified'] !== true){
    die(t("Unauthorized access"));
}

/* OTP expiration: 5 phút */
if(time() - ($_SESSION['otp_time'] ?? 0) > 300){
    unset($_SESSION['reset_user'], $_SESSION['otp_verified'], $_SESSION['otp_time'], $_SESSION['otp']);
    die(t("OTP expired. Please request a new reset."));
}

/* ================== CSRF TOKEN ================== */
if(empty($_SESSION['csrf_token'])){
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";

/* ================== HANDLE POST ================== */
if($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['reset'])){
    
    if(!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')){
        die(t("CSRF attack detected"));
    }

    $password = $_POST['password'] ?? "";
    $confirm  = $_POST['confirm'] ?? "";
    $user_id = $_SESSION['reset_user'];

    // Password match
    if($password !== $confirm){
        $message = t("Passwords do not match!");
    }
    // Password strength
    elseif(!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\W]).{8,}$/', $password)){
        $message = t("Password must be at least 8 characters, contain uppercase, lowercase, number and special character.");
    }
    else {
        // Lấy password cũ
        $stmt = $conn->prepare("SELECT password FROM users WHERE id=? LIMIT 1");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if(password_verify($password, $user['password'])){
            $message = t("New password cannot be the same as the old password!");
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("UPDATE users SET password=?, failed_attempts=0 WHERE id=?");
            $stmt->bind_param("si", $hash, $user_id);

            if($stmt->execute()){
                // Clear all reset session
                unset($_SESSION['reset_user'], $_SESSION['otp_verified'], $_SESSION['otp'], $_SESSION['otp_time']);
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // regenerate CSRF

                header("Location: login.php?msg=reset_success");
                exit;
            } else {
                $message = t("Something went wrong! Please try again.");
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo t("Reset Password"); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
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

    .strength {
        font-size: 13px;
        margin-top: 3px;
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

    .error {
        color: red;
        font-size: 13px;
    }
    </style>
</head>

<body>
    <div class="overlay">
        <div class="form-box">
            <h2 class="text-center mb-4"><?php echo t("Reset Password"); ?></h2>

            <?php if($message !== ""): ?>
            <div class="alert alert-info"><?php echo htmlspecialchars($message); ?></div>
            <?php endif; ?>

            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <!-- New Password -->
                <div class="mb-3 position-relative">
                    <label><?php echo t("New Password"); ?></label>
                    <input type="password" class="form-control" name="password" id="password"
                        placeholder="<?php echo t("Enter new password"); ?>" onkeyup="checkStrength()" required>
                    <i class="bi bi-eye-slash" id="togglePassword"
                        style="position:absolute; right:10px; top:38px; cursor:pointer; color:white;"></i>
                    <div id="strength" class="strength"></div>
                </div>

                <!-- Password Rules -->
                <div id="password-rules" style="font-size:13px; margin-top:8px;">
                    <div class="rule" id="rule-length"><i class="bi bi-check-circle"></i> 8-20 characters</div>
                    <div class="rule" id="rule-upper"><i class="bi bi-check-circle"></i> Uppercase letter</div>
                    <div class="rule" id="rule-lower"><i class="bi bi-check-circle"></i> Lowercase letter</div>
                    <div class="rule" id="rule-number"><i class="bi bi-check-circle"></i> Number</div>
                    <div class="rule" id="rule-special"><i class="bi bi-check-circle"></i> Special character (!@#$%^&*)
                    </div>
                </div>

                <!-- Confirm Password -->
                <div class="mb-3 position-relative">
                    <label><?php echo t("Confirm Password"); ?></label>
                    <input type="password" class="form-control" name="confirm" id="confirm"
                        placeholder="<?php echo t("Confirm password"); ?>" onkeyup="checkStrength()" required>
                    <i class="bi bi-eye-slash" id="toggleConfirm"
                        style="position:absolute; right:10px; top:38px; cursor:pointer; color:white;"></i>
                    <div id="confirm-error" class="error"></div>
                </div>

                <button type="submit" name="reset"
                    class="btn btn-primary w-100"><?php echo t("Reset password"); ?></button>
                <a href="login.php" class="btn btn-secondary w-100 mt-2"><?php echo t("Back"); ?></a>
            </form>
        </div>
    </div>

    <script>
    const togglePassword = document.getElementById('togglePassword');
    const password = document.getElementById('password');
    togglePassword.addEventListener('click', () => {
        const type = password.type === 'password' ? 'text' : 'password';
        password.type = type;
        togglePassword.classList.toggle('bi-eye');
        togglePassword.classList.toggle('bi-eye-slash');
    });

    const toggleConfirm = document.getElementById('toggleConfirm');
    const confirm = document.getElementById('confirm');
    toggleConfirm.addEventListener('click', () => {
        const type = confirm.type === 'password' ? 'text' : 'password';
        confirm.type = type;
        toggleConfirm.classList.toggle('bi-eye');
        toggleConfirm.classList.toggle('bi-eye-slash');
    });

    function checkStrength() {
        let pass = password.value;
        let conf = confirm.value;
        let strength = document.getElementById('strength');
        let confirmError = document.getElementById('confirm-error');

        let rules = {
            length: pass.length >= 8 && pass.length <= 20,
            upper: /[A-Z]/.test(pass),
            lower: /[a-z]/.test(pass),
            number: /[0-9]/.test(pass),
            special: /[!@#$%^&*]/.test(pass)
        };

        Object.keys(rules).forEach(key => {
            let el = document.getElementById('rule-' + key);
            let icon = el.querySelector('i');
            if (rules[key]) {
                el.classList.add('valid');
                icon.classList.replace('bi-check-circle', 'bi-check-circle-fill');
            } else {
                el.classList.remove('valid');
                icon.classList.replace('bi-check-circle-fill', 'bi-check-circle');
            }
        });

        let valid = Object.values(rules).every(v => v);
        if (!pass) {
            strength.innerHTML = '';
        } else if (valid) {
            strength.innerHTML = 'Strong password';
            strength.style.color = 'lightgreen';
        } else {
            strength.innerHTML = 'Password not strong enough';
            strength.style.color = 'red';
        }

        if (conf && pass !== conf) {
            confirmError.innerHTML = 'Password mismatch';
        } else {
            confirmError.innerHTML = '';
        }
    }
    </script>
</body>

</html>