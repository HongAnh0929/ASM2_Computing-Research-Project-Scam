<?php
session_start();
require '../Database/database.php';
require_once 'functions/translate.php';
require_once 'send_otp.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();
$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ================== POST HANDLER ================== */
if($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* ===== RESEND OTP ===== */
    if(isset($_POST['resend'])){
        if(empty($_SESSION['otp_email'])){
            echo t("Session expired"); exit;
        }

        // chống spam resend < 30s
        if(isset($_SESSION['last_resend']) && time() - $_SESSION['last_resend'] < 30){
            echo t("Wait 30s before resend"); exit;
        }
        $_SESSION['last_resend'] = time();

        if(!isset($_SESSION['resend_count'])) $_SESSION['resend_count'] = 0;
        if($_SESSION['resend_count'] >= 5){
            echo t("Max resend reached"); exit;
        }
        $_SESSION['resend_count']++;

        $otp = random_int(100000,999999);
        $_SESSION['otp'] = password_hash($otp,PASSWORD_DEFAULT);
        $_SESSION['otp_time'] = time();
        $_SESSION['attempts'] = 0;

        $email = $_SESSION['otp_email'];

        echo sendOTPReset($email, $otp)
            ? t("OTP resent ({$_SESSION['resend_count']}/5)")
            : t("Resend failed");

        exit;
    }

    /* ===== VERIFY OTP ===== */
    if(empty($_SESSION['otp']) || empty($_SESSION['otp_time'])){
        echo t("Session expired"); exit;
    }

    if(time() - $_SESSION['otp_time'] > 180){ // ⬅ 3 phút = 180s
        echo t("OTP expired"); exit;
    }

    $otp_input = $_POST['otp'] ?? '';
    if(!password_verify($otp_input, $_SESSION['otp'])){
        $_SESSION['attempts'] = ($_SESSION['attempts'] ?? 0) + 1;
        if($_SESSION['attempts'] >= 3){
            session_unset();
            echo t("Too many attempts!"); exit;
        }
        $remaining = 3 - $_SESSION['attempts'];
        echo t("Invalid OTP. $remaining attempts left."); exit;
    }

    // OTP đúng, cho hiển thị form reset
    $_SESSION['otp_verified'] = true;
    echo "VERIFIED";
    exit;
}

/* ================== HANDLE RESET PASSWORD ================== */
if(isset($_POST['new_password']) && ($_SESSION['otp_verified'] ?? false)){
    $new_password = trim($_POST['new_password']);
    $confirm_password = trim($_POST['confirm_password'] ?? '');

    if(strlen($new_password) < 6){
        $error = t("Password must be at least 6 characters.");
    } elseif($new_password !== $confirm_password){
        $error = t("Passwords do not match.");
    } else {
        $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("UPDATE users SET password=? WHERE email=?");
        $stmt->bind_param("ss", $password_hash, $_SESSION['otp_email']);
        if($stmt->execute()){
            session_unset();
            header("Location: login.php?reset=success");
            exit;
        } else {
            $error = t("Failed to reset password.");
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Verify OTP</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body {
        background: url('img/background.png') center/cover;
        height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .overlay {
        position: fixed;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .otp-box {
        background: rgba(0, 0, 0, 0.85);
        padding: 50px 40px;
        border-radius: 20px;
        text-align: center;
        color: white;
        width: 450px;
    }

    .otp-inputs {
        display: flex;
        gap: 12px;
        justify-content: center;
        margin-bottom: 20px;
    }

    .otp-inputs input {
        width: 60px;
        height: 65px;
        font-size: 24px;
        text-align: center;
        border-radius: 12px;
        border: 2px solid #0ea5e9;
        background: rgba(0, 0, 0, 0.6);
        color: white;
    }

    .otp-box h3 {
        margin-bottom: 35px;
    }

    #message {
        margin-top: 10px;
        min-height: 22px;
    }

    .timer-resend {
        display: flex;
        justify-content: space-between;
        margin-top: 15px;
    }
    </style>
</head>

<body>
    <div class="overlay">
        <div class="otp-box">
            <h3>Enter OTP</h3>
            <div class="otp-inputs">
                <input maxlength="1"><input maxlength="1"><input maxlength="1">
                <input maxlength="1"><input maxlength="1"><input maxlength="1">
            </div>
            <p id="message"></p>
            <div class="timer-resend">
                <div id="timer">03:00</div>
                <button id="resendBtn" class="btn btn-warning btn-sm">Resend OTP</button>
            </div>

            <!-- RESET PASSWORD FORM -->
            <form id="resetForm" method="POST" style="display:none;" class="mt-3">
                <input type="password" name="new_password" class="form-control mb-2"
                    placeholder="<?php echo t('New Password');?>" required>
                <input type="password" name="confirm_password" class="form-control mb-2"
                    placeholder="<?php echo t('Confirm Password');?>" required>
                <button class="btn btn-success w-100"><?php echo t("Reset Password");?></button>
            </form>
        </div>
    </div>

    <script>
    let locked = false;
    const inputs = document.querySelectorAll(".otp-inputs input");
    const message = document.getElementById("message");
    const resendBtn = document.getElementById("resendBtn");
    let time = 180,
        countdown; // ⬅ 3 phút

    function startTimer() {
        clearInterval(countdown);
        countdown = setInterval(() => {
            let m = Math.floor(time / 60),
                s = time % 60;
            document.getElementById("timer").innerHTML = m + ":" + (s < 10 ? "0" + s : s);
            time--;
            if (time < 0) {
                clearInterval(countdown);
                document.getElementById("timer").innerHTML = "Expired";
                resendBtn.classList.remove("disabled");
            }
        }, 1000);
    }

    inputs.forEach((input, idx) => {
        input.addEventListener("input", () => {
            input.value = input.value.replace(/[^0-9]/g, '');
            if (input.value && idx < inputs.length - 1) inputs[idx + 1].focus();
            let otp = "";
            inputs.forEach(i => otp += i.value);
            if (otp.length === 6 && !locked) verifyOTP(otp);
        });
        input.addEventListener("keydown", (e) => {
            if (e.key === "Backspace" && !input.value && idx > 0) inputs[idx - 1].focus();
        });
    });

    function verifyOTP(otp) {
        locked = true;
        message.innerHTML = "Verifying...";
        fetch("verify_otp.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: "otp=" + otp
            })
            .then(res => res.text())
            .then(data => {
                if (data.trim() === "VERIFIED") {
                    message.innerHTML = "Verified! Enter new password.";
                    document.getElementById("resetForm").style.display = "block";
                    document.querySelector(".otp-inputs").style.display = "none";
                } else {
                    locked = false;
                    message.innerHTML = data;
                    message.style.color = "red";
                }
            }).catch(() => {
                locked = false;
                message.innerHTML = "Network error";
            });
    }

    resendBtn.addEventListener("click", () => {
        if (resendBtn.classList.contains("disabled")) return;
        resendBtn.classList.add("disabled");
        fetch("verify_otp.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: "resend=1"
            })
            .then(res => res.text())
            .then(data => {
                message.innerHTML = data;
                message.style.color = "lightgreen";
                locked = false;
                time = 180;
                startTimer();
                inputs.forEach(i => i.value = "");
                inputs[0].focus();
            }).catch(() => {
                message.innerHTML = "Resend failed";
                resendBtn.classList.remove("disabled");
            });
    });

    startTimer();
    window.addEventListener("load", () => {
        setTimeout(() => {
            inputs[0].focus();
        }, 200);
    });
    </script>
</body>

</html>