<?php
session_start();
require_once '../Database/database.php';
require_once '../vendor/autoload.php';
require_once 'send_otp.php';

use Dotenv\Dotenv;

/* ================= ENV ================= */
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* =========================================================
   HANDLE AJAX REQUEST (VERIFY + RESEND)
========================================================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* ================= VERIFY OTP ================= */
    if (isset($_POST['otp'])) {

        header('Content-Type: application/json');

        if (empty($_SESSION['otp']) || empty($_SESSION['reset_user']) || empty($_SESSION['otp_email'])) {
            echo json_encode(["status" => "EXPIRED"]);
            exit;
        }

        // check time expire (3 phút)
        if (time() - ($_SESSION['otp_time'] ?? 0) > 180) {
            echo json_encode(["status" => "EXPIRED"]);
            exit;
        }

        $_SESSION['otp_attempts'] = $_SESSION['otp_attempts'] ?? 0;

        // limit attempts
        if ($_SESSION['otp_attempts'] >= 3) {
            session_unset();
            echo json_encode(["status" => "LOCKED"]);
            exit;
        }

        $otp_input = trim($_POST['otp']);

        if (password_verify($otp_input, $_SESSION['otp'])) {

            $_SESSION['otp_verified'] = true;

            echo json_encode([
                "status" => "SUCCESS"
            ]);
            exit;

        } else {

            $_SESSION['otp_attempts']++;

            echo json_encode([
                "status" => "INVALID",
                "attempts_left" => 3 - $_SESSION['otp_attempts']
            ]);
            exit;
        }
    }

    /* ================= RESEND OTP ================= */
    if (isset($_POST['resend'])) {

        header('Content-Type: application/json');

        if (empty($_SESSION['reset_user']) || empty($_SESSION['otp_email'])) {
            echo json_encode(["status" => "EXPIRED"]);
            exit;
        }

        // anti spam 30s
        if (isset($_SESSION['last_resend']) && time() - $_SESSION['last_resend'] < 30) {
            echo json_encode(["status" => "WAIT"]);
            exit;
        }

        $_SESSION['last_resend'] = time();

        $_SESSION['resend_count'] = $_SESSION['resend_count'] ?? 0;

        if ($_SESSION['resend_count'] >= 5) {
            echo json_encode(["status" => "LIMIT"]);
            exit;
        }

        $_SESSION['resend_count']++;

        // generate OTP mới
        $otp = random_int(100000, 999999);

        $_SESSION['otp'] = password_hash($otp, PASSWORD_DEFAULT);
        $_SESSION['otp_time'] = time();
        $_SESSION['otp_attempts'] = 0;

        $email = $_SESSION['otp_email'];
        $username = $_SESSION['otp_username'] ?? "User";

        $send = sendOTPReset($email, $username, $otp);

        echo json_encode([
            "status" => $send ? "RESENT" : "FAILED",
            "count" => $_SESSION['resend_count']
        ]);
        exit;
    }
}
?>

<!-- =========================================================
     UI VERIFY OTP (FULL DESIGN LIKE LOGIN OTP)
========================================================= -->
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

.otp-inputs.success input {
    border-color: #22c55e;
}

.otp-inputs.error input {
    border-color: #ef4444;
}

#message {
    margin-top: 10px;
    min-height: 22px;
    font-weight: 500;
}

.timer-resend {
    display: flex;
    justify-content: space-between;
    margin-top: 15px;
}

#timer {
    font-weight: bold;
    color: #facc15;
}
</style>
</head>

<body>

<div class="overlay">
<div class="otp-box">

    <h3>Enter OTP</h3>

    <?php if(isset($_SESSION['otp_message'])): ?>
        <div class="alert alert-success">
            <?php
                echo $_SESSION['otp_message'];
                unset($_SESSION['otp_message']);
            ?>
        </div>
    <?php endif; ?>

    <div class="otp-inputs">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
    </div>

    <p id="message"></p>

    <div class="timer-resend">
        <div id="timer">03:00</div>
        <button id="resendBtn" class="btn btn-warning btn-sm">Resend OTP</button>
    </div>

</div>
</div>

<script>
let inputs = document.querySelectorAll(".otp-inputs input");
let message = document.getElementById("message");
let resendBtn = document.getElementById("resendBtn");

let time = 180;
let countdown;

/* ================= TIMER ================= */
function startTimer() {
    clearInterval(countdown);

    countdown = setInterval(() => {
        let m = Math.floor(time / 60);
        let s = time % 60;

        document.getElementById("timer").innerHTML =
            m + ":" + (s < 10 ? "0" + s : s);

        time--;

        if (time < 0) {
            clearInterval(countdown);
            document.getElementById("timer").innerHTML = "Expired";
        }

    }, 1000);
}

/* ================= GET OTP ================= */
function getOTP() {
    let otp = "";
    inputs.forEach(i => otp += i.value);
    return otp;
}

/* ================= INPUT OTP ================= */
inputs.forEach((input, idx) => {

    input.addEventListener("input", () => {

        input.value = input.value.replace(/[^0-9]/g, '');

        if (input.value && idx < inputs.length - 1) {
            inputs[idx + 1].focus();
        }

        let otp = getOTP();

        if (otp.length === 6) {
            verifyOTP(otp);
        }
    });

    input.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" && !input.value && idx > 0) {
            inputs[idx - 1].focus();
        }
    });
});

/* ================= VERIFY OTP ================= */
function verifyOTP(otp) {

    message.innerHTML = "Verifying...";
    message.style.color = "orange";

    fetch("verify_otp.php", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "otp=" + otp
    })
    .then(res => res.json())
    .then(data => {

        if (data.status === "SUCCESS") {

            message.innerHTML = "OTP correct. Redirecting...";
            message.style.color = "lightgreen";

            setTimeout(() => {
                window.location.href = "reset_password.php";
            }, 800);

        } else if (data.status === "EXPIRED") {

            message.innerHTML = "OTP expired";
            message.style.color = "red";

        } else if (data.status === "LOCKED") {

            message.innerHTML = "Too many attempts";
            message.style.color = "red";

        } else {

            message.innerHTML = "Wrong OTP (" + (data.attempts_left ?? 0) + " left)";
            message.style.color = "red";
        }
    })
    .catch(() => {
        message.innerHTML = "Network error";
        message.style.color = "red";
    });
}

/* ================= RESEND OTP ================= */
resendBtn.addEventListener("click", () => {

    fetch("verify_otp.php", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "resend=1"
    })
    .then(res => res.json())
    .then(data => {

        if (data.status === "RESENT") {

            message.innerHTML = "OTP resent (" + data.count + "/5)";
            message.style.color = "lightgreen";

            inputs.forEach(i => i.value = "");
            inputs[0].focus();

            time = 180;
            startTimer();

        } else if (data.status === "WAIT") {

            message.innerHTML = "Please wait 30s";
            message.style.color = "orange";

        } else if (data.status === "LIMIT") {

            message.innerHTML = "Resend limit reached";
            message.style.color = "red";

        } else {

            message.innerHTML = "Session expired";
            message.style.color = "red";
        }
    })
    .catch(() => {
        message.innerHTML = "Resend failed";
        message.style.color = "red";
    });
});

/* ================= INIT ================= */
startTimer();

window.addEventListener("load", () => {
    setTimeout(() => inputs[0].focus(), 200);
});
</script>

</body>
</html>