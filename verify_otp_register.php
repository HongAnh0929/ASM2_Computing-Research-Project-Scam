<?php
session_start();

require_once '../Database/database.php';
require_once '../vendor/autoload.php';
require_once 'send_otp.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ===== HANDLE POST ===== */
if($_SERVER['REQUEST_METHOD'] === 'POST'){

    /* ===== RESEND ===== */
    if(isset($_POST['resend'])){
        if(empty($_SESSION['register_data'])){
            echo "Session expired"; exit;
        }

        // chống spam
if(isset($_SESSION['last_resend']) && time() - $_SESSION['last_resend'] < 30){
    echo "Wait 30s before resend"; exit;
}
$_SESSION['last_resend'] = time();

// reset attempts
$_SESSION['attempts'] = 0;

        if(!isset($_SESSION['resend_count'])) $_SESSION['resend_count'] = 0;

        if($_SESSION['resend_count'] >= 5){
            echo "Max resend reached"; exit;
        }

        $_SESSION['resend_count']++;

        $data = $_SESSION['register_data'];

        $otp = random_int(100000,999999);
        $_SESSION['otp'] = password_hash($otp,PASSWORD_DEFAULT);
        $_SESSION['otp_time'] = time();

        // decrypt email để gửi lại
        $decoded = base64_decode($data['email_encrypted']);
        $iv = substr($decoded,0,16);
        $enc = substr($decoded,16);

        $email = openssl_decrypt($enc,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);

        echo sendOTPRegister($email,"User",$otp)
            ? "OTP resent ({$_SESSION['resend_count']}/5)" 
            : "Resend failed";

        exit;
    }

    /* ===== VERIFY ===== */
    if(empty($_SESSION['otp']) || empty($_SESSION['otp_time'])){
        echo "Session expired"; exit;
    }

    if(time() - $_SESSION['otp_time'] > 180){
        echo "OTP expired"; exit;
    }

    if(!isset($_POST['otp']) || !password_verify($_POST['otp'], $_SESSION['otp'])){

        $_SESSION['attempts'] = ($_SESSION['attempts'] ?? 0) + 1;

        if($_SESSION['attempts'] >= 3){
            session_unset();
            echo "Too many attempts!"; exit;
        }

        echo "Invalid OTP"; exit;
    }

    if(empty($_SESSION['register_data'])){
        echo "Session expired"; exit;
    }

    $data = $_SESSION['register_data'];

    /* ===== INSERT ===== */
    $stmt = $conn->prepare("
        INSERT INTO users
        (username_encrypted, username_hash,
         email_encrypted, email_hash,
         phone_encrypted, phone_hash,
         password, role, status,
         dob_encrypted, gender_encrypted)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    ");

    $role = "User";
    $status = "Active";

    $stmt->bind_param("sssssssssss",
        $data['username_encrypted'],
        $data['username_hash'],
        $data['email_encrypted'],
        $data['email_hash'],
        $data['phone_encrypted'],
        $data['phone_hash'],
        $data['password'],
        $role,
        $status,
        $data['dob_encrypted'],
        $data['gender_encrypted']
    );

    if($stmt->execute()){

    /* DECRYPT EMAIL để gửi mail */
    $decoded = base64_decode($data['email_encrypted']);
    $iv = substr($decoded,0,16);
    $enc = substr($decoded,16);

    $email = openssl_decrypt($enc,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);

    /* 📩 SEND SUCCESS EMAIL */
    require_once 'send_otp.php';
    sendSuccessEmail($email, $username);

    session_unset();

    echo "SUCCESS";
} else {
        echo "Insert failed";
    }

    exit;
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

    .otp-inputs {
        margin-top: 10px;
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

            <!-- 🔥 THÔNG BÁO TỪ REGISTER -->
            <?php if(isset($_SESSION['otp_message'])): ?>
            <div id="otpAlert" class="alert text-center" style="background:#16a34a;color:white;border:none;">
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
    let locked = false;

    const inputs = document.querySelectorAll(".otp-inputs input");
    const message = document.getElementById("message");
    const resendBtn = document.getElementById("resendBtn");

    let time = 180;
    let countdown;

    /* ===== START TIMER ===== */
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

                resendBtn.classList.remove("disabled"); // 🔥 mở nút
            }
        }, 1000);
    }

    /* ===== INPUT OTP ===== */
    inputs.forEach((input, idx) => {
        input.addEventListener("input", () => {

            input.value = input.value.replace(/[^0-9]/g, '');

            if (input.value && idx < inputs.length - 1) {
                inputs[idx + 1].focus();
            }

            let otp = "";
            inputs.forEach(i => otp += i.value);

            if (otp.length === 6 && !locked) {
                verifyOTP(otp);
            }
        });

        input.addEventListener("keydown", (e) => {
            if (e.key === "Backspace" && !input.value && idx > 0) {
                inputs[idx - 1].focus();
            }
        });
    });

    /* ===== VERIFY OTP ===== */
    function verifyOTP(otp) {
        locked = true;
        message.innerHTML = "Verifying...";

        fetch("verify_otp_register.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: "otp=" + otp
            })
            .then(res => res.text())
            .then(data => {
                if (data.trim() === "SUCCESS") {
                    message.innerHTML = "Verified! Redirecting...";
                    document.querySelector(".otp-inputs").classList.add("success");

                    setTimeout(() => {
                        window.location.href = "login.php";
                    }, 1000);

                } else {
                    locked = false;
                    message.innerHTML = data;
                    message.style.color = "red";

                    document.querySelector(".otp-inputs").classList.add("error");

                    setTimeout(() => {
                        document.querySelector(".otp-inputs").classList.remove("error");
                    }, 1000);
                }
            })
            .catch(() => {
                locked = false;
                message.innerHTML = "Network error";
            });
    }

    /* ===== CLEAR OTP INPUT ===== */
    function clearOTP() {
        inputs.forEach(i => i.value = "");
        inputs[0].focus();
    }

    /* ===== RESEND ===== */
    resendBtn.addEventListener("click", () => {

        if (resendBtn.classList.contains("disabled")) return;

        resendBtn.classList.add("disabled");

        fetch("verify_otp_register.php", {
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

                clearOTP(); // 🔥 clear OTP cũ
                locked = false; // 🔥 mở lại verify

                time = 180;
                startTimer(); // 🔥 restart timer
            })
            .catch(() => {
                message.innerHTML = "Resend failed";
                resendBtn.classList.remove("disabled");
            });
    });

    /* ===== INIT ===== */
    startTimer();

    window.addEventListener("load", () => {
        setTimeout(() => {
            inputs[0].focus();
        }, 200);
    });
    </script>
</body>

</html>