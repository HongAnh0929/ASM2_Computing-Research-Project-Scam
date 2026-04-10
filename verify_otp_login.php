<?php
session_start();
require_once '../Database/database.php';
require_once '../vendor/autoload.php';
require_once 'send_otp.php'; // đảm bảo có sendOTPLogin
// nếu chưa có file logger.php thì dán luôn function logActivity dưới đây

use Dotenv\Dotenv;

/* ================= ENV ================= */
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();
$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ================= LOGGER ================= */
function encryptData($data,$key){
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data,'AES-256-CBC',$key,OPENSSL_RAW_DATA,$iv);
    $hmac = hash_hmac('sha256',$iv.$encrypted,$key,true);
    return base64_encode($iv.$encrypted.$hmac);
}

function logActivity($conn, $user_id, $username, $role, $action, $target, $alert_type, $secret_key){
    $username_enc = encryptData($username,$secret_key);
    $action_enc   = encryptData($action,$secret_key);
    $target_enc   = encryptData($target,$secret_key);
    $ip_enc       = encryptData($_SERVER['REMOTE_ADDR'],$secret_key);
    $ua_enc       = encryptData($_SERVER['HTTP_USER_AGENT'],$secret_key);

    $username_hash = hash_hmac('sha256',$username,$secret_key);
    $target_hash   = hash_hmac('sha256',$target,$secret_key);
    $ip_hash       = hash_hmac('sha256',$_SERVER['REMOTE_ADDR'],$secret_key);

    $stmt = $conn->prepare("
        INSERT INTO activity_logs 
        (user_id, username_encrypted, username_hash, role,
         action, action_encrypted,
         target_encrypted, target_hash,
         ip_address_encrypted, ip_hash,
         user_agent_encrypted, alert_type)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ");

    $stmt->bind_param("isssssssssss",
        $user_id,
        $username_enc,
        $username_hash,
        $role,
        $action,
        $action_enc,
        $target_enc,
        $target_hash,
        $ip_enc,
        $ip_hash,
        $ua_enc,
        $alert_type
    );

    $stmt->execute();
}

/* ================= RESEND OTP ================= */
if(isset($_POST['resend'])){
    if(empty($_SESSION['login_temp'])){
        echo json_encode(["status"=>"EXPIRED"]);
        exit;
    }

    // chống spam 30s
    if(isset($_SESSION['last_resend']) && time() - $_SESSION['last_resend'] < 30){
        echo json_encode(["status"=>"WAIT"]);
        exit;
    }
    $_SESSION['last_resend'] = time();

    // reset attempts
    $_SESSION['otp_attempts'] = 0;

    if(!isset($_SESSION['resend_count'])) $_SESSION['resend_count'] = 0;
    if($_SESSION['resend_count'] >= 5){
        echo json_encode(["status"=>"LIMIT"]);
        exit;
    }

    $_SESSION['resend_count']++;

    $otp = random_int(100000,999999);
    $_SESSION['otp'] = password_hash($otp,PASSWORD_DEFAULT);
    $_SESSION['otp_time'] = time();

    $email = $_SESSION['login_temp']['email'];
    $username = $_SESSION['login_temp']['username'];

    sendOTPLogin($email,$username,$otp);

    logActivity($conn, $_SESSION['login_temp']['user_id'], $username, $_SESSION['login_temp']['role'], "OTP_RESEND", $username, "INFO", $secret_key);

    echo json_encode([
        "status"=>"RESENT",
        "count"=>$_SESSION['resend_count']
    ]);
    exit;
}

/* ================= VERIFY OTP ================= */
if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['otp'])){
    if(empty($_SESSION['otp']) || empty($_SESSION['login_temp'])){
        echo json_encode(["status"=>"EXPIRED"]);
        exit;
    }

    if(time() - $_SESSION['otp_time'] > 180){
        echo json_encode(["status"=>"EXPIRED"]);
        exit;
    }

    $_SESSION['otp_attempts'] = $_SESSION['otp_attempts'] ?? 0;

    if($_SESSION['otp_attempts'] >= 3){
        $user_id = $_SESSION['login_temp']['user_id'];

        logActivity($conn, $user_id, $_SESSION['login_temp']['username'], $_SESSION['login_temp']['role'], "OTP_FAILED_LOCK", $_SESSION['login_temp']['username'], "HIGH", $secret_key);

        $stmt = $conn->prepare("UPDATE users SET is_locked=1, status='Blocked' WHERE id=?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();

        session_unset();
        echo json_encode(["status"=>"LOCKED"]);
        exit;
    }

    if(password_verify($_POST['otp'], $_SESSION['otp'])){
        $_SESSION['user_id'] = $_SESSION['login_temp']['user_id'];
        $_SESSION['username'] = $_SESSION['login_temp']['username'];
        $_SESSION['role'] = $_SESSION['login_temp']['role'];

        $stmt = $conn->prepare("UPDATE users SET status='Active' WHERE id=?");
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();

        logActivity($conn, $_SESSION['user_id'], $_SESSION['username'], $_SESSION['role'], "LOGIN_SUCCESS", $_SESSION['username'], "INFO", $secret_key);

        unset($_SESSION['login_temp'],$_SESSION['otp'],$_SESSION['otp_time']);

        echo json_encode([
            "status"=>"SUCCESS",
            "role"=>$_SESSION['role']
        ]);
        exit;
    } else {
        $_SESSION['otp_attempts']++;
        logActivity($conn, $_SESSION['login_temp']['user_id'], $_SESSION['login_temp']['username'], $_SESSION['login_temp']['role'], "OTP_INVALID", $_SESSION['login_temp']['username'], "WARNING", $secret_key);

        echo json_encode(["status"=>"INVALID"]);
        exit;
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

    .otp-inputs {
        margin-top: 10px;
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
        text-align: left;
        color: #facc15;
    }
    </style>
</head>

<body>

    <div class="overlay">
        <div class="otp-box">

            <h3>Enter OTP</h3>

            <!-- 🔥 ALERT -->
            <?php if(isset($_SESSION['otp_message'])): ?>
            <div id="otpAlert" class="alert text-center" style="background:#16a34a;color:white;">
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
    const otpBox = document.querySelector(".otp-inputs");

    let time = 180;
    let countdown;

    /* ===== TIMER ===== */
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
                resendBtn.classList.remove("disabled");
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
        message.style.color = "orange";

        fetch("verify_otp_login.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: "otp=" + otp
            })
            .then(res => res.json())
            .then(data => {

                if (data.status === "SUCCESS") {
                    otpBox.classList.add("success");

                    message.innerHTML = "Login success! Redirecting...";

                    setTimeout(() => {
                        if (data.role === "Admin") {
                            window.location.href = "admin/admin_dashboard.php";
                        } else {
                            window.location.href = "index.php";
                        }
                    }, 1000);

                } else if (data.status === "EXPIRED") {
                    message.innerHTML = "OTP expired";
                    message.style.color = "orange";
                    locked = false;

                } else if (data.status === "LOCKED") {
                    message.innerHTML = "Too many attempts!";
                    message.style.color = "red";

                } else {
                    otpBox.classList.add("error");

                    message.innerHTML = "Wrong OTP";
                    message.style.color = "red";

                    locked = false;

                    setTimeout(() => {
                        otpBox.classList.remove("error");
                    }, 1200);
                }

            })
            .catch((err) => {
                console.error(err);
                message.innerHTML = "Network error";
                message.style.color = "red";
                locked = false;
            });
    }

    /* ===== CLEAR OTP ===== */
    function clearOTP() {
        inputs.forEach(i => i.value = "");
        inputs[0].focus();
    }

    /* ===== RESEND ===== */
    resendBtn.addEventListener("click", () => {

        if (resendBtn.classList.contains("disabled")) return;

        resendBtn.classList.add("disabled");

        message.innerHTML = "Sending OTP...";
        message.style.color = "orange";

        fetch("verify_otp_login.php", {
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

                    clearOTP();
                    locked = false;

                    time = 180;
                    startTimer();

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