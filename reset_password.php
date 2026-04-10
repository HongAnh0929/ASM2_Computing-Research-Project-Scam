<?php
session_start();
require '../Database/database.php';
require_once 'functions/translate.php';

/* ================== CHECK OTP VERIFIED ================== */
if (!isset($_SESSION['reset_user'], $_SESSION['otp_verified']) || $_SESSION['otp_verified'] !== true) {
    die(t("Unauthorized access"));
}

/* OTP expiration: 5 minutes */
if (time() - ($_SESSION['otp_time'] ?? 0) > 300) {
    unset($_SESSION['reset_user'], $_SESSION['otp_verified'], $_SESSION['otp_time'], $_SESSION['otp']);
    die(t("OTP expired. Please request a new reset."));
}

/* ================== CSRF ================== */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";

/* ================== HANDLE RESET ================== */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['reset'])) {

    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        die(t("CSRF attack detected"));
    }

    $password = $_POST['password'] ?? "";
    $confirm  = $_POST['confirm'] ?? "";
    $user_id  = $_SESSION['reset_user'];

    if ($password !== $confirm) {
        $message = t("Passwords do not match!");
    }

    elseif (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\W]).{8,}$/', $password)) {
        $message = t("Password not strong enough!");
    }

    else {
        $stmt = $conn->prepare("SELECT password FROM users WHERE id=? LIMIT 1");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        if (password_verify($password, $user['password'])) {
            $message = t("New password cannot be same as old password!");
        } else {

            $hash = password_hash($password, PASSWORD_BCRYPT);

            $stmt = $conn->prepare("UPDATE users SET password=?, failed_attempts=0 WHERE id=?");
            $stmt->bind_param("si", $hash, $user_id);

            if ($stmt->execute()) {

                unset($_SESSION['reset_user'], $_SESSION['otp_verified'], $_SESSION['otp'], $_SESSION['otp_time']);

                header("Location: login.php?msg=reset_success");
                exit;

            } else {
                $message = t("Something went wrong!");
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
    background: url("img/background.png") center/cover;
    margin: 0;
}

.overlay {
    background: rgba(0,0,0,0.55);
    min-height: 100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    color:white;
}

.form-box {
    width: 450px;
    background: rgba(0,0,0,0.6);
    padding: 30px;
    border-radius: 10px;
}

.rule {
    font-size: 13px;
    opacity: 0.4;
    display:flex;
    gap:6px;
    align-items:center;
    transition:0.2s;
}

.rule.valid {
    opacity: 1;
    color:#4ade80;
}

.error {
    color:red;
    font-size:13px;
}
</style>
</head>

<body>

<div class="overlay">
<div class="form-box">

<h3 class="text-center mb-4"><?php echo t("Reset Password"); ?></h3>

<?php if($message): ?>
<div class="alert alert-info"><?php echo htmlspecialchars($message); ?></div>
<?php endif; ?>

<form method="POST">

<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

<!-- PASSWORD -->
<div class="mb-2">
<label><?php echo t("New Password"); ?></label>
<input type="password" id="password" name="password"
class="form-control" onkeyup="checkStrength()" required>
</div>

<!-- RULES -->
<div id="rules" style="font-size:13px;margin-bottom:10px;">
    <div class="rule" id="r-length">✔ 8-20 characters</div>
    <div class="rule" id="r-upper">✔ Uppercase letter</div>
    <div class="rule" id="r-lower">✔ Lowercase letter</div>
    <div class="rule" id="r-number">✔ Number</div>
    <div class="rule" id="r-special">✔ Special character</div>
</div>

<!-- CONFIRM -->
<div class="mb-3">
<label><?php echo t("Confirm Password"); ?></label>
<input type="password" id="confirm" name="confirm"
class="form-control" onkeyup="checkStrength()" required>
<div id="confirm-error" class="error"></div>
</div>

<!-- BUTTONS (HORIZONTAL) -->
<div class="d-flex gap-2 mt-3">
    <button type="submit" name="reset" class="btn btn-primary w-50">
        <?php echo t("Reset password"); ?>
    </button>

    <a href="login.php" class="btn btn-secondary w-50 text-center">
        <?php echo t("Back"); ?>
    </a>
</div>

</form>

</div>
</div>

<script>
function checkStrength() {

    let pass = document.getElementById('password').value;
    let conf = document.getElementById('confirm').value;

    let rules = {
        length: pass.length >= 8 && pass.length <= 20,
        upper: /[A-Z]/.test(pass),
        lower: /[a-z]/.test(pass),
        number: /[0-9]/.test(pass),
        special: /[\W]/.test(pass)
    };

    for (let r in rules) {
        let el = document.getElementById("r-" + r);
        if (rules[r]) {
            el.classList.add("valid");
        } else {
            el.classList.remove("valid");
        }
    }

    let confirmError = document.getElementById("confirm-error");

    if (conf && pass !== conf) {
        confirmError.innerHTML = "Password mismatch";
    } else {
        confirmError.innerHTML = "";
    }
}
</script>

</body>
</html>