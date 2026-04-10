<?php
session_start();
require_once '../Database/database.php';
require_once 'functions/translate.php';
require_once 'functions/security.php';

require_once __DIR__ . '/../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$error = "";

/* ===== LANGUAGE ===== */
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: $currentPage");
    exit;
}

$lang = $_SESSION['lang'] ?? 'en';

/* ===== ACTIVITY LOG ===== */
function addLog($conn,$action,$target){

    $user_id = $_SESSION['user_id'] ?? NULL;
    $username = $_SESSION['username'] ?? "Guest";
    $role = $_SESSION['role'] ?? "Guest";

    $ip = $_SERVER['REMOTE_ADDR'];
    $browser = $_SERVER['HTTP_USER_AGENT'];

    $username_hash = hash("sha256", $username);
    $target_hash = hash("sha256", $target);
    $ip_hash = hash("sha256", $ip);

    $username_enc = encryptData($username);
    $action_enc = encryptData($action);
    $target_enc = encryptData($target);
    $ip_enc = encryptData($ip);
    $ua_enc = encryptData($browser);

    $stmt = $conn->prepare("
        INSERT INTO activity_logs
        (user_id, username_encrypted, username_hash, role,
         action, action_encrypted,
         target_encrypted, target_hash,
         ip_address_encrypted, ip_hash,
         user_agent_encrypted)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    ");

    $stmt->bind_param(
        "issssssssss",
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
        $ua_enc
    );

    $stmt->execute();
}

/* ===== LIMIT SEARCH ===== */
if (!isset($_SESSION['user_id'])) {

    if (!isset($_SESSION['search_count'])) {
        $_SESSION['search_count'] = 0;
    }

    $_SESSION['search_count']++;

    if ($_SESSION['search_count'] > 5) {
        header("Location: register.php");
        exit;
    }
}

/* ===== HANDLE SUBMIT ===== */
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $phone = preg_replace('/\D/', '', $_POST['phone']);

    if (!preg_match('/^(0\d{7,10}|1900\d{4})$/', $phone)) {
        $error = "Invalid phone number!";
    } else {

        // GHI LOG
        addLog($conn, "Search Phone", $phone);

        header("Location: result.php?phone=" . urlencode($phone));
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

    <title><?php echo t("Check Phone Number");?></title>

    <style>
    html,
    body {
        height: 100%;
        margin: 0;
        padding: 0;
    }

    body {
        display: flex;
        flex-direction: column;
        min-height: 100vh;
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        /*background-attachment: fixed;*/
        /* Bỏ đi */
        color: white;
    }

    /* FIX overlay chuẩn */
    .overlay {
        flex-grow: 1;
        /* Chiếm hết không gian còn lại giữa header và footer */
        display: flex;
        justify-content: center;
        align-items: center;
        /* Giữ form chính giữa theo chiều dọc và ngang */
        padding-top: 80px;
        padding-bottom: 40px;

        background: rgba(0, 0, 0, 0.55);
        /* không set height hay min-height để tránh tràn */
    }

    .row {
        width: 100%;
    }

    /* Navbar */
    .navbar {
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(6px);
        z-index: 10500;
    }

    /* Footer */
    .footer-custom {
        background: rgba(0, 0, 0, 0.75);
        color: white;
        padding: 15px 0;
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

    .footer-link {
        color: #ddd;
        text-decoration: none;
    }

    .footer-link:hover {
        color: white;
        text-decoration: underline;
    }
    </style>

</head>

<body class="d-flex flex-column min-vh-100">
    <!-- ================= NAVBAR ================= -->
    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
        <div class="container-fluid">

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php"><?php echo t("SCAM BTEC"); ?></a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">

                <!-- Menu trái -->
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="index.php"><?php echo t("HOME");?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page"
                            href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="scan_url.php"><?php echo t("URL");?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page"
                            href="scan_email.php"><?php echo t("EMAIL");?></a>
                    </li>
                </ul>

                <!-- Menu phải (User) -->
                <div class="d-flex align-items-center gap-3">

                    <?php $lang = $_SESSION['lang'] ?? 'en'; ?>
                    <div class="d-flex gap-2 ms-3 align-items-center">

                        <a href="?lang=en" class="lang-btn <?php echo $lang=='en' ? 'active' : ''; ?>">
                            <img src="https://flagcdn.com/w40/gb.png" class="flag-img" alt="English">
                            <span class="ms-1">EN</span>
                        </a>

                        <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
                            <img src="https://flagcdn.com/w40/vn.png" class="flag-img" alt="Vietnamese">
                            <span class="ms-1">VI</span>
                        </a>

                    </div>

                    <?php if (isset($_SESSION['user_id'])): ?>

                    <!-- Dropdown User -->
                    <div class="dropdown">
                        <a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle" href="#"
                            role="button" data-bs-toggle="dropdown" aria-expanded="false">

                            <i class="bi bi-person-circle fs-3"></i>
                        </a>

                        <ul class="dropdown-menu dropdown-menu-end shadow">

                            <li class="dropdown-header">
                                <a href="profile.php" class="text-decoration-none text-dark">
                                    <?php echo htmlspecialchars($_SESSION['username'] ?? 'Guest') ?>
                                </a>
                            </li>

                            <li>
                                <a class="dropdown-item" href="history.php">
                                    <i class="bi bi-clock-history me-2"></i>
                                    <?php echo t("History"); ?>
                                </a>
                            </li>

                            <li>
                                <hr class="dropdown-divider">
                            </li>

                            <li>
                                <a class="dropdown-item text-danger" href="logout.php">
                                    <i class="bi bi-box-arrow-right me-2"></i>
                                    <?php echo t("Logout"); ?>
                                </a>
                            </li>

                        </ul>
                    </div>

                    <?php else: ?>

                    <a href="login.php" class="btn btn-outline-info">
                        <?php echo t("Sign in"); ?>
                    </a>

                    <a href="register.php" class="btn btn-outline-info">
                        <?php echo t("Sign up"); ?>
                    </a>

                    <?php endif; ?>

                </div>
            </div>
        </div>
    </nav>

    <!-- MAIN CONTENT -->
    <div class="overlay">
        <div class="container">

            <div class="row justify-content-center">

                <div class="col-md-8 col-lg-7">

                    <h2 class="text-center mb-4">
                        <?php echo t("CHECK PHONE NUMBER");?>
                    </h2>

                    <form method="POST" onsubmit="return validateForm()">

                        <input type="text" id="phoneInput" name="phone" class="form-control mb-2"
                            placeholder="Enter phone number..." oninput="validatePhone()" required>

                        <small id="phoneInfo" class="text-warning d-none">
                            <?php echo t("Phone number must start with 0 and contain 8, 9, 10, or 11 digits.");?>
                        </small>

                        <button type="submit" class="btn btn-primary w-100 mt-3">
                            <?php echo t("Check Phone number");?>
                        </button>

                    </form>

                    <?php if($error!=""){ ?>
                    <div class="alert alert-danger text-center mt-3">
                        <?php echo $error; ?>
                    </div>
                    <?php } ?>

                </div>

            </div>

        </div>
    </div>

    <!-- FOOTER -->

    <footer class="py-3 border-top footer-custom">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center small">

                <div>
                    <?php echo t("© 2026 Scam Detection Platform – BTEC FPT"); ?>
                </div>

                <div>
                    <a href="#" class="footer-link"><?php echo t("Privacy Policy");?></a>
                    &middot;
                    <a href="#" class="footer-link"><?php echo t("Terms & Conditions");?></a>
                </div>

            </div>
        </div>
    </footer>

</body>

</html>

<script>
function validatePhone() {

    const phoneInput = document.getElementById("phoneInput");
    const phoneInfo = document.getElementById("phoneInfo");

    const phone = phoneInput.value.trim();

    const phoneRegex = /^(0\d{7,10}|1900\d{4})$/;

    if (!phoneRegex.test(phone)) {

        phoneInput.classList.add("is-invalid");
        phoneInput.classList.remove("is-valid");

        phoneInfo.classList.add("d-none");

        return false;

    } else {

        phoneInput.classList.remove("is-invalid");
        phoneInput.classList.add("is-valid");

        if (/^1900\d{4}$/.test(phone)) {
            phoneInfo.textContent = "This is a premium service number (1900).";
            phoneInfo.classList.remove("d-none");
        } else {
            phoneInfo.classList.add("d-none");
        }

        return true;
    }
}

function validateForm() {
    return validatePhone();
}
</script>