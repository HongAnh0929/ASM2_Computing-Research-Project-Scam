<?php
session_start();
require_once '../Database/database.php';
require_once '../vendor/autoload.php';
require_once 'functions/translate.php';

use Dotenv\Dotenv;

/* ===== LOAD ENV ===== */
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ===== CHECK LOGIN ===== */
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Xử lý thay đổi ngôn ngữ
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {

    $_SESSION['lang'] = $_GET['lang'];

    // Lấy đúng trang hiện tại (không bị quay về index)
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');

    header("Location: $currentPage");
    exit;
}

$lang = $_SESSION['lang'] ?? 'en';

/* ===== DECRYPT ===== */
function decryptData($data){
    global $secret_key;
    if(empty($data)) return "";
    $data = base64_decode($data);
    $iv = substr($data,0,16);
    $enc = substr($data,16);
    return openssl_decrypt($enc,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);
}

/* ===== GET USER DATA ===== */
$stmt = $conn->prepare("
    SELECT 
        username_encrypted,
        email_encrypted,
        phone_encrypted,
        gender_encrypted,
        dob_encrypted,
        created_at,
        status
    FROM users 
    WHERE id=?
");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
if ($result->num_rows === 0) die("User not found");
$user = $result->fetch_assoc();

/* ===== DECRYPT ===== */
$username = decryptData($user['username_encrypted']);
$email    = decryptData($user['email_encrypted']);
$phone    = decryptData($user['phone_encrypted']);
$gender   = decryptData($user['gender_encrypted']);
$dob      = decryptData($user['dob_encrypted']);
$status   = $user['status'];
$created  = $user['created_at'];
?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

    <title>User Profile</title>

    <style>
    html,
    body {
        height: 100%;
        margin: 0;
        padding: 0;
    }

    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        padding-top: 50px;
    }

    /* Overlay làm mờ background */
    .overlay {
        background: rgba(0, 0, 0, 0.55);
        width: 100%;
        min-height: calc(100vh - 50px);
        /* trừ navbar */
        display: flex;
        justify-content: center;
        /* canh giữa ngang */
        align-items: flex-start;
        /* canh từ trên xuống */
        padding-top: 60px;
        /* cách navbar vừa phải */
        padding-bottom: 40px;
    }

    /* Container bên trong overlay */
    .overlay .container {
        padding: 0;
        max-width: 100%;
        display: flex;
        justify-content: center;
    }

    /* Nút đổi ngôn ngữ */
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

    .lang-btn:hover:not(.active) {
        background: #e2e8f0;
        transform: translateY(-1px);
    }

    .flag-img {
        width: 20px;
        height: 15px;
        object-fit: cover;
        border-radius: 2px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }

    /* Profile card */
    .profile-card {
        background: white;
        border-radius: 12px;
        padding: 30px;
        /* giảm padding card */
        max-width: 500px;
        width: 100%;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.2);
    }

    /* Tiêu đề card */
    .profile-card h3 {
        font-weight: 700;
        margin-bottom: 25px;
        text-align: center;
        color: #0ea5e9;
    }

    /* Label */
    .profile-card label {
        font-weight: 600;
        color: #334155;
    }

    /* Input */
    .profile-card input.form-control {
        background: #f1f5f9;
        border: 1px solid #cbd5e1;
        color: #1e293b;
    }

    .profile-card input.form-control:focus {
        border-color: #0ea5e9;
        box-shadow: 0 0 5px rgba(14, 165, 233, 0.5);
    }

    /* Back button */
    .text-end a.btn {
        background-color: #0ea5e9;
        color: white;
        border: none;
    }

    .text-end a.btn:hover {
        background-color: #0284c7;
    }

    /* Navbar */
    .navbar {
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(6px);
    }

    /* Banner box (nếu dùng) */
    .banner-box {
        border: 2px solid #000;
        padding: 40px;
        background: rgba(0, 0, 0, 0.7);
        color: white;
        min-height: 250px;
        margin-top: 80px;
        display: flex;
        align-items: center;
    }

    .banner-text {
        max-width: 500px;
    }

    /* Footer */
    .footer-custom {
        background: rgba(0, 0, 0, 0.75);
        color: white;
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

<body>

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

    <div class="overlay">
        <div class="container">
            <div class="profile-card">
                <h3 class="mb-4 text-center text-black"><?php echo t("User Profile");?></h3>
                <div class="mb-3">
                    <label><?php echo t("Username");?></label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($username); ?>" readonly>
                </div>
                <div class="mb-3">
                    <label><?php echo t("Email");?></label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($email); ?>" readonly>
                </div>
                <div class="mb-3">
                    <label><?php echo t("Phone");?></label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($phone); ?>" readonly>
                </div>
                <div class="mb-3">
                    <label><?php echo t("Gender");?></label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($gender); ?>" readonly>
                </div>
                <div class="mb-3">
                    <label><?php echo t("Day of Birth");?></label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($dob); ?>" readonly>
                </div>
                <div class="mb-3">
                    <label><?php echo t("Status");?></label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($status); ?>" readonly>
                </div>
                <div class="mb-3">
                    <label><?php echo t("Account Created");?></label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($created); ?>" readonly>
                </div>

                <a href="index.php" class="btn btn-secondary mt-3">← Back</a>

            </div>
        </div>
    </div>

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