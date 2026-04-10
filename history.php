<?php
session_start();
require_once '../Database/database.php';
require_once '../vendor/autoload.php';
require_once 'functions/translate.php';
require_once 'functions/security.php'; // chứa encryptData, decryptData, hashData

use Dotenv\Dotenv;

/* ================= ENV ================= */
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

/* ================= LANGUAGE ================= */
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: $currentPage");
    exit;
}
$lang = $_SESSION['lang'] ?? 'en';

/* ================= CHECK LOGIN ================= */
if(!isset($_SESSION['user_id'])){
    header("Location: login.php");
    exit;
}
$user_id = $_SESSION['user_id'];

/* ================= SEARCH ================= */
$search = trim($_GET['search'] ?? '');

if($search !== ""){
    // Nếu nhập số → hash để tìm
    $search_phone = preg_replace('/\D/', '', $search);
    $phone_hash = hashData($search_phone);

    $like = "%$search%";

    $stmt = $conn->prepare("
        SELECT * FROM search_history
        WHERE user_id = ? 
        AND (phonenumber_hash = ? OR searched_at LIKE ?)
        ORDER BY searched_at DESC
    ");
    $stmt->bind_param("iss", $user_id, $phone_hash, $like);
} else {
    $stmt = $conn->prepare("
        SELECT * FROM search_history
        WHERE user_id = ?
        ORDER BY searched_at DESC
    ");
    $stmt->bind_param("i", $user_id);
}
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap" rel="stylesheet">
    <title><?php echo t("Search History");?></title>

    <style>
    body {
        margin: 0;
        padding: 0;
        font-family: 'Inter', sans-serif;
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
    }

    .navbar {
        background: rgba(0, 0, 0, 0.55);
        backdrop-filter: blur(6px);
    }

    .overlay {
        min-height: 100vh;
        width: 100%;
        background: rgba(0, 0, 0, 0.55);
        flex: 1;
        padding: 120px 20px 60px 20px;
        /* top: tăng 120px để cách navbar vừa phải */
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        justify-content: flex-start;
    }

    .overlay .container {
        margin-top: 5px;
        /* đẩy nội dung xuống, tạo khoảng cách vừa phải với navbar */
    }

    h1.text-white {
        margin-bottom: 20px;
        /* tạo khoảng cách giữa tiêu đề và search bar */
    }

    .history-card {
        background: white;
        border-radius: 10px;
        padding: 30px;
        box-shadow: 0 5px 20px rgba(0, 0, 0, 0.2);
        overflow-x: auto;
    }

    .table-hover tbody tr:hover {
        background-color: #f1f1f1;
    }

    .status-safe {
        color: #16a34a;
        font-weight: bold;
    }

    .status-scam {
        color: #dc2626;
        font-weight: bold;
    }

    .status-unknown {
        color: #eab308;
        font-weight: bold;
    }

    .highlight-row {
        background-color: #fff3cd;
        font-weight: 600;
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

    .footer-custom {
        background: rgba(0, 0, 0, 0.75);
        color: white;
        margin-top: auto;
        padding: 15px 0;
        text-align: center;
    }

    .footer-link {
        color: #ddd;
        text-decoration: none;
        margin: 0 5px;
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
                        <a class="nav-link active" aria-current="page" href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="scan_url.php"><?php echo t("URL");?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="scan_email.php"><?php echo t("EMAIL");?></a>
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

            <!-- TITLE + SEARCH -->
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h1 class="text-white"><?php echo t("Phone Search History"); ?></h1>
                <form class="d-flex" method="GET" action="history.php">
                    <div class="input-group" style="width:350px">
                        <span class="input-group-text"><i class="bi bi-search"></i></span>
                        <input class="form-control" type="text" name="search" placeholder="Search phone or date"
                            value="<?php echo htmlspecialchars($search);?>">
                        <button class="btn btn-success" type="submit"><?php echo t("Search");?></button>
                    </div>
                </form>
            </div>

            <!-- TABLE -->
            <div class="history-card">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th><?php echo t("Phone Number");?></th>
                            <th><?php echo t("Result");?></th>
                            <th><?php echo t("Date");?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
$i=1;
while($row = $result->fetch_assoc()){
    $phone = decryptData($row['phonenumber_encrypted']);
    if(!$phone) $phone = t("Unknown"); // tránh lỗi null
    $highlight = "";
    if($search != "" && (strpos($phone,$search)!==false || strpos($row['searched_at'],$search)!==false)){
        $highlight = "highlight-row";
    }
?>
                        <tr class="<?php echo $highlight;?>">
                            <td><?php echo $i++;?></td>
                            <td><a
                                    href="result.php?phone=<?php echo urlencode($phone);?>"><?php echo htmlspecialchars($phone);?></a>
                            </td>
                            <td>
                                <?php
$type = $row['result_type'];
if($type=="Legitimate") echo "<span class='status-safe'>".t("Legitimate")."</span>";
elseif($type=="Scam") echo "<span class='status-scam'>".t("Scam")."</span>";
else echo "<span class='status-unknown'>".t("Unknown")."</span>";
?>
                            </td>
                            <td><?php echo $row['searched_at'];?></td>
                        </tr>
                        <?php } ?>
                    </tbody>
                </table>
            </div>

            <div class="text-end mt-3">
                <a href="index.php" class="btn btn-secondary"><?php echo t("← Back");?></a>
            </div>

        </div>
    </div>

    <footer class="py-3 border-top footer-custom">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center small">
                <div><?php echo t("© 2026 Scam Detection Platform – BTEC FPT"); ?></div>
                <div><a href="#" class="footer-link"><?php echo t("Privacy Policy");?></a> &middot; <a href="#"
                        class="footer-link"><?php echo t("Terms & Conditions");?></a></div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>