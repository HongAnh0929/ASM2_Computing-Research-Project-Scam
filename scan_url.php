<?php
session_start();
require_once '../Database/database.php';
require_once 'functions/translate.php';

// --- CSRF Token ---
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Handle Language Switch ---
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
}
$lang = $_SESSION['lang'] ?? 'en';

// --- Guest scan limit ---
$alertMessage = '';
$canScan = true;
$max_scans = 5;
$scan_reset_hours = 24;

// Reset count nếu chưa set hoặc quá 24h
if (!isset($_SESSION['user_id'])) {
    if (!isset($_SESSION['url_search_count']) || !isset($_SESSION['url_search_start'])) {
        $_SESSION['url_search_count'] = 0;
        $_SESSION['url_search_start'] = time();
    } elseif (time() - $_SESSION['url_search_start'] >= $scan_reset_hours * 3600) {
        $_SESSION['url_search_count'] = 0;
        $_SESSION['url_search_start'] = time();
    }
}

// --- Handle form POST ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $url = trim($_POST['url'] ?? '');
    $csrf = $_POST['csrf_token'] ?? '';

    // CSRF check
    if ($csrf !== ($_SESSION['csrf_token'] ?? '')) {
        $alertMessage = t("Invalid CSRF token");
        $canScan = false;
    }

    // Validate URL
    if ($canScan && !filter_var($url, FILTER_VALIDATE_URL)) {
        $alertMessage = t("Invalid URL format. Make sure to include http:// or https://");
        $canScan = false;
    }

    // Guest limit check
    if (!isset($_SESSION['user_id']) && $_SESSION['url_search_count'] >= $max_scans) {
        $alertMessage = t("You have reached the maximum number of scans as a guest. Please register to continue.");
        $canScan = false;
    }

    // Nếu hợp lệ và không vượt limit -> tăng count
    if ($canScan && !isset($_SESSION['user_id'])) {
        $_SESSION['url_search_count']++;
    }

    // Nếu hợp lệ -> redirect sang result_url.php
    if ($canScan) {
        $_SESSION['scan_url'] = $url;
        header('Location: result_url.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($lang); ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo t("URL Scan"); ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
<style>
html, body {height:100%;margin:0;padding:0;}
body {display:flex;flex-direction:column;min-height:100vh;background-image:url('img/background.png');background-size:cover;background-position:center;color:white;}
.overlay {flex-grow:1;display:flex;justify-content:center;align-items:flex-start;padding-top:120px;padding-bottom:40px;background:rgba(0,0,0,0.55);}
.overlay .container {max-width:700px;width:100%;padding:2rem;background:rgba(0,0,0,0.75);border-radius:12px;}
.overlay h1 {text-align:center;font-size:2.5rem;font-weight:700;margin-bottom:0.5rem;color:white;}
.overlay h2 {text-align:center;font-size:1.3rem;font-weight:400;margin-bottom:1.5rem;color:white;}
.form-control {background:white;color:black;border:1px solid #ccc;border-radius:8px;padding:10px;}
.form-control::placeholder {color:#6b7280;}
.form-control:focus {background:white;color:black;border-color:#0ea5e9;box-shadow:0 0 5px rgba(14,165,233,0.5);}
.btn-primary {background-color:#0ea5e9;border-color:#0ea5e9;color:white;}
.btn-primary:hover {background-color:#0284c7;border-color:#0284c7;}
.navbar {background: rgba(0,0,0,0.5);backdrop-filter:blur(6px);z-index:10500;}
.footer-custom {background:rgba(0,0,0,0.75);color:white;padding:15px 0;}
.footer-link {color:#ddd;text-decoration:none;}
.footer-link:hover {color:white;text-decoration:underline;}
.lang-btn {display:flex;align-items:center;padding:4px 10px;border-radius:6px;font-size:0.85rem;font-weight:600;text-decoration:none;transition:all 0.3s ease;background:#f8f9fa;color:#334155;border:1px solid #e2e8f0;}
.lang-btn.active {background:#0ea5e9;color:white;border-color:#0ea5e9;box-shadow:0 0 10px rgba(14,165,233,0.4);}
.flag-img {width:20px;height:15px;object-fit:cover;border-radius:2px;}
.lang-btn:hover:not(.active) {background:#e2e8f0;}
</style>
</head>
<body class="d-flex flex-column min-vh-100">

<!-- NAVBAR -->
<nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
<div class="container-fluid">
<a class="navbar-brand fw-bold fs-3 me-5" href="index.php"><?php echo t("SCAM BTEC"); ?></a>
<button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
<span class="navbar-toggler-icon"></span>
</button>
<div class="collapse navbar-collapse" id="navbarNav">
<ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
<li class="nav-item"><a class="nav-link active" href="index.php"><?php echo t("HOME");?></a></li>
<li class="nav-item"><a class="nav-link active" href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a></li>
<li class="nav-item"><a class="nav-link active" href="scan_url.php"><?php echo t("URL");?></a></li>
<li class="nav-item"><a class="nav-link active" href="scan_email.php"><?php echo t("EMAIL");?></a></li>
</ul>
<div class="d-flex align-items-center gap-3">
<div class="d-flex gap-2 ms-3 align-items-center">
<a href="?lang=en" class="lang-btn <?php echo $lang=='en' ? 'active':'';?>"><img src="https://flagcdn.com/w40/gb.png" class="flag-img"> EN</a>
<a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active':'';?>"><img src="https://flagcdn.com/w40/vn.png" class="flag-img"> VI</a>
</div>
<?php if(isset($_SESSION['user_id'])): ?>
<div class="dropdown">
<a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown"><i class="bi bi-person-circle fs-3"></i></a>
<ul class="dropdown-menu dropdown-menu-end shadow">
<li class="dropdown-header"><a href="profile.php" class="text-decoration-none text-dark"><?php echo htmlspecialchars($_SESSION['username'] ?? 'Guest'); ?></a></li>
<li><a class="dropdown-item" href="history.php"><i class="bi bi-clock-history me-2"></i><?php echo t("History");?></a></li>
<li><hr class="dropdown-divider"></li>
<li><a class="dropdown-item text-danger" href="logout.php"><i class="bi bi-box-arrow-right me-2"></i><?php echo t("Logout");?></a></li>
</ul>
</div>
<?php else: ?>
<a href="login.php" class="btn btn-outline-info"><?php echo t("Sign in");?></a>
<a href="register.php" class="btn btn-outline-info"><?php echo t("Sign up");?></a>
<?php endif; ?>
</div>
</div>
</div>
</nav>

<!-- MAIN -->
<div class="overlay">
<div class="container">
<h1><?php echo t("URL Scan"); ?></h1>
<h2><?php echo t("Check links before you click them"); ?></h2>

<?php if($alertMessage): ?>
<div class="alert alert-warning text-center" role="alert">
<?php echo $alertMessage; ?>
</div>
<?php endif; ?>

<form method="post" action="">
<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
<input type="url" name="url" class="form-control mb-3" placeholder="<?php echo t("Enter URL..."); ?>" required>
<button type="submit" class="btn btn-primary w-100"><?php echo t("Scan URL"); ?></button>
</form>
</div>
</div>

<!-- FOOTER -->
<footer class="py-3 border-top footer-custom mt-auto">
<div class="container d-flex justify-content-between small">
<div><?php echo t("© 2026 Scam Detection Platform – BTEC FPT"); ?></div>
<div><a href="#" class="footer-link"><?php echo t("Privacy Policy");?></a> · <a href="#" class="footer-link"><?php echo t("Terms & Conditions");?></a></div>
</div>
</footer>

</body>
</html>