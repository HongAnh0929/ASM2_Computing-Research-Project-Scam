<?php
session_start();
require_once '../Database/database.php';
require_once 'functions/translate.php';

// --- Guest scan limit ---
$alertMessage = '';
$remaining_scans = 5; // mặc định cho guest

if (!isset($_SESSION['user_id'])) { // Chỉ guest mới bị giới hạn
    if (!isset($_SESSION['email_search_count'])) {
        $_SESSION['email_search_count'] = 0;
    }
    $remaining_scans = 5 - $_SESSION['email_search_count'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email_address'] ?? '';

    if (!isset($_SESSION['user_id'])) {
        $_SESSION['email_search_count']++;
        $remaining_scans = 5 - $_SESSION['email_search_count'];

        if ($_SESSION['email_search_count'] > 5) {
            $alertMessage = t("You have exceeded the maximum number of free email scans. Please register to continue.");
        }
    }

    // Nếu user đã login, không giới hạn
    // Tiếp tục xử lý gửi form sang scan.php
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo t("Check Email");?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
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
        color: white;
    }

    .overlay {
        flex-grow: 1;
        display: flex;
        justify-content: center;
        align-items: flex-start;
        padding-top: 120px;
        padding-bottom: 40px;
        background: rgba(0, 0, 0, 0.55);
    }

    .col-md-8.col-lg-7 {
        max-width: 700px;
        width: 100%;
    }

    .navbar {
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(6px);
        z-index: 10500;
    }

    .footer-custom {
        background: rgba(0, 0, 0, 0.75);
        color: white;
        padding: 15px 0;
    }

    .form-control {
        background: white;
        color: black;
        border: 1px solid #ccc;
        border-radius: 8px;
        padding: 10px;
    }

    .btn-primary {
        background-color: #0ea5e9;
        border-color: #0ea5e9;
    }

    .btn-primary:hover {
        background-color: #0284c7;
        border-color: #0284c7;
    }

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

    .flag-img {
        width: 20px;
        height: 15px;
        object-fit: cover;
        border-radius: 2px;
    }

    .lang-btn:hover:not(.active) {
        background: #e2e8f0;
    }
    </style>
</head>

<body class="d-flex flex-column min-vh-100">

    <!-- NAVBAR -->
    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
        <div class="container-fluid">
            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php"><?php echo t("SCAM BTEC"); ?></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span
                    class="navbar-toggler-icon"></span></button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item"><a class="nav-link active" href="index.php"><?php echo t("HOME");?></a></li>
                    <li class="nav-item"><a class="nav-link active"
                            href="phonenumber.php"><?php echo t("PHONE NUMBER");?></a></li>
                    <li class="nav-item"><a class="nav-link active" href="scan_url.php"><?php echo t("URL");?></a></li>
                    <li class="nav-item"><a class="nav-link active" href="scan_email.php"><?php echo t("EMAIL");?></a>
                    </li>
                </ul>
                <div class="d-flex align-items-center gap-3">
                    <?php $lang = $_SESSION['lang'] ?? 'en'; ?>
                    <div class="d-flex gap-2 ms-3 align-items-center">
                        <a href="?lang=en" class="lang-btn <?php echo $lang=='en'?'active':'';?>"><img
                                src="https://flagcdn.com/w40/gb.png" class="flag-img"> EN</a>
                        <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi'?'active':'';?>"><img
                                src="https://flagcdn.com/w40/vn.png" class="flag-img"> VI</a>
                    </div>
                    <?php if(isset($_SESSION['user_id'])): ?>
                    <div class="dropdown">
                        <a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle" href="#"
                            data-bs-toggle="dropdown"><i class="bi bi-person-circle fs-3"></i></a>
                        <ul class="dropdown-menu dropdown-menu-end shadow">
                            <li class="dropdown-header"><a href="profile.php"
                                    class="text-decoration-none text-dark"><?php echo htmlspecialchars($_SESSION['username'] ?? 'Guest'); ?></a>
                            </li>
                            <li><a class="dropdown-item" href="history.php"><i
                                        class="bi bi-clock-history me-2"></i><?php echo t("History");?></a></li>
                            <li>
                                <hr class="dropdown-divider">
                            </li>
                            <li><a class="dropdown-item text-danger" href="logout.php"><i
                                        class="bi bi-box-arrow-right me-2"></i><?php echo t("Logout");?></a></li>
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
            <div class="row justify-content-center">
                <div class="col-md-8 col-lg-7">
                    <h2 class="text-center mb-4"><?php echo t("CHECK EMAIL"); ?></h2>

                    <div class="p-4 bg-secondary bg-opacity-25 border border-light rounded">
                        <?php if($alertMessage): ?>
                        <div class="alert alert-warning text-dark text-center">
                            <?php echo $alertMessage; ?>
                        </div>
                        <script>
                        setTimeout(() => {
                            window.location.href = 'register.php';
                        }, 3000);
                        </script>
                        <?php else: ?>
                        <?php if(!isset($_SESSION['user_id'])): ?>
                        <p><?php echo t("Remaining free email scans: "); ?><?php echo $remaining_scans; ?></p>
                        <?php endif; ?>
                        <form method="post" action="result_email.php">
                            <input type="hidden" name="type" value="email">
                            <div class="mb-3">
                                <label for="emailAddrInput" class="form-label"><?php echo t("Email address"); ?></label>
                                <input type="email" class="form-control" id="emailAddrInput" name="email_address"
                                    placeholder="user@example.com" required>
                            </div>
                            <div class="mb-3">
                                <label for="emailSubjectInput"
                                    class="form-label"><?php echo t("Email subject"); ?></label>
                                <input type="text" class="form-control" id="emailSubjectInput" name="email_subject"
                                    placeholder="<?php echo t("Subject line shown in your inbox"); ?>" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label"><?php echo t("Attachments (if any)"); ?></label>
                                <div class="form-check"><input class="form-check-input" type="checkbox" value="image"
                                        id="attImage" name="attachments[]"><label class="form-check-label"
                                        for="attImage"><?php echo t("Images (JPG, PNG, etc.)"); ?></label></div>
                                <div class="form-check"><input class="form-check-input" type="checkbox" value="pdf"
                                        id="attPdf" name="attachments[]"><label class="form-check-label"
                                        for="attPdf"><?php echo t("Documents"); ?></label></div>
                                <div class="form-check"><input class="form-check-input" type="checkbox" value="video"
                                        id="attVideo" name="attachments[]"><label class="form-check-label"
                                        for="attVideo"><?php echo t("Video files"); ?></label></div>
                                <div class="form-check"><input class="form-check-input" type="checkbox" value="other"
                                        id="attOther" name="attachments[]"><label class="form-check-label"
                                        for="attOther"><?php echo t("Other / unknown file type"); ?></label></div>
                                <small
                                    class="text-muted"><?php echo t("You don’t need to upload files, just tell us what types were attached."); ?></small>
                            </div>
                            <div class="mb-3">
                                <label for="emailContentInput"
                                    class="form-label"><?php echo t("Email contents"); ?></label>
                                <textarea class="form-control" id="emailContentInput" name="email_content" rows="6"
                                    placeholder="<?php echo t("Paste the full email body here"); ?>"
                                    required></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary w-100"><?php echo t("Scan Email"); ?></button>
                            <div class="container-fluid bg-black text-center p-3 mt-3 rounded">
                                <p class="sub mb-0">
                                    <?php echo t("Disclaimer: This website is for educational purposes only. Use responsibly."); ?>
                                </p>
                            </div>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- FOOTER -->
    <footer class="py-3 border-top footer-custom mt-auto">
        <div class="container d-flex justify-content-between small">
            <div><?php echo t("© 2026 Scam Detection Platform – BTEC FPT"); ?></div>
            <div><a href="#" class="footer-link"><?php echo t("Privacy Policy"); ?></a> · <a href="#"
                    class="footer-link"><?php echo t("Terms & Conditions"); ?></a></div>
        </div>
    </footer>

</body>

</html>