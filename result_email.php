<?php
session_start();

require_once __DIR__ . '/../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

require_once '../Database/database.php';
require_once 'functions/translate.php';

/* ================= LANG SWITCH ================= */
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $query = $_GET;
    unset($query['lang']);
    $newQuery = http_build_query($query);
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: " . $currentPage . ($newQuery ? "?$newQuery" : ""));
    exit;
}

$lang = $_SESSION['lang'] ?? 'en';

/* ================= AI FUNCTION ================= */
function analyse_email_with_gemini($sender, $subject, $body, $attachments, $lang) {
    $api_key = $_ENV['GEMINI_API_KEY'] ?? '';
    if (!$api_key) {
        return [
            'risk_level' => 'unknown',
            'score' => 0,
            'reasons' => ['API KEY NOT FOUND'],
            'advice' => '',
            'explanation' => ''
        ];
    }

    $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" . $api_key;
    $attachmentDesc = empty($attachments) ? "none" : implode(', ', $attachments);
    $language_instruction = ($lang === 'vi') ? "Vietnamese" : "English";

    $prompt = "
        You are a cybersecurity expert.

        Analyse the email and return STRICT JSON ONLY.

        NO explanation outside JSON.
        NO markdown.
        NO extra text.

        Write in $language_instruction.

        FORMAT:
        {
        \"risk_level\":\"LOW|MEDIUM|HIGH\",
        \"score\": number,
        \"reasons\":[],
        \"advice\":\"\",
        \"explanation\":\"\"
        }
    ";

    $emailDetails = "Sender: $sender\nSubject: $subject\nAttachments: $attachmentDesc\nBody:\n$body";

    $payload = [
        "contents" => [
            [
                "parts" => [
                    ["text" => $prompt],
                    ["text" => $emailDetails]
                ]
            ]
        ]
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_TIMEOUT => 20
    ]);

    $response = curl_exec($ch);

    if ($response === false) {
        return [
            'risk_level' => 'unknown',
            'score' => 0,
            'reasons' => ['CURL ERROR: ' . curl_error($ch)],
            'advice' => '',
            'explanation' => ''
        ];
    }

    curl_close($ch);

    $data = json_decode($response, true);
    $text = $data['candidates'][0]['content']['parts'][0]['text'] ?? '';

    if (!$text) {
        return [
            'risk_level' => 'unknown',
            'score' => 0,
            'reasons' => ['EMPTY AI RESPONSE', json_encode($data)],
            'advice' => t('AI did not return any result'),
            'explanation' => ''
        ];
    }

    $text = trim($text);
    $text = preg_replace('/```(json)?/i', '', $text);
    preg_match('/\{.*\}/s', $text, $matches);
    $json_string = $matches[0] ?? '';
    $parsed = json_decode($json_string, true);

    if (!is_array($parsed)) {
        return [
            'risk_level' => 'unknown',
            'score' => 0,
            'reasons' => ["AI RAW: " . $text],
            'advice' => t('AI response could not be parsed'),
            'explanation' => ''
        ];
    }

    return [
        'risk_level' => $parsed['risk_level'] ?? 'unknown',
        'score' => intval($parsed['score'] ?? 0),
        'reasons' => $parsed['reasons'] ?? [],
        'advice' => $parsed['advice'] ?? '',
        'explanation' => $parsed['explanation'] ?? ''
    ];
}

/* ================= HANDLE POST ================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email_address'] ?? '';
    $subject = $_POST['email_subject'] ?? '';
    $content = $_POST['email_content'] ?? '';
    $attachments = $_POST['attachments'] ?? [];

    $analysis = analyse_email_with_gemini($email, $subject, $content, $attachments, $lang);

    $_SESSION['analysis'] = $analysis;
    $_SESSION['email_data'] = compact('email','subject','content');

    $query = [];
    if (isset($_SESSION['lang'])) $query['lang'] = $_SESSION['lang'];

    header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?') . '?' . http_build_query($query));
    exit;
}

/* ================= LOAD RESULT ================= */
$email_address = $_SESSION['email_data']['email'] ?? '';
$email_subject = $_SESSION['email_data']['subject'] ?? '';
$email_content = $_SESSION['email_data']['content'] ?? '';
$attachments = $_POST['attachments'] ?? [];
$analysis = $_SESSION['analysis'] ?? [];

/* ================= SET COLORS & SCORE FOR RISK LEVEL ================= */
$risk_level = strtoupper($analysis['risk_level'] ?? 'UNKNOWN');

switch ($risk_level) {
    case 'LOW':
        $color = '#28a745';
        $percent = 20;
        break;
    case 'MEDIUM':
        $color = '#ffc107';
        $percent = 55;
        break;
    case 'HIGH':
        $color = '#dc3545';
        $percent = 90;
        break;
    default:
        $color = '#6c757d';
        $percent = 0;
}
?>

<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">

<head>
    <meta charset="UTF-8">
    <title><?php echo t("Email Scan Result"); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        font-family: Arial;
    }

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        padding-top: 120px;
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

    .ai-box,
    .original-email {
        width: 90%;
        max-width: 700px;
        padding: 25px;
        border-radius: 10px;
    }

    .ai-box {
        background: #1c1c1c;
        border-left: 5px solid #0d6efd;
        color: #fff;
    }

    .original-email {
        background: #1c1c1c;
        color: #f8f9fa;
        text-align: left;
    }


    .original-email h5 {
        font-weight: bold;
        margin-bottom: 10px;
    }

    .original-email pre {
        background: #212529;
        color: #f8f9fa;
        padding: 10px;
        border-radius: 5px;
        max-height: 250px;
        overflow: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        font-size: 14px;
    }

    .progress-circle {
        width: 80px;
        height: 80px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        font-size: 16px;
        position: relative;
        margin-left: auto;
    }

    .progress-circle span {
        position: relative;
        z-index: 2;
    }

    .progress-circle::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        border-radius: 50%;
        background: conic-gradient(var(--circle-color, #28a745) calc(var(--circle-percent, 0)*1%), #e9ecef 0);
    }

    .btn-back {
        margin-top: 20px;
    }

    .navbar {
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(6px);
    }

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
                <div class="d-flex gap-2 ms-3 align-items-center">

                    <?php
                    $query = $_GET ?? []; // FIX lỗi undefined

                    $query_en = $query;
                    $query_en['lang'] = 'en';
                    ?>

                    <a href="?<?php echo http_build_query($query_en); ?>"
                        class="lang-btn <?php echo $lang=='en' ? 'active' : ''; ?>">
                        <img src="https://flagcdn.com/w40/gb.png" class="flag-img" alt="English">
                        <span class="ms-1">EN</span>
                    </a>

                    <?php
                    $query_vi = $query;
                    $query_vi['lang'] = 'vi';
                    ?>

                    <a href="?<?php echo http_build_query($query_vi); ?>"
                        class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
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
        <div class="container py-5">
            <div class="text-center text-white mb-4">
                <h2><?php echo t("Email Scan Result"); ?></h2>
            </div>
            <div class="d-flex justify-content-center">
                <div class="ai-box">
                    <h3><?php echo t("AI Email Analysis"); ?></h3>
                    <p><?php echo t("Risk Level"); ?>: <span
                            style="color:<?php echo $color;?>"><?php echo $risk_level;?></span>
                    </p>
                    <div class="progress-circle" data-percent="<?php echo $percent;?>"
                        data-color="<?php echo $color;?>">
                        <span><?php echo $percent;?>%</span>
                    </div>

                    <?php if (!empty($analysis['reasons'])): ?>
                    <h5><?php echo t("Reasons Detected"); ?>:</h5>
                    <ul>
                        <?php foreach ($analysis['reasons'] as $r): ?>
                        <li><?php echo htmlspecialchars($r);?></li>
                        <?php endforeach;?>
                    </ul>
                    <?php endif; ?>

                    <?php if (!empty($analysis['advice'])): ?>
                    <h5><?php echo t("Advice"); ?>:</h5>
                    <p><?php echo nl2br(htmlspecialchars($analysis['advice']));?></p>
                    <?php endif; ?>
                </div>
            </div>

            <?php if(!empty($email_address) && !empty($email_content)): ?>
            <div class="original-email">
                <h5><?php echo t("Original Email"); ?></h5>
                <p><strong><?php echo t("From"); ?>:</strong> <?php echo htmlspecialchars($email_address); ?></p>
                <p><strong><?php echo t("Subject"); ?>:</strong> <?php echo htmlspecialchars($email_subject); ?></p>
                <p><strong><?php echo t("Attachments"); ?>:</strong>
                    <?php echo empty($attachments)?t('None'):implode(', ', array_map('htmlspecialchars',$attachments)); ?>
                </p>
                <pre><?php echo htmlspecialchars($email_content); ?></pre>
            </div>
            <?php endif; ?>

            <a href="scan_email.php" class="btn btn-secondary btn-back">← <?php echo t("Back"); ?></a>
        </div>

    </div>

    <!-- ================= FOOTER ================= -->

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

    <script>
    document.querySelectorAll('.progress-circle').forEach(el => {
        const percent = el.getAttribute('data-percent') || 0;
        const color = el.getAttribute('data-color') || '#28a745';
        el.style.setProperty('--circle-percent', percent);
        el.style.setProperty('--circle-color', color);
    });
    </script>

</body>

</html>