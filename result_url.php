<?php
session_start();

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../Database/database.php';
require_once 'functions/translate.php';
require_once 'logger.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$Parsedown = new Parsedown();
$Parsedown->setSafeMode(true);

$GEMINI_API_KEY = $_ENV['GEMINI_API_KEY'] ?? '';
$GOOGLE_SAFEBROWSING_KEY = $_ENV['GOOGLE_SAFEBROWSING_KEY'] ?? '';
$VIRUSTOTAL_KEY = $_ENV['VIRUSTOTAL_KEY'] ?? '';

/* ================= INPUT ================= */
$url_input = $_SESSION['scan_url'] ?? '';
if (!$url_input) {
    header('Location: scan_url.php');
    exit;
}

if (!filter_var($url_input, FILTER_VALIDATE_URL)) {
    die("Invalid URL");
}

$lang = $_SESSION['lang'] ?? 'en';

/* ================= RISK COLOR ================= */
function risk_color($r){
    return match(strtoupper($r)){
        "LOW" => "#198754",
        "MEDIUM" => "#ffc107",
        "HIGH" => "#dc3545",
        default => "#6c757d"
    };
}

/* ================= INDICATORS (FIXED) ================= */
function detect_indicators($url){

    $indicators = [];
    $host = parse_url($url, PHP_URL_HOST) ?? '';

    if(!str_starts_with($url,'https://')){
        $indicators[] = [
            'title'=>'No HTTPS',
            'desc'=>'Connection is not encrypted',
            'risk'=>30
        ];
    }

    if(strlen($host) > 35){
        $indicators[] = [
            'title'=>'Suspicious domain length',
            'desc'=>'Domain unusually long',
            'risk'=>15
        ];
    }

    $suspicious_words = ['login','secure','verify','update','password','bank'];

    foreach($suspicious_words as $word){
        if(stripos($url,$word) !== false && !str_contains($host,'microsoft.com') && !str_contains($host,'google.com')){
            $indicators[] = [
                'title'=>'Phishing keyword',
                'desc'=>"Detected keyword: $word (context checked)",
                'risk'=>10
            ];
        }
    }

    $official = ['google.com','facebook.com','apple.com','microsoft.com'];

    foreach($official as $brand){
        if(str_contains($host,$brand) && !preg_match("/(^|\.)$brand$/",$host)){
            $indicators[] = [
                'title'=>'Brand impersonation',
                'desc'=>"Fake subdomain mimicking $brand",
                'risk'=>40
            ];
        }
    }

    return $indicators;
}

/* ================= SAFE BROWSING ================= */
function check_google_safebrowsing($url){
    global $GOOGLE_SAFEBROWSING_KEY;

    if(!$GOOGLE_SAFEBROWSING_KEY){
        return ['safe'=>true];
    }

    $endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=".$GOOGLE_SAFEBROWSING_KEY;

    $body = [
        "client"=>["clientId"=>"scan","clientVersion"=>"1.0"],
        "threatInfo"=>[
            "threatTypes"=>["MALWARE","SOCIAL_ENGINEERING"],
            "platformTypes"=>["ANY_PLATFORM"],
            "threatEntryTypes"=>["URL"],
            "threatEntries"=>[["url"=>$url]]
        ]
    ];

    $ch = curl_init($endpoint);
    curl_setopt_array($ch,[
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_POST=>true,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
        CURLOPT_POSTFIELDS=>json_encode($body)
    ]);

    $res = curl_exec($ch);
    curl_close($ch);

    $json = json_decode($res,true);

    if(!empty($json['matches'])){
        return ['safe'=>false,'desc'=>'Flagged by Google Safe Browsing'];
    }

    return ['safe'=>true];
}

/* ================= VIRUSTOTAL ================= */
function check_virustotal($url){
    global $VIRUSTOTAL_KEY;

    if(!$VIRUSTOTAL_KEY){
        return ['safe'=>true];
    }

    $ch = curl_init("https://www.virustotal.com/api/v3/urls");
    curl_setopt_array($ch,[
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_POST=>true,
        CURLOPT_HTTPHEADER=>["x-apikey:$VIRUSTOTAL_KEY"],
        CURLOPT_POSTFIELDS=>http_build_query(['url'=>$url])
    ]);

    $res = curl_exec($ch);
    curl_close($ch);

    $json = json_decode($res,true);

    if(!isset($json['data']['id'])){
        return ['safe'=>true];
    }

    $id = $json['data']['id'];

    sleep(2);

    $ch = curl_init("https://www.virustotal.com/api/v3/analyses/$id");
    curl_setopt_array($ch,[
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_HTTPHEADER=>["x-apikey:$VIRUSTOTAL_KEY"]
    ]);

    $res = curl_exec($ch);
    curl_close($ch);

    $report = json_decode($res,true);

    $mal = $report['data']['attributes']['stats']['malicious'] ?? 0;

    return ($mal > 0)
        ? ['safe'=>false,'desc'=>"Detected malicious ($mal engines)"]
        : ['safe'=>true];
}

/* ================= AI ================= */
function call_ai($url,$indicators,$score,$key,$lang){

    if(!$key) return "";

    $endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=".$key;

    // =========================
    // AUTO LEVEL LOGIC
    // =========================
    if($score < 40){
        $level = "LOW";
        $instruction = "VERY SHORT SUMMARY ONLY (2-4 sentences max). No deep explanation. Focus on whether it is safe or not.";
    }
    elseif($score < 70){
        $level = "MEDIUM";
        $instruction = "MODERATE DETAIL. Explain key risks briefly, but do NOT over-explain.";
    }
    else{
        $level = "HIGH";
        $instruction = "DETAILED SECURITY ANALYSIS. Provide deep technical breakdown.";
    }

    // =========================
    // PROMPT
    // =========================
    $prompt = "You are a cybersecurity analyst.\n\n";

    $prompt .= "Analysis level: $instruction\n\n";

    $prompt .= "You MUST follow this output format strictly:\n";
    $prompt .= "Detailed Technical Analysis\nUser Warning\nConclusion\n\n";

    $prompt .= "RULES:\n";
    $prompt .= "- Do NOT repeat same information\n";
    $prompt .= "- LOW = short safe summary only\n";
    $prompt .= "- MEDIUM = moderate explanation\n";
    $prompt .= "- HIGH = full deep analysis\n\n";
    
    $prompt .= "URL: $url\n";
    $prompt .= "Risk Score: $score%\n";
    $prompt .= "Risk Level: $level\n\n";

    $prompt .= "Indicators:\n";

    foreach($indicators as $i){
        $prompt .= "- {$i['title']} ({$i['risk']}%): {$i['desc']}\n";
    }

    // =========================
    // REQUEST
    // =========================
    $data = [
        "contents"=>[
            ["parts"=>[
                ["text"=>$prompt]
            ]]
        ]
    ];

    $ch = curl_init($endpoint);
    curl_setopt_array($ch,[
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_POST=>true,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
        CURLOPT_POSTFIELDS=>json_encode($data),
        CURLOPT_TIMEOUT=>30
    ]);

    $res = curl_exec($ch);
    curl_close($ch);

    $json = json_decode($res,true);

    return $json['candidates'][0]['content']['parts'][0]['text'] ?? "";
}

/* ================= CLEAN AI ================= */
function clean_ai($text){
    return trim(str_replace(['```','**','###','---'], '', $text));
}

function highlight_text($text){
    $keywords = [
        'Brand impersonation',
        'Google Safe Browsing',
        'VirusTotal',
        'Phishing keyword',
        'HIGH RISK'
    ];

    foreach($keywords as $k){
        $text = str_replace(
            $k,
            "<span style='color:#dc3545;font-weight:700;'>$k</span>",
            $text
        );
    }

    return $text;
}

/* ================= PARSE ================= */
function section($text,$start,$end=null){
    $pattern = $end ? "/$start(.*)$end/s" : "/$start(.*)/s";
    return preg_match($pattern,$text,$m) ? trim($m[1]) : '';
}

/* ================= MAIN ================= */
$indicators = detect_indicators($url_input);

$gsb = check_google_safebrowsing($url_input);
if(!$gsb['safe']){
    $indicators[] = ['title'=>'Google Safe Browsing','desc'=>$gsb['desc'],'risk'=>80];
}

$vt = check_virustotal($url_input);
if(!$vt['safe']){
    $indicators[] = ['title'=>'VirusTotal','desc'=>$vt['desc'],'risk'=>80];
}

$score = min(array_sum(array_column($indicators,'risk')),100);

$risk = ($score >= 70) ? "HIGH" : (($score >= 40) ? "MEDIUM" : "LOW");

$ai_raw = clean_ai(call_ai($url_input,$indicators,$score,$GEMINI_API_KEY,$lang));

$analysis = [
    'risk_level' => $risk,
    'reasons' => $indicators,
    'advice' => ''
];

$risk = strtoupper($analysis['risk_level']);

if(!$ai_raw){
    $ai_raw = "Detailed Technical Analysis\nNo data available\nUser Warning\nNo warning\nConclusion\nNo conclusion";
}

$technical_html = nl2br(section($ai_raw,'Detailed Technical Analysis','User Warning'));
$user_warning_html = nl2br(section($ai_raw,'User Warning','Conclusion'));
$conclusion_html = nl2br(section($ai_raw,'Conclusion'));

/* DEBUG 
error_log("===== URL SCAN =====");
error_log("URL: $url_input");
error_log("Score: $score");
error_log("Risk: $risk");
error_log("Indicators: ".count($indicators));
error_log("====================");

log_block("URL SCAN");

log_line("🌐 URL: $url_input");
log_warning("Score: $score%");
log_line("🔥 Risk: $risk");
log_line("📊 Indicators: " . count($indicators));

foreach($indicators as $i){
    log_line("🔎 {$i['title']} ({$i['risk']}%)");
}

log_success("Scan completed");*/
?>

<!DOCTYPE html>
<html>

<head>
    <title><?php echo t("URL Scan Result"); ?></title>
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

    .result-card {
        max-width: 900px;
        margin: auto;
        padding: 30px;
        background: #fff;
        border-radius: 12px;
        margin-top: 60px;
        /* 👈 giảm từ 100px xuống */
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .url-box {
        font-size: 0.95rem;
    }

    .url-box a {
        font-size: 1.25rem;
        font-weight: 700;
        color: #0d6efd;
        text-decoration: none;
    }

    .url-box a:hover {
        text-decoration: underline;
    }

    .risk-wrapper {
        margin-top: 25px;
        /* 👈 đẩy xuống để không bị đè */
        margin-bottom: 25px;
    }

    .risk-bar {
        height: 18px;
        border-radius: 10px;
        background: #e9ecef;
        overflow: visible;
        position: relative;
    }

    /* số % */
    .risk-bar-label {
        position: absolute;
        top: -28px;
        transform: translateX(-50%);
        font-weight: 700;
        font-size: 13px;
        background: white;
        padding: 2px 8px;
        border-radius: 6px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
        white-space: nowrap;
    }

    .risk-bar-fill {
    height: 100%;
    width: 0%;
    transition: width .5s ease;
}

/* LOW */
.risk-bar.low .risk-bar-fill {
    background: #22c55e;
}

/* MEDIUM */
.risk-bar.medium .risk-bar-fill {
    background: #facc15;
}

/* HIGH */
.risk-bar.high .risk-bar-fill {
    background: #ef4444;
}

    /* Common card style cho tất cả box */
    .result-box {
        background: #fff;
        border-radius: 12px;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08);
        padding: 20px 25px;
        margin-top: 20px;
        font-size: 0.95rem;
        line-height: 1.5;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }

    .result-box.warning {
        border-left: 5px solid #ffc107;
        background: #fffbe6;
    }

    .result-box.conclusion {
        border-left: 5px solid #ffcd39;
        background: #fff3cd;
    }

    /* Hover effect giống Phone Number card */
    .result-box:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.12);
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
        <div class="result-card">
            <h2 class="text-center mb-4"><?php echo t("URL Scan Result"); ?></h2>

            <div class="url-box text-center mb-4">
                <span><?php echo t('URL to scan'); ?>:</span>
                <a href="<?=htmlspecialchars($url_input)?>" target="_blank"><?=htmlspecialchars($url_input)?></a>
            </div>

            <div class="mb-3">
                <b><?php echo t("Risk Level"); ?>:</b>
                <span style="font-weight:700;color:<?=risk_color($risk)?>;font-size:1.2rem"><?=$risk?></span>
                <div class="risk-wrapper">
                    <div class="risk-bar <?= strtolower($risk) ?>">
                        <div class="risk-bar-fill"></div>
                        <div class="risk-bar-label" id="riskText"><?=$score?>%</div>
                    </div>
                </div>
            </div>

            <h4><?php echo t("Indicators"); ?></h4>
            <ul>
                <?php foreach($indicators as $i): ?>

                <?php
                $is_critical = in_array($i['title'], [
                    'VirusTotal',
                    'Google Safe Browsing',
                    'Brand impersonation'
                ]);
                ?>

                <li style="<?= $is_critical ? 'background:#ffe5e5;padding:8px;border-radius:6px;' : '' ?>">

                    <b style="<?= $is_critical ? 'color:#dc3545;font-size:16px;' : '' ?>">
                        <?=htmlspecialchars($i['title'])?> (<?=$i['risk']?>%)
                    </b>

                    <br>

                    <span>
                        <?=htmlspecialchars($i['desc'])?>
                    </span>

                </li>

                <?php endforeach; ?>
            </ul>

            <div class="result-box">
                <h4><i class="bi bi-robot"></i> <?php echo t("Detailed Technical Analysis"); ?></h4>
                <div><?=$technical_html?></div>
            </div>

            <div class="result-box warning">
                <h4><i class="bi bi-bell-fill"></i> <?php echo t("User Warning"); ?></h4>
                <div><?=$user_warning_html?></div>
            </div>

            <div class="result-box conclusion">
                <h4><?php echo t("Conclusion"); ?></h4>
                <div><?= highlight_text($conclusion_html) ?></div>
            </div>

            <div class="text-center mt-4">
                <a href="scan_url.php" class="btn btn-secondary">← <?php echo t("Back"); ?></a>
            </div>
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
</body>

</html>

<script>
const score = Number(<?=json_encode($score)?>) || 0;

window.addEventListener('DOMContentLoaded', () => {
    const fill = document.querySelector('.risk-bar-fill');
    const label = document.getElementById('riskText');

    // fill thanh
    if (fill) {
        fill.style.width = score + "%";
    }

    // di chuyển số %
    if (label) {
        let pos = score;

        // tránh bị tràn
        if (pos < 5) pos = 5;
        if (pos > 95) pos = 95;

        label.style.left = pos + "%";
        label.innerText = score + "%";
    }
});
</script>