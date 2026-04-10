<?php
session_start();
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../Database/database.php';
require_once 'functions/translate.php';

// =========================
// LOAD ENV
// =========================
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$GEMINI_API_KEY = $_ENV['GEMINI_API_KEY'] ?? '';
$GOOGLE_SAFEBROWSING_KEY = $_ENV['GOOGLE_SAFEBROWSING_KEY'] ?? '';
$VIRUSTOTAL_KEY = $_ENV['VIRUSTOTAL_KEY'] ?? '';

// =========================
// Xử lý ngôn ngữ
// =========================
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

// =========================
// ENCRYPT / DECRYPT
// =========================
function encryptData($data){
    $key = $_ENV['APP_ENCRYPT_KEY'] ?? 'default_secret_key_32chars!!';
    return openssl_encrypt($data, 'AES-256-CBC', substr(hash('sha256',$key,true),0,32), 0, substr(hash('sha256',$key,true),0,16));
}
function decryptData($data){
    $key = $_ENV['APP_ENCRYPT_KEY'] ?? 'default_secret_key_32chars!!';
    return openssl_decrypt($data, 'AES-256-CBC', substr(hash('sha256',$key,true),0,32), 0, substr(hash('sha256',$key,true),0,16));
}

// =========================
// GET URL
// =========================
$url_input = $_SESSION['scan_url'] ?? '';
if(!$url_input){ header('Location: scan_url.php'); exit; }
if(!filter_var($url_input, FILTER_VALIDATE_URL)){ die("Invalid URL"); }

// =========================
// PARSEDOWN
// =========================
$Parsedown = new Parsedown();
$Parsedown->setSafeMode(true);

// =========================
// DETECT INDICATORS
// =========================
function detect_indicators($url){
    $indicators = [];
    $domain = parse_url($url, PHP_URL_HOST);

    if(!str_starts_with($url,'https://')){
        $indicators[] = ['title'=>t('No HTTPS'),'desc'=>t('Connection not secure'),'risk'=>40];
    }
    if($domain && strlen($domain) > 25){
        $indicators[] = ['title'=>t('Suspicious domain'),'desc'=>t('Domain unusually long'),'risk'=>20];
    }

    $brands = [
        'Microsoft'=>'/microsoft|office365/i',
        'Google'=>'/google|gmail|drive/i',
        'Apple'=>'/apple|icloud/i',
        'Facebook'=>'/facebook|fb/i',
        'Amazon'=>'/amazon|aws/i',
        'Paypal'=>'/paypal/i',
        'Netflix'=>'/netflix/i'
    ];
    foreach($brands as $brand => $pattern){
        if(preg_match($pattern,$url) && !preg_match('/(^|\.)'.strtolower($brand).'\.com$/i',$domain)){
            $indicators[] = ['title'=>t('Brand impersonation'),'desc'=>t("Attempt to impersonate $brand"),'risk'=>30];
        }
    }

    return $indicators;
}

// =========================
// GOOGLE SAFE BROWSING
// =========================
function check_google_safebrowsing($url) {
    $apiKey = $_ENV['GOOGLE_SAFEBROWSING_KEY'] ?? '';
    if (!$apiKey) return ['safe'=>null, 'desc'=>t("Google Safe Browsing API key missing")];

    $endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$apiKey";

    $body = [
        "client" => ["clientId" => "SCAM_BTEC","clientVersion" => "1.0"],
        "threatInfo" => [
            "threatTypes" => ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes" => ["ANY_PLATFORM"],
            "threatEntryTypes" => ["URL"],
            "threatEntries" => [["url" => $url]]
        ]
    ];

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($body),
        CURLOPT_TIMEOUT => 10
    ]);

    $res = curl_exec($ch);
    if ($res === false) return ['safe'=>null, 'desc'=>curl_error($ch)];
    curl_close($ch);

    $json = json_decode($res, true);
    if (!empty($json['matches'])) {
        return ['safe'=>false, 'desc'=>t("Unsafe URL detected by Google Safe Browsing")];
    }
    return ['safe'=>true, 'desc'=>t("URL appears safe by Google Safe Browsing")];
}

// =========================
// VIRUSTOTAL CHECK
// =========================
function check_virustotal($url) {
    $apiKey = $_ENV['VIRUSTOTAL_KEY'] ?? '';
    if (!$apiKey) return ['safe'=>null, 'desc'=>t("VirusTotal API key missing")];

    $endpoint = "https://www.virustotal.com/api/v3/urls";
    $data = ["url" => $url];

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['x-apikey: '.$apiKey,'Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_POSTFIELDS => http_build_query($data),
        CURLOPT_TIMEOUT => 10
    ]);
    $res = curl_exec($ch);
    if ($res===false) return ['safe'=>null,'desc'=>curl_error($ch)];
    $json = json_decode($res,true);
    if(isset($json['data']['id'])){
        $analysis_id = $json['data']['id'];
        $report_url = "https://www.virustotal.com/api/v3/analyses/$analysis_id";

        $ch2 = curl_init($report_url);
        curl_setopt_array($ch2, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['x-apikey: '.$apiKey],
            CURLOPT_TIMEOUT => 10
        ]);
        $res2 = curl_exec($ch2);
        curl_close($ch2);
        $report = json_decode($res2,true);

        $malicious = $report['data']['attributes']['stats']['malicious'] ?? 0;
        if($malicious>0) return ['safe'=>false,'desc'=>t("Detected as malicious by VirusTotal")];
        return ['safe'=>true,'desc'=>t("No threats found on VirusTotal")];
    }

    return ['safe'=>null,'desc'=>t("VirusTotal scan unavailable")];
}

// =========================
// CALL AI
// =========================
function call_ai($url,$indicators,$score,$key,$lang){
    if(!$key) return "❌ GEMINI API KEY MISSING";

    $endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=".$key;
    $language_instruction = ($lang == 'vi') ? t("Write the report in Vietnamese.") : t("Write the report in English.");

    $prompt = "You are an automated website analysis system.\n";
    $prompt .= "Analyze the following URL and output in this exact format (Markdown with sections):\n\n";
    $prompt .= "Detailed Technical Analysis\n--------------------------\n";
    $prompt .= "[Provide a detailed technical analysis of the URL, its protocol, domain, and indicators]\n\n";
    $prompt .= "Indicator Name (XX%): Explanation\n";
    $prompt .= "User Warning\n------------\n";
    $prompt .= "[Provide clear, urgent user warning with steps to protect themselves]\n\n";
    $prompt .= "Conclusion\n----------\n";
    $prompt .= "[Provide a concise conclusion summarizing the risk]\n\n";
    $prompt .= "URL: $url\n";
    $prompt .= "Risk Score: $score%\n";

    $data = ["contents"=>[["parts"=>[["text"=>$prompt]]]]];

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($data),
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10
    ]);

    $res = curl_exec($ch);
    if($res===false) return "CURL ERROR: ".curl_error($ch);
    $json = json_decode($res,true);
    curl_close($ch);

    if(isset($json['error'])) return "API ERROR: ".$json['error']['message'];
    return $json['candidates'][0]['content']['parts'][0]['text'] ?? "AI ERROR";
}

// =========================
// CHECK CACHE
// =========================
$url_hash = hash('sha256',$url_input);
$stmt = $conn->prepare("SELECT ai_encrypted, score_encrypted, risk_encrypted, indicators_encrypted FROM url_results WHERE url_hash=? LIMIT 1");
$stmt->bind_param("s",$url_hash);
$stmt->execute();
$stmt->store_result();
$cached = false;
if($stmt->num_rows>0){
    $stmt->bind_result($enc_ai,$enc_score,$enc_risk,$enc_indicators);
    $stmt->fetch();
    $ai_raw = decryptData($enc_ai);
    $score = (int)decryptData($enc_score);
    $risk = decryptData($enc_risk);
    $indicators = json_decode(decryptData($enc_indicators),true);
    $cached = true;
}

// =========================
// RUN SCAN
// =========================
if(!$cached){
    $indicators = detect_indicators($url_input);

    // Google Safe Browsing
    $gsb = check_google_safebrowsing($url_input);
    if($gsb['safe']===false) $indicators[]=['title'=>t('Google Safe Browsing'),'desc'=>$gsb['desc'],'risk'=>50];

    // VirusTotal
    $vt = check_virustotal($url_input);
    if($vt['safe']===false) $indicators[]=['title'=>t('VirusTotal'),'desc'=>$vt['desc'],'risk'=>50];

    $score = min(array_sum(array_column($indicators,'risk')),100);
    if ($score < 40) {
        $risk = t('LOW');
    } elseif ($score < 75) {
        $risk = t('MEDIUM');
    } else {
        $risk = t('HIGH');
    }
    $ai_raw = call_ai($url_input,$indicators,$score,$GEMINI_API_KEY,$lang);

    // =========================
    // SAVE TO DATABASE
    // =========================
    $enc_url = encryptData($url_input);
    $enc_indicators = encryptData(json_encode($indicators));
    $enc_score = encryptData((string)$score);
    $enc_risk = encryptData($risk);
    $enc_ai = encryptData($ai_raw);

    $stmt = $conn->prepare("
        INSERT INTO url_results (url_encrypted,url_hash,indicators_encrypted,score_encrypted,risk_encrypted,ai_encrypted)
        VALUES (?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE updated_at=NOW()
    ");
    $stmt->bind_param("ssssss",$enc_url,$url_hash,$enc_indicators,$enc_score,$enc_risk,$enc_ai);
    $stmt->execute();
}

// =========================
// SPLIT AI OUTPUT
// =========================
$technical_raw=$user_warning_raw=$conclusion_raw='';
if(preg_match('/Detailed Technical Analysis\s*-+\s*(.*?)\nUser Warning\s*-+\s*(.*?)\nConclusion\s*-+\s*(.*)/si',$ai_raw,$m)){
    $technical_raw=trim($m[1]);
    $user_warning_raw=trim($m[2]);
    $conclusion_raw=trim($m[3]);
}else{
    $technical_raw=$ai_raw;
    $user_warning_raw=t("⚠️ Unable to split AI sections correctly");
    $conclusion_raw=t("AI response format error");
}

// Convert Markdown -> HTML
$technical_html = $Parsedown->text($technical_raw);
$user_warning_html = $Parsedown->text($user_warning_raw);
$conclusion_html = $Parsedown->text($conclusion_raw);

// =========================
// UTILS
// =========================
function risk_color($r){ return $r==t('LOW')?'green':($r==t('MEDIUM')?'orange':'red'); }
$score_label_pos = max(5,min(95,$score));
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
        margin-top: 100px;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .url-box {
        background: #f8f9fa;
        padding: 15px 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        word-break: break-word;
    }

    .risk-bar {
        height: 25px;
        border-radius: 12px;
        background: #e9ecef;
        position: relative;
        margin-top: 10px;
        margin-bottom: 20px;
    }

    .risk-bar-fill {
        height: 100%;
        background: linear-gradient(90deg, #22c55e, #facc15, #ef4444);
        width: 0%;
        transition: width 0.5s ease;
    }

    .risk-bar-label {
        position: absolute;
        top: -28px;
        transform: translateX(-50%);
        font-weight: bold;
        font-size: 0.95rem;
        color: #333;
        white-space: nowrap;
        z-index: 10;
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
                <div class="risk-bar">
                    <div class="risk-bar-fill"></div>
                    <div class="risk-bar-label"><?=$score?>%</div>
                </div>
            </div>

            <h4><?php echo t("Indicators"); ?></h4>
            <ul>
                <?php foreach($indicators as $i): ?>
                <?php 
                    // Nổi bật Google Safe Browsing & VirusTotal
                    $highlight = in_array($i['title'], [t('Google Safe Browsing'), t('VirusTotal')]) ? 'color:red;font-weight:bold;' : '';
                ?>
                <li style="<?= $highlight ?>">
                    <b><?=htmlspecialchars($i['title'])?> (<?=$i['risk']?>%)</b>
                    <?php if(!empty($i['desc'])): ?>
                    - <?=htmlspecialchars($i['desc'])?>
                    <?php endif; ?>
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
                <div><?=$conclusion_html?></div>
            </div>

            <div class="text-center mt-4">
                <a href="scan_url.php" class="btn btn-secondary">← <?php echo t("Back"); ?></a>
            </div>
        </div>
    </div>

    <script>
    const barFill = document.querySelector('.risk-bar-fill');
    const barLabel = document.querySelector('.risk-bar-label');
    barFill.style.width = "<?=$score?>%";
    barLabel.style.left = "<?=$score_label_pos?>%";
    </script>
</body>

</html>