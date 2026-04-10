<?php
session_start();
require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

require_once '../Database/database.php';
require_once 'functions/translate.php';
require_once 'functions/security.php';

// Xử lý thay đổi ngôn ngữ
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {

    $_SESSION['lang'] = $_GET['lang']; 

    $query = $_GET;
    unset($query['lang']); // bỏ lang

    $newQuery = http_build_query($query);
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');

    header("Location: " . $currentPage . ($newQuery ? "?$newQuery" : ""));
    exit;
}

$lang = $_SESSION['lang'] ?? 'en';

/* ================= PHONE + VIETNAM PHONE NORMALIZATION ================= */
$phone = $_GET['phone'] ?? '';
$phone = preg_replace('/\D/', '', $phone);

if (!$phone) die("No phone");

if(substr($phone,0,2)=="84"){
    $phone="0".substr($phone,2);
}
if(substr($phone,0,4)=="0084"){
    $phone="0".substr($phone,4);
}

if(!preg_match('/^(0\d{7,10}|1900\d{4})$/', $phone)){
    die("Invalid Vietnam phone number");
}

$phone_hash = hashData($phone);

/* =========================
METADATA CACHE
========================= */
$carrier="Unknown";
$number_type="Unknown";
$from_cache=false;

$stmt = $conn->prepare("
SELECT carrier_encrypted, type_encrypted 
FROM phone_metadata 
WHERE phone_hash = ? 
AND updated_at > NOW() - INTERVAL 7 DAY 
LIMIT 1
");
$stmt->bind_param("s", $phone_hash);
$stmt->execute();
$res=$stmt->get_result();

if($row=$res->fetch_assoc()){
    $carrier = decryptData($row['carrier_encrypted']);
    $number_type = decryptData($row['type_encrypted']);
    $from_cache=true;
}

/* =========================
NUMVERIFY API
========================= */
$numverify_valid = false;
$numverify_carrier = "";
$numverify_line_type = "";

if(!$from_cache){
$key = $_ENV['NUMVERIFY_API_KEY'] ?? '';
    if($key){
        $url="http://apilayer.net/api/validate?access_key={$key}&number={$phone}&country_code=VN&format=1";

        $ch = curl_init($url);

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5
        ]);

        $response = curl_exec($ch);

        if($response === false){
            // debug nếu cần
            // echo "CURL ERROR: " . curl_error($ch);
        } else {
            $json = json_decode($response, true);

            $numverify_valid = $json['valid'] ?? false;
            $numverify_carrier = $json['carrier'] ?? "";
            $numverify_line_type = $json['line_type'] ?? "";
        }

        curl_close($ch);
    }
}

/* =========================
CARRIER DETECTION
========================= */
$prefix3 = substr($phone,0,3);
$prefix4 = substr($phone,0,4);
$prefix5 = substr($phone,0,5);

$carriers=[

"Viettel"=>["032","033","034","035","036","037","038","039","086","096","097","098"],
"Vinaphone"=>["081","082","083","084","085","088","091","094"],
"Mobifone"=>["070","076","077","078","079","089","090","093"],
"Vietnamobile"=>["092","056","058"],
"Gmobile"=>["099","059"],
"Itelecom"=>["087"]

];

if($carrier == "Unknown"){
    foreach($carriers as $name=>$list){
        if(in_array($prefix3,$list)){
            $carrier=$name;
            break;
        }
    }
}

/* =========================
DEFAULT TYPE
========================= */
if($number_type == "Unknown"){
    if($prefix3 == "024" || $prefix3 == "028"){
        $number_type = "Landline";
    } else {
        $number_type = "Mobile";
    }
}

/* =========================
OVERRIDE WITH NUMVERIFY
========================= */
if($numverify_valid){
    if(!empty($numverify_carrier)){
        $carrier = $numverify_carrier;
    }

    if($numverify_line_type == "mobile"){
        $number_type = "Mobile";
    } elseif($numverify_line_type == "landline"){
        $number_type = "Landline";
    }
}

if($prefix4=="1900"){
$number_type="Premium Service";
}

$country="VietNam";

/* =========================
ADMIN PHONE CHECK
========================= */
$stmt=$conn->prepare("SELECT description_encrypted FROM phonenumbers WHERE phonenumber_hash=? LIMIT 1");
$stmt->bind_param("s",$phone_hash);
$stmt->execute();
$res=$stmt->get_result();

$admin_flag=false;
$admin_description="";

if($row=$res->fetch_assoc()){
    $admin_flag=true;
    $admin_description = decryptData($row['description_encrypted'] ?? "");
}

/* =========================
USER REPORTS (CHỈ LẤY REPORT ĐÃ DUYỆT)
========================= */
$stmt = $conn->prepare("
    SELECT report_reason_encrypted 
    FROM reports 
    WHERE phone_hash=? 
    AND status='Accepted'
");
$stmt->bind_param("s", $phone_hash);
$stmt->execute();
$res = $stmt->get_result();

$db_reports = 0;
$report_types = [];

while($row = $res->fetch_assoc()) {
    $db_reports++;
    $report_types[] = decryptData($row['report_reason_encrypted']);
}


/* =========================
RISK CALCULATION
========================= */

$risk_score=0;

if($admin_flag){
$risk_score=90;
}else{

if($db_reports>=5){
$risk_score+=40;
}
elseif($db_reports>=3){
$risk_score+=25;
}
elseif($db_reports>=1){
$risk_score+=15;
}

if(in_array($prefix3,["089","088","086","058","056","024","028","059","092","039","033","070"])){
$risk_score+=15;
}

if(in_array($prefix5,["02483","02883","02889"])){
$risk_score+=15;
}

if($prefix4=="1900"){
$risk_score+=25;
}

if(preg_match('/(\d)\1{3,}/',$phone)){
$risk_score+=15;
}

if(preg_match('/1234|2345|3456|4567|5678|6789|1111|2222|3333/',$phone)){
$risk_score+=10;
}

$risk_score=min($risk_score,100);
}

/* =========================
STATUS ENGINE
========================= */
if($admin_flag){

    $status_text="SCAM";
    $status_class="scam-banner-red";
    $status_desc="This number is flagged by system admin as dangerous.";
    $status_icon='<svg xmlns="http://www.w3.org/2000/svg" height="48px" viewBox="0 -960 960 960" width="48px" fill="#FFFFFF"><path d="M480-281q14 0 24.5-10.5T515-316q0-14-10.5-24.5T480-351q-14 0-24.5 10.5T445-316q0 14 10.5 24.5T480-281Zm-30-144h60v-263h-60v263ZM330-120 120-330v-300l210-210h300l210 210v300L630-120H330Zm25-60h250l175-175v-250L605-780H355L180-605v250l175 175Zm125-300Z"/></svg> ';

}
elseif($risk_score>=70){

    $status_text="SCAM";
    $status_class="scam-banner-red";
    $status_desc="This number has strong indicators of scam activity.";
    $status_icon='<svg xmlns="http://www.w3.org/2000/svg" height="48px" viewBox="0 -960 960 960" width="48px" fill="#FFFFFF"><path d="M480-281q14 0 24.5-10.5T515-316q0-14-10.5-24.5T480-351q-14 0-24.5 10.5T445-316q0 14 10.5 24.5T480-281Zm-30-144h60v-263h-60v263ZM330-120 120-330v-300l210-210h300l210 210v300L630-120H330Zm25-60h250l175-175v-250L605-780H355L180-605v250l175 175Zm125-300Z"/></svg> ';

}
elseif($risk_score >= 40 || $db_reports > 0){

    $status_text="SUSPICIOUS";
    $status_class="scam-banner-orange";
    $status_desc="This number may be suspicious based on community reports.";
    $status_icon=' <svg xmlns="http://www.w3.org/2000/svg" height="40" viewBox="0 -960 960 960" width="40" fill="#dffa15"> <path d="M480-280q17 0 28.5-11.5T520-320q0-17-11.5-28.5T480-360q-17 0-28.5 11.5T440-320q0 17 11.5 28.5T480-280Zm-40-120h80v-280h-80v280Z"/> </svg> ';

}
else{

    $status_text="NO DATA";
    $status_class="scam-banner-gray";
    $status_desc="No scam reports have been found for this number yet.";
    $status_icon='<svg xmlns="http://www.w3.org/2000/svg" height="40px" viewBox="0 -960 960 960" width="40px" fill="#FFFF55"><path d="M505.17-290.15q10.16-10.16 10.16-25.17 0-15.01-10.15-25.18-10.16-10.17-25.17-10.17-15.01 0-25.18 10.16-10.16 10.15-10.16 25.17 0 15.01 10.15 25.17Q464.98-280 479.99-280q15.01 0 25.18-10.15Zm-56.5-145.18h66.66V-684h-66.66v248.67ZM480.18-80q-82.83 0-155.67-31.5-72.84-31.5-127.18-85.83Q143-251.67 111.5-324.56T80-480.33q0-82.88 31.5-155.78Q143-709 197.33-763q54.34-54 127.23-85.5T480.33-880q82.88 0 155.78 31.5Q709-817 763-763t85.5 127Q880-563 880-480.18q0 82.83-31.5 155.67Q817-251.67 763-197.46q-54 54.21-127 85.84Q563-80 480.18-80Zm.15-66.67q139 0 236-97.33t97-236.33q0-139-96.87-236-96.88-97-236.46-97-138.67 0-236 96.87-97.33 96.88-97.33 236.46 0 138.67 97.33 236 97.33 97.33 236.33 97.33ZM480-480Z"/></svg>';

}

/* =========================
FINAL VERDICT SYNC (OPTIONAL BUT STRONG)
========================= */

$final_verdict = $status_text;

if(!empty($ai_explanation) && strpos($ai_explanation, 'SCAM') !== false){
    $final_verdict = "SCAM";
}
elseif(!empty($ai_explanation) && strpos($ai_explanation, 'SUSPICIOUS') !== false && $final_verdict !== "SCAM"){
    $final_verdict = "SUSPICIOUS";
}

/* =========================
SAVE METADATA
========================= */
if(!$from_cache){
    $stmt=$conn->prepare("
    INSERT INTO phone_metadata(phone_encrypted,phone_hash,carrier_encrypted,type_encrypted)
    VALUES(?,?,?,?)
    ON DUPLICATE KEY UPDATE
    carrier_encrypted=VALUES(carrier_encrypted),
    type_encrypted=VALUES(type_encrypted)
    ");

    $enc_phone = encryptData($phone);
    $enc_carrier = encryptData($carrier);
    $enc_type = encryptData($number_type);

    $stmt->bind_param("ssss",
        $enc_phone,
        $phone_hash,
        $enc_carrier,
        $enc_type
    );
    $stmt->execute();
}

/* =========================
AI ANALYSIS FUNCTION (GEMINI)
========================= */
function generateAI($phone, $carrier, $country, $reports, $risk, $type, $report_types, $admin_flag, $lang) {
    $api_key = $_ENV['GEMINI_API_KEY'] ?? ''; // Ensure this is set in your environment
    
    if(!$api_key){
    return "AI KEY NOT FOUND";
}

    $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=" . $api_key;
    $types = htmlspecialchars(implode(", ", $report_types));
    $admin_status = $admin_flag ? "FLAGGED AS DANGEROUS BY ADMIN" : "Neutral";

    $language_instruction = ($lang == 'vi') 
    ? "Write the report in Vietnamese." 
    : "Write the report in English.";
    
    $prompt = "You are a cyber-security expert specializing in telecommunications fraud. 
Analyze the following phone number: $phone.

System Data:
- Carrier: $carrier
- Line Type: $type
- Community Reports: $reports
- System Risk Score: $risk%
- Admin Status: $admin_status
- Reported Violations: $types

Task: Write a detailed security report in $language_instruction including:
1. Risk Summary
2. Risk Level
3. Safety Advice

Return ONLY clean HTML using tags like <b>, <p>, <ul>, <li>.
DO NOT use markdown.
DO NOT wrap the response in ``` or code blocks.

If you output Risk Level, format EXACTLY like:
<p><b>Risk Level:</b> <span class='risk-high'>SCAM</span></p>
OR
<p><b>Risk Level:</b> <span class='risk-medium'>SUSPICIOUS</span></p>
OR
<p><b>Risk Level:</b> <span class='risk-low'>NO DATA</span></p>";

    $data = [
        "contents" => [["parts" => [["text" => $prompt]]]]
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

    $res = curl_exec($ch);

if($res === false){
    return "CURL ERROR: " . curl_error($ch);
}

if($res === false){
    curl_close($ch);
    return "AI_REQUEST_FAILED";
}

$json = json_decode($res, true);
curl_close($ch);

// DEBUG FULL RESPONSE
if(isset($json['error'])){
    return "API ERROR: " . $json['error']['message'];
}

if(!isset($json['candidates'][0]['content']['parts'][0]['text'])){
    return "AI_RESPONSE_EMPTY";
}

$ai_explanation = $json['candidates'][0]['content']['parts'][0]['text'];

// Remove markdown nếu AI vẫn trả
$ai_explanation = preg_replace('/```html|```/', '', $ai_explanation);

return trim($ai_explanation);
}

/* =========================
CARD BORDER COLOR (FIXED)
========================= */

if($admin_flag || $risk_score >= 70){
    $card_border = "border-scam";
}
elseif($risk_score >= 40 || $db_reports > 0){
    $card_border = "border-warning";
}
else{
    $card_border = "border-safe";
}

/* =========================
AI CACHING LOGIC
========================= */
$stmt = $conn->prepare("
    SELECT ai_result_encrypted 
    FROM risk_analysis 
    WHERE phone_hash = ? 
    AND lang = ?
    LIMIT 1
");
$stmt->bind_param("ss", $phone_hash, $lang);
$stmt->execute();
$res_ai = $stmt->get_result();

if ($row = $res_ai->fetch_assoc()) {
    $ai_explanation = decryptData($row['ai_result_encrypted']);
} else {

    // Tạo kết quả AI mới
    $ai_explanation = generateAI($phone, $carrier, $country, $db_reports, $risk_score, $number_type, $report_types, $admin_flag, $lang);

    // Mã hóa các biến trước khi bind_param
    $encPhone = encryptData($phone);             // 🔹 phone_encrypted
    $encExplanation = encryptData($ai_explanation); // 🔹 ai_result_encrypted

    // Chuẩn bị câu lệnh INSERT với ON DUPLICATE KEY UPDATE
    $sql = "
        INSERT INTO risk_analysis (phone_encrypted, phone_hash, risk_score, ai_result_encrypted, lang)
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            risk_score = VALUES(risk_score),
            ai_result_encrypted = VALUES(ai_result_encrypted),
            lang = VALUES(lang)
    ";

    $stmt_save = $conn->prepare($sql);

    // Bind các biến
    $stmt_save->bind_param("sisss",
        $encPhone,
        $phone_hash,
        $risk_score,
        $encExplanation,
        $lang
    );

    // Thực thi
    if (!$stmt_save->execute()) {
        die("Error saving AI result: " . $stmt_save->error);
    }
}

/* =========================
REPORT SYSTEM
========================= */
if(isset($_POST['report'])){
    if(!isset($_POST['csrf']) || $_POST['csrf'] !== $_SESSION['csrf']){
        die("CSRF validation failed");
    }

    $reason = trim($_POST['reason'] ?? '');
    $comment = trim($_POST['comment'] ?? '');
    $other_reason = trim($_POST['other_reason'] ?? '');

    // phần code còn lại giữ nguyên...


    // Nếu chọn OTHER thì lấy input user
    if($reason === "Other"){
        if(empty($other_reason)){
            die("Please specify your reason");
        }
        $reason = $other_reason;
    }

    if(empty($reason)){
        die("Invalid report");
    }

    $stmt = $conn->prepare("
        INSERT INTO reports(
            phone_encrypted,
            phone_hash,
            report_reason_encrypted,
            comment_encrypted,
            status
        )
        VALUES(?,?,?,?, 'Pending')
    ");

    $enc_phone = encryptData($phone);
    $enc_reason = encryptData($reason);
    $enc_comment = encryptData($comment);

    $stmt->bind_param("ssss", $enc_phone, $phone_hash, $enc_reason, $enc_comment);
    $stmt->execute();

    // Redirect về result page
    header("Location: result.php?phone=".$phone);
    exit;
}

/* =========================
SAVE SEARCH HISTORY
========================= */
if(isset($_SESSION['user_id'])){

    // Map status_text -> ENUM DB
    $result_type = "Unknown";

    if($status_text == "SCAM"){
        $result_type = "Scam";
    } elseif($status_text == "NO DATA"){
        $result_type = "Unknown";
    } elseif($status_text == "SUSPICIOUS"){
        $result_type = "Unknown";
    }

    $stmt = $conn->prepare("
        INSERT INTO search_history (
            user_id,
            phonenumber_encrypted,
            phonenumber_hash,
            result_type
        )
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            searched_at = NOW()
    ");

    $enc_phone = encryptData($phone);

    $stmt->bind_param(
        "isss",
        $_SESSION['user_id'],
        $enc_phone,
        $phone_hash,
        $result_type
    );

    if(!$stmt->execute()){
        die("History error: " . $stmt->error);
    }
}
?>

<!DOCTYPE html>
<html>

<head>

    <title>Phone Check Result</title>

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
        width: 900px;
        max-width: 95%;
        background: white;
        border-radius: 12px;
        box-shadow: 0 0 25px rgba(0, 0, 0, 0.5);
        padding: 30px;
        border: 6px solid transparent;
        outline: 3px solid rgba(0, 0, 0, 0.1);
    }

    /*scam */
    .border-scam {
        border-color: #e72337;
        box-shadow: 0 0 25px rgba(220, 53, 69, 0.5);
    }

    /* suspicious */

    .border-warning {
        border-color: #fd7e14;
        box-shadow: 0 0 25px rgba(253, 126, 20, 0.4);
    }

    /* safe */

    .border-safe {
        border-color: #28a745;
        box-shadow: 0 0 25px rgba(40, 167, 69, 0.4);
    }

    /* unknown */

    .border-unknown {
        border-color: #6c757d;
        box-shadow: 0 0 25px rgba(108, 117, 125, 0.4);
    }

    .risk-high {
        color: #dc3545;
        font-weight: bold;
    }

    .risk-medium {
        color: #fd7e14;
        font-weight: bold;
    }

    .risk-low {
        color: #28a745;
        font-weight: bold;
    }

    .result-header {
        background: black;
        color: white;
        font-weight: bold;
        text-align: center;
        padding: 18px;
        margin: -30px -30px 30px -30px;

        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
    }

    /* chữ header */

    .header-text {
        letter-spacing: 3px;
        font-size: 25px;
    }

    .phone-number {
        font-size: 50px;
        text-align: center;
        font-weight: bold;
        letter-spacing: 3px;
    }

    .scam-banner {
        color: white;
        font-size: 30px;
        text-align: center;
        padding: 15px;
        border-radius: 8px;
        margin: 20px auto;
        width: fit-content;
        min-width: 300px;
    }

    .scam-banner-red {
        background: #f8071f;
    }

    .scam-banner-orange {
        background: #fd7e14;
    }

    .scam-banner-green {
        background: #28a745;
    }

    .scam-banner-gray {
        background: #6c757d;
    }

    .scam-text {

        text-align: center;
        margin-top: 10px;

    }

    .info-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 20px;
        margin-top: 25px;
    }

    .info-item {

        background: #f3f4f6;
        padding: 9px;
        border-radius: 8px;
        text-align: center;

    }

    .community-box {
        background: #fff3cd;
        border-left: 6px solid #ff9800;
        padding: 15px;
        border-radius: 8px;
    }

    .safety-box {

        background: #f8f9fa;
        border-left: 6px solid #6c757d;
        padding: 20px;
        border-radius: 8px;
        margin-top: 20px;

    }

    .ai-box {
        background: #f8f9fa;
        border-left: 5px solid #0d6efd;
        padding: 20px;
        border-radius: 8px;
        line-height: 1.6;
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

                <div class="d-flex align-items-center gap-3">

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

        <div class="result-card <?php echo $card_border ?>">

            <div class="result-header">

                <svg xmlns="http://www.w3.org/2000/svg" height="60" viewBox="0 -960 960 960" width="60" fill="#EA3323">

                    <path
                        d="M480-81q-140-35-230-162.5T160-523v-238l320-120 320 120v238q0 152-90 279.5T480-81Zm0-62q115-38 187.5-143.5T740-523v-196l-260-98-260 98v196q0 131 72.5 236.5T480-143Zm0-337Zm-90 160h180q13 0 21.5-8.5T600-350v-140q0-13-8.5-21.5T570-520h-10v-40q0-33-23.5-56.5T480-640q-33 0-56.5 23.5T400-560v40h-10q-13 0-21.5 8.5T360-490v140q0 13 8.5 21.5T390-320Zm40-200v-40q0-20 15-33.5t35-13.5q20 0 35 13.5t15 33.5v40H430Z" />

                </svg>

                <span class="header-text">
                    <?php echo t("PHONE NUMBER REGISTRY CHECK RESULT");?>
                </span>

            </div>
            <h3 class="text-center mb-3 phone-number">

                <?php echo htmlspecialchars($phone); ?>

            </h3>


            <div class="scam-banner <?php echo $status_class ?> text-center p-3 text-white">
                <strong><?php echo $status_icon ?></strong>
                <strong><?php echo $status_text ?></strong>

            </div>


            <p class="text-center">

                <?php echo $status_desc ?>

            </p>


            <div class="info-grid">

                <div class="info-item">
                    <i class="bi bi-globe"></i>
                    <strong class="info-item"> <?php echo t("Country: ");?></strong>
                    <?php echo $country ?>
                </div>

                <div class="info-item">
                    <i class="bi bi-broadcast"></i>
                    <strong class="info-item"> <?php echo t("Carrier Network: ");?></strong>
                    <?php echo htmlspecialchars($carrier)?>
                </div>

                <div class="info-item">
                    <i class="bi bi-flag"></i>
                    <strong class="info-item"> <?php echo t("Community Reports: ");?></strong>
                    <?php echo $db_reports ?>
                </div>

                <div class="info-item">
                    <i class="bi bi-telephone"></i>
                    <strong class="info-item"> <?php echo t("Phone Prefix: ");?></strong>
                    <?php echo $prefix4=="1900" ? $prefix4 : $prefix3 ?>
                </div>

                <div class="info-item">
                    <i class="bi bi-phone"></i>
                    <strong class="info-item"> <?php echo t("Number Type: ");?></strong>
                    <?php echo $number_type ?>
                </div>

                <div class="info-item">
                    <?php

                        $color="text-success";

                        if($risk_score>=70){
                        $color="text-danger";
                        }
                        elseif($risk_score>=40){
                        $color="text-warning";
                        }

                    ?>
                    <i class="bi bi-shield-exclamation"></i>
                    <strong class="info-item <?php echo $color ?>"> <?php echo t("Risk Score: ");?></strong>
                    <?php echo $risk_score ?>%
                </div>

            </div>


            <div class="ai-box mt-4">
                <h5><i class="bi bi-robot"></i> <?php echo t("AI Risk Analysis");?>
                    <span class="badge bg-secondary"><?php echo strtoupper($lang); ?></span>
                </h5>
                <?php
                $clean_ai = strip_tags($ai_explanation ?? '', "<b><p><ul><li><span>");

                // FORCE đồng bộ màu theo AI text
                if(strpos($ai_explanation, 'SCAM') !== false){
                    $clean_ai = preg_replace('/SCAM/', '<span class="risk-high">SCAM</span>', $clean_ai);
                }

                if(strpos($ai_explanation, 'SUSPICIOUS') !== false){
                    $clean_ai = preg_replace('/SUSPICIOUS/', '<span class="risk-medium">SUSPICIOUS</span>', $clean_ai);
                }

                if(strpos($ai_explanation, 'NO DATA') !== false){
                    $clean_ai = preg_replace('/NO DATA/', '<span class="risk-low">NO DATA</span>', $clean_ai);
                }
                ?>

                <div><?php echo $clean_ai; ?></div>
                <p style="font-size: 0.90rem; color: orange; font-style: bolid; margin-top: 5px;">
                    <?php echo t("NOTE: This report is for reference purposes only and does not constitute legal or professional advice.");?>
                </p>
            </div>

            <div class="community-box mt-3">

                <strong><i class="bi bi-people-fill"></i> <?php echo t("Community Status");?></strong>

                <?php if(empty($admin_description) && empty($report_types)): ?>

                <p> <?php echo t("No reports yet.");?></p>

                <?php else: ?>

                <?php if($admin_description): ?>
                <p>
                    <i class="bi bi-bell-fill text-danger"></i>
                    <strong class="text-danger"> <?php echo t("Admin Warning:");?></strong>
                    <?php echo t($admin_description); ?>
                </p>
                <?php endif; ?>

                <?php if(!empty($report_types)): ?>
                <ul>
                    <?php foreach($report_types as $t){
echo "<li>".htmlspecialchars($t)."</li>";
} ?>
                </ul>
                <?php endif; ?>

                <?php endif; ?>

            </div>

            <div class="safety-box mt-3">

                <strong>
                    <i class="bi bi-shield-check me-1"></i>
                    <?php echo t("Safety Advice");?>
                </strong>

                <ul class="mt-2 mb-0">

                    <li> <?php echo t("Do not share OTP codes with unknown callers.");?></li>

                    <li> <?php echo t("Never transfer money to strangers.");?></li>

                    <li> <?php echo t("Verify the caller through official company channels.")?></li>

                    <li> <?php echo t("If the caller pressures you to act quickly, it may be a scam.");?></li>

                </ul>

            </div>


            <div class="mt-4 text-center">

                <a href="phonenumber.php" class="btn btn-secondary">

                    <?php echo t("← Back");?>

                </a>

                <button onclick="showReport()" class="btn btn-danger">

                    <?php echo t("Report Number");?>

                </button>

            </div>


            <div id="reportForm" style="display:none;margin-top:20px;">

                <form method="POST">
                    <input type="hidden" name="csrf" value="<?php echo $_SESSION['csrf']; ?>">

                    <select name="reason" id="reasonSelect" class="form-select mb-2">
                        <option value="">Select Reason</option>
                        <optgroup label="<?php echo t('Financial & Payment Scams');?>">
                            <option value="Bank Fraud"><?php echo t('Impersonating a bank / account issues');?></option>
                            <option value="Loan Fraud"><?php echo t('Fake loan offers / upfront fees');?></option>
                            <option value="Investment Scam"><?php echo t('Unrealistic investment returns');?></option>
                            <option value="Crypto Scam"><?php echo t('Cryptocurrency fraud');?></option>
                            <option value="Payment Request Scam"><?php echo t('Suspicious payment request');?></option>
                            <option value="Refund Scam"><?php echo t('Fake refund or reimbursement');?></option>
                        </optgroup>

                        <optgroup label="<?php echo t('Impersonation Scams');?>">
                            <option value="Government Scam"><?php echo t('Impersonating police or government');?>
                            </option>
                            <option value="Bank Staff Scam"><?php echo t('Impersonating bank staff');?></option>
                            <option value="Tech Support Scam"><?php echo t('Fake technical support');?></option>
                            <option value="Delivery Scam"><?php echo t('Fake delivery issue');?></option>
                            <option value="Friend/Relative Scam"><?php echo t('Impersonating a friend or relative');?>
                            </option>
                        </optgroup>

                        <optgroup label="<?php echo t('Online & Social Scams');?>">
                            <option value="Ecommerce Scam"><?php echo t('Online shopping fraud');?></option>
                            <option value="Job Scam"><?php echo t('Fake job offer / recruitment scam');?></option>
                            <option value="Dating Scam"><?php echo t('Romance or dating scam');?></option>
                            <option value="Prize Scam"><?php echo t('Fake prize or lottery win');?></option>
                            <option value="Phishing"><?php echo t('Phishing link / data theft');?></option>
                        </optgroup>

                        <optgroup label="<?php echo t('Spam & Unwanted Calls');?>">
                            <option value="Telemarketing"><?php echo t('Sales or marketing calls');?></option>
                            <option value="Robocall"><?php echo t('Automated or prerecorded call');?></option>
                            <option value="Repeated Spam"><?php echo t('Repeated unwanted calls');?></option>
                            <option value="Silent Call"><?php echo t('Silent or hang-up call');?></option>
                        </optgroup>

                        <optgroup label="<?php echo t('Threats & Abuse');?>">
                            <option value="Harassment"><?php echo t('Harassment or nuisance');?></option>
                            <option value="Threatening Call"><?php echo t('Threats or intimidation');?></option>
                            <option value="Extortion Scam"><?php echo t('Blackmail or extortion');?></option>
                        </optgroup>

                        <optgroup label="<?php echo t('Other');?>">
                            <option value="Suspicious Call"><?php echo t('Suspicious or unknown call');?></option>
                            <option value="Other"><?php echo t('Other');?></option>
                        </optgroup>

                    </select>
                    <input type="text" name="other_reason" id="otherReason" class="form-control mt-2 d-none"
                        placeholder="<?php echo t('Enter your reason...');?>">

                    <textarea name="comment" class="form-control" rows="3"
                        placeholder="Describe the scam..."></textarea>

                    <button type="submit" name="report" class="btn btn-danger mt-2">
                        <?php echo t("Submit Report");?>
                    </button>

                </form>

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
document.addEventListener("DOMContentLoaded", function() {

    const reasonSelect = document.getElementById("reasonSelect");
    const otherInput = document.getElementById("otherReason");

    if (reasonSelect) {
        reasonSelect.addEventListener("change", function() {

            if (this.value === "Other") {
                otherInput.classList.remove("d-none");
                otherInput.required = true;
            } else {
                otherInput.classList.add("d-none");
                otherInput.required = false;
                otherInput.value = "";
            }

        });
    }

});

function showReport() {

    var f = document.getElementById("reportForm");

    if (f.style.display == "none") {
        f.style.display = "block";
    } else {
        f.style.display = "none";
    }

}
</script>