<?php
session_start();
require_once '../Database/database.php';

$phone = $_GET['phone'] ?? '';
$phone = preg_replace('/\D/', '', $phone);

/* =========================
VIETNAM PHONE NORMALIZATION
========================= */

if(substr($phone,0,2) == "84"){
    $phone = "0".substr($phone,2);
}

if(substr($phone,0,4) == "0084"){
    $phone = "0".substr($phone,4);
}

if(strlen($phone) != 10){
    die("Invalid Vietnam phone number");
}

/* =========================
PHONE VARIANTS
========================= */

$phone_variants = [];

$phone_variants[] = $phone;
$phone_variants[] = "+84".substr($phone,1);
$phone_variants[] = "84".substr($phone,1);
$phone_variants[] = substr($phone,0,4)." ".substr($phone,4,3)." ".substr($phone,7);
$phone_variants[] = substr($phone,0,4)."-".substr($phone,4,3)."-".substr($phone,7);

/* =========================
DATABASE CHECK
========================= */

$db_reports = 0;

$stmt = $conn->prepare("SELECT report_count FROM phonenumbers WHERE phonenumber=?");
$stmt->bind_param("s",$phone);
$stmt->execute();
$result = $stmt->get_result();

if($row = $result->fetch_assoc()){
    $db_reports = $row['report_count'];
}

/* =========================
VIETNAM CARRIER DETECTION
========================= */

$prefix = substr($phone,0,3);

$carriers = [

"Viettel"=>["032","033","034","035","036","037","038","039","086","096","097","098"],
"Vinaphone"=>["081","082","083","084","085","088","091","094"],
"Mobifone"=>["070","076","077","078","079","089","090","093"],
"Vietnamobile"=>["092","056","058"],
"Gmobile"=>["099","059"],
"Itelecom"=>["087"]

];

$carrier="Unknown";

foreach($carriers as $name=>$list){
    if(in_array($prefix,$list)){
        $carrier=$name;
        break;
    }
}

$country="Vietnam";

/* =========================
GOOGLE SEARCH
========================= */

$google_results = 0;

$keywords = ["scam","fraud","spam call","phone scam","scammer","complaint"];

$search_query = "";

foreach($phone_variants as $v){
    foreach($keywords as $k){
        $search_query .= '"'.$v.'" '.$k.' OR ';
    }
}

$search_query = rtrim($search_query," OR ");

$google_api="YOUR_GOOGLE_API_KEY";
$google_cx="YOUR_SEARCH_ENGINE_ID";

$url="https://www.googleapis.com/customsearch/v1?q=".urlencode($search_query)."&key=".$google_api."&cx=".$google_cx;

$response=@file_get_contents($url);
$data=json_decode($response,true);

if(isset($data['searchInformation']['totalResults'])){
    $google_results=min((int)$data['searchInformation']['totalResults'],50);
}

/* =========================
RISK SCORE
========================= */

$risk_score = min(100, ($google_results*2)+($db_reports*30));

$risk_level="Low";
$status_text="SAFE";
$status_class="scam-banner-green";
$status_desc="Hiện chưa phát hiện báo cáo lừa đảo liên quan đến số này.";
$icon=' <svg xmlns="http://www.w3.org/2000/svg" height="40" viewBox="0 -960 960 960" width="40" fill="#41d24b"> <path d="m421-298 283-283-46-45-237 237-120-120-45 45 165 166Z"/> </svg> ';

/* =========================
NO DATA CHECK
========================= */

if($google_results == 0 && $db_reports == 0){

$risk_level="Unknown";
$status_text="NO DATA";
$status_class="scam-banner-green";
$status_desc="Số điện thoại này chưa có trong cơ sở dữ liệu và chưa tìm thấy báo cáo trên internet.";
$icon=' <svg xmlns="http://www.w3.org/2000/svg" height="40" viewBox="0 -960 960 960" width="40" fill="#6c757d"><path d="M440-440h80v-240h-80v240Zm40 320q-83 0-156-31.5T197-242q-54-54-85.5-127T80-520q0-83 31.5-156T197-803q54-54 127-85.5T480-920q83 0 156 31.5T763-803q54 54 85.5 127T880-520q0 83-31.5 156T763-242q-54 54-127 85.5T480-120Zm0-80q134 0 227-93t93-227q0-134-93-227t-227-93q-134 0-227 93t-93 227q0 134 93 227t227 93Z"/></svg>';
}
elseif($risk_score>=70){
$risk_level="High";
$status_text="SCAM";
$status_class="scam-banner-red";
$status_desc="Đây là số điện thoại: <strong>SCAM</strong><br>(LỪA ĐẢO TÀI CHÍNH)";
$icon=' <svg xmlns="http://www.w3.org/2000/svg" height="40" viewBox="0 -960 960 960" width="40" fill="#EA3323"> <path d="M450-284h60v-257h-60v257Z"/> </svg> ';
}
elseif($risk_score>=30){
$risk_level="Medium";
$status_text="SUSPICIOUS";
$status_class="scam-banner-orange";
$status_desc="Số điện thoại này có dấu hiệu đáng ngờ. Hãy cẩn thận khi giao dịch.";
$icon=' <svg xmlns="http://www.w3.org/2000/svg" height="40" viewBox="0 -960 960 960" width="40" fill="#facc15"> <path d="M480-280q17 0 28.5-11.5T520-320q0-17-11.5-28.5T480-360q-17 0-28.5 11.5T440-320q0 17 11.5 28.5T480-280Zm-40-120h80v-280h-80v280Z"/> </svg> ';
}

/* =========================
CONFIDENCE
========================= */

$confidence = min(95, 40 + ($db_reports*10) + ($google_results));

/* =========================
REPORT SYSTEM
========================= */

if(isset($_POST['report'])){

$reason=$_POST['reason'];
$comment=$_POST['comment'] ?? '';

$stmt=$conn->prepare("
INSERT INTO phone_reports (phone,report_reason,comment)
VALUES (?,?,?)
");

$stmt->bind_param("sss",$phone,$reason,$comment);
$stmt->execute();

$stmt=$conn->prepare("
INSERT INTO phonenumbers (phonenumber,country,report_count)
VALUES (?,?,1)
ON DUPLICATE KEY UPDATE report_count=report_count+1
");

$stmt->bind_param("ss",$phone,$country);
$stmt->execute();

header("Location: result.php?phone=".$phone."&reported=1");
exit;

/* =========================
GET REPORT DESCRIPTION
========================= */

$description = "";

$stmt = $conn->prepare("
SELECT report_reason, comment
FROM phonenumbers
WHERE phone=?
ORDER BY id DESC
LIMIT 1
");

$stmt->bind_param("s",$phone);
$stmt->execute();
$result = $stmt->get_result();

if($row = $result->fetch_assoc()){

$description = $row['report_reason'];

if(!empty($row['comment'])){
$description .= " - ".$row['comment'];
}

}
}
?>

<!DOCTYPE html>
<html>

<head>

    <title>Phone Check Result</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">

    <style>
    html,
    body {
        height: 100%;
        margin: 0;
    }

    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        font-family: Arial;
        color: black;
    }

    /* overlay phủ toàn bộ trang */

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        min-height: 100vh;
        width: 100%;

        display: flex;
        justify-content: center;
        /* căn giữa ngang */
        align-items: center;
        /* căn giữa dọc */

        padding-top: 100px;
        padding-bottom: 60px;
    }

    /* khung trắng */

    .result-card {

        width: 900px;
        max-width: 95%;

        background: white;
        border-radius: 10px;

        box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);

        margin: auto;
        /* đảm bảo nằm giữa */

        padding: 30px;
        padding-top: 0;

    }

    /* thanh header đen */

    .result-header {

        background: black;
        color: white;

        font-size: 18px;
        font-weight: bold;

        padding: 14px;

        text-align: center;

        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;

        letter-spacing: 1px;

        margin: 0 -30px 25px -30px;

    }

    /* số điện thoại */

    .phone-number {

        font-size: 40px;
        text-align: center;
        font-weight: bold;
        letter-spacing: 3px;

        margin-bottom: 20px;

    }

    /* banner trạng thái */

    .scam-banner {

        color: white;
        font-size: 32px;

        text-align: center;

        padding: 15px;

        font-weight: bold;

        border-radius: 8px;

        margin: 10px auto;

        width: 60%;

        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;

    }

    /* màu */

    .scam-banner-red {
        background: linear-gradient(#c9302c, #a0201c);
    }

    .scam-banner-orange {
        background: linear-gradient(#f0ad4e, #d58512);
    }

    .scam-banner-green {
        background: linear-gradient(#28a745, #1e7e34);
    }

    /* mô tả */

    .scam-text {

        text-align: center;
        font-size: 15px;

        margin-top: 10px;

        color: black;

    }

    /* grid thông tin */

    .info-grid {

        display: grid;
        grid-template-columns: repeat(3, 1fr);

        gap: 10px 40px;

        margin-top: 25px;

    }

    /* info */

    .info {

        font-size: 15px;

    }

    /* nút */

    .result-actions {

        display: flex;

        justify-content: center;

        gap: 10px;

        margin-top: 25px;

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

<body>
    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
        <div class="container-fluid">

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php">SCAM BTEC</a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">

                <!-- Menu trái -->
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="index.php">HOME</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="phonenumber.php">PHONE NUMBER</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">URL</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">EMAIL</a>
                    </li>
                </ul>

                <!-- Menu phải (User) -->
                <div class="d-flex align-items-center gap-3">

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
                                    <?php echo htmlspecialchars($_SESSION['user_name']); ?>
                                </a>
                            </li>

                            <li>
                                <a class="dropdown-item" href="history.php">
                                    <i class="bi bi-clock-history me-2"></i>
                                    History
                                </a>
                            </li>

                            <li>
                                <hr class="dropdown-divider">
                            </li>

                            <li>
                                <a class="dropdown-item text-danger" href="logout.php">
                                    <i class="bi bi-box-arrow-right me-2"></i>
                                    Logout
                                </a>
                            </li>

                        </ul>
                    </div>

                    <?php else: ?>

                    <a href="login.php" class="btn btn-outline-info">
                        Sign in
                    </a>

                    <a href="register.php" class="btn btn-outline-info">
                        Sign up
                    </a>

                    <?php endif; ?>

                </div>
            </div>
        </div>
    </nav>

    <div class="overlay">

        <div class="container">

            <div class="result-card">

                <div class="result-header">
                    <i class="bi bi-lock-fill"></i>
                    PHONE NUMBER REGISTRY CHECK RESULT
                </div>

                <div class="phone-number">
                    <?php echo htmlspecialchars($phone); ?>
                </div>

                <div class="scam-banner <?php echo $status_class ?>">
                    <?php echo $icon; ?>
                    <?php echo $status_text; ?>
                </div>

                <div class="scam-text">
                    <?php echo $status_desc ?>
                </div>

                <div class="info-grid">

                    <div class="info">Risk Level: <strong><?php echo $risk_level ?></strong></div>

                    <div class="info">Risk Score: <strong><?php echo $risk_score ?>/100</strong></div>

                    <div class="info">Confidence: <strong><?php echo $confidence ?>%</strong></div>

                    <div class="info">Country: <strong><?php echo $country ?></strong></div>

                    <div class="info">Carrier: <strong><?php echo $carrier ?></strong></div>

                    <div class="info">Google Mentions: <strong><?php echo $google_results ?></strong></div>

                    <div class="info">User Reports: <strong><?php echo $db_reports ?></strong></div>


                    <?php if($description!=""): ?>
                    <br>
                    <small style="color:#c9302c;">
                        Description: <?php echo htmlspecialchars($description); ?>
                    </small>
                    <?php endif; ?>


                </div>

                <div class="alert alert-warning mt-3">

                    <strong>Disclaimer:</strong><br>

                    This result is generated automatically based on user reports and public information on the internet.

                    It is provided for <strong>reference purposes only</strong> and may not be fully accurate.

                    Always verify the caller identity before taking any action.

                </div>

                <div class="result-actions">

                    <a href="phonenumber.php" class="btn btn-secondary">
                        Back
                    </a>

                    <button onclick="showReport()" class="btn btn-danger">
                        <i class="bi bi-flag"></i> Report
                    </button>

                </div>

                <div id="reportForm" style="display:none;margin-top:20px;">

                    <form method="POST">

                        <select name="reason" class="form-select mb-2">

                            <option value="Scam Call">Scam Call</option>
                            <option value="Bank Scam">Pretending to be a bank</option>
                            <option value="Loan Scam">Fake loan service</option>
                            <option value="Investment Scam">Fake investment</option>
                            <option value="Prize Scam">Fake lottery prize</option>
                            <option value="Impersonation">Police/Government impersonation</option>
                            <option value="Spam Telemarketing">Telemarketing spam</option>
                            <option value="Harassment">Harassment call</option>

                        </select>

                        <textarea name="comment" class="form-control" rows="3"
                            placeholder="Describe what happened during the call..."></textarea>

                        <button type="submit" name="report" class="btn btn-danger mt-2">
                            Submit Report
                        </button>

                    </form>

                </div>

            </div>

        </div>

    </div>

    <footer class="py-3 border-top footer-custom">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center small">

                <div>
                    © 2026 Scam Detection Platform – BTEC FPT
                </div>

                <div>
                    <a href="#" class="footer-link">Privacy Policy</a>
                    &middot;
                    <a href="#" class="footer-link">Terms & Conditions</a>
                </div>

            </div>
        </div>
    </footer>

    <script>
    function showReport() {

        var form = document.getElementById("reportForm");

        if (form.style.display === "none") {
            form.style.display = "block";
        } else {
            form.style.display = "none";
        }

    }
    </script>

</body>

</html>