<?php
session_start();
require_once "../../Database/database.php";
require_once '../../vendor/autoload.php';

use Dotenv\Dotenv;

/* ===== ENV ===== */
$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ===== ENCRYPT FUNCTION ===== */
function decryptData($data){
    global $secret_key;

    if(empty($data)) return "";

    $data = base64_decode($data);
    $iv = substr($data,0,16);
    $enc = substr($data,16);

    return openssl_decrypt($enc,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);
}

/* ===== INPUT ===== */
$keyword = trim($_GET['keyword'] ?? '');

if(!$keyword){
    die("No keyword");
}

/* ===== LOG SEARCH ===== */
$user_id = $_SESSION['user_id'] ?? NULL;
$username = $_SESSION['username'] ?? 'Guest';
$role = $_SESSION['role'] ?? 'Guest';

$stmt = $conn->prepare("
INSERT INTO activity_logs
(user_id, username, role, action, target, ip_address, user_agent)
VALUES (?,?,?,?,?,?,?)
");

$stmt->bind_param(
    "issssss",
    $user_id,
    $username,
    $role,
    $action = "Search",
    $target = "Keyword: ".$keyword,
    $_SERVER['REMOTE_ADDR'],
    $_SERVER['HTTP_USER_AGENT']
);

$stmt->execute();

/* ===== HASH FOR SEARCH ===== */
$keyword_hash = hash_hmac('sha256',$keyword,$secret_key);

/* ===== SEARCH USERS ===== */
$stmt = $conn->prepare("
SELECT id, username_encrypted
FROM users
WHERE username_hash=? OR email_hash=? OR phone_hash=?
");
$stmt->bind_param("sss",$keyword_hash,$keyword_hash,$keyword_hash);
$stmt->execute();
$user_result = $stmt->get_result();

/* ===== SEARCH PHONE ===== */
$phone_query = $conn->prepare("
SELECT phonenumber FROM phonenumbers WHERE phonenumber LIKE ?
");
$like = "%$keyword%";
$phone_query->bind_param("s",$like);
$phone_query->execute();
$phone_result = $phone_query->get_result();

/* ===== SEARCH REPORT (CHỈ APPROVED) ===== */
$report_query = $conn->prepare("
SELECT phone FROM reports WHERE phone LIKE ? AND approved=1
");
$report_query->bind_param("s",$like);
$report_query->execute();
$report_result = $report_query->get_result();

/* ===== SEARCH LOG ===== */
$log_query = $conn->prepare("
SELECT action FROM activity_logs WHERE action LIKE ?
");
$log_query->bind_param("s",$like);
$log_query->execute();
$log_result = $log_query->get_result();
?>

<h2>Search Result</h2>

<table class="table table-bordered">
    <tr>
        <th>Type</th>
        <th>Result</th>
    </tr>

    <!-- USER RESULTS -->
    <?php while($row = $user_result->fetch_assoc()): ?>
    <tr>
        <td>User</td>
        <td><?php echo htmlspecialchars(decryptData($row['username_encrypted'])); ?></td>
    </tr>
    <?php endwhile; ?>

    <!-- PHONE RESULTS -->
    <?php while($row = $phone_result->fetch_assoc()): ?>
    <tr>
        <td>Phone</td>
        <td><?php echo htmlspecialchars($row['phonenumber']); ?></td>
    </tr>
    <?php endwhile; ?>

    <!-- REPORT RESULTS (CHỈ APPROVED) -->
    <?php while($row = $report_result->fetch_assoc()): ?>
    <tr>
        <td>Report</td>
        <td><?php echo htmlspecialchars($row['phone']); ?></td>
    </tr>
    <?php endwhile; ?>

    <!-- ACTIVITY LOG RESULTS -->
    <?php while($row = $log_result->fetch_assoc()): ?>
    <tr>
        <td>Activity</td>
        <td><?php echo htmlspecialchars($row['action']); ?></td>
    </tr>
    <?php endwhile; ?>

</table>