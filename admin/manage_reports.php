<?php
session_start();
require_once "../../Database/database.php";
require_once '../../vendor/autoload.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ===== CHECK ADMIN ===== */
if(!isset($_SESSION['role']) || $_SESSION['role'] != "Admin"){
    header("Location: ../index.php");
    exit;
}

/* ===== ENCRYPT ===== */
function encryptData($data){
    global $secret_key;
    $iv = random_bytes(16);
    $enc = openssl_encrypt($data,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);
    return base64_encode($iv.$enc);
}

function decryptData($data){
    global $secret_key;
    if(!$data) return "";
    $data = base64_decode($data);
    $iv = substr($data,0,16);
    $enc = substr($data,16);
    return openssl_decrypt($enc,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);
}

/* ===== ACTIVITY LOG ===== */
function logActivity($conn,$action,$target){

    global $secret_key;

    $user_id = $_SESSION['user_id'] ?? null;
    $username = $_SESSION['username'];
    $role = $_SESSION['role'];

    $ip = $_SERVER['REMOTE_ADDR'];
    $ua = $_SERVER['HTTP_USER_AGENT'];

    $username_hash = hash_hmac('sha256',$username,$secret_key);
    $target_hash = hash_hmac('sha256',$target,$secret_key);
    $ip_hash = hash_hmac('sha256',$ip,$secret_key);

    $stmt = $conn->prepare("
        INSERT INTO activity_logs
        (user_id, username_encrypted, username_hash, role,
         action, action_encrypted,
         target_encrypted, target_hash,
         ip_address_encrypted, ip_hash,
         user_agent_encrypted)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    ");

    $stmt->bind_param(
        "issssssssss",
        $user_id,
        encryptData($username),
        $username_hash,
        $role,
        $action,
        encryptData($action),
        encryptData($target),
        $target_hash,
        encryptData($ip),
        $ip_hash,
        encryptData($ua)
    );

    $stmt->execute();
}

/* ===== UPDATE STATUS ===== */
if(isset($_GET['action']) && isset($_GET['id'])){
    $id = intval($_GET['id']);
    $status = $_GET['action'];

    if(in_array($status,['Accepted','Rejected'])){
        $stmt = $conn->prepare("UPDATE reports SET status=? WHERE id=?");
        $stmt->bind_param("si",$status,$id);
        $stmt->execute();

        $res = $conn->prepare("SELECT phone_encrypted FROM reports WHERE id=?");
        $res->bind_param("i",$id);
        $res->execute();
        $row = $res->get_result()->fetch_assoc();

        $phone = decryptData($row['phone_encrypted']);

        logActivity($conn,"UPDATE_REPORT",$phone." -> ".$status);

        header("Location: manage_reports.php");
        exit;
    }
}

/* ===== LIST ===== */
$result = mysqli_query($conn,"SELECT * FROM reports ORDER BY created_at DESC");
?>



<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Reported Numbers Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
    <style>
    body {
        background: #fafcfe;
        font-family: Arial;
    }

    .sidebar {
        position: fixed;
        width: 250px;
        height: 100vh;
        background: #1f2d3d;
        color: white;
        transition: 0.3s;
    }

    .sidebar.collapsed {
        width: 70px;
    }

    .sidebar h4 {
        padding: 20px;
        font-size: 30px;
        font-weight: 700;
        letter-spacing: 1px;
    }

    .sidebar a {
        display: flex;
        align-items: center;
        padding: 12px 20px;
        color: #c2c7d0;
        text-decoration: none;
        gap: 10px;
    }

    .sidebar a:hover {
        background: #2c3b4a;
        color: white;
    }

    .sidebar.collapsed h4,
    .sidebar.collapsed p,
    .sidebar.collapsed span {
        display: none;
    }

    .sidebar.collapsed a {
        justify-content: center;
    }

    .sidebar.collapsed i {
        margin-right: 0;
        font-size: 20px;
    }

    .topbar {
        position: fixed;
        top: 0;
        left: 250px;
        right: 0;
        height: 60px;
        background: #343a40;
        color: white;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 20px;
        z-index: 1000;
        transition: 0.3s;
    }

    .topbar.expanded {
        left: 70px;
    }

    .content {
        margin-left: 250px;
        padding: 90px 30px;
        transition: 0.3s;
    }

    .content.expanded {
        margin-left: 70px;
    }
    </style>
</head>

<body>

    <!-- SIDEBAR -->

    <div class="sidebar">

        <h4 class="fw-bold fs-1">
            <strong><i class="bi bi-shield-lock fs-1"></i> SCAM SYSTEM</strong>
        </h4>

        <p class="px-3 text-secondary">OVERVIEW</p>

        <a href="admin_dashboard.php">
            <i class="bi bi-speedometer2"></i>
            <span>Dashboard</span>
        </a>

        <p class="px-3 text-secondary mt-3">MANAGEMENT</p>

        <a href="manage_users.php">
            <i class="bi bi-people"></i>
            <span>All Users</span>
        </a>

        <a href="manage_numbers.php">
            <i class="bi bi-telephone"></i>
            <span>Phone Numbers</span>
        </a>

        <a href="manage_reports.php">
            <i class="bi bi-exclamation-triangle"></i>
            <span>Reported Numbers</span>
        </a>

        <p class="px-3 text-secondary mt-3">SYSTEM</p>

        <a href="manage_activity_logs.php">
            <i class="bi bi-activity"></i>
            <span>Activity Logs</span>
        </a>

        <a href="../index.php">
            <i class="bi bi-box-arrow-left"></i>
            <span>Logout</span>
        </a>

    </div>

    <!-- TOPBAR -->
    <div class="topbar">
        <button class="btn btn-dark" onclick="toggleSidebar()"><i class="bi bi-list"></i></button>
        <div class="d-flex align-items-center gap-3">
            <form action="manage_reports.php" method="GET" class="d-flex">
                <input class="form-control me-2" name="search" style="width:300px;" placeholder="Search">
                <button class="btn btn-primary"><i class="bi bi-search"></i></button>
            </form>
            <div class="d-flex align-items-center">
                <i class="bi bi-person-circle fs-4 me-2"></i>
                <?php if($_SESSION['role']=="Admin"){ ?>
                <span>
                    Admin | <?php echo $_SESSION['username']; ?>
                </span>
                <?php } ?>
            </div>
        </div>
    </div>

    <!-- CONTENT -->
    <div class="content">
        <div class="container mt-1">
            <h1>Reported Numbers</h1>
            <div class="d-flex align-items-center justify-content-between mt-4 mb-3">

                <form method="GET" class="d-flex" action="search.php" style="max-width:400px; width:100%;">

                    <input type="text" name="search" class="form-control me-2" placeholder="Search phone number..."
                        value="<?php echo $_GET['search'] ?? ''; ?>">

                    <button class="btn btn-primary me-2">
                        <i class="bi bi-search"></i>
                    </button>

                    <a href="manage_reports.php" class="btn btn-secondary">
                        Reset
                    </a>

                </form>

            </div>
            <table class="table table-bordered table-striped table-hover mt-4">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Phone</th>
                        <th>Reported By</th>
                        <th>Report Reason</th>
                        <th>Comment</th>
                        <th>Status</th>
                        <th>Created at</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = mysqli_fetch_assoc($result)):
                $phone = decryptData($row['phone_encrypted'],$secret_key);
                $reason = decryptData($row['report_reason_encrypted'],$secret_key);
                $comment = decryptData($row['comment_encrypted'],$secret_key);
                $count = $reportCount[$row['phone_hash']] ?? 0;
                $status = $row['status'];

                if($count >=5) $badge = "bg-danger";
                elseif($count >=3) $badge = "bg-warning";
                elseif($count >0) $badge = "bg-info";
                else $badge = "bg-secondary";

                if($status == "Pending") echo "<span class='badge bg-warning text-dark'>$status</span>";
                elseif($status == "Accepted") echo "<span class='badge bg-success'>$status</span>";
                elseif($status == "Rejected") echo "<span class='badge bg-danger'>$status</span>";
                else echo "<span class='badge bg-secondary'>$status</span>";
            ?>
                    <tr>
                        <td><?php echo $row['id']; ?></td>
                        <td><?php echo htmlspecialchars($phone); ?></td>
                        <td><span class="text-secondary">Anonymous</span></td>
                        <td style="max-width:200px;"><?php echo htmlspecialchars($reason); ?></td>
                        <td><?php echo htmlspecialchars($comment); ?></td>
                        <td><span class="badge <?php echo $badge; ?>"><?php echo $count; ?></span></td>
                        <td class="status-<?php echo $status;?>"><?php echo $status;?></td>
                        <td><?php echo $row['created_at']; ?></td>
                        <td>
                            <a href="?accept=<?php echo $row['id']; ?>" class="btn btn-success btn-sm"
                                onclick="return confirm('Accept this report?')"><i class="bi bi-check-circle"></i></a>
                            <a href="?reject=<?php echo $row['id']; ?>" class="btn btn-danger btn-sm"
                                onclick="return confirm('Reject this report?')"><i class="bi bi-x-circle"></i></a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
            <a href="admin_dashboard.php" class="btn btn-secondary">Back</a>
        </div>
    </div>

    <script>
    function toggleSidebar() {
        let sidebar = document.querySelector(".sidebar");
        let content = document.querySelector(".content");
        let topbar = document.querySelector(".topbar");
        sidebar.classList.toggle("collapsed");
        content.classList.toggle("expanded");
        topbar.classList.toggle("expanded");
    }
    </script>

</body>

</html>