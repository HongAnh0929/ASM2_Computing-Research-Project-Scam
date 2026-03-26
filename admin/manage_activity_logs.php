<?php
session_start();
require_once "../../Database/database.php";
require_once '../../vendor/autoload.php';

use Dotenv\Dotenv;

/* ================= ENV ================= */
$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ================= CHECK ADMIN ================= */
if(!isset($_SESSION['role']) || $_SESSION['role'] != "Admin"){
    header("Location: ../index.php");
    exit;
}

/* ================= DECRYPT ================= */
function decryptData($data,$key){
    if(!$data) return "";
    $data = base64_decode($data,true);
    if($data===false) return "";
    $iv = substr($data,0,16);
    $hmac = substr($data,-32);
    $encrypted = substr($data,16,-32);

    if(!hash_equals(hash_hmac('sha256',$iv.$encrypted,$key,true),$hmac)){
        return "";
    }

    return openssl_decrypt($encrypted,'AES-256-CBC',$key,OPENSSL_RAW_DATA,$iv);
}

/* ================= SEARCH ================= */
$search = $_GET['search'] ?? '';
$search = trim($search);

if($search != ""){
    $search_hash = hash_hmac('sha256', $search, $secret_key);

    $stmt = $conn->prepare("
        SELECT * FROM activity_logs
        WHERE username_hash = ? OR target_hash = ?
        ORDER BY created_at DESC
    ");
    $stmt->bind_param("ss",$search_hash,$search_hash);
    $stmt->execute();
    $result = $stmt->get_result();
}else{
    $result = mysqli_query($conn,"SELECT * FROM activity_logs ORDER BY created_at DESC");
}

/* ================= ACTION COLOR ================= */
function getActionClass($action){
    $action = strtolower($action);

    if(str_contains($action,'delete') || str_contains($action,'remove')){
        return 'table-danger';
    }
    if(str_contains($action,'update') || str_contains($action,'edit')){
        return 'table-warning';
    }
    if(str_contains($action,'add') || str_contains($action,'create')){
        return 'table-success';
    }
    if(str_contains($action,'login') || str_contains($action,'logout')){
        return 'table-primary';
    }

    return '';
}
?>



<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activity Logs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
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
    .sidebar.collapsed span {
        display: none;
    }

    .sidebar.collapsed a {
        justify-content: center;
    }

    .topbar {
        position: fixed;
        top: 0;
        right: 0;
        left: 250px;
        height: 60px;
        background: #343a40;
        color: white;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 20px;
        transition: 0.3s;
        z-index: 1000;
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

        <button class="btn btn-dark" onclick="toggleSidebar()">
            <i class="bi bi-list"></i>
        </button>

        <div class="d-flex align-items-center gap-3">

            <form action="search.php" method="GET" class="d-flex">
                <input class="form-control me-2" name="keyword" style="width:300px;" placeholder="Search">
                <button class="btn btn-primary">
                    <i class="bi bi-search"></i>
                </button>
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

    <div class="content">
        <div class="container mt-1">
            <h1>Activity Logs</h1>
            <div class="d-flex align-items-center justify-content-between mt-4 mb-3">
                <form method="GET" class="d-flex" style="max-width:400px; width:100%;">
                    <input type="text" name="search" class="form-control me-2" placeholder="Search user..."
                        value="<?php echo htmlspecialchars($search) ?>">
                    <button class="btn btn-primary me-2"><i class="bi bi-search"></i></button>
                    <a href="manage_activity_logs.php" class="btn btn-secondary">Reset</a>
                </form>
            </div>

            <table class="table table-bordered table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>User</th>
                        <th>Role</th>
                        <th>Action</th>
                        <th>Target</th>
                        <th>IP Address</th>
                        <th>Browser</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row=mysqli_fetch_assoc($result)){ 
                            $username = decryptData($row['username_encrypted'],$secret_key) ?? "Unknown";
                            $action = decryptData($row['action_encrypted'],$secret_key) ?? "";
                            $target = decryptData($row['target_encrypted'],$secret_key) ?? "";
                            $ip = decryptData($row['ip_address_encrypted'],$secret_key) ?? "";
                            $ua = decryptData($row['user_agent_encrypted'],$secret_key) ?? "";
                        ?>
                    <tr>
                        <td><?php echo $row['id']; ?></td>
                        <td><?php echo htmlspecialchars($username); ?></td>
                        <td><?php echo $row['role']; ?></td>
                        <td><?php echo htmlspecialchars($action); ?></td>
                        <td><?php echo htmlspecialchars($target); ?></td>
                        <td><?php echo htmlspecialchars($ip); ?></td>
                        <td style="max-width:250px;"><?php echo htmlspecialchars($ua); ?></td>
                        <td><?php echo $row['created_at']; ?></td>
                    </tr>
                    <?php } ?>
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