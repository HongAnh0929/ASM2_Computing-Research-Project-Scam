<?php
session_start();
require_once "../../Database/database.php";

/* ADMIN CHECK */

if(!isset($_SESSION['role']) || $_SESSION['role'] != 'Admin'){
    header("Location: ../index.php");
    exit;
}

/* ===============================
   SEARCH ACTIVITY LOGS
================================ */

$search = $_GET['search'] ?? "";

if($search != ""){

$stmt = $conn->prepare("
SELECT * FROM activity_logs
WHERE username LIKE ?
OR target LIKE ?
ORDER BY created_at DESC
");

$like = "%$search%";

$stmt->bind_param("ss",$like,$like);

$stmt->execute();

$result = $stmt->get_result();

}else{

$result = mysqli_query($conn,"
SELECT * FROM activity_logs
ORDER BY created_at DESC
");

}

function addLog($conn,$action,$target){

$user_id = $_SESSION['user_id'] ?? NULL;
$username = $_SESSION['user_name'] ?? "Guest";
$role = $_SESSION['role'] ?? "Guest";

$ip = $_SERVER['REMOTE_ADDR'];
$browser = $_SERVER['HTTP_USER_AGENT'];

$stmt = $conn->prepare("
INSERT INTO activity_logs
(user_id,username,role,action,target,ip_address,user_agent)
VALUES (?,?,?,?,?,?,?)
");

$stmt->bind_param(
"issssss",
$user_id,
$username,
$role,
$action,
$target,
$ip,
$browser
);

$stmt->execute();

}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>

    <title>Document</title>

    <style>
    body {
        background: #f4f6f9;
        font-family: Arial;
    }

    /* SIDEBAR */

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

    /* TOPBAR */

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

    /* CONTENT */

    .content {
        margin-left: 250px;
        padding: 90px 30px;
        transition: 0.3s;
    }

    .content.expanded {
        margin-left: 70px;
    }

    .card {
        border-radius: 10px;
    }
    </style>
</head>
<body>
    <!-- SIDEBAR -->

    <div class="sidebar">

        <h4>SCAM SYSTEM</h4>

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

            <input class="form-control" style="width:250px;" placeholder="Search number">

            <button class="btn btn-primary">
                <i class="bi bi-search"></i>
            </button>

            <div class="d-flex align-items-center ms-3">

                <i class="bi bi-person-circle fs-4 me-2"></i>
                <?php if($_SESSION['role']=="Admin"){ ?>


                <span>
                    Admin | <?php echo $_SESSION['user_name']; ?>
                </span>
                <?php } ?>

            </div>

        </div>

    </div>

    <div class="content">
 <div class="container mt-1">

<h2>Activity Logs</h2>

<form method="GET" class="mb-3 d-flex mt-4" style="max-width:400px;">

<input type="text"
name="search"
class="form-control me-2"
placeholder="Search phone number"
value="<?php echo $_GET['search'] ?? ''; ?>">

<button class="btn btn-primary">
<i class="bi bi-search"></i>
</button>

</form>

    <table class="table table-bordered table-striped">

<thead class="table-dark">

<tr>

<th>ID</th>
<th>User</th>
<th>Role</th>
<th>Action</th>
<th>Target</th>
<th>IP</th>
<th>Browser</th>
<th>Time</th>

</tr>

</thead>

<tbody>

<?php while($row=mysqli_fetch_assoc($result)){ 

$rowClass="";

if($row['alert_type']=="login_failed"){
$rowClass="table-danger";
}

if($row['alert_type']=="after_hours"){
$rowClass="table-warning";
}

?>

<tr class="<?php echo $rowClass; ?>">

<td><?php echo $row['id']; ?></td>

<td><?php echo $row['username']; ?></td>

<td>

<?php
if($row['role']=="Admin"){
echo '<span class="badge bg-danger">Admin</span>';
}
elseif($row['role']=="User"){
echo '<span class="badge bg-primary">User</span>';
}
elseif($row['role']=="Employee"){
echo '<span class="badge bg-success">Employee</span>';
}
?>
</td>

<td><?php echo $row['action']; ?></td>

<td><?php echo $row['target']; ?></td>

<td><?php echo $row['ip_address']; ?></td>

<td style="max-width:200px;">
<?php echo substr($row['user_agent'],0,40); ?>
</td>

<td><?php echo $row['created_at']; ?></td>

</tr>

<?php } ?>

</tbody>

</table>

<a href="admin_dashboard.php" class="btn btn-secondary">
                Back
            </a>

</div>

    </div>
</body>
</html>

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