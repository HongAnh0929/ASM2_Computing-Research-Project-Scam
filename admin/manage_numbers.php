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

/* ================= ENCRYPT / DECRYPT ================= */
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

/* ================= ACTIVITY LOG ================= */
function logActivity($conn,$action,$target){

    global $secret_key;

    $user_id = $_SESSION['user_id'] ?? null;
    $username = $_SESSION['username'];
    $role = $_SESSION['role'];

    $ip = $_SERVER['REMOTE_ADDR'];
    $ua = $_SERVER['HTTP_USER_AGENT'];

    /* HASH */
    $username_hash = hash_hmac('sha256',$username,$secret_key);
    $target_hash = hash_hmac('sha256',$target,$secret_key);
    $ip_hash = hash_hmac('sha256',$ip,$secret_key);

    /* ENCRYPT */
    $username_enc = encryptData($username);
    $action_enc = encryptData($action);
    $target_enc = encryptData($target);
    $ip_enc = encryptData($ip);
    $ua_enc = encryptData($ua);

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
        $username_enc,
        $username_hash,
        $role,
        $action,
        $action_enc,
        $target_enc,
        $target_hash,
        $ip_enc,
        $ip_hash,
        $ua_enc
    );

    $stmt->execute();
}

/* ================= ACTION ================= */
$action = $_GET['action'] ?? 'list';
$search = $_GET['keyword'] ?? '';

/* ================= DELETE ================= */
if($action == "delete"){
    $id = intval($_GET['id']);

    $stmt = $conn->prepare("SELECT phonenumber_encrypted FROM phonenumbers WHERE id=?");
    $stmt->bind_param("i",$id);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();

    $phone = decryptData($row['phonenumber_encrypted']);

    $stmt = $conn->prepare("DELETE FROM phonenumbers WHERE id=?");
    $stmt->bind_param("i",$id);
    $stmt->execute();

    logActivity($conn,"DELETE_NUMBER",$phone);

    header("Location: manage_numbers.php");
    exit;
}

/* ================= ADD ================= */
if(isset($_POST['add_number'])){
    $phone_raw = $_POST['phonenumber'];
    $phone = preg_replace('/\D/', '', $phone_raw);

    $type = $_POST['type'];
    $country = $_POST['country'];
    $description = $_POST['description'];

    $phone_hash = hash_hmac('sha256',$phone,$secret_key);

    $stmt = $conn->prepare("SELECT id FROM phonenumbers WHERE phonenumber_hash=?");
    $stmt->bind_param("s",$phone_hash);
    $stmt->execute();

    if($stmt->get_result()->num_rows > 0){
        die("Phone already exists");
    }

    $stmt = $conn->prepare("
        INSERT INTO phonenumbers
        (phonenumber_encrypted, phonenumber_hash, type, country_encrypted, description_encrypted)
        VALUES (?,?,?,?,?)
    ");

    $stmt->bind_param(
        "sssss",
        encryptData($phone),
        $phone_hash,
        $type,
        encryptData($country),
        encryptData($description)
    );

    $stmt->execute();

    logActivity($conn,"ADD_NUMBER",$phone);

    header("Location: manage_numbers.php");
    exit;
}

/* ================= UPDATE ================= */
if(isset($_POST['update_number'])){
    $id = intval($_POST['id']);

    $phone_raw = $_POST['phonenumber'];
    $phone = preg_replace('/\D/', '', $phone_raw);

    $type = $_POST['type'];
    $country = $_POST['country'];
    $description = $_POST['description'];

    $phone_hash = hash_hmac('sha256',$phone,$secret_key);

    $stmt = $conn->prepare("
        UPDATE phonenumbers
        SET phonenumber_encrypted=?, phonenumber_hash=?, type=?, country_encrypted=?, description_encrypted=?
        WHERE id=?
    ");

    $stmt->bind_param(
        "sssssi",
        encryptData($phone),
        $phone_hash,
        $type,
        encryptData($country),
        encryptData($description),
        $id
    );

    $stmt->execute();

    logActivity($conn,"UPDATE_NUMBER",$phone);

    header("Location: manage_numbers.php");
    exit;
}

/* ================= LIST ================= */
$result = mysqli_query($conn,"SELECT * FROM phonenumbers ORDER BY id DESC");
?>



<!DOCTYPE html>
<html>

<head>
    <title>Phone Number Management</title>
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
        color: #e4e9f4;
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

    .card {
        border-radius: 10px;
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
            <form action="search.php" method="GET" class="d-flex">
                <input class="form-control me-2" name="keyword" style="width:300px;" placeholder="Search">
                <button class="btn btn-primary"><i class="bi bi-search"></i></button>
            </form>
            <div class="d-flex align-items-center">
                <i class="bi bi-person-circle fs-4 me-2"></i>
                <?php if($_SESSION['role']=="Admin"){ ?>
                <span>Admin | <?php echo $_SESSION['username']; ?></span>
                <?php } ?>
            </div>
        </div>
    </div>

    <div class="content">
        <div class="container mt-1">
            <?php if($action == "list"){ ?>
            <h1>Phone Number Management</h1>
            <?php } ?>

            <!-- ADD FORM -->
            <?php if($action == "add"){ ?>
            <h4>Add Phone Number</h4>
            <form method="POST">
                <label class="mt-3">Phone Number</label>
                <input type="text" name="phonenumber" class="form-control mb-2" required>
                <label class="mt-3">Type</label>
                <select name="type" class="form-control mb-2">
                    <option>Legitimate</option>
                    <option>Scam</option>
                    <option>Unknown</option>
                </select>
                <label class="mt-3">Country</label>
                <input type="text" name="country" class="form-control mb-2">
                <label class="mt-3">Description</label>
                <textarea name="description" class="form-control mb-2"></textarea>
                <div class="d-flex justify-content-between mt-4">
                    <button class="btn btn-success" name="add_number">Create</button>
                    <a href="manage_numbers.php" class="btn btn-secondary">Back</a>
                </div>
            </form>
            <?php } ?>

            <!-- EDIT FORM -->
            <?php if($action == "edit"):
            $id = intval($_GET['id']);
            $row = mysqli_fetch_assoc(mysqli_query($conn,"SELECT * FROM phonenumbers WHERE id='$id'"));
            $phone_dec = decryptData($row['phonenumber'],$secret_key);
        ?>
            <h4>Edit Phone Number</h4>
            <form method="POST">
                <input type="hidden" name="id" value="<?php echo $row['id']; ?>">
                <label class="mt-3">Phone Number</label>
                <input type="text" name="phonenumber" class="form-control mb-2"
                    value="<?php echo htmlspecialchars($phone_dec); ?>" required>
                <label class="mt-3">Type</label>
                <select name="type" class="form-control mb-2">
                    <option <?php if($row['type']=="Legitimate") echo "selected"; ?>>Legitimate</option>
                    <option <?php if($row['type']=="Scam") echo "selected"; ?>>Scam</option>
                    <option <?php if($row['type']=="Unknown") echo "selected"; ?>>Unknown</option>
                </select>
                <label class="mt-3">Country</label>
                <input type="text" name="country" class="form-control mb-2"
                    value="<?php echo htmlspecialchars($row['country']); ?>">
                <label class="mt-3">Description</label>
                <textarea name="description"
                    class="form-control mb-2"><?php echo htmlspecialchars($row['description']); ?></textarea>
                <div class="d-flex justify-content-between mt-4">
                    <button class="btn btn-primary" name="update_number">Update</button>
                    <a href="manage_numbers.php" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
            <?php endif; ?>

            <!-- SEARCH + ADD BUTTON -->
            <div class="d-flex justify-content-between mb-3 mt-4">
                <form method="GET" class="d-flex" action="search.php" style="max-width:400px; width:100%;">
                    <input type="text" name="keyword" class="form-control me-2" placeholder="Search phone..."
                        value="<?php echo htmlspecialchars($search); ?>">
                    <button class="btn btn-primary me-2">
                        <i class="bi bi-search"></i>
                    </button> <a href="manage_numbers.php" class="btn btn-secondary">Reset</a>
                </form>
                <a href="?action=add" class="btn btn-success">Add Phone</a>
            </div>

            <!-- TABLE -->
            <table class="table table-bordered table-striped">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Phone</th>
                        <th>Type</th>
                        <th>Country</th>
                        <th>Description</th>
                        <th>Reports</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row=mysqli_fetch_assoc($result)):
                $phone = decryptData($row['phonenumber'],$secret_key);

                $rowClass = "";
                if($row['report_count'] >= 5){ $rowClass = "table-danger"; }
                elseif($row['report_count'] >= 3){ $rowClass = "table-warning"; }
                elseif($row['report_count'] > 0){ $rowClass = "table-info"; }
            ?>
                    <tr class="<?php echo $rowClass; ?>">
                        <td><?php echo $row['id']; ?></td>
                        <td><?php echo htmlspecialchars($phone); ?></td>
                        <td>
                            <?php
                        if($row['type']=="Scam"){ echo "<span class='text-danger fw-bold'>Scam</span>"; }
                        elseif($row['type']=="Legitimate"){ echo "<span class='text-success fw-bold'>Legitimate</span>"; }
                        else{ echo "<span class='text-secondary'>Unknown</span>"; }
                        ?>
                        </td>
                        <td><?php echo $row['country']; ?></td>
                        <td><?php echo $row['description']; ?></td>
                        <td class="d-flex gap-1">
                            <a href="manage_numbers.php?action=edit&id=<?php echo $row['id'] ?>"
                                class="btn btn-warning btn-sm">Edit</a>
                            <a href="manage_numbers.php?action=delete&id=<?php echo $row['id'] ?>"
                                class="btn btn-danger btn-sm"
                                onclick="return confirm('Delete this number: <?php echo htmlspecialchars($phone); ?> ?')">Delete</a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
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