<?php
session_start();
require_once '../../Database/database.php';
require_once '../../vendor/autoload.php';

use Dotenv\Dotenv;

/* ===== ENV ===== */
$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$secret_key = $_ENV['SECRET_KEY'] ?? die("SECRET_KEY missing");

/* ===== CHECK ADMIN ===== */
if(!isset($_SESSION['role']) || $_SESSION['role'] != "Admin"){

    logActivity($conn, "UNAUTHORIZED_ACCESS", "manage_users");

    header("Location: ../index.php");
    exit;
}

/* ===== INIT ===== */
$errors = [];

/* ===== ENCRYPT ===== */
function encryptData($data){
    global $secret_key;
    $iv = random_bytes(16);
    $enc = openssl_encrypt($data,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);
    return base64_encode($iv.$enc);
}

function decryptData($data){
    global $secret_key;
    if(empty($data)) return "";
    $data = base64_decode($data);
    $iv = substr($data,0,16);
    $enc = substr($data,16);
    return openssl_decrypt($enc,'aes-256-cbc',$secret_key,OPENSSL_RAW_DATA,$iv);
}

/* ===== NORMALIZE PHONE ===== */
function normalizePhone($phone){
    $phone = preg_replace('/\D/', '', $phone);
    if(substr($phone,0,1) == '0'){
        $phone = '84'.substr($phone,1);
    }
    return $phone;
}

/* ===== ACTIVITY LOG ===== */
function logActivity($conn, $action, $target){
    global $secret_key;

    $user_id = $_SESSION['user_id'] ?? null;
    $username = $_SESSION['username'] ?? 'unknown';
    $role = $_SESSION['role'] ?? 'User';

    $ip = $_SERVER['REMOTE_ADDR'];
    $ua = $_SERVER['HTTP_USER_AGENT'];

    /* HASH */
    $username_hash = hash_hmac('sha256', $username, $secret_key);
    $target_hash = hash_hmac('sha256', $target, $secret_key);
    $ip_hash = hash_hmac('sha256', $ip, $secret_key);

    /* ENCRYPT */
    $username_enc = encryptData($username);
    $action_enc = encryptData($action);
    $target_enc = encryptData($target);
    $ip_enc = encryptData($ip);
    $ua_enc = encryptData($ua);

    /* ALERT */
    $alert = "INFO";
    if($action == "DELETE_USER") $alert = "HIGH";
    if($action == "UPDATE_USER") $alert = "WARNING";

    $stmt = $conn->prepare("
        INSERT INTO activity_logs
        (user_id, username_encrypted, username_hash, role,
         action, action_encrypted,
         target_encrypted, target_hash,
         ip_address_encrypted, ip_hash,
         user_agent_encrypted, alert_type)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ");

    $stmt->bind_param(
        "isssssssssss",
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
        $ua_enc,
        $alert
    );

    $stmt->execute();
}

/* ===== ACTION ===== */
$action = $_GET['action'] ?? 'list';

/* ===== DELETE ===== */
if($action == "delete"){
    $id = intval($_GET['id']);

/* LẤY USER TRƯỚC KHI XÓA */
    $stmt = $conn->prepare("SELECT username_encrypted FROM users WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $res = $stmt->get_result();
    $user = $res->fetch_assoc();

    $username = decryptData($user['username_encrypted']);

/* LOG CHI TIẾT */
    logActivity($conn, "DELETE_USER", "ID: $id | Username: $username");

/* DELETE */
    $stmt = $conn->prepare("DELETE FROM users WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();

    header("Location: manage_users.php");
    exit;
}

/* ===== ADD USER ===== */
if(isset($_POST['add_user'])){

    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $phoneRaw = $_POST['phone'];
    $phone = normalizePhone($phoneRaw);
    $password = $_POST['password'];
    $dob = $_POST['dob'];
    $gender = $_POST['gender'];
    $role = $_POST['role'];

    /* VALIDATE */
    if(!preg_match('/^[A-Za-z0-9_]{8,20}$/',$username)){
        $errors['username'] = "Username 8-20 chars";
    }

    if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
        $errors['email'] = "Invalid email";
    }

    if(!preg_match('/^[0-9]{10}$/',$phoneRaw)){
        $errors['phone'] = "Phone must be 10 digits";
    }

    if(!$dob || $dob > date('Y-m-d')){
        $errors['dob'] = "Invalid DOB";
    }

    if(!$gender){
        $errors['gender'] = "Select gender";
    }

    if(!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,20}$/',$password)){
        $errors['password'] = "Weak password";
    }

    if(empty($errors)){

        $password_hash = password_hash($password, PASSWORD_BCRYPT);

        $username_hash = hash_hmac('sha256',$username,$secret_key);
        $email_hash = hash_hmac('sha256',$email,$secret_key);
        $phone_hash = hash_hmac('sha256',$phone,$secret_key);

        /* CHECK DUPLICATE */
        $check = $conn->prepare("SELECT id FROM users WHERE username_hash=? OR email_hash=? OR phone_hash=?");
        $check->bind_param("sss",$username_hash,$email_hash,$phone_hash);
        $check->execute();

        if($check->get_result()->num_rows > 0){
            $errors['general'] = "User already exists";

            logActivity($conn, "ADD_USER_FAILED", $username);
        } else {

            $status = "Inactive";

            $stmt = $conn->prepare("
                INSERT INTO users(
                    username_encrypted, username_hash,
                    email_encrypted, email_hash,
                    phone_encrypted, phone_hash,
                    password,
                    dob_encrypted, gender_encrypted,
                    role, status
                )
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ");

            $stmt->bind_param("sssssssssss",
                encryptData($username), $username_hash,
                encryptData($email), $email_hash,
                encryptData($phone), $phone_hash,
                $password_hash,
                encryptData($dob), encryptData($gender),
                $role, $status
            );

            $stmt->execute();

            logActivity($conn, "ADD_USER", $username);

            header("Location: manage_users.php");
            exit;
        }
    }
}

/* ===== UPDATE ===== */
if(isset($_POST['update_user'])){

    $id = intval($_POST['id']);
    $new_role = $_POST['role'];

/* LẤY ROLE CŨ */
    $stmt = $conn->prepare("SELECT role FROM users WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $old = $stmt->get_result()->fetch_assoc();

/* UPDATE */
    $stmt = $conn->prepare("UPDATE users SET role=? WHERE id=?");
    $stmt->bind_param("si", $new_role, $id);
    $stmt->execute();

/* LOG */
    logActivity(
        $conn,
        "UPDATE_USER",
        "ID: $id | Role: ".$old['role']." -> ".$new_role
    );

    header("Location: manage_users.php");
    exit;
}
?>


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
    body {
        background: #ffffff;
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
            <?php if($action == "list"){ ?>

            <h1>User Management</h1>

            <?php } ?>

            <?php if($action == "add"){ ?>

            <h2>Add User</h2>

            <?php if(!empty($errors['general'])): ?>
            <div class="alert alert-danger"><?php echo $errors['general']; ?></div>
            <?php endif; ?>

            <form method="POST" class="container mt-1 ">

                <label class="mt-3">Username</label>
                <input type="text" name="username" class="form-control mb-2">
                <small class="text-danger"><?php echo $errors['username'] ?? ''; ?></small>

                <label class="mt-3">Email</label>
                <input type="email" name="email" class="form-control mb-2">
                <small class="text-danger"><?php echo $errors['email'] ?? ''; ?></small>

                <label class="mt-3">Phone</label>
                <input type="text" name="phone" class="form-control mb-2">
                <small class="text-danger"><?php echo $errors['phone'] ?? ''; ?></small>

                <label class="mt-3">Password</label>
                <div class="input-group mb-2">
                    <input type="password" id="password" name="password" class="form-control" required>
                    <span class="input-group-text" id="toggle-password" style="cursor:pointer;">
                        <i class="bi bi-eye" id="eye-icon"></i>
                    </span>
                </div>
                <small class="text-danger"><?php echo $errors['password'] ?? ''; ?></small>

                <!-- PASSWORD RULES -->
                <div id="password-rules" class="p-2 border rounded mb-2">
                    <div id="rule-length" class="text-success-emphasis">• 8-20 characters long</div>
                    <div id="rule-uppercase" class="text-success-emphasis">• At least one uppercase letter (A-Z)</div>
                    <div id="rule-lowercase" class="text-success-emphasis">• At least one lowercase letter (a-z)</div>
                    <div id="rule-number" class="text-success-emphasis">• At least one number (0-9)</div>
                    <div id="rule-special" class="text-success-emphasis">• At least one special character (!@#$%^&*)
                    </div>
                </div>
                <label class="mt-3">DOB</label>
                <input type="date" name="dob" class="form-control mb-2">
                <small class="text-danger"><?php echo $errors['dob'] ?? ''; ?></small>

                <label class="mt-3">Gender</label>
                <select name="gender" class="form-control mb-2">
                    <option value="">Select Gender</option>
                    <option>Male</option>
                    <option>Female</option>
                </select>
                <small class="text-danger"><?php echo $errors['gender'] ?? ''; ?></small>

                <label class="mt-3">Role</label>
                <select name="role" class="form-control mb-2">
                    <option value="">Select Role</option>
                    <option>User</option>
                    <option>Employee</option>
                    <option>Admin</option>
                </select>

                <div class="d-flex justify-content-between mt-4">
                    <button class="btn btn-success" id="create-btn" name="add_user" disabled>
                        Create
                    </button>
                    <a href="manage_users.php" class="btn btn-secondary">
                        Back
                    </a>
                </div>
            </form>

            <?php } elseif($action == "edit"){ 
                $id = intval($_GET['id']);
                $res = mysqli_query($conn,"SELECT * FROM users WHERE id='$id'");
                $user = mysqli_fetch_assoc($res);
                $username_dec = decryptData($user['username_encrypted']);
                $email_dec = decryptData($user['email_encrypted']);
                $phone_dec = decryptData($user['phone_encrypted']);
                $dob_dec = decryptData($user['dob_encrypted']);
                $gender_dec = decryptData($user['gender_encrypted']);
            ?>

            <h2>Edit User</h2>
            <form method="POST">
                <input type="hidden" name="id" value="<?php echo $user['id']; ?>">
                <label class="mt-2">Username</label>
                <input type="text" name="username" value="<?php echo htmlspecialchars($username_dec); ?>"
                    class="form-control mb-2">
                <label class="mt-2">Email</label>
                <input type="email" name="email" value="<?php echo htmlspecialchars($email_dec); ?>"
                    class="form-control mb-2">
                <label class="mt-2">Phone</label>
                <input type="text" name="phone" value="<?php echo htmlspecialchars($phone_dec); ?>"
                    class="form-control mb-2">
                <label class="mt-2">DOB</label>
                <input type="date" name="dob" value="<?php echo $dob_dec; ?>" class="form-control mb-2"
                    max="<?php echo date('Y-m-d'); ?>">
                <label class="mt-2">Gender</label>
                <select name="gender" class="form-control mb-2">
                    <option value="">Select Gender</option>
                    <option <?php if($gender_dec=="Male") echo "selected"; ?>>Male</option>
                    <option <?php if($gender_dec=="Female") echo "selected"; ?>>Female</option>
                </select>
                <label class="mt-2">Role</label>
                <select name="role" class="form-control mb-2">
                    <option <?php if($user['role']=="User") echo "selected"; ?>>User</option>
                    <option <?php if($user['role']=="Employee") echo "selected"; ?>>Employee</option>
                    <option <?php if($user['role']=="Admin") echo "selected"; ?>>Admin</option>
                </select>
                <label class="mt-2">Status</label>
                <input type="text" class="form-control mb-2" value="<?php echo $user['status']; ?>" readonly>
                <button type="submit" name="update_user" class="btn btn-primary">Update</button>
                <a href="manage_users.php" class="btn btn-secondary">Cancel</a>
            </form>
            <?php } else { 
        $res = mysqli_query($conn,"SELECT * FROM users ORDER BY id DESC");
    ?>
            <div class="d-flex align-items-center justify-content-between mt-4 mb-3">
                <form method="GET" action="search.php" class="d-flex" style="max-width:400px; width:100%;">

                    <input class="form-control me-2" name="keyword" placeholder="Search users...">

                    <button class="btn btn-primary me-2">
                        <i class="bi bi-search"></i>
                    </button>

                    <a href="manage_users.php" class="btn btn-secondary">
                        Reset
                    </a>

                </form>

                <a href="manage_users.php?action=add" class="btn btn-success mb-2">Add User</a>

            </div>
            <table class="table table-bordered table-striped">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>DOB</th>
                        <th>Gender</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Active</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = mysqli_fetch_assoc($res)):
                    $username_dec = decryptData($row['username_encrypted']);
                    $email_dec = decryptData($row['email_encrypted']);
                    $phone_dec = decryptData($row['phone_encrypted']);
                    $dob_dec = decryptData($row['dob_encrypted']);
                    $gender_dec = decryptData($row['gender_encrypted']);
                ?>
                    <tr>
                        <td><?php echo $row['id']; ?></td>
                        <td><?php echo htmlspecialchars($username_dec); ?></td>
                        <td><?php echo htmlspecialchars($email_dec); ?></td>
                        <td><?php echo htmlspecialchars($phone_dec); ?></td>
                        <td><?php echo $dob_dec; ?></td>
                        <td><?php echo $gender_dec; ?></td>
                        <td><?php echo $row['role']; ?></td>
                        <td><?php echo $row['status']; ?></td>
                        <td>
                            <a href="manage_users.php?action=edit&id=<?php echo $row['id']; ?>"
                                class="btn btn-warning btn-sm">Edit</a>
                            <a href="manage_users.php?action=delete&id=<?php echo $row['id']; ?>"
                                class="btn btn-danger btn-sm"
                                onclick="return confirm('Are you sure you want to delete user: <?php echo htmlspecialchars(decryptData($row['username_encrypted'])); ?> ?')">
                                Delete
                            </a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
            <?php } ?>
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

const passwordInput = document.getElementById('password');
const createBtn = document.getElementById('create-btn');
const rulesDiv = document.getElementById('password-rules');
const rules = {
    length: document.getElementById('rule-length'),
    uppercase: document.getElementById('rule-uppercase'),
    lowercase: document.getElementById('rule-lowercase'),
    number: document.getElementById('rule-number'),
    special: document.getElementById('rule-special')
};

function checkPasswordRules() {
    const val = passwordInput.value;

    const lengthOk = val.length >= 8 && val.length <= 20;
    const upperOk = /[A-Z]/.test(val);
    const lowerOk = /[a-z]/.test(val);
    const numberOk = /[0-9]/.test(val);
    const specialOk = /[!@#$%^&*]/.test(val);

    rules.length.className = lengthOk ? "text-success" : "text-success-emphasis";
    rules.uppercase.className = upperOk ? "text-success" : "text-success-emphasis";
    rules.lowercase.className = lowerOk ? "text-success" : "text-success-emphasis";
    rules.number.className = numberOk ? "text-success" : "text-success-emphasis";
    rules.special.className = specialOk ? "text-success" : "text-success-emphasis";

    const allOk = lengthOk && upperOk && lowerOk && numberOk && specialOk;

    rulesDiv.style.display = allOk ? "none" : "block";

    // Nếu tất cả thỏa thì enable nút Create, còn không disable
    createBtn.disabled = !allOk;
}

// Listen input event
passwordInput.addEventListener('input', checkPasswordRules);

// Prevent form submission if password rules not met (double check)
document.querySelector('form').addEventListener('submit', function(e) {
    const val = passwordInput.value;
    const allOk = val.length >= 8 && val.length <= 20 &&
        /[A-Z]/.test(val) &&
        /[a-z]/.test(val) &&
        /[0-9]/.test(val) &&
        /[!@#$%^&*]/.test(val);
    if (!allOk) {
        e.preventDefault();
        alert("Password does not meet all rules!");
    }
});

// TOGGLE PASSWORD VISIBILITY
const togglePassword = document.getElementById('toggle-password');
const eyeIcon = document.getElementById('eye-icon');

togglePassword.addEventListener('click', function() {
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        eyeIcon.classList.remove('bi-eye');
        eyeIcon.classList.add('bi-eye-slash');
    } else {
        passwordInput.type = "password";
        eyeIcon.classList.remove('bi-eye-slash');
        eyeIcon.classList.add('bi-eye');
    }
});
</script>