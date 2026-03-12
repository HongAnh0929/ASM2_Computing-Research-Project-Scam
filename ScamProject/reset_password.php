<?php
session_start();
require '../Database/database.php';

if(isset($_POST['reset'])){

$password = $_POST['password'];
$confirm = $_POST['confirm'];

if($password != $confirm){

echo "Password not match";
exit;

}

$hash = password_hash($password,PASSWORD_BCRYPT);

$username = $_SESSION['reset_user'];

$sql = "UPDATE users SET password=? WHERE username=?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ss",$hash,$username);
$stmt->execute();

echo "Password updated successfully";

session_destroy();

}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <title>Document</title>
</head>

<body>
    <div class="container mt-5">
        <h1>Reset Password</h1>
        <div class="container">
            <form method="POST">
                <div class="mb-3">
                    <label for="password" class="form-label">New Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Confirm Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button name="reset" class="btn btn-primary">Reset Password</button>
                <a href="login.php" class="btn btn-secondary">Back</a>
            </form>
            <br>
        </div>
    </div>

</body>

</html>