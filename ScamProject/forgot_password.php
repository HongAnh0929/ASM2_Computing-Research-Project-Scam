<?php
session_start();
require '../Database/database.php';

$otp = "";
$username = "";

if(isset($_POST['check_user'])){

$username = $_POST['username'];

$sql = "SELECT * FROM users WHERE username=?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s",$username);
$stmt->execute();
$result = $stmt->get_result();

if($result->num_rows > 0){

$otp = rand(100000,999999);

$_SESSION['reset_user'] = $username;
$_SESSION['otp'] = $otp;

}else{
echo "Username not found";
}

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

<h3>Forgot Password</h3>

<form method="POST">

<input type="text" name="username" class="form-control mb-3" placeholder="Enter username">

<button name="check_user" class="btn btn-primary">Send OTP</button>

</form>

<?php if($otp!=""){ ?>

<hr>

<p>OTP generated (demo): <b id="otpText"><?php echo $otp; ?></b></p>

<form action="verify_otp.php" method="POST">

<input type="text" id="otpInput" name="otp" class="form-control mb-3" placeholder="Enter OTP">

<button class="btn btn-success">Verify OTP</button>

</form>
<?php } ?>
</div>

</body>
</html>

<script>

let otp = document.getElementById("otpText").innerText;
document.getElementById("otpInput").value = otp;

</script>