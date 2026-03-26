<?php
session_start();
require_once '../Database/database.php';

// Lưu lại ngôn ngữ trước khi destroy session
$lang = $_SESSION['lang'] ?? 'en';

// Cập nhật trạng thái user nếu đang login
if(isset($_SESSION['user_id'])){
    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("UPDATE users SET status='Inactive' WHERE id=?");
    if($stmt){
        $stmt->bind_param("i",$user_id);
        $stmt->execute();
        $stmt->close();
    }
}

// Hủy session hiện tại
session_unset();
session_destroy();

// Tạo session mới và giữ ngôn ngữ
session_start();
$_SESSION['lang'] = $lang;

// Chuyển về login
header("Location: login.php");
exit();
?>