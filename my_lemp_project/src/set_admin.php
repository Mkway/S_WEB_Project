<?php
session_start();
require_once 'db.php';

// Admin check
$allowed_ips = ['127.0.0.1', '::1', '172.22.0.1'];
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips) && (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin'])) {
    die("Access denied. You are not an admin.");
}

if (isset($_GET['id'])) {
    $user_id = $_GET['id'];

    $stmt = $pdo->prepare("UPDATE users SET is_admin = 1 WHERE id = ?");
    $stmt->execute([$user_id]);

    header("Location: admin.php");
    exit;
}
?>