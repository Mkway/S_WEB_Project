<?php
session_start();
require_once 'db.php';

// Admin check
$allowed_ips = ['127.0.0.1', '::1', '172.22.0.1'];
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips) && (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin'])) {
    die("Access denied. You are not an admin.");
}

$action = $_GET['action'] ?? null;
$id = $_GET['id'] ?? null;

if (!$action || !$id) {
    header("Location: admin.php");
    exit;
}

if ($action === 'delete_user') {
    // Prevent deleting the admin user themselves (or other admins)
    $stmt = $pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
    $stmt->execute([$id]);
    $user = $stmt->fetch();

    if ($user && $user['is_admin']) {
        die("Cannot delete an admin account.");
    }

    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$id]);
}

if ($action === 'delete_post') {
    // First, delete associated files
    $stmt = $pdo->prepare("SELECT filepath FROM files WHERE post_id = ?");
    $stmt->execute([$id]);
    $files = $stmt->fetchAll();
    foreach ($files as $file) {
        if (file_exists($file['filepath'])) {
            unlink($file['filepath']);
        }
    }
    $pdo->prepare("DELETE FROM files WHERE post_id = ?")->execute([$id]);

    // Then, delete the post
    $stmt = $pdo->prepare("DELETE FROM posts WHERE id = ?");
    $stmt->execute([$id]);
}

if ($action === 'unset_admin') {
    $stmt = $pdo->prepare("UPDATE users SET is_admin = 0 WHERE id = ?");
    $stmt->execute([$id]);
}

header("Location: admin.php");
exit;
?>