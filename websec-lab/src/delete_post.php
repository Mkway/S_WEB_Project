<?php
session_start();
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$post_id = $_GET['id'];

// Fetch post to get user_id for permission check
$stmt = $pdo->prepare("SELECT user_id FROM posts WHERE id = ?");
$stmt->execute([$post_id]);
$post = $stmt->fetch();

if (!$post || $post['user_id'] !== $_SESSION['user_id']) {
    die("Post not found or you don't have permission to delete.");
}

// Delete associated files first
$stmt = $pdo->prepare("SELECT * FROM files WHERE post_id = ?");
$stmt->execute([$post_id]);
$files = $stmt->fetchAll();
foreach ($files as $file) {
    unlink($file['filepath']);
}

$stmt = $pdo->prepare("DELETE FROM files WHERE post_id = ?");
$stmt->execute([$post_id]);

// Delete post
$stmt = $pdo->prepare("DELETE FROM posts WHERE id = ?");
$stmt->execute([$post_id]);

header("Location: index.php");
exit;
?>