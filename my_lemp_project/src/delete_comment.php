<?php
session_start();
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

if (isset($_GET['id']) && isset($_GET['post_id'])) {
    $comment_id = $_GET['id'];
    $post_id = $_GET['post_id'];
    $user_id = $_SESSION['user_id'];
    $is_admin = $_SESSION['is_admin'] ?? false;

    // Check if the user is the comment author or an admin
    $stmt = $pdo->prepare("SELECT user_id FROM comments WHERE id = ?");
    $stmt->execute([$comment_id]);
    $comment = $stmt->fetch();

    if ($comment && ($comment['user_id'] == $user_id || $is_admin)) {
        $delete_stmt = $pdo->prepare("DELETE FROM comments WHERE id = ?");
        $delete_stmt->execute([$comment_id]);
    } else {
        die("Access denied. You don't have permission to delete this comment.");
    }

    header("Location: view_post.php?id=" . $post_id);
    exit;
}
?>