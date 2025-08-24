<?php
session_start();
require_once 'db.php';
require_once 'utils.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF 토큰 검증 (취약점 모드가 아닐 때만)
    if (!(defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true)) {
        if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
            die("Invalid CSRF token.");
        }
    }
    
    $post_id = clean_input($_POST['post_id']);
    $user_id = $_SESSION['user_id'];
    $content = clean_input($_POST['content']);

    if (empty($content)) {
        die("Comment content cannot be empty.");
    }

    $stmt = $pdo->prepare("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)");
    $stmt->execute([$post_id, $user_id, $content]);
    $comment_id = $pdo->lastInsertId();

    // Get post author's user_id
    $post_author_stmt = $pdo->prepare("SELECT user_id FROM posts WHERE id = ?");
    $post_author_stmt->execute([$post_id]);
    $post_author_id = $post_author_stmt->fetchColumn();

    // Create notification for the post author
    if ($post_author_id && $post_author_id != $user_id) { // Don't notify if author comments on their own post
        $notification_message = safe_output($_SESSION['username']) . " commented on your post: " . safe_output(substr($content, 0, 50)) . "...";
        $notification_stmt = $pdo->prepare("INSERT INTO notifications (user_id, type, source_id, message) VALUES (?, ?, ?, ?)");
        $notification_stmt->execute([$post_author_id, 'new_comment', $comment_id, $notification_message]);
    }

    header("Location: view_post.php?id=" . $post_id);
    exit;
}
?>