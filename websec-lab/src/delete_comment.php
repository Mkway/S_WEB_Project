<?php
session_start();
require_once 'db.php';
require_once 'config.php';
require_once 'utils.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

if (isset($_GET['id']) && isset($_GET['post_id'])) {
    $comment_id = $_GET['id'];
    $post_id = $_GET['post_id'];
    $user_id = $_SESSION['user_id'];
    $is_admin = $_SESSION['is_admin'] ?? false;
    
    // CSRF 보호 검사 (취약점 모드가 아닐 때만)
    if (!(defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true)) {
        // 안전한 모드: CSRF 토큰 검증
        if (!isset($_GET['csrf_token']) || !verify_csrf_token($_GET['csrf_token'])) {
            if (function_exists('log_security')) {
                log_security('csrf_attempt', 'CSRF attempt detected in comment deletion', [
                    'comment_id' => $comment_id,
                    'user_id' => $user_id,
                    'referer' => $_SERVER['HTTP_REFERER'] ?? 'unknown'
                ]);
            }
            die("CSRF token validation failed.");
        }
    } else {
        // 취약점 모드: CSRF 보호 없이 실행 (교육 목적)
        if (function_exists('log_security')) {
            log_security('csrf_vulnerability', 'Comment deletion without CSRF protection', [
                'comment_id' => $comment_id,
                'user_id' => $user_id,
                'vulnerability_mode' => true,
                'referer' => $_SERVER['HTTP_REFERER'] ?? 'unknown'
            ]);
        }
    }

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