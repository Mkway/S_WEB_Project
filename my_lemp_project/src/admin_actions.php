<?php
session_start();
require_once 'db.php';

// Admin check
$allowed_ips = ['127.0.0.1', '::1', '172.22.0.1'];
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips) && (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin'])) {
    die("Access denied. You are not an admin.");
}

$action = $_GET['action'] ?? ($_POST['action'] ?? null);
$id = $_GET['id'] ?? null;

if (!$action) {
    header("Location: admin.php");
    exit;
}

switch ($action) {
    case 'delete_user':
        // Prevent deleting the admin user themselves (or other admins)
        $stmt = $pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch();

        if ($user && $user['is_admin']) {
            die("Cannot delete an admin account.");
        }

        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$id]);
        break;

    case 'delete_post':
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
        break;

    case 'unset_admin':
        $stmt = $pdo->prepare("UPDATE users SET is_admin = 0 WHERE id = ?");
        $stmt->execute([$id]);
        break;

    case 'add_category':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $category_name = trim($_POST['category_name']);
            if (!empty($category_name)) {
                $stmt = $pdo->prepare("INSERT IGNORE INTO categories (name) VALUES (?)");
                $stmt->execute([$category_name]);
            }
        }
        break;

    case 'edit_category':
        $category_id = $_GET['id'] ?? null;
        $new_name = trim($_GET['name'] ?? null);
        if ($category_id && !empty($new_name)) {
            $stmt = $pdo->prepare("UPDATE categories SET name = ? WHERE id = ?");
            $stmt->execute([$new_name, $category_id]);
        }
        break;

    case 'delete_category':
        $category_id = $_GET['id'] ?? null;
        if ($category_id) {
            // post_categories 테이블에서 먼저 삭제
            $pdo->prepare("DELETE FROM post_categories WHERE category_id = ?")->execute([$category_id]);
            // categories 테이블에서 삭제
            $stmt = $pdo->prepare("DELETE FROM categories WHERE id = ?");
            $stmt->execute([$category_id]);
        }
        break;

    default:
        // Unknown action
        break;
}

header("Location: admin.php");
exit;
?>