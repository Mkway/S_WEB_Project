<?php
session_start();
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$post_id = $_GET['id'];

// Fetch post
$stmt = $pdo->prepare("SELECT * FROM posts WHERE id = ?");
$stmt->execute([$post_id]);
$post = $stmt->fetch();

$allowed_ips = ['127.0.0.1', '::1', '172.22.0.1'];
if (!$post || ($post['user_id'] !== $_SESSION['user_id'] && !$_SESSION['is_admin'] && !in_array($_SERVER['REMOTE_ADDR'], $allowed_ips))) {
    die("Post not found or you don't have permission to edit.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = $_POST['title'];
    $content = $_POST['content'];

    $stmt = $pdo->prepare("UPDATE posts SET title = ?, content = ? WHERE id = ?");
    $stmt->execute([$title, $content, $post_id]);

    header("Location: view_post.php?id=" . $post_id);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Edit Post</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Edit Post</h1>
        <form method="post">
            <input type="text" name="title" value="<?php echo htmlspecialchars($post['title']); ?>" required><br>
            <textarea name="content" required><?php echo htmlspecialchars($post['content']); ?></textarea><br>
            <button type="submit">Update Post</button>
        </form>
    </div>
</body>
</html>