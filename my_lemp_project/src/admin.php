<?php
session_start();
require_once 'db.php';

// Admin check
$allowed_ips = ['127.0.0.1', '::1', '172.22.0.1'];
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips) && (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin'])) {
    die("Access denied. You are not an admin.");
}

// Fetch all users
$users_stmt = $pdo->query("SELECT id, username, created_at, is_admin FROM users ORDER BY created_at DESC");
$users = $users_stmt->fetchAll();

// Fetch all posts
$posts_stmt = $pdo->query("SELECT posts.id, posts.title, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC");
$posts = $posts_stmt->fetchAll();

?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Page</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
    <h1>Admin Page</h1>

    <h2>Users</h2>
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Registered At</th>
            <th>Action</th>
        </tr>
        <?php foreach ($users as $user): ?>
            <tr>
                <td><?php echo $user['id']; ?></td>
                <td><?php echo htmlspecialchars($user['username']); ?></td>
                <td><?php echo $user['created_at']; ?></td>
                <td>
                    <a href="admin_actions.php?action=delete_user&id=<?php echo $user['id']; ?>" onclick="return confirm('Are you sure you want to delete this user?')">Delete</a>
                    <?php if ($user['is_admin']): ?>
                        <a href="admin_actions.php?action=unset_admin&id=<?php echo $user['id']; ?>">Unset Admin</a>
                    <?php else: ?>
                        <a href="set_admin.php?id=<?php echo $user['id']; ?>">Set Admin</a>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endforeach; ?>
    </table>

    <h2>Posts</h2>
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Author</th>
            <th>Action</th>
        </tr>
        <?php foreach ($posts as $post): ?>
            <tr>
                <td><?php echo $post['id']; ?></td>
                <td><?php echo htmlspecialchars($post['title']); ?></td>
                <td><?php echo htmlspecialchars($post['username']); ?></td>
                <td>
                    <a href="edit_post.php?id=<?php echo $post['id']; ?>">Edit</a>
                    <a href="admin_actions.php?action=delete_post&id=<?php echo $post['id']; ?>" onclick="return confirm('Are you sure you want to delete this post?')">Delete</a>
                </td>
            </tr>
        <?php endforeach; ?>
    </table>

    <br>
    <a href="index.php" class="btn">Back to Board</a>
</div>
</body>
</html>