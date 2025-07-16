<?php
session_start();
require_once 'db.php';

$post_id = $_GET['id'];

// Fetch post
$stmt = $pdo->prepare("SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = ?");
$stmt->execute([$post_id]);
$post = $stmt->fetch();

if (!$post) {
    die("Post not found.");
}

// Fetch files
$stmt = $pdo->prepare("SELECT * FROM files WHERE post_id = ?");
$stmt->execute([$post_id]);
$files = $stmt->fetchAll();

?>
<!DOCTYPE html>
<html>
<head>
    <title><?php echo htmlspecialchars($post['title']); ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1><?php echo htmlspecialchars($post['title']); ?></h1>
        <p>By <?php echo htmlspecialchars($post['username']); ?> on <?php echo $post['created_at']; ?></p>
        <div class="post-content">
            <?php echo nl2br(htmlspecialchars($post['content'])); ?>
        </div>

        <?php if ($files): ?>
            <h3>Attachments:</h3>
            <ul>
                <?php foreach ($files as $file): ?>
                    <li><a href="<?php echo htmlspecialchars($file['filepath']); ?>" download><?php echo htmlspecialchars($file['filename']); ?></a></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <div class="nav">
            <a href="index.php" class="btn">Back to list</a>
            <div>
            <?php if (isset($_SESSION['user_id']) && ($_SESSION['user_id'] == $post['user_id'] || $_SESSION['is_admin'])): ?>
                <a href="edit_post.php?id=<?php echo $post['id']; ?>" class="btn">Edit</a>
                <a href="delete_post.php?id=<?php echo $post['id']; ?>" class="btn btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
            <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>