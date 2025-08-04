<?php
session_start();
require_once 'db.php';

$user_id = isset($_GET['id']) ? (int)$_GET['id'] : null;

if (!$user_id) {
    die("User ID not specified.");
}

// Fetch user details
$stmt = $pdo->prepare("SELECT id, username, created_at FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$profile_user = $stmt->fetch();

if (!$profile_user) {
    die("User not found.");
}

// Fetch posts by this user
$posts_stmt = $pdo->prepare("SELECT id, title, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC");
$posts_stmt->execute([$profile_user['id']]);
$user_posts = $posts_stmt->fetchAll();

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($profile_user['username']); ?>'s Profile</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1><?php echo htmlspecialchars($profile_user['username']); ?>'s Profile</h1>
        <p><strong>Registered Since:</strong> <?php echo $profile_user['created_at']; ?></p>

        <h2>Posts by <?php echo htmlspecialchars($profile_user['username']); ?></h2>
        <?php if (empty($user_posts)): ?>
            <p>No posts found for this user.</p>
        <?php else: ?>
            <div class="table-container">
                <table>
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Date</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($user_posts as $post): ?>
                        <tr>
                            <td><a href="view_post.php?id=<?php echo $post['id']; ?>"><?php echo htmlspecialchars($post['title']); ?></a></td>
                            <td><?php echo $post['created_at']; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
                </table>
            </div>
        <?php endif; ?>

        <br>
        <a href="index.php" class="btn">Back to Board</a>
    </div>
</body>
</html>