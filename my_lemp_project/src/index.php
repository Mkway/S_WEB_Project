<?php session_start(); ?>
<!DOCTYPE html>
<html>
<head>
    <title>My Board</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="nav">
            <h1>My Board</h1>
            <div>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
                    <a href="logout.php" class="btn">Logout</a>
                    <a href="create_post.php" class="btn">New Post</a>
                <?php else: ?>
                    <a href="login.php" class="btn">Login</a>
                    <a href="register.php" class="btn">Register</a>
                <?php endif; ?>
            </div>
        </div>

        <h2>Posts</h2>
        <table>
            <thead>
                <tr>
                    <th>Title</th>
                    <th>Author</th>
                </tr>
            </thead>
            <tbody>
                <?php
                require_once 'db.php';
                $stmt = $pdo->query("SELECT posts.id, posts.title, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC");
                $posts = $stmt->fetchAll();
                foreach ($posts as $post):
                ?>
                    <tr>
                        <td><a href="view_post.php?id=<?php echo $post['id']; ?>"><?php echo htmlspecialchars($post['title']); ?></a></td>
                        <td><?php echo htmlspecialchars($post['username']); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>