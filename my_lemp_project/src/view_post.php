<?php
session_start();
require_once 'db.php';
require_once 'config.php';
require_once 'utils.php';

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

// Fetch comments
$comments_stmt = $pdo->prepare("SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE comments.post_id = ? ORDER BY comments.created_at ASC");
$comments_stmt->execute([$post_id]);
$comments = $comments_stmt->fetchAll();

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($post['title']); ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true): ?>
            <div class="vulnerability-mode-warning">
                ⚠️ 취약점 테스트 모드 활성화 (교육 목적)
            </div>
        <?php endif; ?>
        <h1><?php echo htmlspecialchars($post['title']); ?></h1>
        <p>By <a href="profile.php?id=<?php echo $post['user_id']; ?>"><?php echo htmlspecialchars($post['username']); ?></a> on <?php echo $post['created_at']; ?></p>
        <div class="categories">
            <strong>Categories:</strong>
            <?php
            $categories_stmt = $pdo->prepare("SELECT c.id, c.name FROM categories c JOIN post_categories pc ON c.id = pc.category_id WHERE pc.post_id = ?");
            $categories_stmt->execute([$post_id]);
            $categories = $categories_stmt->fetchAll();
            if ($categories) {
                foreach ($categories as $index => $category) {
                    echo '<a href="index.php?category=' . $category['id'] . '">' . htmlspecialchars($category['name']) . '</a>';
                    if ($index < count($categories) - 1) {
                        echo ', ';
                    }
                }
            } else {
                echo 'Uncategorized';
            }
            ?>
        </div>
        <div class="post-content">
            <?php echo $post['content']; ?>
        </div>

        <?php if ($files): ?>
            <h3>Attachments:</h3>
            <ul>
                <?php foreach ($files as $file): ?>
                    <li>
                        <?php
                        $file_extension = pathinfo($file['filename'], PATHINFO_EXTENSION);
                        $image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
                        if (in_array(strtolower($file_extension), $image_extensions)) {
                            echo '<img src="' . htmlspecialchars($file['filepath']) . '" alt="' . htmlspecialchars($file['filename']) . '" style="max-width: 100%; height: auto;"><br>';
                        }
                        ?>
                        <a href="<?php echo htmlspecialchars($file['filepath']); ?>" download><?php echo htmlspecialchars($file['filename']); ?></a>
                    </li>
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

        <hr>

        <h2>Comments</h2>
        <?php if (empty($comments)): ?>
            <p>No comments yet.</p>
        <?php else: ?>
            <div class="comments-section">
                <?php foreach ($comments as $comment): ?>
                    <div class="comment" style="border: 1px solid #eee; padding: 10px; margin-bottom: 10px; border-radius: 5px;">
                        <p><strong><?php echo htmlspecialchars($comment['username']); ?></strong> on <?php echo $comment['created_at']; ?></p>
                        <p>
                        <?php 
                        // 취약점 모드일 때 XSS 허용 (교육 목적)
                        if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true) {
                            // 위험한 패턴 감지 (로깅 목적)
                            $dangerous_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'onclick'];
                            $is_suspicious = false;
                            foreach ($dangerous_patterns as $pattern) {
                                if (stripos($comment['content'], $pattern) !== false) {
                                    $is_suspicious = true;
                                    break;
                                }
                            }
                            
                            if ($is_suspicious && function_exists('log_security')) {
                                log_security('xss_attempt', 'Potential XSS in comment display', [
                                    'comment_content' => $comment['content'],
                                    'comment_id' => $comment['id'],
                                    'vulnerability_mode' => true
                                ]);
                            }
                            
                            // 취약한 출력 (직접 출력)
                            echo nl2br($comment['content']);
                        } else {
                            // 안전한 출력 (HTML 엔티티 인코딩)
                            echo nl2br(htmlspecialchars($comment['content']));
                        }
                        ?>
                        </p>
                        <?php if (isset($_SESSION['user_id']) && ($_SESSION['user_id'] == $comment['user_id'] || $_SESSION['is_admin'])): ?>
                            <?php
                            // CSRF 토큰 조건부 추가
                            $delete_url = "delete_comment.php?id=" . $comment['id'] . "&post_id=" . $post['id'];
                            if (!(defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true)) {
                                $delete_url .= "&csrf_token=" . generate_csrf_token();
                            }
                            ?>
                            <a href="<?php echo $delete_url; ?>" class="btn btn-danger" style="font-size: 0.8em; padding: 3px 8px;" onclick="return confirm('Are you sure you want to delete this comment?')">Delete</a>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if (isset($_SESSION['user_id'])): ?>
            <h3>Add a Comment</h3>
            <form action="add_comment.php" method="post">
                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                <textarea name="content" placeholder="Your comment" required></textarea><br>
                <button type="submit" class="btn">Submit Comment</button>
            </form>
        <?php else: ?>
            <p>Please <a href="login.php">login</a> to add a comment.</p>
        <?php endif; ?>

    </div>
</body>
</html>