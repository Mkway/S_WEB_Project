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

// Fetch files associated with the post
$files_stmt = $pdo->prepare("SELECT * FROM files WHERE post_id = ?");
$files_stmt->execute([$post_id]);
$existing_files = $files_stmt->fetchAll();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = $_POST['title'];
    $content = $_POST['content'];

    // Update post content
    $stmt = $pdo->prepare("UPDATE posts SET title = ?, content = ? WHERE id = ?");
    $stmt->execute([$title, $content, $post_id]);

    // Update categories
    $pdo->prepare("DELETE FROM post_categories WHERE post_id = ?")->execute([$post_id]);
    if (isset($_POST['categories']) && is_array($_POST['categories'])) {
        $stmt = $pdo->prepare("INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)");
        foreach ($_POST['categories'] as $category_id) {
            $stmt->execute([$post_id, $category_id]);
        }
    }

    // Handle file deletions
    if (isset($_POST['delete_files']) && is_array($_POST['delete_files'])) {
        foreach ($_POST['delete_files'] as $file_id) {
            $file_id = (int)$file_id;
            // Get file path before deleting from DB
            $file_path_stmt = $pdo->prepare("SELECT filepath FROM files WHERE id = ? AND post_id = ?");
            $file_path_stmt->execute([$file_id, $post_id]);
            $file_to_delete = $file_path_stmt->fetchColumn();

            if ($file_to_delete && file_exists($file_to_delete)) {
                unlink($file_to_delete); // Delete from file system
            }
            $delete_stmt = $pdo->prepare("DELETE FROM files WHERE id = ? AND post_id = ?");
            $delete_stmt->execute([$file_id, $post_id]);
        }
    }

    // Handle new file uploads
    if (isset($_FILES['new_files'])) {
        $upload_dir = 'uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0777, true);
        }
        foreach ($_FILES['new_files']['name'] as $key => $name) {
            if ($_FILES['new_files']['error'][$key] == UPLOAD_ERR_OK) {
                $tmp_name = $_FILES['new_files']['tmp_name'][$key];
                $filename = basename($name);
                $filepath = $upload_dir . $filename;
                move_uploaded_file($tmp_name, $filepath);

                $stmt = $pdo->prepare("INSERT INTO files (post_id, filename, filepath, filesize) VALUES (?, ?, ?, ?)");
                $stmt->execute([$post_id, $filename, $filepath, $_FILES['new_files']['size'][$key]]);
            }
        }
    }

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
        <form method="post" enctype="multipart/form-data">
            <label for="title">Title:</label>
            <input type="text" id="title" name="title" value="<?php echo htmlspecialchars($post['title']); ?>" required><br>

            <label for="content">Content:</label>
                        <textarea id="content" name="content" required><?php echo htmlspecialchars($post['content']); ?></textarea><br>
            <script src="https://cdn.ckeditor.com/4.16.2/standard/ckeditor.js"></script>
            <script>
                CKEDITOR.replace( 'content' );
            </script>

            <div class="form-group">
                <h3>Categories</h3>
                <?php
                // Fetch all categories
                $all_categories_stmt = $pdo->query("SELECT * FROM categories ORDER BY name");
                $all_categories = $all_categories_stmt->fetchAll();

                // Fetch categories for the current post
                $post_categories_stmt = $pdo->prepare("SELECT category_id FROM post_categories WHERE post_id = ?");
                $post_categories_stmt->execute([$post_id]);
                $post_category_ids = $post_categories_stmt->fetchAll(PDO::FETCH_COLUMN);

                foreach ($all_categories as $category):
                    $checked = in_array($category['id'], $post_category_ids) ? 'checked' : '';
                ?>
                    <label>
                        <input type="checkbox" name="categories[]" value="<?php echo $category['id']; ?>" <?php echo $checked; ?>>
                        <?php echo htmlspecialchars($category['name']); ?>
                    </label>
                <?php endforeach; ?>
            </div>

            <h3>Current Attachments:</h3>
            <?php if (empty($existing_files)): ?>
                <p>No files attached.</p>
            <?php else: ?>
                <ul>
                    <?php foreach ($existing_files as $file): ?>
                        <li>
                            <input type="checkbox" name="delete_files[]" value="<?php echo $file['id']; ?>" id="file_<?php echo $file['id']; ?>">
                            <label for="file_<?php echo $file['id']; ?>">Delete <?php echo htmlspecialchars($file['filename']); ?></label>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <label for="new_files">Add New Files:</label>
            <input type="file" id="new_files" name="new_files[]" multiple><br><br>

            <button type="submit" class="btn">Update Post</button>
        </form>
    </div>
</body>
</html>