<?php
session_start();
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// Fetch categories
$categories_stmt = $pdo->query("SELECT * FROM categories ORDER BY name");
$categories = $categories_stmt->fetchAll();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = $_POST['title'];
    $content = $_POST['content'];
    $user_id = $_SESSION['user_id'];

    $stmt = $pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
    $stmt->execute([$user_id, $title, $content]);
    $post_id = $pdo->lastInsertId();

    // Handle categories
    if (isset($_POST['categories']) && is_array($_POST['categories'])) {
        $stmt = $pdo->prepare("INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)");
        foreach ($_POST['categories'] as $category_id) {
            $stmt->execute([$post_id, $category_id]);
        }
    }

    // File upload
    if (isset($_FILES['files'])) {
        $upload_dir = 'uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0777, true);
        }
        foreach ($_FILES['files']['name'] as $key => $name) {
            if ($_FILES['files']['error'][$key] == UPLOAD_ERR_OK) {
                $tmp_name = $_FILES['files']['tmp_name'][$key];
                $filename = basename($name);
                $filepath = $upload_dir . $filename;
                move_uploaded_file($tmp_name, $filepath);

                $stmt = $pdo->prepare("INSERT INTO files (post_id, filename, filepath, filesize) VALUES (?, ?, ?, ?)");
                $stmt->execute([$post_id, $filename, $filepath, $_FILES['files']['size'][$key]]);
            }
        }
    }

    header("Location: index.php");
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Create Post</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Create New Post</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="text" name="title" placeholder="Title" required><br>
                        <textarea name="content" id="content" placeholder="Content" required></textarea><br>
            <script src="https://cdn.ckeditor.com/4.22.1/standard/ckeditor.js"></script>
            <script>
                CKEDITOR.replace( 'content' );
            </script>
            <div class="form-group">
                <h3>Categories</h3>
                <?php foreach ($categories as $category): ?>
                    <label>
                        <input type="checkbox" name="categories[]" value="<?php echo $category['id']; ?>">
                        <?php echo htmlspecialchars($category['name']); ?>
                    </label>
                <?php endforeach; ?>
            </div>
            <label>Files: <input type="file" name="files[]" multiple></label><br><br>
            <button type="submit">Create Post</button>
        </form>
    </div>
</body>
</html>