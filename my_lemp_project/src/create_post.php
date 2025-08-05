<?php
session_start();
require_once 'db.php';
require_once 'config.php';
require_once 'utils.php';

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
                
                // 파일 확장자 검사 (취약점 모드가 아닐 때만)
                $upload_allowed = true;
                $upload_error = '';
                
                if (!(defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true)) {
                    // 안전한 모드: 파일 확장자 및 크기 검증
                    $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                    $allowed_extensions = array_merge(ALLOWED_IMAGE_EXTENSIONS, ALLOWED_DOCUMENT_EXTENSIONS);
                    
                    if (!in_array($file_extension, $allowed_extensions)) {
                        $upload_allowed = false;
                        $upload_error = "허용되지 않는 파일 형식입니다: $file_extension";
                    }
                    
                    if ($_FILES['files']['size'][$key] > MAX_FILE_SIZE) {
                        $upload_allowed = false;
                        $upload_error = "파일 크기가 너무 큽니다.";
                    }
                    
                    // 위험한 파일 내용 검사
                    $file_content = file_get_contents($tmp_name);
                    if (strpos($file_content, '<?php') !== false || strpos($file_content, '<script') !== false) {
                        $upload_allowed = false;
                        $upload_error = "위험한 파일 내용이 감지되었습니다.";
                    }
                } else {
                    // 취약점 모드: 파일 업로드 제한 없음 (교육 목적)
                    $dangerous_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'js', 'exe', 'bat', 'sh'];
                    $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                    
                    if (in_array($file_extension, $dangerous_extensions) && function_exists('log_security')) {
                        log_security('malicious_upload', 'Potentially malicious file uploaded', [
                            'filename' => $filename,
                            'extension' => $file_extension,
                            'size' => $_FILES['files']['size'][$key],
                            'vulnerability_mode' => true
                        ]);
                    }
                }
                
                if ($upload_allowed) {
                    move_uploaded_file($tmp_name, $filepath);
                    $stmt = $pdo->prepare("INSERT INTO files (post_id, filename, filepath, filesize) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$post_id, $filename, $filepath, $_FILES['files']['size'][$key]]);
                    
                    log_file_upload($filename, true);
                } else {
                    log_file_upload($filename, false, $upload_error);
                    // 취약점 모드가 아닐 때만 에러 표시
                    if (!(defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true)) {
                        $_SESSION['upload_error'] = $upload_error;
                    }
                }
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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Post</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true): ?>
            <div class="vulnerability-mode-warning">
                ⚠️ 취약점 테스트 모드 활성화 (교육 목적) - 파일 업로드 제한 없음
            </div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['upload_error'])): ?>
            <div class="alert alert-error">
                <?php echo htmlspecialchars($_SESSION['upload_error']); ?>
                <?php unset($_SESSION['upload_error']); ?>
            </div>
        <?php endif; ?>
        
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