<?php
$message = '';
$error = '';
$upload_dir = '../my_lemp_project/src/uploads/'; // 기존 업로드 디렉토리 사용

if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['uploaded_file'])) {
        $file = $_FILES['uploaded_file'];

        // 파일 업로드 오류 확인
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $error = "파일 업로드 중 오류가 발생했습니다: " . $file['error'];
        } else {
            $filename = basename($file['name']);
            $target_file = $upload_dir . $filename;

            // !!! 경고: 이 코드는 파일 업로드 취약점에 매우 취약합니다. !!!
            // 파일의 MIME 타입이나 확장자를 제대로 검증하지 않습니다.
            // 따라서 PHP 스크립트 파일(.php)도 업로드될 수 있습니다.
            if (move_uploaded_file($file['tmp_name'], $target_file)) {
                $message = "파일이 성공적으로 업로드되었습니다: <a href=\"" . str_replace('../my_lemp_project/src/', '/', $target_file) . "\" target=\"_blank\">" . htmlspecialchars($filename) . "</a>";
            } else {
                $error = "파일 업로드에 실패했습니다.";
            }
        }
    } else {
        $error = "업로드할 파일을 선택해주세요.";
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>File Upload Vulnerability Test</title>
    <link rel="stylesheet" href="../my_lemp_project/src/style.css">
    <style>
        .container { max-width: 600px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>File Upload Vulnerability Challenge</h1>
        <p>이 페이지는 업로드되는 파일의 확장자를 제대로 검증하지 않습니다. 악의적인 스크립트 파일(웹쉘)을 업로드하여 서버를 제어할 수 있는지 테스트해보세요.</p>

        <?php if ($message): ?>
            <p style="color:green;"><?php echo htmlspecialchars($message); ?></p>
        <?php endif; ?>
        <?php if ($error): ?>
            <p style="color:red;"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>

        <form action="file_upload.php" method="POST" enctype="multipart/form-data">
            <label for="uploaded_file">업로드할 파일 선택:</label>
            <input type="file" id="uploaded_file" name="uploaded_file" required>
            <button type="submit">파일 업로드</button>
        </form>

        <hr style="margin-top: 30px;">

        <div>
            <h3>테스트 아이디어</h3>
            <ul>
                <li>간단한 PHP 웹쉘을 만들어 업로드해보세요. (예: `&lt;?php system($_GET['cmd']); ?&gt;`)</li>
                <li>업로드 후 웹쉘에 접근하여 `?cmd=ls -al`과 같은 명령어를 실행해보세요.</li>
                <li>확장자를 `image.php.jpg`와 같이 이중 확장자로 변경하여 우회할 수 있을까요?</li>
            </ul>
        </div>
        <a href="index.php" style="display: block; margin-top: 20px;"> &laquo; 뒤로 가기</a>
    </div>
</body>
</html>
