<?php
$file_content = '';
$error = '';

if (isset($_GET['file']) && $_GET['file'] !== '') {
    $filename = $_GET['file'];

    // !!! 경고: 이 코드는 디렉토리 트래버설에 매우 취약합니다. !!!
    // 사용자의 입력을 전혀 필터링하지 않고 파일 경로에 직접 사용합니다.
    $target_file = './files/' . $filename; // 예시: ./files/ 디렉토리 아래에 파일이 있다고 가정

    if (file_exists($target_file)) {
        $file_content = htmlspecialchars(file_get_contents($target_file));
    } else {
        $error = "파일을 찾을 수 없거나 접근할 수 없습니다.";
    }
} else {
    $error = "파일 이름을 입력해주세요.";
}

// 테스트를 위한 더미 파일 생성 (없으면 생성)
$dummy_dir = __DIR__ . '/files/';
if (!is_dir($dummy_dir)) {
    mkdir($dummy_dir, 0777, true);
}
if (!file_exists($dummy_dir . 'secret.txt')) {
    file_put_contents($dummy_dir . 'secret.txt', '이것은 민감한 정보입니다. 아무도 볼 수 없어야 합니다!');
}
if (!file_exists($dummy_dir . 'normal.txt')) {
    file_put_contents($dummy_dir . 'normal.txt', '이것은 일반적인 파일입니다.');
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Directory Traversal Test</title>
    <link rel="stylesheet" href="../my_lemp_project/src/style.css">
    <style>
        .container { max-width: 800px; }
        .file-content-display {
            background-color: #f0f0f0;
            border: 1px solid #ccc;
            padding: 15px;
            margin-top: 20px;
            border-radius: 5px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Directory Traversal Challenge</h1>
        <p>파일 이름을 입력하여 해당 파일의 내용을 확인하세요. `../`와 같은 경로 조작을 통해 웹 루트 외부의 파일을 읽을 수 있는지 테스트해보세요.</p>

        <form action="directory_traversal.php" method="GET">
            <label for="file">파일 이름:</label>
            <input type="text" id="file" name="file" placeholder="예: normal.txt" required>
            <button type="submit">파일 읽기</button>
        </form>

        <?php if ($error): ?>
            <p style="color:red; margin-top: 20px;"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>

        <?php if ($file_content): ?>
            <h3 style="margin-top: 20px;">파일 내용:</h3>
            <div class="file-content-display">
                <?php echo $file_content; ?>
            </div>
        <?php endif; ?>

        <hr style="margin-top: 30px;">

        <div>
            <h3>테스트 아이디어</h3>
            <ul>
                <li>`secret.txt` 파일을 읽어보세요.</li>
                <li>`../my_lemp_project/src/db.php`와 같이 상위 디렉토리로 이동하여 중요한 설정 파일을 읽을 수 있을까요?</li>
                <li>`../../../../etc/passwd`와 같이 시스템 파일을 읽을 수 있을까요? (리눅스 환경)</li>
            </ul>
        </div>
        <a href="index.php" style="display: block; margin-top: 20px;"> &laquo; 뒤로 가기</a>
    </div>
</body>
</html>
