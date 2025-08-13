<?php
/**
 * Insecure File Upload 테스트 페이지
 */
session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$message = '';
$uploaded_file_path = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['uploaded_file'])) {
    $upload_dir = '../uploads/';
    $file = $_FILES['uploaded_file'];

    if ($file['error'] === UPLOAD_ERR_OK) {
        $filename = basename($file['name']);
        $target_path = $upload_dir . $filename;

        // --- 취약점 발생 지점 --- //
        // 확장자 검증이 없거나 매우 미흡함
        /*
        // 안전한 로직 예시
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (!in_array($file_extension, $allowed_extensions)) {
            $message = "허용되지 않는 파일 형식입니다. (jpg, jpeg, png, gif만 가능)";
        } else if (move_uploaded_file($file['tmp_name'], $target_path)) {
            $message = "파일이 성공적으로 업로드되었습니다.";
            $uploaded_file_path = htmlspecialchars($target_path, ENT_QUOTES, 'UTF-8');
        } else {
            $message = "파일 업로드 중 오류가 발생했습니다.";
        }
        */

        // 취약한 로직: 확장자 검증 없음
        if (move_uploaded_file($file['tmp_name'], $target_path)) {
            $message = "파일이 성공적으로 업로드되었습니다.";
            $uploaded_file_path = htmlspecialchars($target_path, ENT_QUOTES, 'UTF-8');
        } else {
            $message = "파일 업로드 중 오류가 발생했습니다.";
        }

    } else {
        $message = "파일 업로드 중 오류 발생: " . $file['error'];
    }
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insecure File Upload 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>Insecure File Upload 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 안전하지 않은 파일 업로드 취약점</h3>
            <p>서버 측에서 업로드되는 파일의 확장자나 내용을 제대로 검증하지 않을 때 발생하는 취약점입니다.</p>
            <p>공격자는 웹쉘(Web Shell)과 같은 악성 스크립트 파일을 업로드하여 서버의 제어권을 획득할 수 있습니다.</p>
        </div>

        <div class="test-form">
            <h3>🧪 파일 업로드 테스트</h3>
            <p>아래 폼을 사용하여 파일을 업로드해 보세요. 이 폼은 확장자를 검증하지 않으므로, PHP 웹쉘 파일도 업로드될 수 있습니다.</p>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="uploaded_file" required>
                <button type="submit" class="btn">파일 업로드</button>
            </form>
        </div>

        <?php if ($message): ?>
            <div class="result-box">
                <h3>📊 업로드 결과</h3>
                <p><?php echo htmlspecialchars($message); ?></p>
                <?php if ($uploaded_file_path): ?>
                    <p>업로드된 파일 경로: <a href="<?php echo $uploaded_file_path; ?>" target="_blank"><?php echo $uploaded_file_path; ?></a></p>
                    <p><small><strong>경고:</strong> 업로드한 파일이 웹쉘인 경우, 위 링크를 클릭하면 서버에서 실행될 수 있습니다. 각별히 주의하세요.</small></p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="payload-section">
            <h3>🎯 공격 시나리오</h3>
            <ol>
                <li>간단한 PHP 웹쉘 파일을 만듭니다. (예: `<?php system($_GET['cmd']); ?>`)</li>
                <li>위 폼을 사용하여 웹쉘 파일을 서버에 업로드합니다.</li>
                <li>업로드 성공 시 표시되는 경로로 접근하여 `cmd` 파라미터로 시스템 명령어를 실행합니다.</li>
                <li><strong>예시:</strong> `http://localhost/uploads/webshell.php?cmd=ls -la`</li>
            </ol>
        </div>

        <div class="info-box">
            <h3>🛡️ 안전한 파일 업로드 방안</h3>
            <ul>
                <li><strong>확장자 화이트리스트:</strong> 허용할 확장자 목록(Whitelist)을 만들어, 목록에 있는 확장자만 업로드를 허용합니다. (블랙리스트 방식은 우회 가능성이 높아 위험)</li>
                <li><strong>MIME 타입 검증:</strong> 파일의 MIME 타입을 서버 측에서 다시 한번 확인하여 파일 종류를 검증합니다.</li>
                <li><strong>파일 내용 검증:</strong> 이미지 파일의 경우, `getimagesize()` 함수 등으로 실제 이미지 파일이 맞는지 확인합니다.</li>
                <li><strong>저장 경로 및 권한 설정:</strong> 업로드된 파일은 웹 루트(Document Root) 외부의 안전한 경로에 저장하고, 실행 권한을 제거합니다.</li>
                <li><strong>파일명 재정의:</strong> 업로드된 파일의 이름을 예측 불가능한 임의의 이름으로 변경하여 저장합니다.</li>
            </ul>
        </div>
    </div>
</body>
</html>
