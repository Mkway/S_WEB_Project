<?php
/**
 * Zip Slip 취약점 테스트 페이지
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
$extracted_files = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['zip_file'])) {
    $zip_file = $_FILES['zip_file'];

    if ($zip_file['error'] === UPLOAD_ERR_OK) {
        $upload_dir = '../uploads/';
        $temp_zip_path = $upload_dir . basename($zip_file['name']);

        if (move_uploaded_file($zip_file['tmp_name'], $temp_zip_path)) {
            $zip = new ZipArchive;
            if ($zip->open($temp_zip_path) === TRUE) {
                $extract_path = $upload_dir . 'extracted/' . uniqid() . '/';
                if (!is_dir($extract_path)) {
                    mkdir($extract_path, 0777, true);
                }

                // --- 취약점 발생 지점 ---
                // 압축 해제 시 파일 경로 검증 없음
                // (실제로는 각 파일의 경로를 검증하여 상위 디렉토리로의 이동을 막아야 함)
                
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $filename = $zip->getNameIndex($i);
                    $target_file = $extract_path . $filename;

                    // 취약한 로직: 경로 조작 방어 없음
                    // if (strpos($target_file, $extract_path) !== 0) { continue; } // 방어 로직 예시

                    if (strpos($filename, '../') !== false) {
                        $message .= "<p style=\"color:red;\">경고: Zip Slip 공격 시도 감지! (파일: " . htmlspecialchars($filename) . ")</p>";
                    }

                    if ($zip->extractTo($extract_path, $filename)) {
                        $extracted_files[] = htmlspecialchars($target_file);
                    } else {
                        $message .= "<p style=\"color:red;\">파일 추출 실패: " . htmlspecialchars($filename) . "</p>";
                    }
                }
                $zip->close();
                $message .= "<p style=\"color:green;\">ZIP 파일이 성공적으로 업로드 및 추출되었습니다.</p>";
            } else {
                $message = "ZIP 파일을 열 수 없습니다.";
            }
            unlink($temp_zip_path); // 임시 ZIP 파일 삭제
        } else {
            $message = "ZIP 파일 업로드 중 오류가 발생했습니다.";
        }
    } else {
        $message = "파일 업로드 중 오류 발생: " . $zip_file['error'];
    }
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zip Slip 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>Zip Slip 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 Zip Slip 취약점</h3>
            <p>압축 파일(ZIP, TAR 등)을 해제할 때, 압축 파일 내의 파일 경로에 <code>../</code>와 같은 상위 디렉토리 이동 문자가 포함되어 있어, 
압축 해제 경로를 벗어나 임의의 위치에 파일을 생성하거나 덮어쓸 수 있는 취약점입니다.</p>
            <p>이를 통해 웹쉘 업로드, 설정 파일 변조, 시스템 파일 덮어쓰기 등의 공격이 가능합니다.</p>
        </div>

        <div class="test-form">
            <h3>🧪 ZIP 파일 업로드 및 해제 테스트</h3>
            <p>아래 폼을 사용하여 ZIP 파일을 업로드하고 해제해 보세요. 이 기능은 Zip Slip 공격에 취약합니다.</p>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="zip_file" accept=".zip" required>
                <button type="submit" class="btn">ZIP 파일 업로드 및 해제</button>
            </form>
        </div>

        <?php if ($message): ?>
            <div class="result-box">
                <h3>📊 결과</h3>
                <p><?php echo htmlspecialchars($message); ?></p>
                <?php if (!empty($extracted_files)): ?>
                    <h4>추출된 파일:</h4>
                    <ul>
                        <?php foreach ($extracted_files as $file): ?>
                            <li><?php echo $file; ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="payload-section">
            <h3>🎯 공격 시나리오</h3>
            <ol>
                <li>Zip Slip 공격용 ZIP 파일을 생성합니다. (예: <code>evil.zip</code> 내부에 <code>../index.php</code>와 같은 경로 포함)</li>
                <li>위 폼을 사용하여 <code>evil.zip</code> 파일을 업로드합니다.</li>
                <li>서버의 취약한 압축 해제 로직으로 인해 <code>index.php</code> 파일이 웹 루트에 덮어쓰여질 수 있습니다.</li>
            </ol>
            <p><strong>Zip Slip 공격용 ZIP 파일 생성 예시 (Linux/macOS):</strong></p>
            <pre><code>echo "&lt;?php phpinfo(); ?&gt;" > evil.php
zip evil.zip "../evil.php"
</code></pre>
            <p><strong>주의:</strong> 실제 환경에서는 매우 위험한 공격이므로, 반드시 격리된 테스트 환경에서만 시도하세요.</p>
        </div>

        <div class="info-box">
            <h3>🛡️ Zip Slip 방어 방법</h3>
            <ul>
                <li>압축 해제 전, 각 파일의 경로가 지정된 대상 디렉토리 내에 있는지 확인합니다.</li>
                <li><code>../</code>와 같은 상위 디렉토리 이동 문자가 포함된 파일 경로는 거부합니다.</li>
                <li>`ZipArchive::extractTo()` 대신 각 파일을 수동으로 처리하고 경로를 검증하는 로직을 사용합니다.</li>
                <li>최신 버전의 압축 해제 라이브러리나 함수를 사용합니다.</li>
            </ul>
        </div>
    </div>
</body>
</html>
