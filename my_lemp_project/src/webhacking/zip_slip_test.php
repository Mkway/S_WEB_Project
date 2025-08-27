<?php
// 출력 버퍼링 시작 (헤더 전송 문제 방지)
ob_start();

// 세션 시작 (TestPage 전에)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . "/../db.php";
require_once __DIR__ . "/../utils.php";

// 로그인 확인
if (!is_logged_in()) {
    header("Location: ../login.php");
    exit();
}

require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Zip Slip';
$description = '<p><strong>Zip Slip</strong>은 압축 파일(ZIP, TAR 등)을 해제할 때, 압축 파일 내의 파일 경로에 `../`와 같은 상위 디렉토리 이동 문자가 포함되어 있어, 압축 해제 경로를 벗어나 임의의 위치에 파일을 생성하거나 덮어쓸 수 있는 취약점입니다.</p>
<p>이를 통해 웹쉘 업로드, 설정 파일 변조, 시스템 파일 덮어쓰기 등의 공격이 가능합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🎯 공격 시나리오',
        'description' => '아래 폼을 사용하여 ZIP 파일을 업로드하고 해제해 보세요. 이 기능은 Zip Slip 공격에 취약합니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "압축 해제 전, 각 파일의 경로가 지정된 대상 디렉토리 내에 있는지 확인합니다.",
    "`../`와 같은 상위 디렉토리 이동 문자가 포함된 파일 경로는 거부합니다.",
    "`ZipArchive::extractTo()` 대신 각 파일을 수동으로 처리하고 경로를 검증하는 로직을 사용합니다.",
    "최신 버전의 압축 해제 라이브러리나 함수를 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Zip Slip" => "https://owasp.org/org/www-community/attacks/Zip_Slip",
    "Snyk - Zip Slip Vulnerability" => "https://snyk.io/research/zip-slip-vulnerability"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<form method="post" enctype="multipart/form-data" class="test-form">
    <h3>🧪 ZIP 파일 업로드 및 해제 테스트</h3>
    <p>아래 폼을 사용하여 ZIP 파일을 업로드하고 해제해 보세요. 이 기능은 Zip Slip 공격에 취약합니다.</p>
    <input type="file" name="zip_file" accept=".zip" required>
    <br><br>
    <button type="submit" class="btn">ZIP 파일 업로드 및 해제</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data, $file_data) {
    $message = '';
    $extracted_files = [];
    $error = '';

    if (isset($file_data['zip_file']) && $file_data['zip_file']['error'] === UPLOAD_ERR_OK) {
        $upload_dir = __DIR__ . '/../uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0777, true);
        }
        $temp_zip_path = $upload_dir . basename($file_data['zip_file']['name']);

        if (move_uploaded_file($file_data['zip_file']['tmp_name'], $temp_zip_path)) {
            $zip = new ZipArchive;
            if ($zip->open($temp_zip_path) === TRUE) {
                $extract_base_path = $upload_dir . 'extracted/' . uniqid() . '/';
                if (!is_dir($extract_base_path)) {
                    mkdir($extract_base_path, 0777, true);
                }

                $zip_slip_detected = false;
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $filename = $zip->getNameIndex($i);
                    $target_file_path = $extract_base_path . $filename;

                    // --- 취약점 발생 지점 --- (경로 검증 없음)
                    // 방어 로직 예시: if (strpos($target_file_path, realpath($extract_base_path)) !== 0) { continue; }

                    if (strpos($filename, '../') !== false || strpos($filename, '..\') !== false) {
                        $zip_slip_detected = true;
                        $message .= "<p style=\"color:red;\">경고: Zip Slip 공격 시도 감지! (파일: " . htmlspecialchars($filename) . ")</p>";
                    }

                    // 실제 추출 (취약한 방식)
                    if ($zip->extractTo($extract_base_path, $filename)) {
                        $extracted_files[] = htmlspecialchars($target_file_path);
                    } else {
                        $message .= "<p style=\"color:red;\">파일 추출 실패: " . htmlspecialchars($filename) . "</p>";
                    }
                }
                $zip->close();
                
                if ($zip_slip_detected) {
                    $message .= "<p style=\"color:red; font-weight:bold;\">Zip Slip 공격이 성공적으로 시뮬레이션되었습니다!</p>";
                    $message .= "<p>공격자는 압축 해제 경로를 벗어나 임의의 위치에 파일을 생성하거나 덮어쓸 수 있습니다.</p>";
                } else {
                    $message .= "<p style=\"color:green;\">ZIP 파일이 성공적으로 업로드 및 추출되었습니다. Zip Slip 패턴이 감지되지 않았습니다.</p>";
                }

                if (!empty($extracted_files)) {
                    $message .= "<h4>추출된 파일:</h4><ul>";
                    foreach ($extracted_files as $file) {
                        $message .= "<li>" . $file . "</li>";
                    }
                    $message .= "</ul>";
                }

            } else {
                $error = "ZIP 파일을 열 수 없습니다.";
            }
            unlink($temp_zip_path); // 임시 ZIP 파일 삭제
        } else {
            $error = "ZIP 파일 업로드 중 오류가 발생했습니다.";
        }
    } else {
        $error = "파일 업로드 중 오류 발생: " . ($file_data['zip_file']['error'] ?? '알 수 없음');
    }

    return ['result' => $message, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
