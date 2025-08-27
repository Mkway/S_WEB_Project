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
$page_title = 'Insecure File Upload';
$description = '<p>서버 측에서 업로드되는 파일의 확장자나 내용을 제대로 검증하지 않을 때 발생하는 취약점입니다.</p>
<p>공격자는 웹쉘(Web Shell)과 같은 악성 스크립트 파일을 업로드하여 서버의 제어권을 획득할 수 있습니다.</p>';

// 2. 페이로드 정의 (공격 시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🎯 공격 시나리오',
        'description' => '아래 폼을 사용하여 파일을 업로드해 보세요. 이 폼은 확장자를 검증하지 않으므로, PHP 웹쉘 파일도 업로드될 수 있습니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>확장자 화이트리스트:</strong> 허용할 확장자 목록(Whitelist)을 만들어, 목록에 있는 확장자만 업로드를 허용합니다. (블랙리스트 방식은 우회 가능성이 높아 위험)",
    "<strong>MIME 타입 검증:</strong> 파일의 MIME 타입을 서버 측에서 다시 한번 확인하여 파일 종류를 검증합니다.",
    "<strong>파일 내용 검증:</strong> 이미지 파일의 경우, `getimagesize()` 함수 등으로 실제 이미지 파일이 맞는지 확인합니다.",
    "<strong>저장 경로 및 권한 설정:</strong> 업로드된 파일은 웹 루트(Document Root) 외부의 안전한 경로에 저장하고, 실행 권한을 제거합니다.",
    "<strong>파일명 재정의:</strong> 업로드된 파일의 이름을 예측 불가능한 임의의 이름으로 변경하여 저장합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Unrestricted File Upload" => "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<div class="info-box" style="background: #f8d7da; border-color: #f5c6cb; color: #721c24;">
    <h3>🚨 안전하지 않은 파일 업로드 취약점</h3>
    <p><strong>경고:</strong> 업로드한 파일이 웹쉘인 경우, 위 링크를 클릭하면 서버에서 실행될 수 있습니다. 각별히 주의하세요.</p>
</div>

<form method="post" enctype="multipart/form-data" class="test-form">
    <h3>🧪 파일 업로드 테스트</h3>
    <input type="file" name="uploaded_file" required>
    <br><br>
    <button type="submit" class="btn">파일 업로드</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data, $file_data) {
    $result = '';
    $error = '';
    $uploaded_file_path = '';

    if (isset($file_data['uploaded_file']) && $file_data['uploaded_file']['error'] === UPLOAD_ERR_OK) {
        $upload_dir = __DIR__ . '/../uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0777, true);
        }

        $file = $file_data['uploaded_file'];
        $filename = basename($file['name']);
        $target_path = $upload_dir . $filename;

        // --- 취약점 발생 지점 ---
        // 확장자 검증이 없거나 매우 미흡함
        if (move_uploaded_file($file['tmp_name'], $target_path)) {
            $uploaded_file_path = str_replace(__DIR__ . '/../', '', $target_path); // 웹 경로로 변환
            $result = "<p>파일이 성공적으로 업로드되었습니다.</p>";
            $result .= "<p>업로드된 파일 경로: <a href=\"/{$uploaded_file_path}\" target=\"_blank\">/{$uploaded_file_path}</a></p>";
        } else {
            $error = "파일 업로드 중 오류가 발생했습니다.";
        }
    } else {
        $error = "파일 업로드 중 오류 발생: " . ($file_data['uploaded_file']['error'] ?? '알 수 없음');
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>