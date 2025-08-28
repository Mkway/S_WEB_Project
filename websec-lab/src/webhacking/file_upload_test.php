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

    if (isset($file_data['uploaded_file']) && $file_data['uploaded_file']['error'] === UPLOAD_ERR_OK) {
        $file = $file_data['uploaded_file'];
        $filename = basename($file['name']);
        $file_size = $file['size'];
        $file_type = $file['type'];
        $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        // 취약한 파일 업로드 실행
        $result .= "<div class='info-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $result .= "<strong>⚠️ 취약한 파일 업로드 실행:</strong><br>";
        $result .= "파일명: <code>" . htmlspecialchars($filename) . "</code><br>";
        $result .= "파일 크기: " . number_format($file_size) . " bytes<br>";
        $result .= "MIME 타입: <code>" . htmlspecialchars($file_type) . "</code><br>";
        $result .= "확장자: <code>" . htmlspecialchars($file_ext) . "</code>";
        $result .= "</div>";

        // 업로드 디렉토리 생성
        $upload_dir = __DIR__ . '/../uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }

        $target_path = $upload_dir . $filename;

        $result .= "<div class='vulnerable-output' style='background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 15px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $result .= "<strong>취약한 파일 업로드 결과:</strong><br>";

        // 위험한 확장자 체크
        $dangerous_extensions = ['php', 'php3', 'php4', 'php5', 'phtml', 'asp', 'aspx', 'jsp', 'js', 'py', 'sh', 'exe', 'bat'];
        
        if (in_array($file_ext, $dangerous_extensions)) {
            $result .= "<strong>🚨 위험한 파일 확장자 감지!</strong><br>";
            $result .= "확장자 '<code>." . htmlspecialchars($file_ext) . "</code>'는 서버에서 실행 가능한 스크립트일 수 있습니다.<br><br>";
            
            // 실제 파일 업로드 실행 (교육용)
            if (move_uploaded_file($file['tmp_name'], $target_path)) {
                $web_path = '/websec-lab/src/uploads/' . $filename;
                $result .= "<strong>✅ 파일 업로드 성공!</strong><br>";
                $result .= "<strong>업로드된 경로:</strong> " . htmlspecialchars($target_path) . "<br>";
                $result .= "<strong>웹 접근 경로:</strong> <a href='" . htmlspecialchars($web_path) . "' target='_blank' style='color: #721c24; font-weight: bold;'>" . htmlspecialchars($web_path) . "</a><br>";
                
                // 파일 내용 미리보기 (처음 500자)
                $file_content = file_get_contents($target_path, false, null, 0, 500);
                if ($file_content !== false) {
                    $result .= "<br><strong>파일 내용 미리보기:</strong><br>";
                    $result .= "<pre style='background: #f1f1f1; padding: 10px; max-height: 200px; overflow-y: auto; font-size: 12px;'>" . htmlspecialchars($file_content) . "</pre>";
                }
                
                $result .= "<br><strong>⚠️ 경고:</strong> 웹쉘이나 악성 스크립트가 업로드되었을 수 있습니다!<br>";
                $result .= "<em>실제 환경에서는 이런 파일이 서버 전체를 장악할 수 있습니다.</em>";
            } else {
                $result .= "<strong>❌ 파일 업로드 실패</strong><br>";
                $result .= "서버 오류로 인해 파일을 저장할 수 없습니다.";
            }
        } else {
            // 일반 파일 업로드
            if (move_uploaded_file($file['tmp_name'], $target_path)) {
                $web_path = '/websec-lab/src/uploads/' . $filename;
                $result .= "<strong>✅ 일반 파일 업로드 성공</strong><br>";
                $result .= "<strong>업로드된 경로:</strong> " . htmlspecialchars($target_path) . "<br>";
                $result .= "<strong>웹 접근 경로:</strong> <a href='" . htmlspecialchars($web_path) . "' target='_blank'>" . htmlspecialchars($web_path) . "</a><br>";
                $result .= "<br>이 파일은 실행 가능한 스크립트가 아니므로 상대적으로 안전합니다.";
            } else {
                $result .= "<strong>❌ 파일 업로드 실패</strong><br>";
                $result .= "서버 오류로 인해 파일을 저장할 수 없습니다.";
            }
        }
        $result .= "</div>";

        // 안전한 구현과 비교
        $result .= "<div class='info-box' style='background: #d4edda; border-color: #c3e6cb; color: #155724; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $result .= "<strong>✅ 안전한 구현이었다면:</strong><br>";
        $result .= "1. 확장자 화이트리스트 검증: <code>in_array(\$ext, ['jpg', 'png', 'gif', 'pdf'])</code><br>";
        $result .= "2. MIME 타입 재검증: <code>mime_content_type(\$file)</code><br>";
        $result .= "3. 파일 크기 제한: <code>filesize() < MAX_SIZE</code><br>";
        $result .= "4. 안전한 경로에 저장: 웹 루트 외부 디렉토리<br>";
        $result .= "5. 파일명 재정의: <code>uniqid() . '.ext'</code>";
        $result .= "</div>";

        // 보안 권장사항
        $result .= "<div class='info-box' style='background: #d1ecf1; border-color: #bee5eb; color: #0c5460; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $result .= "<strong>🛡️ 보안 권장사항:</strong><br>";
        $result .= "- 확장자 화이트리스트 방식 사용<br>";
        $result .= "- MIME 타입 서버 사이드 검증<br>";
        $result .= "- 파일 내용 무결성 검사<br>";
        $result .= "- 업로드 크기 제한 설정<br>";
        $result .= "- 웹 루트 외부에 저장<br>";
        $result .= "- 바이러스 스캔 적용";
        $result .= "</div>";

    } else {
        $error = "<div class='error-box'>파일 업로드 중 오류 발생: " . ($file_data['uploaded_file']['error'] ?? '알 수 없음') . "</div>";
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "File_Upload_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>