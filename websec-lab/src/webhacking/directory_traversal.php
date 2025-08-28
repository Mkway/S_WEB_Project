<?php
// 출력 버퍼링 시작 (헤더 전송 문제 방지)
ob_start();

// 세션 시작 (TestPage 전에)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Directory Traversal';
$description = '<p><strong>Directory Traversal (경로 조작)</strong>은 공격자가 웹 서버의 파일 시스템에 접근하여 제한된 디렉토리를 벗어나 다른 파일이나 디렉토리를 읽거나 쓸 수 있도록 하는 취약점입니다.</p>
<p>이를 통해 민감한 정보 유출, 설정 파일 변경, 심지어 원격 코드 실행으로 이어질 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'basic' => [
        'title' => '🔧 기본 페이로드',
        'description' => '가장 기본적인 경로 조작 페이로드입니다.',
        'payloads' => [
            '../../../../etc/passwd',
            '../../../../windows/win.ini',
            'file:///etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd' // URL 인코딩
        ]
    ],
    'advanced' => [
        'title' => '🔍 고급 페이로드',
        'description' => '다양한 인코딩 및 우회 기법을 사용한 페이로드입니다.',
        'payloads' => [
            '....//....//....//....//etc/passwd',
            '..%c0%af..%c0%afetc/passwd',
            '..%252f..%252fetc/passwd',
            '/var/www/html/../etc/passwd'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 값 검증:</strong> 사용자 입력에서 `../`, `..\`, `%00` 등 경로 조작에 사용될 수 있는 문자를 필터링하거나 제거합니다.",
    "<strong>화이트리스트 기반 검증:</strong> 허용된 파일 이름이나 경로만 허용하고, 그 외의 모든 입력은 거부합니다.",
    "<strong>절대 경로 사용:</strong> 파일 접근 시 사용자 입력으로 구성된 상대 경로 대신, 미리 정의된 안전한 절대 경로를 사용합니다.",
    "<strong>`basename()` 사용:</strong> 파일 이름만 추출하여 경로 정보를 제거합니다.",
    "<strong>최소 권한 원칙:</strong> 웹 서버 프로세스가 필요한 최소한의 파일 시스템 권한만 가지도록 설정합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Path Traversal" => "https://owasp.org/www-community/attacks/Path_Traversal",
    "PortSwigger - Directory traversal" => "https://portswigger.net/web-security/file-path-traversal"
];

// 5. 테스트 폼 UI 정의
$file_path_input = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 파일 내용 읽기 테스트</h3>
    <p>아래 입력 필드에 읽고 싶은 파일의 경로를 입력하세요. (예: <code>../../../../etc/passwd</code>)</p>
    <label for="payload">파일 경로:</label>
    <textarea name="payload" id="payload" placeholder="예: ../../../../etc/passwd">{$file_path_input}</textarea>
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">파일 읽기</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $file_path_input = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($file_path_input)) {
        $error = "파일 경로를 입력해주세요.";
        return ['result' => $result, 'error' => $error];
    }

    // 취약한 구현 - 실제 Directory Traversal 실행
    $result .= "<div class='info-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>⚠️ 취약한 Directory Traversal 실행:</strong><br>";
    $result .= "요청한 파일 경로: <code>" . htmlspecialchars($file_path_input) . "</code>";
    $result .= "</div>";

    $result .= "<div class='vulnerable-output' style='background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 15px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>Directory Traversal 실행 결과:</strong><br>";

    // URL 디코딩 처리
    $decoded_path = urldecode($file_path_input);
    
    // 취약한 파일 접근 시도 (교육용)
    if (file_exists($decoded_path) && is_readable($decoded_path)) {
        $file_content = file_get_contents($decoded_path, false, null, 0, 2000); // 최대 2000자만 읽기
        if ($file_content !== false) {
            $result .= "<strong>✅ 파일 읽기 성공!</strong><br>";
            $result .= "<strong>실제 파일 경로:</strong> " . htmlspecialchars(realpath($decoded_path)) . "<br>";
            $result .= "<strong>파일 크기:</strong> " . filesize($decoded_path) . " bytes<br><br>";
            $result .= "<strong>파일 내용:</strong><br>";
            $result .= "<pre style='background: #f1f1f1; padding: 10px; max-height: 400px; overflow-y: auto; font-size: 12px;'>" . htmlspecialchars($file_content) . "</pre>";
            
            // 파일이 잘렸을 경우 알림
            if (strlen($file_content) >= 2000) {
                $result .= "<em>※ 파일 내용이 2000자로 제한되어 표시되었습니다.</em>";
            }
        } else {
            $result .= "<strong>❌ 파일을 읽을 수 없습니다.</strong><br>";
            $result .= "권한이 없거나 바이너리 파일일 수 있습니다.";
        }
    } else {
        $result .= "<strong>❌ 파일이 존재하지 않거나 접근할 수 없습니다.</strong><br>";
        $result .= "요청한 경로: " . htmlspecialchars($decoded_path) . "<br>";
        
        // 일반적으로 시도되는 파일들에 대한 힌트
        $common_files = ['/etc/passwd', '/etc/hosts', '/proc/version', '/etc/shadow'];
        $result .= "<br><strong>일반적으로 시도되는 파일들:</strong><br>";
        foreach ($common_files as $file) {
            $result .= "- " . htmlspecialchars($file) . "<br>";
        }
    }
    $result .= "</div>";

    // 안전한 구현과 비교
    $result .= "<div class='info-box' style='background: #d4edda; border-color: #c3e6cb; color: #155724; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>✅ 안전한 구현이었다면:</strong><br>";
    
    $base_dir = realpath(__DIR__ . '/../');
    $safe_path = realpath($base_dir . '/' . basename($file_path_input));
    
    if ($safe_path && strpos($safe_path, $base_dir) === 0) {
        $result .= "허용된 디렉토리 내의 파일만 접근 가능<br>";
        $result .= "안전한 경로: " . htmlspecialchars($safe_path);
    } else {
        $result .= "<strong>접근 차단됨!</strong> 허용된 디렉토리를 벗어나는 경로입니다.<br>";
        $result .= "기본 디렉토리: " . htmlspecialchars($base_dir);
    }
    $result .= "</div>";

    // 보안 권장사항
    $result .= "<div class='info-box' style='background: #d1ecf1; border-color: #bee5eb; color: #0c5460; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>🛡️ 보안 권장사항:</strong><br>";
    $result .= "- realpath()로 경로 정규화 및 검증<br>";
    $result .= "- basename()으로 파일명만 추출<br>";
    $result .= "- 화이트리스트 기반 파일 접근<br>";
    $result .= "- 최소 권한 원칙 적용<br>";
    $result .= "- 사용자 입력 검증 및 필터링";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Directory_Traversal_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>