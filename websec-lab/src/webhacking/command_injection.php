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
$page_title = 'Command Injection';
$description = '<p><strong>Command Injection</strong>은 애플리케이션이 사용자 입력을 시스템 명령어에 포함시킬 때 발생하는 취약점입니다.</p>
<p>공격자가 임의의 시스템 명령어를 실행할 수 있게 되어 매우 위험합니다.</p>
<p><strong>참고:</strong> 이 페이지에서는 안전한 환경에서 테스트하며, 실제 위험한 명령어는 실행되지 않습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'basic' => [
        'title' => '🔧 Basic Command Injection',
        'description' => '기본적인 명령어 연결 문자를 사용한 페이로드입니다.',
        'payloads' => ['; ls', '&& ls', '| ls', '; id', '&& id', '| id']
    ],
    'advanced' => [
        'title' => '🔍 Advanced Command Injection',
        'description' => '시스템 정보를 수집하는 고급 페이로드입니다.',
        'payloads' => ['; cat /etc/passwd', '&& ps aux', '| netstat -an']
    ],
    'blind' => [
        'title' => '👁️ Blind Command Injection',
        'description' => '출력을 직접 볼 수 없을 때 사용하는 블라인드 인젝션 페이로드입니다.',
        'payloads' => ['; sleep 5', '&& ping -c 4 127.0.0.1', '| curl http://example.com']
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 검증:</strong> 사용자 입력을 철저히 검증하고 화이트리스트 방식 사용",
    "<strong>이스케이프 처리:</strong> 셸 메타문자를 적절히 이스케이프 (e.g., `escapeshellarg()`, `escapeshellcmd()`)",
    "<strong>API 함수 사용:</strong> 직접 시스템 명령어 대신 언어별 API 함수 사용",
    "<strong>최소 권한 원칙:</strong> 웹 서버를 최소한의 권한으로 실행",
    "<strong>샌드박스 환경:</strong> 명령어 실행을 제한된 환경에서 수행"
];

// 4. 참고 자료 정의
$references = [
    "PayloadsAllTheThings - Command Injection" => "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection",
    "OWASP - Command Injection" => "https://owasp.org/www-community/attacks/Command_Injection",
    "PortSwigger - OS Command Injection" => "https://portswigger.net/web-security/os-command-injection"
];

// 5. 테스트 폼 UI 정의
$command = htmlspecialchars($_POST["payload"] ?? '');
$test_form_ui = <<<HTML
<div class="info-box" style="background: #fff3cd; border-color: #ffeeba; color: #856404;">
    <h3>✅ 테스트 가능한 안전한 명령어</h3>
    <p>이 페이지에서는 다음 명령어만 안전하게 테스트할 수 있습니다: <code>ping 127.0.0.1</code>, <code>date</code>, <code>whoami</code>, <code>pwd</code></p>
</div>
<form method="post" class="test-form">
    <h3>🧪 Command Injection 테스트</h3>
    <label for="payload">명령어 입력:</label>
    <textarea name="payload" id="payload" placeholder="예: ping 127.0.0.1; ls">{$command}</textarea>
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">명령어 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $command = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    $sanitized_command = preg_replace('/[;&|`$(){}\[\]]/', '', $command);
    $safe_commands = ['ping', 'date', 'whoami', 'pwd'];
    
    $is_safe = false;
    foreach ($safe_commands as $safe_cmd) {
        if ($sanitized_command !== null && strpos($sanitized_command, $safe_cmd) !== false) {
            $is_safe = true;
            break;
        }
    }

    if ($is_safe && $sanitized_command === $command) {
        // 실제 명령어 실행
        $output = [];
        $return_var = 0;
        
        // 안전한 명령어만 실행
        exec($command . ' 2>&1', $output, $return_var);
        
        if ($return_var === 0) {
            $result = "<pre>" . htmlspecialchars(implode("\n", $output)) . "</pre>";
        } else {
            $result = "<div class=\"error-box\">명령어 실행 실패 (종료 코드: $return_var)<br>";
            $result .= "<pre>" . htmlspecialchars(implode("\n", $output)) . "</pre></div>";
        }
    } else {
        $result = "<div class=\"error-box\">⚠️ 보안 위험: 입력된 명령어에 위험한 문자가 포함되어 있습니다.<br>";
        $result .= "원본: " . htmlspecialchars($command ?? '') . "<br>";
        $result .= "필터링 후: " . htmlspecialchars($sanitized_command ?? '') . "<br>";
        $result .= "이러한 문자들은 Command Injection 공격에 사용될 수 있습니다: ; & | ` $ ( ) { } [ ] < ></div>";
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Command_Injection_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>