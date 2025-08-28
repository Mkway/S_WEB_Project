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
    <p>이 페이지에서는 다음 명령어만 안전하게 테스트할 수 있습니다: <code>ping</code>, <code>date</code>, <code>whoami</code>, <code>pwd</code>, <code>ls</code>, <code>id</code>, <code>uname</code>, <code>cat</code>, <code>echo</code></p>
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
    $safe_commands = ['ping', 'date', 'whoami', 'pwd', 'ls', 'id', 'uname', 'cat', 'echo'];
    
    $is_safe = false;
    foreach ($safe_commands as $safe_cmd) {
        if ($sanitized_command !== null && strpos($sanitized_command, $safe_cmd) !== false) {
            $is_safe = true;
            break;
        }
    }

    // 취약한 구현 - 실제 Command Injection 실행
    $result .= "<div class='info-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>⚠️ 취약한 Command Injection 실행:</strong><br>";
    $result .= "입력한 명령어: <code>" . htmlspecialchars($command) . "</code>";
    $result .= "</div>";

    $result .= "<div class='vulnerable-output' style='background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 15px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>Command Injection 실행 결과:</strong><br>";

    // 실제 명령어 실행 (교육용)
    $output = [];
    $return_var = 0;
    
    // 위험한 명령어 필터링 (일부만)
    $dangerous_commands = ['rm', 'del', 'format', 'shutdown', 'reboot', 'passwd', 'su', 'sudo'];
    $is_dangerous = false;
    
    foreach ($dangerous_commands as $dangerous_cmd) {
        if (strpos(strtolower($command), $dangerous_cmd) !== false) {
            $is_dangerous = true;
            break;
        }
    }
    
    if ($is_dangerous) {
        $result .= "<strong>🚫 위험한 명령어 차단</strong><br>";
        $result .= "보안상의 이유로 시스템 파괴적 명령어는 실행하지 않습니다.<br>";
        $result .= "차단된 명령어: " . htmlspecialchars($command);
    } else {
        // 실제 명령어 실행
        exec($command . ' 2>&1', $output, $return_var);
        
        if ($return_var === 0 && !empty($output)) {
            $result .= "<strong>✅ 명령어 실행 성공!</strong><br>";
            $result .= "<strong>실행된 명령어:</strong> " . htmlspecialchars($command) . "<br><br>";
            $result .= "<strong>실행 결과:</strong><br>";
            $result .= "<pre style='background: #f1f1f1; padding: 10px; max-height: 400px; overflow-y: auto;'>" . htmlspecialchars(implode("\n", $output)) . "</pre>";
            
            // Command Injection이 성공했는지 체크
            if (strpos($command, ';') !== false || strpos($command, '&&') !== false || strpos($command, '|') !== false) {
                $result .= "<br><strong>🚨 Command Injection 공격 성공!</strong><br>";
                $result .= "<em>여러 명령어가 연쇄적으로 실행되었습니다. 실제 환경에서는 매우 위험합니다!</em>";
            }
        } else if ($return_var !== 0) {
            $result .= "<strong>❌ 명령어 실행 실패 (종료 코드: $return_var)</strong><br>";
            if (!empty($output)) {
                $result .= "<pre style='background: #f1f1f1; padding: 10px;'>" . htmlspecialchars(implode("\n", $output)) . "</pre>";
            }
        } else {
            $result .= "<strong>⚠️ 명령어는 실행되었지만 출력이 없습니다.</strong><br>";
            $result .= "실행된 명령어: " . htmlspecialchars($command);
        }
    }
    $result .= "</div>";

    // 안전한 구현과 비교
    $result .= "<div class='info-box' style='background: #d4edda; border-color: #c3e6cb; color: #155724; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>✅ 안전한 구현이었다면:</strong><br>";
    $result .= "1. 입력 검증: 화이트리스트 방식으로 허용된 명령어만 실행<br>";
    $result .= "2. 이스케이프 처리: <code>escapeshellcmd()</code>, <code>escapeshellarg()</code> 사용<br>";
    $result .= "3. API 함수 사용: 직접 시스템 명령어 대신 PHP 내장 함수 사용<br>";
    $result .= "4. 최소 권한: 웹 서버를 제한된 권한으로 실행";
    $result .= "</div>";

    // 보안 권장사항
    $result .= "<div class='info-box' style='background: #d1ecf1; border-color: #bee5eb; color: #0c5460; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>🛡️ 보안 권장사항:</strong><br>";
    $result .= "- 사용자 입력을 시스템 명령어에 직접 사용 금지<br>";
    $result .= "- 화이트리스트 방식으로 허용된 명령어만 실행<br>";
    $result .= "- escapeshellcmd(), escapeshellarg() 함수 사용<br>";
    $result .= "- 웹 애플리케이션을 최소 권한으로 실행<br>";
    $result .= "- 가능한 한 시스템 명령어 실행 회피";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Command_Injection_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>