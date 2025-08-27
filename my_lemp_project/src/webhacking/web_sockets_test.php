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
$page_title = 'Web Sockets Vulnerabilities';
$description = '<p><strong>Web Sockets Vulnerabilities</strong>는 웹 소켓 통신(`ws://` 또는 `wss://`)에서 발생할 수 있는 취약점입니다. 웹 소켓은 클라이언트와 서버 간의 양방향 통신을 가능하게 하지만, 부적절하게 구현될 경우 다양한 보안 문제를 야기할 수 있습니다.</p>
<p>이는 인증/권한 부여 부족, 메시지 주입, XSS, CSRF, 정보 유출 등으로 이어질 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 웹 소켓 공격 시뮬레이션',
        'description' => '아래 입력 필드에 웹 소켓을 통해 전송할 가상의 메시지를 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>인증 및 권한 부여:</strong> 웹 소켓 연결 및 메시지에 대해 강력한 인증 및 권한 부여를 적용합니다.",
    "<strong>입력 값 검증:</strong> 웹 소켓을 통해 수신되는 모든 메시지에 대해 서버 측에서 철저한 입력 값 검증을 수행합니다.",
    "<strong>Origin 헤더 검증:</strong> 웹 소켓 연결 시 `Origin` 헤더를 검증하여 신뢰할 수 있는 도메인에서만 연결을 허용합니다.",
    "<strong>메시지 암호화:</strong> 민감한 정보는 `wss://` (WebSocket Secure)를 사용하여 암호화된 통신을 보장합니다.",
    "<strong>세션 관리:</strong> 웹 소켓 세션도 HTTP 세션과 동일하게 안전하게 관리합니다.",
    "<strong>로깅 및 모니터링:</strong> 웹 소켓 통신을 로깅하고 비정상적인 활동을 모니터링합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - WebSockets Security" => "https://owasp.org/www-community/attacks/WebSockets_Security",
    "PortSwigger - WebSockets" => "https://portswigger.net/web-security/websockets"
];

// 5. 테스트 폼 UI 정의
$message_to_send = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 웹 소켓 공격 시뮬레이션</h3>
    <p>아래 입력 필드에 웹 소켓을 통해 전송할 가상의 메시지를 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="payload">전송할 메시지:</label>
    <textarea id="payload" name="payload" placeholder="예: {'action': 'admin_command', 'cmd': 'rm -rf /'}" required>{$message_to_send}</textarea>
    <br><br>
    <button type="submit" name="action" value="simulate_websocket_attack" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $message_to_send = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($message_to_send)) {
        $error = "메시지를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $result = "Web Socket 취약점 시뮬레이션이 시작되었습니다.<br>";
    $result .= "전송 시도 메시지: <code>" . htmlspecialchars($message_to_send) . "</code><br>";
    $result .= "<br>만약 웹 소켓 서버가 메시지에 대한 적절한 인증/권한 검증 없이 처리한다면, 공격자는 임의의 메시지를 주입하여 다른 사용자에게 영향을 주거나, 서버의 기능을 오용할 수 있습니다.";
    $result .= "<br>또한, 웹 소켓 통신이 암호화되지 않거나(ws://), 메시지 내용에 대한 검증이 부족하면 정보 유출이나 XSS 등의 공격으로 이어질 수 있습니다.";
    $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 웹 소켓 통신을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
