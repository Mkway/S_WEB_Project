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
$page_title = 'DNS Rebinding';
$description = '<p><strong>DNS Rebinding</strong>은 공격자가 제어하는 도메인의 DNS 레코드를 조작하여, 동일 출처 정책(Same-Origin Policy)을 우회하고 내부 네트워크 자원에 접근하는 공격 기법입니다.</p>
<p>브라우저가 처음에는 공격자 서버의 IP를 받았다가, 짧은 TTL(Time-To-Live) 이후 내부 IP 주소로 재바인딩되도록 하여 내부망 공격을 가능하게 합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 DNS Rebinding 시뮬레이션',
        'description' => '아래 입력 필드에 공격자가 사용할 가상의 도메인을 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [
            'attacker.com',
            'evil.com',
            'phishing.net'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>내부 IP 주소로의 요청 차단:</strong> 웹 서버나 애플리케이션에서 HTTP Host 헤더를 검증하여 내부 IP 주소로의 요청을 차단합니다.",
    "<strong>DNS 응답 검증:</strong> 애플리케이션이 DNS 쿼리를 수행할 때, 응답으로 받은 IP 주소가 내부 IP 대역에 속하는지 확인하고 차단합니다.",
    "<strong>방화벽 규칙 강화:</strong> 내부 네트워크에서 외부로의 불필요한 연결을 제한하고, 외부에서 내부로의 접근을 엄격하게 통제합니다.",
    "<strong>동일 출처 정책 강화:</strong> 웹 애플리케이션에서 CORS(Cross-Origin Resource Sharing) 정책을 엄격하게 설정하여 신뢰할 수 있는 도메인만 리소스에 접근하도록 합니다."
];

// 4. 참고 자료 정의
$references = [
    "PortSwigger - DNS rebinding" => "https://portswigger.net/web-security/dns-rebinding",
    "OWASP - DNS Rebinding" => "https://owasp.org/www-community/attacks/DNS_Rebinding"
];

// 5. 테스트 폼 UI 정의
$target_url_input = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 DNS Rebinding 시뮬레이션</h3>
    <p>아래 입력 필드에 공격자가 사용할 가상의 도메인을 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="payload">공격자 제어 도메인 (가상):</label>
    <input type="text" id="payload" name="payload" value="{$target_url_input}" placeholder="예: attacker.com" required>
    <br><br>
    <button type="submit" name="action" value="simulate_dns_rebinding" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $target_url = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($target_url)) {
        $error = "도메인을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $result = "DNS Rebinding 공격 시뮬레이션이 시작되었습니다.<br>";
    $result .= "공격자는 <code>" . htmlspecialchars($target_url) . "</code>과 같은 도메인을 사용하여 DNS 응답을 조작합니다.<br>";
    $result .= "첫 번째 DNS 쿼리에서는 공격자 서버의 IP를 반환하고, TTL이 짧게 설정됩니다.<br>";
    $result .= "두 번째 DNS 쿼리에서는 내부 네트워크의 IP 주소(예: 192.168.1.1)를 반환하여 동일 출처 정책을 우회합니다.<br>";
    $result .= "이후 브라우저는 내부 IP 주소에 대한 요청을 동일 출처로 간주하여 내부 자원에 접근할 수 있게 됩니다.<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 DNS Rebinding 공격을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "DNS_Rebinding_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();