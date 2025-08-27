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
$page_title = 'Reverse Proxy Misconfigurations';
$description = '<p><strong>Reverse Proxy Misconfigurations</strong>는 리버스 프록시(예: Nginx, Apache)가 잘못 설정되어 내부 서비스나 민감한 정보가 외부에 노출되거나, 보안 제어가 우회되는 취약점입니다.</p>
<p>이는 잘못된 경로 설정, 불필요한 헤더 노출, 내부 IP 주소 노출 등으로 발생할 수 있습니다.</p>
<p>이 페이지에서는 리버스 프록시 설정 오류의 개념과 원리를 시뮬레이션합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 리버스 프록시 설정 오류 시뮬레이션',
        'description' => '아래 입력 필드에 공격자가 직접 접근을 시도할 가상의 내부 경로를 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>경로 및 접근 제어 강화:</strong> 리버스 프록시 설정에서 내부 서비스나 민감한 경로에 대한 외부 접근을 엄격히 제한하고, 필요한 경우 인증 및 권한 부여를 적용합니다.",
    "<strong>불필요한 헤더 제거:</strong> `Server`, `X-Powered-By` 등 서버 정보를 노출하는 헤더를 제거하거나 일반적인 값으로 변경합니다.",
    "<strong>내부 IP 주소 노출 방지:</strong> 에러 페이지나 리다이렉션 시 내부 IP 주소가 노출되지 않도록 설정합니다.",
    "<strong>정기적인 설정 감사:</strong> 리버스 프록시 설정을 정기적으로 검토하고, 보안 모범 사례에 따라 업데이트합니다.",
    "<strong>웹 애플리케이션 방화벽 (WAF) 사용:</strong> WAF를 통해 비정상적인 요청을 탐지하고 차단합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Reverse Proxy Bypass" => "https://owasp.org/www-community/attacks/Reverse_Proxy_Bypass",
    "PortSwigger - Host header attacks (관련)" => "https://portswigger.net/web-security/host-header"
];

// 5. 테스트 폼 UI 정의
$internal_path = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 리버스 프록시 설정 오류 시뮬레이션</h3>
    <p>아래 입력 필드에 공격자가 직접 접근을 시도할 가상의 내부 경로를 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="payload">가상의 내부 경로:</label>
    <input type="text" id="payload" name="payload" value="{$internal_path}" placeholder="예: /admin, /internal-api, /.git" required>
    <br><br>
    <button type="submit" name="action" value="simulate_misconfig" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $internal_path = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($internal_path)) {
        $error = "내부 경로를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $result = "리버스 프록시 설정 오류 시뮬레이션이 시작되었습니다.<br>";
    $result .= "공격자는 <code>" . htmlspecialchars($internal_path) . "</code>와 같은 내부 경로를 직접 요청하여 리버스 프록시의 잘못된 설정을 악용할 수 있습니다.<br>";
    $result .= "예: <code>/admin</code>, <code>/internal-api</code>, <code>/.git</code> 등<br>";
    $result .= "만약 리버스 프록시가 이러한 내부 경로를 적절히 차단하지 못하면, 공격자는 민감한 정보에 접근하거나 내부 시스템을 조작할 수 있습니다.<br><br>";
    $result .= "<strong>참고:</strong> 이 시뮬레이션은 실제 리버스 프록시를 조작하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();