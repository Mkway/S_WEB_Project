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

// 간소화된 OAuth 2.0 시뮬레이션 설정
$auth_server = 'http://localhost/webhacking/oauth_server_sim.php';
$client_id = 'my-client-id';
$client_secret = 'my-client-secret';
$redirect_uri = 'http://localhost/webhacking/oauth_test.php';

// 1. 페이지 설정
$page_title = 'OAuth 2.0 Misconfiguration';
$description = '<p>OAuth 2.0은 안전한 인증/인가 프로토콜이지만, 잘못 설정하면 심각한 취약점이 발생할 수 있습니다.</p>
<p>주요 취약점은 <strong>부적절한 `redirect_uri` 검증</strong>으로, 공격자가 인증 코드를 탈취하여 사용자 계정을 장악할 수 있습니다.</p>';

// 2. 페이로드 정의 (공격 시나리오 설명)
$payloads = [
    'redirect_uri_manipulation' => [
        'title' => '🎯 공격 시나리오: Redirect URI 조작',
        'description' => '만약 인증 서버가 `redirect_uri`를 제대로 검증하지 않는다면, 공격자는 `redirect_uri`를 자신의 서버 주소로 변경하여 인증 코드를 탈취할 수 있습니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>`redirect_uri` 완전 일치 검증:</strong> 인증 서버는 사전에 등록된 `redirect_uri`와 요청 시의 `redirect_uri`가 정확히 일치하는지 반드시 확인해야 합니다.",
    "<strong>State 파라미터 사용:</strong> CSRF 공격을 방지하기 위해 예측 불가능한 `state` 값을 생성하여 요청과 콜백에서 일치하는지 확인합니다.",
    "<strong>PKCE (Proof Key for Code Exchange) 사용:</strong> 모바일 앱 등 public 클라이언트에서 인증 코드 탈취 공격을 방어하기 위해 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OAuth.com - Redirect URIs" => "https://www.oauth.com/oauth2-servers/redirect-uris/",
    "PortSwigger - OAuth 2.0 authentication vulnerabilities" => "https://portswigger.net/web-security/oauth"
];

// 5. 테스트 폼 UI 정의
$info_message = '';
if (isset($_GET['code'])) {
    $code = htmlspecialchars($_GET['code']);
    $info_message = "인증 코드를 받았습니다: {$code}\n이제 이 코드를 사용하여 액세스 토큰을 요청합니다.";
}

// 공격 예시 URL 생성
$malicious_redirect = 'http://attacker.com/callback';
$attack_url = $auth_server . '?response_type=code&client_id=' . $client_id . '&redirect_uri=' . urlencode($malicious_redirect);

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 OAuth 2.0 인증 시작</h3>
    <p>아래 버튼을 클릭하여 OAuth 2.0 인증 프로세스를 시작합니다. 이 과정은 타사 서비스(여기서는 시뮬레이션된 서버)에 대한 접근을 허용하는 것처럼 작동합니다.</p>
    <a href="{$auth_server}?response_type=code&client_id={$client_id}&redirect_uri={$redirect_uri}" class="btn" style="background: #007bff;">인증 시작하기</a>
</form>

<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7;">
    <h4>공격 예시 URL:</h4>
    <p>만약 인증 서버가 `redirect_uri`를 제대로 검증하지 않는다면, 공격자는 `redirect_uri`를 자신의 서버 주소로 변경하여 인증 코드를 탈취할 수 있습니다.</p>
    <pre><code>{$attack_url}</code></pre>
    <p><small>사용자가 위 링크를 클릭하면, 인증 후 `attacker.com`으로 리디렉션되어 인증 코드가 유출됩니다.</small></p>
</div>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($info_message) {
    $result = '';
    $error = '';

    if (!empty($info_message)) {
        $result = "<h3>📊 진행 상황</h3><pre><code>" . htmlspecialchars($info_message) . "</code></pre>";
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>