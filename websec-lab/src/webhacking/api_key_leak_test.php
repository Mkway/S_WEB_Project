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
$page_title = 'API Key Leaks';
$description = '<p><strong>API Key Leaks</strong>는 API 키가 코드에 하드코딩되거나, 버전 관리 시스템에 포함되거나, 클라이언트 측 코드에 노출되어 공격자에게 유출되는 취약점입니다.</p>
<p>유출된 API 키는 서비스 오용, 데이터 접근, 비용 발생 등 심각한 보안 문제로 이어질 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 API 키 노출 시뮬레이션',
        'description' => '아래 버튼을 클릭하면, 개발자 도구(소스 보기)를 통해 코드에 하드코딩된 가상의 API 키가 노출되는 것을 확인할 수 있습니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>환경 변수 사용:</strong> API 키를 코드에 직접 하드코딩하지 않고 환경 변수나 외부 설정 파일을 통해 관리합니다.",
    "<strong>버전 관리 시스템 제외:</strong> `.gitignore` 등을 사용하여 API 키 파일이 버전 관리 시스템에 커밋되지 않도록 합니다.",
    "<strong>클라이언트 측 노출 방지:</strong> 클라이언트 측(프론트엔드) 코드에 민감한 API 키를 직접 포함하지 않습니다. 필요한 경우 백엔드 프록시를 통해 요청을 처리합니다.",
    "<strong>클라우드 서비스의 비밀 관리 도구 사용:</strong> AWS Secrets Manager, Azure Key Vault, Google Secret Manager 등 클라우드 제공자의 비밀 관리 서비스를 활용합니다.",
    "<strong>API 키 제한:</strong> API 키에 필요한 최소한의 권한만 부여하고, IP 주소 제한, HTTP 리퍼러 제한 등을 설정하여 오용을 방지합니다.",
    "<strong>정기적인 키 교체:</strong> API 키를 주기적으로 교체하여 유출 위험을 줄입니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP API Security Top 10 - API10: Insufficient Logging & Monitoring (관련)" => "https://owasp.org/org/project-api-security/api-security-top-10/#api10-insufficient-logging--monitoring",
    "PortSwigger - API keys" => "https://portswigger.net/web-security/api-security/api-keys"
];

// 5. 테스트 폼 UI 정의
$simulated_api_key = 'sk_test_thisisafakeapikey1234567890abcdef'; 
$exposed_key = htmlspecialchars($_POST['action'] ?? '') === 'reveal_key' ? htmlspecialchars($simulated_api_key) : '';

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 API 키 노출 시뮬레이션</h3>
    <p>아래 버튼을 클릭하면, 개발자 도구(소스 보기)를 통해 코드에 하드코딩된 가상의 API 키가 노출되는 것을 확인할 수 있습니다.</p>
    <button type="submit" name="action" value="reveal_key" class="btn" style="background: #dc3545;">API 키 노출 시도</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($simulated_api_key) {
    $result = '';
    $error = '';
    $exposed_key_display = '';

    if (($form_data['action'] ?? '') === 'reveal_key') {
        $exposed_key_display = "<div class=\"info-box\" style=\"background: #ffeeba; border-color: #ffdf7e; color: #856404; font-weight: bold; word-break: break-all;\"><h3>🚨 노출된 가상의 API 키:</h3><code>" . htmlspecialchars($simulated_api_key) . "</code><p><strong>경고:</strong> 이 키는 시연용이며, 실제 API 키는 절대 이렇게 노출되어서는 안 됩니다!</p></div>";
        $result = "가상의 API 키가 노출되었습니다. 실제 환경에서는 이 키를 사용하여 민감한 작업이 수행될 수 있습니다.";
    } else {
        $error = "알 수 없는 요청입니다.";
    }

    return ['result' => $result . $exposed_key_display, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "API_Key_Leak_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>