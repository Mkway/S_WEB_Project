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
$page_title = 'Web Cache Deception';
$description = '<p><strong>Web Cache Deception</strong>은 공격자가 웹 캐시(CDN, 리버스 프록시 등)를 속여 민감한 사용자 정보가 포함된 페이지를 공개적으로 접근 가능한 캐시에 저장하도록 유도하는 취약점입니다.</p>
<p>이는 주로 URL 경로 조작을 통해 발생하며, 캐싱 서버가 동적 콘텐츠를 정적 파일로 오인하여 캐싱할 때 발생합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 Web Cache Deception 시뮬레이션',
        'description' => '아래 버튼을 클릭하여 Web Cache Deception 공격을 시뮬레이션합니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>캐싱 정책 강화:</strong> 민감한 정보가 포함된 페이지는 캐싱하지 않도록 `Cache-Control: no-store, no-cache` 헤더를 설정합니다.",
    "<strong>URL 정규화:</strong> 캐싱 프록시가 URL을 정규화하도록 설정하여 `/profile/user.php/nonexistent.css`와 같은 비정상적인 경로를 동일한 리소스로 인식하도록 합니다.",
    "<strong>파일 확장자 기반 캐싱 지양:</strong> 파일 확장자만으로 캐싱 여부를 결정하지 않고, 콘텐츠 타입(`Content-Type`) 헤더를 기반으로 캐싱을 결정합니다.",
    "<strong>인증된 요청만 캐싱:</strong> 인증된 사용자로부터의 요청은 캐싱하지 않거나, 사용자별로 분리된 캐시를 사용합니다.",
    "<strong>웹 애플리케이션 방화벽 (WAF):</strong> Web Cache Deception 공격 패턴을 탐지하고 차단하는 WAF를 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "PortSwigger - Web cache deception" => "https://portswigger.net/web-security/web-cache-poisoning/web-cache-deception",
    "OWASP - Web Cache Deception" => "https://owasp.org/www-community/attacks/Web_Cache_Deception"
];

// 5. 테스트 폼 UI 정의
$user_profile_data = '사용자 ID: user123, 이메일: user@example.com, 민감한 정보: XXXXX';
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 Web Cache Deception 시뮬레이션</h3>
    <p>아래 버튼을 클릭하여 Web Cache Deception 공격을 시뮬레이션합니다.</p>
    <p><strong>공격 시나리오:</strong> 공격자는 로그인한 사용자에게 <code>https://example.com/profile/user.php/nonexistent.css</code>와 같은 URL을 클릭하도록 유도합니다. 서버는 <code>/profile/user.php</code>의 내용을 반환하지만, 캐싱 프록시는 <code>.css</code> 확장자 때문에 이를 캐싱하여 공격자가 나중에 해당 URL로 접근하여 캐시된 사용자 정보를 탈취할 수 있게 됩니다.</p>
    <br>
    <button type="submit" name="action" value="simulate_cache_deception" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($user_profile_data) {
    $result = '';
    $error = '';

    $result = "Web Cache Deception 시뮬레이션이 실행되었습니다.<br>";
    $result .= "공격자는 <code>/profile/user.php/nonexistent.css</code>와 같은 URL을 생성하여 사용자에게 클릭을 유도합니다.<br>";
    $result .= "웹 서버는 <code>/profile/user.php</code>의 내용을 반환하지만, 캐싱 프록시는 <code>.css</code> 확장자 때문에 이를 정적 파일로 오인하여 캐싱합니다.<br>";
    $result .= "이후 공격자는 <code>/profile/user.php/nonexistent.css</code>에 접근하여 캐시된 민감한 사용자 정보를 탈취할 수 있습니다.<br>";
    $result .= "<br><strong>시뮬레이션된 민감한 사용자 정보:</strong> <code>" . htmlspecialchars($user_profile_data) . "</code><br>";
    $result .= "<br><strong>참고:</strong> 이 시뮬레이션은 실제 캐싱을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();