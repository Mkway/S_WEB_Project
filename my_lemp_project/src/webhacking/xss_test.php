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
$page_title = 'XSS (Cross-Site Scripting)';
$description = '<p><strong>XSS</strong>는 웹 애플리케이션에 악성 스크립트를 주입하여 다른 사용자의 브라우저에서 실행시키는 공격입니다.</p>
<p>이 페이지에서는 Reflected, Stored, DOM-based XSS를 안전한 환경에서 테스트할 수 있습니다.</p>
<p><strong>참고:</strong> 모든 출력은 안전하게 인코딩되어 실제 스크립트는 실행되지 않습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'reflected' => [
        'title' => '🔄 Reflected XSS Payloads',
        'description' => '사용자 입력이 즉시 응답에 반영되는 XSS 공격입니다.',
        'payloads' => [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(1)">',
            '<svg onload="alert(1)">',
            '"><script>alert(1)</script>',
            '\'-alert(1)-\'',
            'javascript:alert(1)',
        ]
    ],
    'stored' => [
        'title' => '💾 Stored XSS Payloads',
        'description' => '악성 스크립트가 서버에 저장되어 다른 사용자에게 영향을 주는 XSS 공격입니다.',
        'payloads' => [
            '<script>alert("Stored XSS")</script>',
            '<img src="x" onerror="alert(\'Stored\')">',
            '<svg/onload=alert(/Stored/)>'
        ]
    ],
    'dom' => [
        'title' => '🌐 DOM-based XSS Payloads',
        'description' => '클라이언트 측 JavaScript에서 DOM 조작을 통해 발생하는 XSS 공격입니다.',
        'payloads' => [
            'javascript:alert(1)',
            '#<img src=x onerror=alert(1)>',
            'data:text/html,<script>alert(1)</script>'
        ]
    ],
    'bypass' => [
        'title' => '🚫 Filter Bypass Payloads',
        'description' => 'XSS 필터를 우회하기 위한 다양한 인코딩 및 난독화 기법입니다.',
        'payloads' => [
            '<ScRiPt>alert(1)</ScRiPt>',
            '<script>al\u0065rt(1)</script>',
            '<svg><script>alert(1)</script></svg>'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>출력 인코딩:</strong> HTML, JavaScript, CSS, URL 컨텍스트에 적절한 인코딩 사용",
    "<strong>입력 검증:</strong> 사용자 입력을 서버 측에서 검증 및 필터링",
    "<strong>Content Security Policy (CSP):</strong> 스크립트 실행을 제한하는 헤더 설정",
    "<strong>HttpOnly 쿠키:</strong> JavaScript에서 쿠키 접근 차단",
    "<strong>템플릿 엔진 사용:</strong> 자동 이스케이프 기능이 있는 템플릿 엔진 활용"
];

// 4. 참고 자료 정의
$references = [
    "PayloadsAllTheThings - XSS Injection" => "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection",
    "OWASP - Cross-site Scripting (XSS)" => "https://owasp.org/www-community/attacks/xss/",
    "MDN - Content Security Policy" => "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
];

// 5. 테스트 폼 UI 정의
$test_type = htmlspecialchars($_POST['test_type'] ?? 'reflected');
$payload = htmlspecialchars($_POST['payload'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 XSS 페이로드 테스트</h3>
    
    <div class="test-type-selector">
        <label><input type="radio" name="test_type" value="reflected" {($test_type === 'reflected' ? 'checked' : '')}> Reflected XSS</label>
        <label><input type="radio" name="test_type" value="stored" {($test_type === 'stored' ? 'checked' : '')}> Stored XSS</label>
        <label><input type="radio" name="test_type" value="dom" {($test_type === 'dom' ? 'checked' : '')}> DOM-based XSS</label>
    </div>
    
    <label for="payload">XSS 페이로드:</label>
    <textarea name="payload" id="payload" placeholder="여기에 테스트할 XSS 페이로드를 입력하거나 위의 버튼을 클릭하세요">{$payload}</textarea>
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">테스트 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $payload = $form_data['payload'] ?? '';
    $test_type = $form_data['test_type'] ?? 'reflected';
    $safe_payload = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');
    $result = '';
    $output = '';

    switch ($test_type) {
        case 'reflected':
            $output = "입력값: " . $safe_payload;
            $result = "Reflected XSS 테스트가 실행되었습니다. htmlspecialchars()로 인해 스크립트가 무력화되었습니다.";
            break;
        case 'stored':
            $output = "저장될 데이터: " . $safe_payload;
            $result = "Stored XSS 테스트가 실행되었습니다. 실제로는 데이터베이스에 저장되지 않으며, 저장 시에도 적절한 인코딩이 적용됩니다.";
            break;
        case 'dom':
            $output = "DOM 조작 시뮬레이션: " . $safe_payload;
            $result = "DOM-based XSS 테스트가 실행되었습니다. 서버 측에서 안전하게 처리되었습니다.";
            break;
        default:
            $result = "알 수 없는 테스트 유형입니다.";
    }
    
    $vulnerable_output = "<br><br><strong>만약 취약했다면 출력:</strong><br><code>" . htmlspecialchars($payload) . "</code><br><em>이 코드는 시연용이며 실제 실행되지 않습니다.</em>";

    return ['result' => $result . $vulnerable_output, 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>