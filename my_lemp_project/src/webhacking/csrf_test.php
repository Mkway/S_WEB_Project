<?php
require_once 'TestPage.php';

// CSRF 토큰 생성 및 세션 관리
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// 1. 페이지 설정
$page_title = 'CSRF (Cross-Site Request Forgery)';
$description = '<p><strong>CSRF</strong>는 사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위를 특정 웹사이트에 요청하게 하는 공격입니다.</p>
<p>사용자가 로그인된 상태에서 악의적인 링크를 클릭하거나 조작된 페이지를 방문할 때 발생합니다.</p>';

// 2. 페이로드 정의 (시연용 코드 샘플)
$payloads = [
    'html_form' => [
        'title' => '📝 HTML Form Based CSRF',
        'description' => '일반적인 HTML 폼을 사용한 CSRF 공격입니다. 사용자가 버튼을 클릭하도록 유도합니다.',
        'payloads' => [
            '<form action="http://victim.com/change-password" method="POST">
<input type="hidden" name="password" value="hacked123">
<input type="submit" value="Click me!">
</form>'
        ]
    ],
    'auto_submit' => [
        'title' => '🤖 Auto Submit CSRF',
        'description' => 'JavaScript를 사용하여 페이지 로드 시 자동으로 폼을 제출하는 CSRF 공격입니다.',
        'payloads' => [
            '<body onload="document.forms[0].submit()">
<form action="http://victim.com/action" method="POST">...</form>
</body>'
        ]
    ],
    'get_csrf' => [
        'title' => '🔗 GET Based CSRF',
        'description' => 'GET 요청을 이용한 CSRF 공격입니다. 이미지나 링크를 통해 실행됩니다.',
        'payloads' => [
            '<img src="http://victim.com/delete?id=123" style="display:none">'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>CSRF 토큰:</strong> 각 폼에 고유하고 예측 불가능한 토큰 포함",
    "<strong>SameSite 쿠키:</strong> 쿠키의 SameSite 속성을 Strict 또는 Lax로 설정",
    "<strong>Referer/Origin 헤더 검증:</strong> 요청의 출처를 확인",
    "<strong>재인증 요구:</strong> 중요한 작업 시 비밀번호 재입력 요구"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Cross-Site Request Forgery" => "https://owasp.org/www-community/attacks/csrf",
    "PortSwigger - CSRF" => "https://portswigger.net/web-security/csrf"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<div class="info-box">
    <strong>현재 세션 CSRF 토큰:</strong><br>
    <code style="word-break: break-all;">{$csrf_token}</code>
</div>

<!-- 취약한 폼 시뮬레이션 -->
<div class="test-form" style="border-color: #ffc107;">
    <h3>⚠️ 취약한 폼 시뮬레이션 (CSRF 토큰 없음)</h3>
    <p>이 폼은 CSRF 토큰이 없어서 취약합니다. 실제로는 차단됩니다.</p>
    <form method="post">
        <input type="hidden" name="payload" value="no_token_form">
        <label>작업 선택:</label><br>
        <div class="action-buttons" style="margin-top:10px;">
            <button type="submit" name="action" value="change_password" class="btn" style="background: #dc3545;">비밀번호 변경</button>
        </div>
        <small>⚠️ CSRF 토큰이 없어서 모든 요청이 차단됩니다.</small>
    </form>
</div>

<!-- 안전한 폼 -->
<div class="test-form" style="border-color: #28a745;">
    <h3>✅ 안전한 폼 (CSRF 토큰 보호)</h3>
    <p>이 폼은 CSRF 토큰으로 보호되어 안전합니다.</p>
    <form method="post">
        <input type="hidden" name="payload" value="safe_form">
        <input type="hidden" name="csrf_token" value="{$csrf_token}">
        <label>작업 선택:</label><br>
        <div class="action-buttons" style="margin-top:10px;">
            <button type="submit" name="action" value="change_password" class="btn" style="background: #28a745;">비밀번호 변경</button>
        </div>
        <small>✅ CSRF 토큰으로 보호되어 안전합니다.</small>
    </form>
</div>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    global $csrf_token;
    $submitted_token = $form_data['csrf_token'] ?? '';
    $action = $form_data['action'] ?? 'N/A';
    $result = '';

    if (hash_equals($csrf_token, $submitted_token)) {
        $result = "<pre>✅ 요청이 안전하게 처리되었습니다.\n";
        $result .= "- 작업: " . htmlspecialchars($action) . "\n";
        $result .= "- CSRF 토큰이 올바르게 검증되었습니다.</pre>";
    } else {
        $result = "<pre>⚠️ CSRF 공격이 차단되었습니다!\n\n";
        $result .= "- 제출된 토큰: " . htmlspecialchars($submitted_token) . " (없거나 일치하지 않음)\n";
        $result .= "- 예상 토큰: " . htmlspecialchars($csrf_token) . "\n\n";
        $result .= "🛡️ CSRF 보호 메커니즘이 정상적으로 작동했습니다.</pre>";
    }
    return ['result' => $result, 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

