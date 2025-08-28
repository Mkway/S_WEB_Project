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
    $payload_type = $form_data['payload'] ?? '';
    $result = '';

    // CSRF 취약점 실제 실행
    $result .= "<div class='info-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>⚠️ CSRF 취약점 테스트 실행:</strong><br>";
    $result .= "요청한 작업: <code>" . htmlspecialchars($action) . "</code><br>";
    $result .= "폼 유형: <code>" . htmlspecialchars($payload_type) . "</code><br>";
    $result .= "제출된 토큰: <code>" . htmlspecialchars($submitted_token ?: '(없음)') . "</code>";
    $result .= "</div>";

    if ($payload_type === 'no_token_form') {
        // 취약한 폼 - CSRF 토큰 없음
        $result .= "<div class='vulnerable-output' style='background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 15px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $result .= "<strong>취약한 CSRF 실행 결과:</strong><br>";
        
        if (empty($submitted_token)) {
            $result .= "<strong>🚨 CSRF 공격 성공!</strong><br>";
            $result .= "토큰 검증 없이 작업이 실행되었습니다!<br>";
            
            switch ($action) {
                case 'change_password':
                    $result .= "🎯 <strong>비밀번호가 변경되었습니다!</strong><br>";
                    $result .= "새 비밀번호: hacked123<br>";
                    $result .= "<em>공격자가 의도한 비밀번호로 변경되었습니다.</em><br>";
                    break;
                default:
                    $result .= "🎯 <strong>작업이 실행되었습니다!</strong><br>";
                    $result .= "<em>공격자가 의도한 작업이 수행되었습니다.</em><br>";
            }
            
            $result .= "<br><strong>⚠️ 경고:</strong> 이런 요청은 실제로 다음과 같이 발생할 수 있습니다:<br>";
            $result .= "1. 악성 웹사이트에서 숨겨진 폼 제출<br>";
            $result .= "2. 이메일의 악성 링크 클릭<br>";
            $result .= "3. 이미지 태그를 통한 GET 요청<br>";
            $result .= "4. JavaScript를 통한 자동 폼 제출";
        } else {
            $result .= "<strong>❌ 예상치 못한 토큰 발견</strong><br>";
            $result .= "취약한 폼임에도 토큰이 제출되었습니다.";
        }
        $result .= "</div>";
        
    } else if ($payload_type === 'safe_form') {
        // 안전한 폼 - CSRF 토큰 있음
        $result .= "<div class='vulnerable-output' style='background: #d4edda; border-color: #c3e6cb; color: #155724; padding: 15px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $result .= "<strong>안전한 CSRF 처리 결과:</strong><br>";
        
        if (hash_equals($csrf_token, $submitted_token)) {
            $result .= "<strong>✅ 정상 요청 처리 완료!</strong><br>";
            $result .= "CSRF 토큰이 올바르게 검증되었습니다.<br>";
            
            switch ($action) {
                case 'change_password':
                    $result .= "🔒 <strong>비밀번호 변경 완료</strong><br>";
                    $result .= "사용자가 의도한 비밀번호로 안전하게 변경되었습니다.";
                    break;
                default:
                    $result .= "🔒 <strong>요청 처리 완료</strong><br>";
                    $result .= "사용자가 의도한 작업이 안전하게 수행되었습니다.";
            }
        } else {
            $result .= "<strong>🛡️ CSRF 공격 차단!</strong><br>";
            $result .= "토큰 불일치로 인해 요청이 차단되었습니다.<br>";
            $result .= "예상 토큰: " . htmlspecialchars($csrf_token) . "<br>";
            $result .= "제출된 토큰: " . htmlspecialchars($submitted_token);
        }
        $result .= "</div>";
    }

    // CSRF 공격 시뮬레이션 예제
    $result .= "<div class='info-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>🎭 실제 CSRF 공격 시뮬레이션:</strong><br>";
    $current_url = $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $csrf_attack_html = "<form action=\"http://$current_url\" method=\"POST\">
    <input type=\"hidden\" name=\"payload\" value=\"no_token_form\">
    <input type=\"hidden\" name=\"action\" value=\"change_password\">
    <input type=\"submit\" value=\"무료 선물 받기!\">
</form>
<script>document.forms[0].submit();</script>";
    
    $result .= "악성 웹사이트에서 다음과 같은 코드를 실행할 수 있습니다:<br>";
    $result .= "<pre style='background: #f1f1f1; padding: 10px; font-size: 12px;'>" . htmlspecialchars($csrf_attack_html) . "</pre>";
    $result .= "</div>";

    // 보안 권장사항
    $result .= "<div class='info-box' style='background: #d1ecf1; border-color: #bee5eb; color: #0c5460; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result .= "<strong>🛡️ 보안 권장사항:</strong><br>";
    $result .= "- 모든 상태 변경 요청에 CSRF 토큰 적용<br>";
    $result .= "- SameSite 쿠키 속성 설정 (Strict/Lax)<br>";
    $result .= "- Referer/Origin 헤더 검증<br>";
    $result .= "- 중요한 작업 시 재인증 요구<br>";
    $result .= "- POST 방식 사용 (GET 요청 지양)";
    $result .= "</div>";

    return ['result' => $result, 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "CSRF_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

