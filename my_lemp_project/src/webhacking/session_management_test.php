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

// --- 세션 고정 취약점 시뮬레이션 --- //
// 공격자가 미리 알고 있는 세션 ID를 URL을 통해 강제
if (isset($_GET['PHPSESSID'])) {
    if (session_id() !== $_GET['PHPSESSID']) {
        session_destroy();
        session_id($_GET['PHPSESSID']);
        session_start();
    }
}

// 1. 페이지 설정
$page_title = 'Session Management';
$description = '<p>안전하지 않은 세션 관리는 인증 우회, 권한 상승 등 심각한 보안 문제로 이어질 수 있습니다.</p>
<p>이 페이지에서는 대표적인 세션 공격인 <strong>세션 고정</strong>과 <strong>세션 하이재킹</strong>을 시뮬레이션합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'fixation' => [
        'title' => '🧪 시나리오 1: 세션 고정 (Session Fixation)',
        'description' => '공격자가 미리 알고 있는 세션 ID를 사용자에게 전달하고, 사용자가 그 세션 ID로 로그인하게 하여 해당 세션을 탈취하는 공격입니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ],
    'hijacking' => [
        'title' => '🧪 시나리오 2: 세션 하이재킹 (Session Hijacking)',
        'description' => 'XSS 취약점이나 네트워크 스니핑 등을 통해 사용자의 세션 ID를 탈취하여 해당 사용자로 위장하는 공격입니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>로그인 성공 시 `session_regenerate_id(true)` 호출:</strong> 세션 고정 공격을 방어하기 위해 로그인 시 항상 새로운 세션 ID를 발급합니다.",
    "<strong>HttpOnly 플래그 사용:</strong> 쿠키에 HttpOnly 플래그를 설정하여 JavaScript가 쿠키에 접근하는 것을 막습니다. (XSS를 통한 하이재킹 방어)",
    "<strong>Secure 플래그 사용 및 HTTPS 적용:</strong> 쿠키에 Secure 플래그를 설정하고 모든 통신을 HTTPS로 암호화하여 네트워크 스니핑을 통한 하이재킹을 방어합니다.",
    "<strong>세션 타임아웃 설정:</strong> 일정 시간 활동이 없으면 세션을 자동으로 만료시켜 탈취된 세션의 유효 시간을 최소화합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Session Management Cheat Sheet" => "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "PortSwigger - Session fixation" => "https://portswigger.net/web-security/session-management/session-fixation"
];

// 5. 테스트 폼 UI 정의
$login_message = '';
$current_session_id = session_id();

$test_form_ui = <<<HTML
<div class="info-box">
    <p><strong>현재 세션 ID:</strong> <code>{$current_session_id}</code></p>
    <p><strong>공격 시뮬레이션:</strong></p>
    <ol>
        <li>아래 '공격용 링크 생성' 버튼을 클릭하여 공격자가 만든 링크를 확인합니다.</li>
        <li>생성된 링크를 새 탭에서 열면, 세션 ID가 공격자의 ID로 고정됩니다.</li>
        <li>그 상태에서 아래 폼으로 로그인을 시도합니다.</li>
        <li>로그인 후에도 세션 ID가 바뀌지 않으므로, 공격자는 원래의 세션 ID로 로그인된 세션을 탈취할 수 있습니다.</li>
    </ol>
    <button class="btn" onclick="generateAttackLink()">공격용 링크 생성</button>
    <p id="attack-link-p" style="display:none;"><strong>생성된 링크:</strong> <a id="attack-link" href=""></a></p>

    <form method="post" style="margin-top: 20px;">
        <h4>로그인 시뮬레이션</h4>
        <input type="text" name="username" placeholder="사용자 이름 (e.g., testuser)" required>
        <button type="submit" class="btn">로그인 (취약한 방식)</button>
    </form>
    <p style="color:green; margin-top:10px;"><strong>로그인 상태:</strong> {$_SESSION['test_user'] ?? '로그아웃됨'}</p>
    <a href="?action=logout" class="btn">로그아웃</a>
</div>

<div class="info-box">
    <h3>세션 하이재킹 설명</h3>
    <p>XSS 취약점이나 네트워크 스니핑 등을 통해 사용자의 세션 ID를 탈취하여 해당 사용자로 위장하는 공격입니다.</p>
    <p>예를 들어, XSS 공격으로 <code>alert(document.cookie)</code> 스크립트를 실행시키면 현재 사용자의 쿠키(세션 ID 포함)가 노출될 수 있습니다.</p>
    <p><strong>현재 세션 쿠키 값 (시뮬레이션):</strong> <code>PHPSESSID={$current_session_id}; ...</code></p>
</div>

<script>
    function generateAttackLink() {
        const attackSessionId = 'attack_session_id_' + Math.random().toString(36).substr(2, 9);
        const url = window.location.pathname + '?PHPSESSID=' + attackSessionId;
        const linkElement = document.getElementById('attack-link');
        linkElement.href = url;
        linkElement.textContent = window.location.origin + url;
        document.getElementById('attack-link-p').style.display = 'block';
    }
</script>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $login_message = '';
    if (isset($form_data['username'])) {
        // 취약한 로직: 로그인 성공 후 세션 ID를 재발급하지 않음
        // session_regenerate_id(true);
        
        $_SESSION['test_user'] = $form_data['username'];
        $login_message = htmlspecialchars($form_data['username']) . '님으로 로그인되었습니다. (취약한 방식)';
    }

    // 로그아웃 처리
    if (isset($_GET['action']) && $_GET['action'] === 'logout') {
        unset($_SESSION['test_user']);
        $login_message = '로그아웃되었습니다.';
    }

    return ['result' => $login_message, 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();