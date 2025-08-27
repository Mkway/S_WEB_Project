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
$page_title = 'Insecure Management Interface';
$description = '<p><strong>Insecure Management Interface</strong>는 관리 인터페이스가 약한 인증, 기본 자격 증명, 또는 불필요한 노출로 인해 공격자에게 무단으로 접근될 수 있는 취약점입니다.</p>
<p>이는 시스템 설정 변경, 데이터 조작, 서비스 중단 등 심각한 보안 문제로 이어질 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 관리 인터페이스 접근 시뮬레이션',
        'description' => '아래 폼을 사용하여 관리 인터페이스에 접근을 시도합니다. 기본 자격 증명(admin/password)을 사용하거나, 노출된 관리자 패널에 직접 접근해보세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>강력한 인증:</strong> 관리 인터페이스에는 강력한 비밀번호 정책, 다단계 인증(MFA)을 적용합니다.",
    "<strong>접근 제한:</strong> 관리 인터페이스는 내부 네트워크에서만 접근 가능하도록 IP 화이트리스트, VPN, 방화벽 등으로 접근을 제한합니다.",
    "<strong>기본 자격 증명 변경:</strong> 모든 기본 자격 증명은 설치 후 즉시 변경하도록 강제합니다.",
    "<strong>로깅 및 모니터링:</strong> 관리 인터페이스에 대한 모든 접근 시도와 실패를 로깅하고, 비정상적인 활동을 모니터링합니다.",
    "<strong>불필요한 노출 방지:</strong> 관리 인터페이스의 URL을 예측하기 어렵게 하거나, 검색 엔진에 노출되지 않도록 `robots.txt` 등을 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Insecure Management Interface" => "https://owasp.org/www-community/attacks/Insecure_Management_Interface",
    "PortSwigger - Admin panel bypass" => "https://portswigger.net/web-security/authentication/admin-panel-bypass"
];

// 5. 테스트 폼 UI 정의
$username_input = htmlspecialchars($_POST['username'] ?? '');
$password_input = htmlspecialchars($_POST['password'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 관리 인터페이스 로그인 시뮬레이션</h3>
    <p><strong>기본 계정:</strong> <code>admin</code> / <code>password</code></p>
    <label for="username">사용자 이름:</label>
    <input type="text" name="username" id="username" value="{$username_input}" required>
    
    <label for="password">비밀번호:</label>
    <input type="password" name="password" id="password" value="{$password_input}" required>
    
    <br><br>
    <button type="submit" name="action" value="login" class="btn" style="background: #dc3545;">로그인 시도</button>
</form>

<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7; color: #856404;">
    <h3>💡 노출된 관리자 패널 시뮬레이션</h3>
    <p>실제 환경에서는 `admin` 또는 `dashboard`와 같은 예측 가능한 URL로 관리자 패널이 노출될 수 있습니다.</p>
    <p>아래 링크는 가상의 노출된 관리자 패널입니다. 클릭하여 접근을 시도해보세요.</p>
    <a href="#" onclick="alert('가상의 관리자 패널에 접근 시도. 실제 환경에서는 로그인 없이 접근되거나 기본 자격 증명으로 접근될 수 있습니다.'); return false;" class="btn" style="background: #007bff;">/admin_panel/dashboard</a>
</div>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $result = '';
    $error = '';
    $username = $form_data['username'] ?? '';
    $password = $form_data['password'] ?? '';
    $action = $form_data['action'] ?? '';

    // 시뮬레이션: 약한 기본 자격 증명
    $default_admin_user = 'admin';
    $default_admin_pass = 'password';

    if ($action === 'login') {
        if ($username === $default_admin_user && $password === $default_admin_pass) {
            $result = "<span style=\"color: red; font-weight: bold;\">관리 인터페이스 접근 성공!</span><br>";
            $result .= "약한 기본 자격 증명(<code>{$default_admin_user}</code>/<code>{$default_admin_pass}</code>)을 통해 관리자 패널에 접근했습니다.";
            $result .= "<br>실제 환경에서는 즉시 기본 자격 증명을 변경해야 합니다.";
        } else {
            $error = "로그인 실패: 잘못된 사용자 이름 또는 비밀번호입니다.";
        }
    } else {
        $error = "알 수 없는 요청입니다.";
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>