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
$page_title = 'External Variable Modification';
$description = '<p><strong>External Variable Modification</strong>은 공격자가 HTTP 헤더, 쿠키, 환경 변수 등 애플리케이션 외부에서 주입되는 변수들을 조작하여 애플리케이션의 동작을 변경하거나 권한을 상승시키는 취약점입니다.</p>
<p>이 페이지에서는 HTTP 헤더 `X-User-Role`을 통해 사용자 역할을 설정하는 취약한 시나리오를 시뮬레이션합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 외부 변수 조작 시뮬레이션',
        'description' => '현재 페이지는 HTTP 요청 헤더 `X-User-Role`의 값에 따라 사용자 역할을 결정합니다. 프록시 도구(예: Burp Suite)를 사용하여 요청 헤더에 `X-User-Role: admin`을 추가한 후 아래 버튼을 클릭해보세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>신뢰할 수 없는 소스 검증:</strong> HTTP 헤더, 쿠키 등 클라이언트 측에서 전송되는 모든 외부 변수는 신뢰할 수 없으므로, 서버 측에서 철저히 검증하고 필터링해야 합니다.",
    "<strong>서버 측에서 중요한 값 관리:</strong> 사용자 역할, 권한 등 보안에 중요한 정보는 서버 측 세션이나 데이터베이스에서 관리하고, 클라이언트 측에서 전송된 값을 직접 사용하지 않습니다.",
    "<strong>화이트리스트 방식 사용:</strong> 허용된 값만 허용하고, 그 외의 모든 입력은 거부합니다.",
    "<strong>최소 권한 원칙:</strong> 애플리케이션이 외부 변수를 통해 접근할 수 있는 권한을 최소화합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - HTTP Parameter Pollution (관련)" => "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
    "PortSwigger - Access control vulnerabilities (관련)" => "https://portswigger.net/web-security/access-control"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 외부 변수 조작 시뮬레이션</h3>
    <p>현재 페이지는 HTTP 요청 헤더 <code>X-User-Role</code>의 값에 따라 사용자 역할을 결정합니다.</p>
    <p>프록시 도구(예: Burp Suite)를 사용하여 요청 헤더에 <code>X-User-Role: admin</code>을 추가한 후 아래 버튼을 클릭해보세요.</p>
    <br>
    <button type="submit" name="action" value="check_role" class="btn" style="background: #dc3545;">역할 확인</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $result = '';
    $error = '';
    $user_role = 'guest'; // 기본 역할

    // 시뮬레이션: HTTP 헤더를 통해 사용자 역할을 설정 (취약한 방식)
    if (isset($_SERVER['HTTP_X_USER_ROLE'])) {
        $user_role = $_SERVER['HTTP_X_USER_ROLE'];
    }

    if (($form_data['action'] ?? '') === 'check_role') {
        $result = "현재 사용자 역할: <strong>" . htmlspecialchars($user_role) . "</strong><br>";
        $result .= "HTTP 헤더 <code>X-User-Role</code>을 조작하여 역할을 변경해보세요. (예: <code>X-User-Role: admin</code>)";
        
        if ($user_role === 'admin') {
            $result .= "<br><span style=\"color: red; font-weight: bold;\">관리자 권한 획득 시뮬레이션 성공!</span>";
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