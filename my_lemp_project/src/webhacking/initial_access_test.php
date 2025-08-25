<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Initial Access';
$description = '<p><strong>Initial Access</strong>는 공격자가 시스템이나 네트워크에 처음으로 발판을 마련하는 단계입니다. 이는 약한 자격 증명, 공개된 관리 인터페이스, 알려진 취약점 악용, 피싱 등 다양한 방법으로 발생할 수 있습니다.</p>
<p>이 페이지에서는 약한 기본 자격 증명을 통한 초기 접근 시나리오를 시뮬레이션합니다.</p>
<p><strong>시뮬레이션 계정:</strong> `admin` / `password`</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 초기 접근 시뮬레이션 (약한 자격 증명)',
        'description' => '아래 입력 필드에 약한 기본 자격 증명을 입력하여 관리자 계정에 접근해보세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>강력한 자격 증명 정책:</strong> 기본 자격 증명을 사용하지 않고, 복잡하고 유추하기 어려운 비밀번호를 강제합니다.",
    "<strong>다단계 인증 (MFA):</strong> 모든 계정에 MFA를 적용하여 자격 증명 탈취 시에도 계정 접근을 어렵게 합니다.",
    "<strong>공개된 관리 인터페이스 제한:</strong> 관리자 페이지나 민감한 서비스는 외부에서 직접 접근할 수 없도록 IP 화이트리스트, VPN, 방화벽 등으로 접근을 제한합니다.",
    "<strong>취약점 관리:</strong> 소프트웨어 및 시스템의 알려진 취약점을 정기적으로 스캔하고 패치합니다.",
    "<strong>로그인 시도 모니터링:</strong> 비정상적인 로그인 시도나 무차별 대입 공격을 탐지하고 차단하는 시스템을 구축합니다."
];

// 4. 참고 자료 정의
$references = [
    "MITRE ATT&CK - Initial Access" => "https://attack.mitre.org/tactics/TA0001/",
    "OWASP Top 10 2021 - A07: Identification and Authentication Failures (관련)" => "https://owasp.org/www-project-top-10/2021/A07_2021-Identification_and_Authentication_Failures"
];

// 5. 테스트 폼 UI 정의
$username_input = htmlspecialchars($_POST['username'] ?? '');
$password_input = htmlspecialchars($_POST['password'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 초기 접근 시뮬레이션 (약한 자격 증명)</h3>
    <p>아래 입력 필드에 약한 기본 자격 증명을 입력하여 관리자 계정에 접근해보세요.</p>
    <label for="username">사용자 이름:</label>
    <input type="text" id="username" name="username" value="{$username_input}" required>
    
    <label for="password">비밀번호:</label>
    <input type="password" id="password" name="password" value="{$password_input}" required>
    
    <br><br>
    <button type="submit" name="action" value="attempt_login" class="btn" style="background: #dc3545;">로그인 시도</button>
</form>
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
    $default_admin_pass = 'password'; // 매우 약한 기본 비밀번호

    if ($action === 'attempt_login') {
        if ($username === $default_admin_user && $password === $default_admin_pass) {
            $result = "<span style=\"color: red; font-weight: bold;\">초기 접근 성공!</span><br>";
            $result .= "약한 기본 자격 증명(<code>{$default_admin_user}</code>/<code>{$default_admin_pass}</code>)을 통해 관리자 계정에 접근했습니다.";
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