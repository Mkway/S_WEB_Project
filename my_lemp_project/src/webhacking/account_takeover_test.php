<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Account Takeover';
$description = '<p><strong>계정 탈취</strong>는 공격자가 합법적인 사용자 계정에 무단으로 접근하는 것을 의미합니다. 이는 약한 비밀번호 재설정 메커니즘, 세션 예측, 또는 기타 인증 우회 시나리오를 시뮬레이션합니다.</p>
<p>이 페이지에서는 약한 비밀번호 재설정 코드를 이용한 계정 탈취 시나리오를 시뮬레이션합니다.</p>
<p><strong>시뮬레이션 계정:</strong> `testuser` (재설정 코드: `123456`), `admin` (재설정 코드: `654321`)</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 계정 탈취 시뮬레이션',
        'description' => '아래 폼을 사용하여 계정 탈취 시나리오를 시뮬레이션합니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>강력한 비밀번호 정책:</strong> 복잡성, 길이, 주기적 변경을 강제합니다.",
    "<strong>다단계 인증 (MFA):</strong> 비밀번호 외 추가 인증 수단을 요구합니다.",
    "<strong>비밀번호 재설정 보안 강화:</strong> 예측 불가능한 일회성 토큰 사용, 재설정 시 기존 세션 무효화, 재설정 후 사용자에게 알림.",
    "<strong>세션 관리 강화:</strong> 예측 불가능한 세션 ID 사용, 짧은 세션 만료 시간, 비활동 시 세션 무효화.",
    "<strong>크리덴셜 스터핑 방어:</strong> 봇 탐지, CAPTCHA, IP 기반 속도 제한.",
    "<strong>로그인 시도 모니터링 및 알림:</strong> 비정상적인 로그인 시도 감지 시 사용자에게 알림.",
    "<strong>계정 잠금 정책:</strong> 일정 횟수 이상 로그인 실패 시 계정 잠금."
];

// 4. 참고 자료 정의
$references = [
    "OWASP Top 10 2021 - A07: Identification and Authentication Failures" => "https://owasp.org/www-project-top-10/2021/A07_2021-Identification_and_Authentication_Failures",
    "PortSwigger - Account takeover" => "https://portswigger.net/web-security/account-takeover"
];

// 5. 테스트 폼 UI 정의
$username_input = htmlspecialchars($_POST['username'] ?? '');
$reset_code_input = htmlspecialchars($_POST['reset_code'] ?? '');
$new_password_input = htmlspecialchars($_POST['new_password'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 계정 탈취 시뮬레이션</h3>
    <label for="username">사용자 이름:</label>
    <input type="text" id="username" name="username" value="{$username_input}" required>
    
    <label for="reset_code">재설정 코드 (취약한 코드):</label>
    <input type="text" id="reset_code" name="reset_code" value="{$reset_code_input}" placeholder="예: 123456" required>
    
    <label for="new_password">새 비밀번호 (실제로는 사용되지 않음):</label>
    <input type="password" id="new_password" name="new_password" value="{$new_password_input}" placeholder="새 비밀번호" required>
    
    <br><br>
    <button type="submit" name="action" value="perform_takeover" class="btn" style="background: #dc3545;">계정 탈취 시도</button>
    <button type="submit" name="action" value="request_reset" class="btn" style="background: #6c757d;">재설정 코드 요청 (시뮬레이션)</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $result = '';
    $error = '';
    $username = $form_data['username'] ?? '';
    $reset_code = $form_data['reset_code'] ?? '';
    $action = $form_data['action'] ?? '';

    // 시연을 위한 가상의 사용자 데이터
    $users = [
        'testuser' => [
            'password' => password_hash('password123', PASSWORD_DEFAULT),
            'reset_code' => '123456' // 매우 취약한 고정 재설정 코드
        ],
        'admin' => [
            'password' => password_hash('adminpass', PASSWORD_DEFAULT),
            'reset_code' => '654321'
        ]
    ];

    if ($action === 'request_reset') {
        if (isset($users[$username])) {
            $result = "{$username}님에게 재설정 코드가 발송되었습니다 (시뮬레이션).";
        } else {
            $error = "사용자 {$username}을(를) 찾을 수 없습니다.";
        }
    } elseif ($action === 'perform_takeover') {
        if (isset($users[$username])) {
            if ($users[$username]['reset_code'] === $reset_code) {
                $result = "사용자 {$username}의 비밀번호가 성공적으로 재설정되었습니다 (시뮬레이션). 계정 탈취 성공!";
            } else {
                $error = "잘못된 재설정 코드입니다.";
            }
        } else {
            $error = "사용자 {$username}을(를) 찾을 수 없습니다.";
        }
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
