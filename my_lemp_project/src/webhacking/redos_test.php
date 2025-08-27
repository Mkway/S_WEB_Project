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
$page_title = 'ReDoS (Regular Expression Denial of Service)';
$description = '<p><strong>ReDoS</strong>는 정규식의 백트래킹 특성을 악용하여 과도한 CPU 사용을 유발하는 공격입니다.</p>
<p>이는 서비스 거부(DoS) 공격으로 이어질 수 있으며, 애플리케이션의 응답성을 저하시키거나 서버를 다운시킬 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'email_redos' => [
        'title' => '이메일 ReDoS',
        'description' => '이메일 검증 정규식에서 백트래킹을 유발하는 입력입니다.',
        'payloads' => [
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!' // Example for vulnerable email regex
        ]
    ],
    'password_redos' => [
        'title' => '비밀번호 ReDoS',
        'description' => '복잡한 패스워드 정규식에서 catastrophic backtracking을 유발합니다.',
        'payloads' => [
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' // Example for vulnerable password regex
        ]
    ],
    'url_redos' => [
        'title' => 'URL ReDoS',
        'description' => 'URL 검증 정규식에서 exponential blowup을 유발합니다.',
        'payloads' => [
            'http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' // Example for vulnerable URL regex
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>원자 그룹 (?>...) 사용:</strong> 정규식 패턴에서 백트래킹을 방지하기 위해 원자 그룹을 사용합니다.",
    "<strong>소유 양화사 (possessive quantifier) 사용:</strong> `++`, `*+`, `?+`와 같은 소유 양화사를 사용하여 백트래킹을 방지합니다.",
    "<strong>입력 길이 제한:</strong> 정규식 검증 전에 입력 문자열의 길이를 제한하여 과도한 처리 시간을 방지합니다.",
    "<strong>정규식 실행 시간 제한:</strong> `set_time_limit()` 또는 `pcre.backtrack_limit` 등을 사용하여 정규식 실행 시간을 제한합니다.",
    "<strong>안전한 정규식 라이브러리 사용:</strong> ReDoS 방어 기능이 내장된 라이브러리를 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - ReDoS" => "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
    "PortSwigger - ReDoS" => "https://portswigger.net/web-security/redos"
];

// 5. 테스트 폼 UI 정의
$test_input_val = htmlspecialchars($_POST['payload'] ?? '');
$test_type_selected = htmlspecialchars($_POST['test_type'] ?? 'email');
$custom_pattern_val = htmlspecialchars($_POST['custom_pattern'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 정규식 성능 테스터</h3>
    <div class="form-group">
        <label for="test_type">테스트 유형:</label>
        <select name="test_type" id="test_type" onchange="toggleCustomPattern()">
            <option value="email" {$test_type_selected === 'email' ? 'selected' : ''}>이메일 검증</option>
            <option value="password" {$test_type_selected === 'password' ? 'selected' : ''}>비밀번호 검증</option>
            <option value="url" {$test_type_selected === 'url' ? 'selected' : ''}>URL 검증</option>
            <option value="custom" {$test_type_selected === 'custom' ? 'selected' : ''}>사용자 정의 정규식</option>
        </select>
    </div>
    
    <div class="form-group" id="custom_pattern_group" style="display: {$test_type_selected === 'custom' ? 'block' : 'none';}">
        <label for="custom_pattern">사용자 정의 정규식 패턴:</label>
        <input type="text" name="custom_pattern" id="custom_pattern" placeholder="/^(a+)+$/" value="{$custom_pattern_val}">
    </div>
    
    <div class="form-group">
        <label for="payload">테스트 입력:</label>
        <textarea name="payload" id="payload" rows="3" placeholder="테스트할 문자열을 입력하세요...">{$test_input_val}</textarea>
    </div>
    
    <button type="submit" class="btn">정규식 성능 테스트 실행</button>
</form>

<script>
    function toggleCustomPattern() {
        const testType = document.getElementById('test_type').value;
        const customGroup = document.getElementById('custom_pattern_group');
        
        if (testType === 'custom') {
            customGroup.style.display = 'block';
        } else {
            customGroup.style.display = 'none';
        }
    }
    document.addEventListener('DOMContentLoaded', function() {
        toggleCustomPattern();
    });
</script>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $result_html = '';
    $error = '';
    $test_type = $form_data['test_type'] ?? '';
    $test_input = $form_data['payload'] ?? '';
    $custom_pattern = $form_data['custom_pattern'] ?? '';

    if (empty($test_input)) {
        $error = "테스트할 문자열을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $pattern = '';
    switch ($test_type) {
        case 'email':
            $pattern = '/^([a-zA-Z0-9])+([a-zA-Z0-9._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9._-]+)+\.[a-zA-Z]{2,6}$/'; // 취약한 이메일 정규식
            break;
        case 'password':
            $pattern = '/^(?=.*[a-z])+(?=.*[A-Z])+(?=.*\d)+(?=.*[@$!%*?&])+[A-Za-z\d@$!%*?&]{8,}$/'; // 취약한 비밀번호 정규식
            break;
        case 'url':
            $pattern = '/^(https?:\/\/(([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})+([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*@)*(([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.)*[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.?|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(:[0-9]+)?(\/([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*(\/([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*)*(\?([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*)?(#([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*)?)?$/'; // 취약한 URL 정규식
            break;
        case 'custom':
            $pattern = $custom_pattern;
            break;
    }

    if (empty($pattern)) {
        $error = "정규식 패턴을 선택하거나 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $start_time = microtime(true);
    $result_match = @preg_match($pattern, $test_input);
    $end_time = microtime(true);
    $execution_time = ($end_time - $start_time) * 1000; // 밀리초

    $result_html .= "<h4>테스트 결과</h4>";
    $result_html .= "<p><strong>유형:</strong> " . htmlspecialchars($test_type) . "</p>";
    $result_html .= "<p><strong>입력:</strong> <code>" . htmlspecialchars($test_input) . "</code></p>";
    if ($test_type === 'custom') {
        $result_html .= "<p><strong>패턴:</strong> <code>" . htmlspecialchars($pattern) . "</code></p>";
    }
    $result_html .= "<p><strong>매칭 결과:</strong> " . ($result_match === 1 ? '✅ 매칭됨' : '❌ 매칭되지 않음') . "</p>";
    $result_html .= "<p><strong>실행 시간:</strong> " . number_format($execution_time, 2) . "ms</p>";

    if ($execution_time > 100) {
        $result_html .= "<p style=\"color:red; font-weight:bold;\">⚠️ ReDoS 위험! 실행 시간이 100ms를 초과했습니다.</p>";
    } elseif ($execution_time > 10) {
        $result_html .= "<p style=\"color:orange; font-weight:bold;\">⚠️ 성능 주의! 실행 시간이 비교적 깁니다.</p>";
    } else {
        $result_html .= "<p style=\"color:green; font-weight:bold;\">✅ 정상! 빠른 실행 시간입니다.</p>";
    }

    return ['result' => $result_html, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

