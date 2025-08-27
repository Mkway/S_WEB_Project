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
$page_title = 'CRLF Injection';
$description = '<p><strong>CRLF Injection</strong>은 캐리지 리턴(CR, <code>%0d</code>)과 라인 피드(LF, <code>%0a</code>) 문자를 주입하여 HTTP 응답 헤더나 로그 파일 등을 조작하는 공격입니다.</p>
<p>이를 통해 HTTP 응답 분할(HTTP Response Splitting), 캐시 오염, 로그 변조 등의 공격이 가능해집니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'response_splitting' => [
        'title' => '🧪 HTTP Response Splitting 페이로드',
        'description' => 'HTTP 응답을 분할하여 악의적인 헤더나 본문을 삽입합니다.',
        'payloads' => [
            "Value%0d%0aSet-Cookie: injected_cookie=malicious",
            "Value%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 25%0d%0a%0d%0a<html>Injected</html>",
            "Value%0d%0aLocation: https://evil-site.com"
        ]
    ],
    'log_injection' => [
        'title' => '🧪 Log Injection 페이로드',
        'description' => '로그 파일에 가짜 항목을 주입하여 분석을 방해하거나 공격 흔적을 숨깁니다.',
        'payloads' => [
            "Normal Log%0d%0aATTACKER_LOG: Malicious activity detected",
            "Normal Log%0d%0a[INFO] User admin logged out.",
            "Normal Log%0d%0a127.0.0.1 - - [" . date('d/M/Y:H:i:s O') . "] \"GET /admin HTTP/1.1\" 401"
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>CRLF 문자 필터링:</strong> 사용자 입력에서 <code>%0d</code> (CR)와 <code>%0a</code> (LF) 문자를 제거하거나 인코딩합니다.",
    "<strong>안전한 API 사용:</strong> HTTP 헤더 설정 시, CRLF 문자를 자동으로 처리하거나 금지하는 내장 함수나 라이브러리를 사용합니다.",
    "<strong>로그 라이브러리 사용:</strong> 안전한 로깅을 위해 검증된 로그 라이브러리를 사용하고, 사용자 입력이 로그에 기록되기 전에 적절히 이스케이프 처리합니다.",
    "<strong>입력 값 검증:</strong> 모든 사용자 입력을 화이트리스트 방식으로 검증하여 예상된 문자만 허용합니다."
];

// 4. 참고 자료 정의
$references = [
    "PayloadsAllTheThings - CRLF Injection" => "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection",
    "OWASP - HTTP Response Splitting" => "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
    "PortSwigger - CRLF injection" => "https://portswigger.net/web-security/crlf-injection"
];

// 5. 테스트 폼 UI 정의
$input_header = htmlspecialchars($_POST['input_header'] ?? '');
$log_entry = htmlspecialchars($_POST['log_entry'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 HTTP Response Splitting 시뮬레이션</h3>
    <p>아래 입력 필드에 <code>%0d%0a</code> (CRLF)를 포함한 문자열을 입력하여 HTTP 응답 헤더를 조작해보세요.</p>
    <label for="input_header">주입할 헤더 값:</label>
    <textarea id="input_header" name="input_header" placeholder="예: Value%0d%0aSet-Cookie: injected_cookie=malicious">{$input_header}</textarea>
    <br><br>
    <button type="submit" name="action" value="http_response_splitting" class="btn" style="background: #dc3545;">HTTP 응답 분할 시도</button>
</form>

<form method="post" class="test-form">
    <h3>🧪 Log Injection 시뮬레이션</h3>
    <p>아래 입력 필드에 <code>%0d%0a</code> (CRLF)를 포함한 문자열을 입력하여 로그 파일을 조작해보세요.</p>
    <label for="log_entry">로그에 기록할 내용:</label>
    <textarea id="log_entry" name="log_entry" placeholder="예: 정상적인 로그%0d%0aATTACKER_LOG: Malicious activity detected">{$log_entry}</textarea>
    <br><br>
    <button type="submit" name="action" value="log_injection" class="btn" style="background: #dc3545;">로그 주입 시도</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $action = $form_data['action'] ?? '';
    $result = '';
    $error = '';

    if ($action === 'http_response_splitting') {
        $input_header = $form_data['input_header'] ?? '';
        // 실제 헤더 주입은 위험하므로 시뮬레이션 결과만 표시
        $result = "HTTP 응답 헤더에 사용자 입력이 반영되었습니다. (시뮬레이션)\n";
        $result .= "실제 상황이었다면, 브라우저 개발자 도구에서 다음과 같은 헤더가 추가되었을 것입니다:\n";
        $result .= "<code>X-User-Input: " . htmlspecialchars($input_header) . "</code>";
        if (strpos($input_header, "%0d%0a") !== false) {
            $result .= "<br><strong style=\"color:red;\">감지된 CRLF Injection!</strong> 헤더가 분할되었을 수 있습니다.";
        }
    } elseif ($action === 'log_injection') {
        $log_entry = $form_data['log_entry'] ?? '';
        $log_file = __DIR__ . '/logs/crlf_test.log';
        if (!file_exists(__DIR__ . '/logs')) mkdir(__DIR__ . '/logs');
        $timestamp = date('Y-m-d H:i:s');
        $log_message = "[{$timestamp}] User input: {$log_entry}\n";
        
        file_put_contents($log_file, $log_message, FILE_APPEND);
        
        $result = "로그 파일에 사용자 입력이 기록되었습니다: <code>" . htmlspecialchars($log_file) . "</code><br>";
        $result .= "기록된 내용: <pre>" . htmlspecialchars($log_message) . "</pre>";
        if (strpos($log_entry, "%0d%0a") !== false) {
            $result .= "<br><strong style=\"color:red;\">감지된 CRLF Injection!</strong> 로그 파일에 여러 줄이 삽입되었을 수 있습니다.";
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