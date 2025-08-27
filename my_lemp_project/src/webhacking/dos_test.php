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
$page_title = 'DoS (Denial of Service)';
$description = '<p><strong>DoS (Denial of Service)</strong> 공격은 서버의 자원(CPU, 메모리, 네트워크 대역폭 등)을 고갈시켜 정상적인 서비스 제공을 방해하는 공격입니다.</p>
<p>이 페이지에서는 서버에 과도한 연산을 유도하여 CPU 자원을 소모시키는 DoS 공격을 시뮬레이션합니다.</p>
<p><strong>주의:</strong> 반복 횟수를 너무 높게 설정하면 실제 서비스에 영향을 줄 수 있으니 주의하세요.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 DoS 시뮬레이션 (CPU 소모)',
        'description' => '아래 반복 횟수를 설정하여 서버의 CPU 자원을 소모시키는 연산을 실행합니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 값 검증 및 제한:</strong> 사용자 입력의 크기, 복잡성, 반복 횟수 등을 제한하여 과도한 리소스 소모를 방지합니다.",
    "<strong>속도 제한 (Rate Limiting):</strong> 특정 IP 주소나 사용자로부터의 요청 빈도를 제한하여 비정상적인 트래픽을 차단합니다.",
    "<strong>웹 애플리케이션 방화벽 (WAF):</strong> DoS 공격 패턴을 탐지하고 차단하는 WAF를 사용합니다.",
    "<strong>로드 밸런싱 및 오토 스케일링:</strong> 트래픽을 분산하고 필요에 따라 서버 자원을 자동으로 확장하여 공격에 대비합니다.",
    "<strong>CDN (Content Delivery Network) 사용:</strong> 정적 콘텐츠를 캐싱하고 분산하여 원본 서버의 부하를 줄입니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Denial of Service" => "https://owasp.org/www-community/attacks/Denial_of_Service",
    "PortSwigger - Denial of service" => "https://portswigger.net/web-security/dos"
];

// 5. 테스트 폼 UI 정의
$iterations = htmlspecialchars($_POST['payload'] ?? 1000000);
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 DoS 시뮬레이션 (CPU 소모)</h3>
    <p>아래 반복 횟수를 설정하여 서버의 CPU 자원을 소모시키는 연산을 실행합니다.</p>
    <label for="payload">반복 횟수:</label>
    <input type="number" id="payload" name="payload" value="{$iterations}" min="1000" step="1000" required>
    <br><br>
    <button type="submit" name="action" value="simulate_dos" class="btn" style="background: #dc3545;">DoS 시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $iterations = $form_data['payload'] ?? 1000000;
    $result = '';
    $error = '';

    if (!is_numeric($iterations) || $iterations < 1000) {
        $error = "반복 횟수는 1000 이상의 숫자여야 합니다.";
        return ['result' => $result, 'error' => $error];
    }

    $start_time = microtime(true);

    // 과도한 연산 시뮬레이션 (CPU 소모)
    for ($i = 0; $i < $iterations; $i++) {
        password_hash(uniqid(), PASSWORD_DEFAULT); // CPU 소모가 큰 연산
    }

    $end_time = microtime(true);
    $execution_time = round($end_time - $start_time, 4);

    $result = "DoS 공격 시뮬레이션이 실행되었습니다.<br>";
    $result .= "반복 횟수: " . number_format($iterations) . "회<br>";
    $result .= "실행 시간: " . $execution_time . "초<br>";
    $result .= "<br><strong>참고:</strong> 반복 횟수를 늘리면 서버의 CPU 사용량이 급증하여 서비스 응답이 느려지거나 중단될 수 있습니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();