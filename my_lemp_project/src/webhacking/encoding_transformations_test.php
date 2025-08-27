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
$page_title = 'Encoding Transformations';
$description = '<p><strong>Encoding Transformations 취약점</strong>은 문자 인코딩 변환 과정에서 입력 검증 필터를 우회하여 악성 코드를 실행하는 취약점입니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'basic_xss' => [
        'title' => '기본 XSS',
        'description' => '가장 기본적인 XSS 페이로드입니다.',
        'payloads' => [
            '<script>alert("XSS")</script>',
            '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E', // URL Encoded
            '%253Cscript%253Ealert%2528%2522XSS%2522%2529%253C%252Fscript%253E' // Double URL Encoded
        ]
    ],
    'html_entity_xss' => [
        'title' => 'HTML 엔티티 XSS',
        'description' => 'HTML 엔티티로 변환된 XSS 페이로드입니다.',
        'payloads' => [
            '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
            '&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;' // Numeric Entities
        ]
    ],
    'sqli' => [
        'title' => 'SQL Injection',
        'description' => '인코딩된 SQL Injection 페이로드입니다.',
        'payloads' => [
            '\' OR 1=1 --',
            '%27%20OR%201%3D1%20--' // URL Encoded
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>정규화 후 검증 (Decode-then-Validate):</strong> 모든 인코딩을 디코딩한 후 검증을 수행합니다.",
    "<strong>화이트리스트 기반 입력 검증:</strong> 허용된 문자만 허용하고, 그 외의 모든 입력은 거부합니다.",
    "<strong>출력 시점 이스케이핑:</strong> 데이터를 HTML, JavaScript, CSS 등 각 컨텍스트에 맞게 적절히 이스케이프합니다.",
    "<strong>Content-Type 헤더 명시:</strong> 올바른 문자셋을 포함한 `Content-Type` 헤더를 명시합니다.",
    "<strong>입력 길이 및 형식 제한:</strong> 입력 필드의 길이를 제한하고 예상되는 형식에 맞는지 검증합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Encoding Transformations" => "https://owasp.org/www-community/attacks/Encoding_Transformations",
    "PortSwigger - Encoding attacks" => "https://portswigger.net/web-security/encoding"
];

// 5. 테스트 폼 UI 정의
$input_text = htmlspecialchars($_POST['payload'] ?? '<script>alert("XSS")</script>');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 인코딩 변환 테스트</h3>
    <label for="payload">입력 텍스트:</label>
    <textarea name="payload" id="payload" placeholder="인코딩할 텍스트를 입력하세요">{$input_text}</textarea>
    <br><br>
    <button type="submit" class="btn">인코딩 변환 및 검증</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $input = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($input)) {
        $error = "입력 텍스트를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] 인코딩 변환 및 검증 분석\n";
    $response_sim .= "원본 입력: " . htmlspecialchars($input) . "\n\n";

    // 다중 디코딩 시뮬레이션
    $decoded_input = $input;
    for ($i = 0; $i < 3; $i++) {
        $previous = $decoded_input;
        $decoded_input = urldecode($decoded_input);
        $decoded_input = html_entity_decode($decoded_input, ENT_QUOTES, 'UTF-8');
        if ($previous === $decoded_input) {
            break;
        }
    }

    $response_sim .= "디코딩 후 입력: " . htmlspecialchars($decoded_input) . "\n\n";

    // 기본적인 XSS 및 SQLi 패턴 검증
    $xss_patterns = ['/<script/i', '/on\w+=/i', '/javascript:/i'];
    $sqli_patterns = ['/union\s+select/i', '/or\s+1=1/i'];

    $is_xss = false;
    foreach ($xss_patterns as $pattern) {
        if (preg_match($pattern, $decoded_input)) {
            $is_xss = true;
            break;
        }
    }

    $is_sqli = false;
    foreach ($sqli_patterns as $pattern) {
        if (preg_match($pattern, $decoded_input)) {
            $is_sqli = true;
            break;
        }
    }

    if ($is_xss || $is_sqli) {
        $response_sim .= "🚨 위험한 패턴 감지됨!\n";
        if ($is_xss) $response_sim .= "- XSS 공격 패턴\n";
        if ($is_sqli) $response_sim .= "- SQL Injection 공격 패턴\n";
        $response_sim .= "인코딩 변환을 통해 필터를 우회하려 시도할 수 있습니다.\n";
    } else {
        $response_sim .= "✅ 안전한 입력으로 판단됩니다.\n";
        $response_sim .= "위험한 패턴이 감지되지 않았습니다.\n";
    }

    return ['result' => "<pre>{"$response_sim"}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

