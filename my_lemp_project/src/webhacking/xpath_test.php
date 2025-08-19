<?php
require_once 'TestPage.php';

// 샘플 XML 데이터 (시뮬레이션용)
$sample_xml = '<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user id="1">
        <username>admin</username>
        <password>admin123</password>
        <role>administrator</role>
        <email>admin@example.com</email>
    </user>
    <user id="2">
        <username>user1</username>
        <password>user123</password>
        <role>user</role>
        <email>user1@example.com</email>
    </user>
    <user id="3">
        <username>guest</username>
        <password>guest</password>
        <role>guest</role>
        <email>guest@example.com</email>
    </user>
</users>';

// 1. 페이지 설정
$page_title = 'XPath Injection';
$description = '<p><strong>XPath Injection</strong>은 XPath 표현식에서 사용자 입력을 적절히 검증하지 않을 때 발생하는 취약점입니다.</p>
<p>XML 데이터의 전체 구조 노출, 인증 우회, 민감한 정보 추출이 가능합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'auth_bypass' => [
        'title' => '인증 우회 페이로드',
        'description' => '인증 과정을 우회하여 접근 권한을 획득합니다.',
        'payloads' => [
            "' or '1'='1",
            "' or 1=1 or '",
            "'] | //user[position()=1] | //user['"
        ]
    ],
    'blind' => [
        'title' => '블라인드 주입 페이로드',
        'description' => '응답을 직접 볼 수 없을 때, 참/거짓 조건으로 정보를 추출합니다.',
        'payloads' => [
            'string-length(//user[1]/password)>5',
            'substring(//user[1]/password,1,1)='a'',
            'count(//user)=3'
        ]
    ],
    'extraction' => [
        'title' => '데이터 추출 페이로드',
        'description' => 'XML 문서에서 민감한 데이터를 추출합니다.',
        'payloads' => [
            '//*',
            '//user/password',
            '//text()'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 검증:</strong> XPath 메타문자 (`'`,`"`,`[`, `]`, `(`, `)`, `/`) 필터링",
    "<strong>매개변수화:</strong> XPath 변수를 사용한 쿼리 구성 (예: `DOMXPath::evaluate()`의 두 번째 인자)",
    "<strong>화이트리스트:</strong> 허용된 문자와 패턴만 허용",
    "<strong>이스케이프 처리:</strong> 특수 문자를 적절히 이스케이프",
    "<strong>최소 권한:</strong> XML 문서 접근 권한 최소화"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - XPath Injection" => "https://owasp.org/www-community/attacks/XPath_Injection",
    "PortSwigger - XPath injection" => "https://portswigger.net/web-security/xpath-injection"
];

// 5. 테스트 폼 UI 정의
$xpath_input = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<div class="info-box" style="background: #f8f9fa; border-color: #dee2e6;">
    <h4>📄 테스트용 XML 데이터 구조:</h4>
    <pre><code>{$sample_xml}</code></pre>
</div>

<form method="post" class="test-form">
    <h3>🧪 XPath 쿼리 테스트</h3>
    <label for="payload">🎯 XPath 쿼리 입력:</label><br>
    <input type="text" id="payload" name="payload" value="{$xpath_input}" placeholder="예: //user[username='admin']">
    <br><br>
    <button type="submit" class="btn">XPath 쿼리 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($sample_xml) {
    $xpath_input = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($xpath_input)) {
        $error = "XPath 쿼리를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    try {
        $dom = new DOMDocument();
        $dom->loadXML($sample_xml);
        $xpath = new DOMXPath($dom);
        
        // --- 취약점 발생 지점 --- (사용자 입력을 직접 XPath 쿼리에 사용)
        $nodes = $xpath->query($xpath_input);
        
        $response_sim = "[시뮬레이션] XPath 쿼리 결과\n";
        $response_sim .= "쿼리: " . htmlspecialchars($xpath_input) . "\n";
        $response_sim .= "결과 노드 수: " . $nodes->length . "\n\n";
        
        if ($nodes->length > 0) {
            $response_sim .= "매칭된 노드:\n";
            foreach ($nodes as $i => $node) {
                if ($i < 5) { // 최대 5개만 표시
                    $response_sim .= "- " . $node->nodeName . ": " . $node->textContent . "\n";
                }
            }
            if ($nodes->length > 5) {
                $response_sim .= "... (더 많은 결과 생략)\n";
            }
        } else {
            $response_sim .= "매칭된 노드가 없습니다.\n";
        }

    } catch (Exception $e) {
        $error = "XPath 쿼리 처리 중 오류 발생: " . $e->getMessage() . "\n올바른 XPath 문법을 사용해주세요.";
    }

    return ['result' => "<pre>{$response_sim}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>