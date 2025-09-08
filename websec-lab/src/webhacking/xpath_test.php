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
            "' or 1=1 or ",
            "'] | //user[position()=1] | //user['"
        ]
    ],
    'blind' => [
        'title' => '블라인드 주입 페이로드',
        'description' => '응답을 직접 볼 수 없을 때, 참/거짓 조건으로 정보를 추출합니다.',
        'payloads' => [
            'string-length(//user[1]/password)>5',
            'substring(//user[1]/password,1,1)=\'a\'',
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
    "<strong>입력 검증:</strong> XPath 메타문자 (`'`,`\"`,`[`, `]`, `(`, `)`, `/`) 필터링",
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

    $result .= "<div class='vulnerable-output'>";
    $result .= "<h4>🚨 취약한 XPath 실행 결과</h4>";
    $result .= "<p><strong>실행된 쿼리:</strong> " . htmlspecialchars($xpath_input) . "</p>";
    
    // 실제 XPath Injection 공격 실행 (교육 목적)
    try {
        $dom = new DOMDocument();
        $dom->loadXML($sample_xml);
        $xpath = new DOMXPath($dom);
        
        // 취약한 XPath 쿼리 실행 (사용자 입력을 직접 사용)
        $nodes = $xpath->query($xpath_input);
        
        if ($nodes !== false) {
            $result .= "<p><strong>쿼리 실행 성공!</strong> 매칭된 노드 수: {$nodes->length}개</p>";
            
            // 공격 패턴 분석
            if (strpos($xpath_input, "' or '1'='1") !== false || strpos($xpath_input, "or 1=1") !== false) {
                $result .= "<p class='danger'>🔥 <strong>인증 우회 공격 감지!</strong> 모든 사용자 정보에 접근 가능</p>";
            } elseif (strpos($xpath_input, '//*') !== false || strpos($xpath_input, '//text()') !== false) {
                $result .= "<p class='danger'>🔥 <strong>전체 데이터 추출 공격!</strong> XML 전체 구조 노출</p>";
            } elseif (strpos($xpath_input, '//user/password') !== false) {
                $result .= "<p class='danger'>🔥 <strong>패스워드 추출 공격!</strong> 모든 사용자 비밀번호 노출</p>";
            } elseif (strpos($xpath_input, 'string-length') !== false || strpos($xpath_input, 'substring') !== false) {
                $result .= "<p class='warning'>⚠️ <strong>블라인드 인젝션 시도!</strong> 데이터 길이/문자 추출 시도</p>";
            }
            
            // 결과 표시 (민감한 정보 포함)
            if ($nodes->length > 0) {
                $result .= "<p><strong>매칭된 노드들:</strong></p>";
                $result_data = "";
                foreach ($nodes as $i => $node) {
                    if ($i < 10) { // 최대 10개 표시
                        $node_info = "";
                        if ($node->nodeType === XML_ELEMENT_NODE) {
                            $node_info = "{$node->nodeName}: " . trim($node->textContent);
                            if ($node->hasAttributes()) {
                                $attrs = [];
                                foreach ($node->attributes as $attr) {
                                    $attrs[] = "{$attr->name}='{$attr->value}'";
                                }
                                $node_info .= " [" . implode(', ', $attrs) . "]";
                            }
                        } else {
                            $node_info = "텍스트: " . trim($node->textContent);
                        }
                        $result_data .= "- {$node_info}\n";
                    }
                }
                if ($nodes->length > 10) {
                    $result_data .= "... (추가 " . ($nodes->length - 10) . "개 노드 생략)\n";
                }
                $result .= "<pre class='attack-result'>" . htmlspecialchars($result_data) . "</pre>";
                
                // 민감한 데이터 노출 경고
                if (strpos($result_data, 'password') !== false) {
                    $result .= "<p class='danger'>🔥 <strong>민감한 정보 노출!</strong> 패스워드가 평문으로 노출되었습니다.</p>";
                }
            }
            
        } else {
            $result .= "<p class='error'>❌ XPath 쿼리 실행 실패</p>";
        }
        
    } catch (Exception $e) {
        $result .= "<p class='error'>❌ XPath 실행 중 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
        $result .= "<p class='warning'>⚠️ 잘못된 XPath 문법이거나 공격 시도가 차단되었습니다.</p>";
    }
    
    $result .= "</div>";
    
    // 안전한 구현 비교
    $result .= "<div class='safe-comparison'>";
    $result .= "<h4>✅ 안전한 XPath 쿼리 구현</h4>";
    
    try {
        // 입력 검증 및 필터링
        $dangerous_patterns = ["'", '"', '[', ']', '(', ')', '//', '*', 'or', 'and', '|'];
        $contains_dangerous = false;
        
        foreach ($dangerous_patterns as $pattern) {
            if (stripos($xpath_input, $pattern) !== false) {
                $contains_dangerous = true;
                break;
            }
        }
        
        if ($contains_dangerous) {
            $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 위험한 XPath 패턴이 감지되어 쿼리가 거부되었습니다.</p>";
            $result .= "<p><strong>감지된 위험 요소:</strong> " . htmlspecialchars(implode(', ', array_filter($dangerous_patterns, function($p) use ($xpath_input) { 
                return stripos($xpath_input, $p) !== false; 
            }))) . "</p>";
        } else {
            // 안전한 쿼리 실행 (화이트리스트 기반)
            $safe_patterns = ['/^\/\/user\[\@id=\'\d+\'\]$/', '/^\/\/user\/username$/', '/^\/\/user\/email$/'];
            $is_safe_query = false;
            
            foreach ($safe_patterns as $pattern) {
                if (preg_match($pattern, $xpath_input)) {
                    $is_safe_query = true;
                    break;
                }
            }
            
            if ($is_safe_query) {
                $result .= "<p class='success'>✅ <strong>안전한 쿼리:</strong> 허용된 XPath 패턴입니다.</p>";
                
                // 제한된 안전한 실행
                $dom = new DOMDocument();
                $dom->loadXML($sample_xml);
                $xpath = new DOMXPath($dom);
                $safe_nodes = $xpath->query($xpath_input);
                
                if ($safe_nodes && $safe_nodes->length > 0) {
                    $safe_result = "";
                    foreach ($safe_nodes as $node) {
                        // 민감한 정보 필터링 (패스워드 제외)
                        if ($node->nodeName !== 'password') {
                            $safe_result .= "- {$node->nodeName}: " . htmlspecialchars($node->textContent) . "\n";
                        }
                    }
                    $result .= "<pre class='safe-result'>{$safe_result}</pre>";
                }
            } else {
                $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 허용된 쿼리 패턴이 아닙니다.</p>";
            }
        }
        
    } catch (Exception $e) {
        $result .= "<p class='success'>🛡️ 안전한 처리 중: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    $result .= "</div>";
    
    // 보안 권장사항
    $result .= "<div class='security-recommendations'>";
    $result .= "<h4>🔒 XPath Injection 방어 권장사항</h4>";
    $result .= "<ul>";
    $result .= "<li><strong>입력 검증:</strong> XPath 메타문자 (<code>'</code>, <code>\"</code>, <code>[</code>, <code>]</code>, <code>/</code>) 필터링</li>";
    $result .= "<li><strong>매개변수화:</strong> XPath 변수를 사용한 안전한 쿼리 구성</li>";
    $result .= "<li><strong>화이트리스트:</strong> 허용된 XPath 패턴만 실행</li>";
    $result .= "<li><strong>이스케이프 처리:</strong> 특수 문자를 적절히 이스케이프</li>";
    $result .= "<li><strong>최소 권한:</strong> XML 데이터 접근 권한 최소화</li>";
    $result .= "<li><strong>민감정보 보호:</strong> 패스워드 등 민감한 노드 접근 제한</li>";
    $result .= "</ul>";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "XPath_Injection_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>