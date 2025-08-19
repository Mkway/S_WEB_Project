
<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'LDAP Injection';
$description = '<p><strong>LDAP (Lightweight Directory Access Protocol) Injection</strong>은 LDAP 쿼리에서 사용자 입력을 적절히 검증하지 않을 때 발생하는 취약점입니다.</p>
<p>인증 우회, 디렉토리 정보 노출, 권한 상승이 가능합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'auth_bypass' => [
        'title' => '인증 우회 페이로드',
        'description' => '인증 과정을 우회하여 접근 권한을 획득합니다.',
        'payloads' => [
            '*)(uid=*',
            '*)(cn=*',
            '*))%00'
        ]
    ],
    'blind' => [
        'title' => '블라인드 주입 페이로드',
        'description' => '응답을 직접 볼 수 없을 때, 참/거짓 조건으로 정보를 추출합니다.',
        'payloads' => [
            '*)(objectClass=*',
            '*)(description=*',
            '(cn=admin*)'
        ]
    ],
    'enumeration' => [
        'title' => '정보 열거 페이로드',
        'description' => 'LDAP 디렉토리의 사용자, 그룹 등 정보를 열거합니다.',
        'payloads' => [
            'objectClass=*',
            'cn=admin*', 
            'uid=*',
            '(objectClass=groupOfNames)'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 검증:</strong> LDAP 메타문자 (`*`, `(`, `)`, `\`, `/`, `|`, `&`, `!`, `=`, `<`, `>`, `~`) 필터링",
    "<strong>이스케이프 처리:</strong> 특수 문자를 적절히 이스케이프 (예: `ldap_escape()` 함수 사용)",
    "<strong>화이트리스트:</strong> 허용된 문자와 패턴만 허용",
    "<strong>최소 권한:</strong> LDAP 서비스 계정 권한 최소화",
    "<strong>로깅 및 모니터링:</strong> 비정상적인 LDAP 쿼리 패턴 감지"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - LDAP Injection" => "https://owasp.org/www-community/attacks/LDAP_Injection",
    "PortSwigger - LDAP injection" => "https://portswigger.net/web-security/ldap-injection"
];

// 5. 테스트 폼 UI 정의
$ldap_input = htmlspecialchars($_POST['payload'] ?? '');
$query_type = htmlspecialchars($_POST['query_type'] ?? 'search');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #e3f2fd; border-color: #2196f3;">
    <h4>📖 LDAP 쿼리 구조</h4>
    <p><strong>기본 구조:</strong> <code>(attribute=value)</code></p>
    <p><strong>논리 연산자:</strong> <code>&</code> (AND), <code>|</code> (OR), <code>!</code> (NOT)</p>
    <p><strong>와일드카드:</strong> <code>*</code></p>
</div>

<form method="post" class="test-form">
    <h3>🧪 LDAP 쿼리 테스트</h3>
    <label for="query_type">🔍 LDAP 작업 유형:</label><br>
    <select id="query_type" name="query_type">
        <option value="search" {$query_type === 'search' ? 'selected' : ''}>Search (검색)</option>
        <option value="bind" {$query_type === 'bind' ? 'selected' : ''}>Bind (인증)</option>
        <option value="modify" {$query_type === 'modify' ? 'selected' : ''}>Modify (수정)</option>
    </select><br><br>
    
    <label for="payload">🎯 LDAP 쿼리 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="LDAP 쿼리를 입력하세요... 예: (uid=testuser)">{$ldap_input}</textarea><br><br>
    <button type="submit" class="btn">LDAP 쿼리 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $ldap_input = $form_data['payload'] ?? '';
    $query_type = $form_data['query_type'] ?? 'search';
    $result = '';
    $error = '';

    if (empty($ldap_input)) {
        $error = "LDAP 쿼리를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] LDAP Injection 공격 분석\n";
    $response_sim .= "쿼리 유형: " . strtoupper($query_type) . "\n";
    $response_sim .= "입력 쿼리: " . htmlspecialchars($ldap_input) . "\n\n";

    // 위험한 패턴 검사
    $dangerous_patterns = [
        'metacharacters' => ['*', '(', ')', '\\', '/', '|', '&', '!', '=', '<', '>', '~'],
        'auth_bypass' => ['*)(uid=*', '*)(cn=*'],
        'blind' => ['*)(objectClass=*'],
        'enumeration' => ['objectClass=*', 'cn=admin*']
    ];

    $payload_detected = false;
    $detected_patterns = [];
    $attack_type = '';

    foreach ($dangerous_patterns as $type => $patterns) {
        foreach ($patterns as $pattern) {
            if (stripos($ldap_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
                $attack_type = $type;
                break 2;
            }
        }
    }

    if ($payload_detected) {
        $response_sim .= "🚨 공격 감지됨!\n";
        $response_sim .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n";
        $response_sim .= "예상 공격 유형: " . $attack_type . "\n\n";
        $response_sim .= "이러한 패턴들은 인증 우회, 정보 노출, 권한 상승 등에 사용될 수 있습니다.\n";
        $response_sim .= "실제 환경에서는 심각한 보안 문제를 야기할 수 있습니다.";
    } else {
        $response_sim .= "✅ 안전한 LDAP 쿼리입니다.\n";
        $response_sim .= "위험한 패턴이 감지되지 않았습니다.\n";
        $response_sim .= "쿼리가 정상적으로 처리될 것으로 예상됩니다.";
    }

    return ['result' => "<pre>{"$response_sim"}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

