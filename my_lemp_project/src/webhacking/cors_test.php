<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'CORS Misconfiguration';
$description = '<p><strong>CORS (Cross-Origin Resource Sharing)</strong> 정책이 잘못 설정되어 있을 때 발생하는 취약점입니다.</p>
<p>악의적 웹사이트에서 사용자의 브라우저를 통해 다른 도메인의 API에 접근하여 민감한 데이터를 탈취하거나 조작할 수 있습니다.</p>';

// 2. 페이로드 정의 (테스트 시나리오)
$payloads = [
    'scenarios' => [
        'title' => '📋 테스트 시나리오',
        'description' => '다양한 Origin을 테스트하여 서버의 CORS 정책을 확인합니다.',
        'payloads' => [
            '*', // 와일드카드
            'null', // Null Origin
            'https://evil-site.com', // 악성 사이트 (반사 공격)
            'https://sub.attacker.com', // 공격자 서브도메인
            'file://localhost', // file 프로토콜
            'https://trusted-site.com' // 안전한 설정
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>엄격한 Origin 화이트리스트:</strong> 신뢰할 수 있는 도메인만 명시적으로 허용",
    "<strong>와일드카드 금지:</strong> `*`와 `credentials: true` 동시 사용 금지",
    "<strong>Null Origin 거부:</strong> `null` origin 요청 차단",
    "<strong>프로토콜 검증:</strong> HTTPS만 허용, `file://`, `data:` 프로토콜 차단",
    "<strong>동적 Origin 검증:</strong> 정규식 기반 서브도메인 검증 시 주의"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - CORS" => "https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
    "PortSwigger - CORS" => "https://portswigger.net/web-security/cors"
];

// 5. 테스트 폼 UI 정의
$test_origin = htmlspecialchars($_POST['payload'] ?? '');
$cors_endpoint = htmlspecialchars($_POST['endpoint'] ?? 'api/data');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 CORS 설정 테스트</h3>
    <label for="payload">🎯 테스트할 Origin:</label><br>
    <input type="text" id="payload" name="payload" value="{$test_origin}" placeholder="예: https://evil-site.com 또는 * 또는 null"><br><br>
    
    <label for="endpoint">📡 API 엔드포인트:</label><br>
    <input type="text" id="endpoint" name="endpoint" value="{$cors_endpoint}" placeholder="예: api/user/profile"><br><br>
    
    <button type="submit" class="btn">CORS 정책 테스트</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $origin = $form_data['payload'] ?? '';
    $endpoint = $form_data['endpoint'] ?? 'api/data';
    
    $response = "<strong>[시뮬레이션] CORS 응답 헤더 분석</strong>\n";
    $response .= "요청 Origin: " . htmlspecialchars($origin ?: '(없음)') . "\n";
    $response .= "API 엔드포인트: " . htmlspecialchars($endpoint) . "\n\n";

    $vulnerabilities = [];
    $cors_headers = [];

    if (empty($origin)) {
        $response .= "CORS 헤더 응답: (설정되지 않음)\n";
        $response .= "상태: 안전함 (기본 Same-Origin Policy 적용)\n";
    } else {
        if ($origin === '*') {
            $cors_headers['Access-Control-Allow-Origin'] = '*';
            $cors_headers['Access-Control-Allow-Credentials'] = 'true';
            $vulnerabilities[] = "치명적: 와일드카드(*)와 Credentials 동시 허용";
        } elseif ($origin === 'null') {
            $cors_headers['Access-Control-Allow-Origin'] = 'null';
            $vulnerabilities[] = "위험: null origin 허용 (iframe sandbox 우회 가능)";
        } else {
            $cors_headers['Access-Control-Allow-Origin'] = $origin; // Origin 반사
            $vulnerabilities[] = "위험: Origin 반사 (신뢰하지 않는 도메인 허용)";
        }
        
        $response .= "<strong>CORS 헤더 응답:</strong>\n";
        foreach ($cors_headers as $header => $value) {
            $response .= htmlspecialchars($header . ": " . $value) . "\n";
        }
    }

    if (!empty($vulnerabilities)) {
        $response .= "\n<strong>🚨 감지된 취약점:</strong>\n";
        foreach ($vulnerabilities as $vuln) {
            $response .= "- " . htmlspecialchars($vuln) . "\n";
        }
        $response .= "\n<strong>공격 시나리오:</strong>\n";
        $response .= "1. 악의적 사이트에서 피해자 브라우저를 통해 API 호출\n";
        $response .= "2. 사용자 세션 쿠키가 자동으로 포함됨\n";
        $response .= "3. 민감한 데이터(개인정보, 토큰 등) 탈취 가능\n";
    }

    return ['result' => "<pre>{"$response"}</pre>", 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

