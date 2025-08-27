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
$page_title = 'Open Redirect';
$description = '<p><strong>Open Redirect</strong>은 사용자 입력을 통해 리다이렉트 URL을 조작할 수 있는 취약점입니다.</p>
<p>신뢰할 수 있는 도메인을 악용하여 사용자를 악의적인 사이트로 유도하는 피싱 공격에 주로 사용됩니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'basic' => [
        'title' => '기본 공격',
        'description' => '가장 기본적인 Open Redirect 공격입니다.',
        'payloads' => [
            'https://evil-site.com',
            'http://attacker.com/malware.exe'
        ]
    ],
    'phishing' => [
        'title' => '피싱 공격',
        'description' => '신뢰할 수 있는 도메인에서 시작하여 사용자를 가짜 로그인 페이지로 리다이렉트합니다.',
        'payloads' => [
            'https://fake-bank.com/login',
            'https://phishing.example.com/login'
        ]
    ],
    'bypass' => [
        'title' => '필터 우회',
        'description' => 'URL 인코딩, 이중 슬래시 등을 사용하여 필터를 우회합니다.',
        'payloads' => [
            '//evil.com',
            'https%3A%2F%2Fevil.com',
            'http://0x7f000001' // 127.0.0.1
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>화이트리스트 검증:</strong> 허용된 도메인/경로만 리다이렉트 허용",
    "<strong>절대 URL 금지:</strong> 상대 경로만 허용하거나 도메인 검증 필수",
    "<strong>URL 파싱:</strong> `parse_url()` 등으로 URL 구성 요소 검증",
    "<strong>프로토콜 제한:</strong> HTTP/HTTPS만 허용, `javascript:`, `data:` 등 차단",
    "<strong>사용자 확인:</strong> 외부 리다이렉트 시 경고 메시지 표시",
    "<strong>토큰 검증:</strong> 리다이렉트 URL에 서명된 토큰 포함"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Open Redirect" => "https://owasp.org/www-community/attacks/Open_redirection",
    "PortSwigger - Open Redirect" => "https://portswigger.net/web-security/open-redirection"
];

// 5. 테스트 폼 UI 정의
$redirect_url = htmlspecialchars($_POST['payload'] ?? '');
$attack_type = htmlspecialchars($_POST['attack_type'] ?? 'basic');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 Open Redirect 테스트</h3>
    <label for="attack_type">🎯 공격 유형 선택:</label>
    <select id="attack_type" name="attack_type">
        <option value="basic" {$attack_type === 'basic' ? 'selected' : ''}>Basic Redirect</option>
        <option value="phishing" {$attack_type === 'phishing' ? 'selected' : ''}>Phishing Attack</option>
        <option value="bypass" {$attack_type === 'bypass' ? 'selected' : ''}>Filter Bypass</option>
    </select><br><br>
    
    <label for="payload">🌐 리다이렉트 URL 입력:</label>
    <input type="text" id="payload" name="payload" value="{$redirect_url}" placeholder="예: https://evil-site.com 또는 //attacker.com">
    <br><br>
    <button type="submit" class="btn">Open Redirect 테스트</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $url = $form_data['payload'] ?? '';
    $type = $form_data['attack_type'] ?? 'basic';
    $result = '';
    $error = '';

    if (empty($url)) {
        $error = "리다이렉트 URL을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] Open Redirect 공격 분석\n";
    $response_sim .= "공격 유형: " . strtoupper($type) . "\n";
    $response_sim .= "리다이렉트 URL: " . htmlspecialchars($url) . "\n\n";

    $parsed_url = parse_url($url);
    $is_external = false;
    $is_dangerous = false;
    $attack_vector = [];

    if (isset($parsed_url['host'])) {
        $host = strtolower($parsed_url['host']);
        $safe_domains = ['example.com', 'localhost', '127.0.0.1'];
        
        if (!in_array($host, $safe_domains)) {
            $is_external = true;
        }

        $malicious_patterns = ['evil', 'malicious', 'phishing', 'fake'];
        foreach ($malicious_patterns as $pattern) {
            if (strpos($host, $pattern) !== false) {
                $is_dangerous = true;
                $attack_vector[] = "악의적 도메인명 포함: {$pattern}";
                break;
            }
        }
    }

    if (isset($parsed_url['scheme'])) {
        $scheme = strtolower($parsed_url['scheme']);
        if (in_array($scheme, ['javascript', 'data', 'vbscript', 'file'])) {
            $is_dangerous = true;
            $attack_vector[] = "위험한 프로토콜: {$scheme}";
        }
    }

    if ($is_dangerous || $is_external) {
        $response_sim .= "🚨 취약점 발견: Open Redirect 공격 가능\n\n";
        if ($is_external) {
            $response_sim .= "위험 요소: 외부 도메인으로 리다이렉트\n";
        }
        if (!empty($attack_vector)) {
            $response_sim .= "감지된 공격 기법:\n";
            foreach ($attack_vector as $vector) {
                $response_sim .= "- " . $vector . "\n";
            }
        }
        $response_sim .= "\n공격 시나리오: 피싱, 멀웨어 배포, OAuth 토큰 탈취 등\n";
        $response_sim .= "실제 리다이렉트 결과: ❌ 위험: 악의적 사이트로 리다이렉트됨\n";
    } else {
        $response_sim .= "✅ 안전한 리다이렉트 URL\n";
        $response_sim .= "내부 도메인으로의 리다이렉트입니다.\n";
        $response_sim .= "위험한 패턴이 감지되지 않았습니다.\n";
    }

    return ['result' => "<pre>{"$response_sim"}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>