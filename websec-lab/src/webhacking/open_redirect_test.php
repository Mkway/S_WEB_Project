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

    $result .= "<div class='vulnerable-output'>";
    $result .= "<h4>🚨 취약한 Open Redirect 실행 결과</h4>";
    $result .= "<p><strong>공격 유형:</strong> " . strtoupper($type) . "</p>";
    $result .= "<p><strong>리다이렉트 URL:</strong> " . htmlspecialchars($url) . "</p>";
    
    // 실제 Open Redirect 공격 실행 분석 (교육 목적)
    try {
        $parsed_url = parse_url($url);
        $is_external = false;
        $is_dangerous = false;
        $attack_vector = [];
        $redirect_simulation = '';

        // URL 파싱 및 분석
        if ($parsed_url === false) {
            $result .= "<p class='error'>❌ 잘못된 URL 형식입니다.</p>";
        } else {
            // 호스트 검증
            if (isset($parsed_url['host'])) {
                $host = strtolower($parsed_url['host']);
                $current_domain = $_SERVER['HTTP_HOST'] ?? 'localhost';
                
                if ($host !== $current_domain && $host !== 'localhost' && $host !== '127.0.0.1') {
                    $is_external = true;
                    $result .= "<p class='danger'>🔥 <strong>외부 도메인 리다이렉트!</strong> 도메인: {$host}</p>";
                }

                // 악성 패턴 검사
                $malicious_patterns = ['evil', 'malicious', 'phishing', 'fake', 'attacker'];
                foreach ($malicious_patterns as $pattern) {
                    if (strpos($host, $pattern) !== false) {
                        $is_dangerous = true;
                        $attack_vector[] = "악의적 도메인명 포함: {$pattern}";
                        $result .= "<p class='danger'>🔥 <strong>악의적 도메인 감지!</strong> 패턴: {$pattern}</p>";
                        break;
                    }
                }
            } elseif (strpos($url, '//') === 0) {
                // Protocol-relative URL (//example.com)
                $is_external = true;
                $attack_vector[] = "프로토콜 상대 URL 사용";
                $result .= "<p class='warning'>⚠️ <strong>프로토콜 상대 URL 감지!</strong> 필터 우회 시도 가능</p>";
            }

            // 프로토콜 검증
            if (isset($parsed_url['scheme'])) {
                $scheme = strtolower($parsed_url['scheme']);
                if (in_array($scheme, ['javascript', 'data', 'vbscript', 'file'])) {
                    $is_dangerous = true;
                    $attack_vector[] = "위험한 프로토콜: {$scheme}";
                    $result .= "<p class='danger'>🔥 <strong>위험한 프로토콜 감지!</strong> {$scheme}://</p>";
                }
            }

            // 실제 리다이렉트 시뮬레이션
            if ($is_external || $is_dangerous) {
                $redirect_simulation = "실제 환경에서는 사용자가 다음 URL로 리다이렉트됩니다:\n";
                $redirect_simulation .= "→ " . htmlspecialchars($url) . "\n\n";
                
                if ($is_dangerous) {
                    $redirect_simulation .= "⚠️ 이는 다음과 같은 공격으로 이어질 수 있습니다:\n";
                    $redirect_simulation .= "- 피싱 사이트로 유도하여 계정 정보 탈취\n";
                    $redirect_simulation .= "- 멀웨어 다운로드 페이지로 리다이렉트\n";
                    $redirect_simulation .= "- OAuth 토큰 가로채기\n";
                    $redirect_simulation .= "- 세션 하이재킹\n";
                } else {
                    $redirect_simulation .= "외부 사이트로의 리다이렉트로 인한 보안 위험이 존재합니다.";
                }
                
                // 취약한 PHP 코드 예시 표시
                $result .= "<p class='danger'>🔥 <strong>취약한 리다이렉트 실행!</strong></p>";
                $result .= "<p><strong>실행된 취약한 코드:</strong></p>";
                $result .= "<pre class='attack-result'>header('Location: " . htmlspecialchars($url) . "');\nexit();</pre>";
                
            } else {
                $redirect_simulation = "내부 도메인으로의 안전한 리다이렉트입니다.\n";
                $redirect_simulation .= "→ " . htmlspecialchars($url);
                $result .= "<p class='success'>✅ 내부 도메인으로의 리다이렉트</p>";
            }
            
            $result .= "<p><strong>리다이렉트 시뮬레이션 결과:</strong></p>";
            $result .= "<pre class='attack-result'>" . $redirect_simulation . "</pre>";
        }
        
    } catch (Exception $e) {
        $result .= "<p class='error'>❌ Open Redirect 분석 중 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    $result .= "</div>";
    
    // 안전한 구현 비교
    $result .= "<div class='safe-comparison'>";
    $result .= "<h4>✅ 안전한 리다이렉트 방어 구현</h4>";
    
    $parsed_url = parse_url($url);
    $is_safe = true;
    $validation_messages = [];

    // 1. URL 형식 검증
    if ($parsed_url === false) {
        $validation_messages[] = "🛡️ 차단됨: 잘못된 URL 형식";
        $is_safe = false;
    } else {
        // 2. 프로토콜 검증
        $allowed_schemes = ['http', 'https'];
        $scheme = $parsed_url['scheme'] ?? '';
        if (!empty($scheme) && !in_array(strtolower($scheme), $allowed_schemes)) {
            $validation_messages[] = "🛡️ 차단됨: 허용되지 않은 프로토콜 '{$scheme}'";
            $is_safe = false;
        }

        // 3. 도메인 화이트리스트 검증
        if (isset($parsed_url['host'])) {
            $host = strtolower($parsed_url['host']);
            $allowed_domains = ['localhost', '127.0.0.1', $_SERVER['HTTP_HOST'] ?? 'localhost'];
            
            if (!in_array($host, $allowed_domains)) {
                $validation_messages[] = "🛡️ 차단됨: 허용되지 않은 외부 도메인 '{$host}'";
                $is_safe = false;
            }
        } elseif (strpos($url, '//') === 0) {
            $validation_messages[] = "🛡️ 차단됨: 프로토콜 상대 URL 사용";
            $is_safe = false;
        }

        // 4. 상대 경로 확인
        if (empty($parsed_url['host']) && strpos($url, '/') === 0) {
            $validation_messages[] = "✅ 허용됨: 안전한 상대 경로";
        }
    }

    if ($is_safe && !empty($validation_messages)) {
        foreach ($validation_messages as $msg) {
            $result .= "<p class='success'>{$msg}</p>";
        }
        $result .= "<p><strong>안전한 리다이렉트 결과:</strong></p>";
        $result .= "<pre class='safe-result'>안전한 경로로 리다이렉트: " . htmlspecialchars($url) . "</pre>";
    } else {
        foreach ($validation_messages as $msg) {
            $result .= "<p class='success'>{$msg}</p>";
        }
        $result .= "<p class='success'>🛡️ 리다이렉트가 보안 정책에 의해 차단되었습니다.</p>";
    }
    
    $result .= "</div>";
    
    // 보안 권장사항
    $result .= "<div class='security-recommendations'>";
    $result .= "<h4>🔒 Open Redirect 방어 권장사항</h4>";
    $result .= "<ul>";
    $result .= "<li><strong>화이트리스트 검증:</strong> 허용된 도메인/경로만 리다이렉트 허용</li>";
    $result .= "<li><strong>절대 URL 금지:</strong> 가능한 상대 경로만 사용</li>";
    $result .= "<li><strong>URL 파싱 검증:</strong> <code>parse_url()</code>로 URL 구성 요소 검증</li>";
    $result .= "<li><strong>프로토콜 제한:</strong> HTTP/HTTPS만 허용</li>";
    $result .= "<li><strong>사용자 확인:</strong> 외부 리다이렉트 시 경고 메시지 표시</li>";
    $result .= "<li><strong>서명된 토큰:</strong> 리다이렉트 URL에 검증 가능한 토큰 포함</li>";
    $result .= "</ul>";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Open_Redirect_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>