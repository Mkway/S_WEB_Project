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
$page_title = 'SSRF (Server-Side Request Forgery)';
$description = '<p><strong>SSRF</strong>는 공격자가 서버로 하여금 임의의 다른 서버로 요청을 보내도록 조작하는 공격입니다.</p>
<p>이를 통해 내부 네트워크 정보 유출, 로컬 파일 접근, 다른 서비스와의 상호작용 등이 가능해질 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'ssrf' => [
        'title' => '🎯 SSRF 페이로드 예시',
        'description' => '서버가 내부 또는 외부 리소스에 접근하도록 유도하는 페이로드입니다.',
        'payloads' => [
            'http://example.com', // 외부 정상 요청
            'http://localhost/admin.php', // 내부 서버의 관리자 페이지 접근 시도
            'file:///etc/passwd', // 로컬 파일 읽기 시도
            'http://169.254.169.254/latest/meta-data/', // 클라우드 메타데이터 접근 시도 (AWS)
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>Whitelist 기반 검증:</strong> 허용된 도메인, IP, 포트 목록을 만들어 해당 목록에 있는 경우에만 요청을 허용합니다.",
    "<strong>IP 주소 검증:</strong> 요청하려는 최종 IP 주소가 내부망(Private) IP 대역인지 확인하고 차단합니다.",
    "<strong>리다이렉션 비활성화:</strong> cURL 사용 시 `CURLOPT_FOLLOWLOCATION` 옵션을 비활성화하여 리다이렉트를 통한 우회를 막습니다.",
    "<strong>프로토콜 제한:</strong> `http`, `https` 등 허용된 프로토콜만 사용하도록 제한합니다. (`file://`, `gopher://` 등 위험한 프로토콜 차단)"
];

// 4. 참고 자료 정의
$references = [
    "PayloadsAllTheThings - SSRF" => "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
    "OWASP - Server Side Request Forgery" => "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    "PortSwigger - Server-side request forgery (SSRF)" => "https://portswigger.net/web-security/ssrf"
];

// 5. 테스트 폼 UI 정의
$url = htmlspecialchars($_POST['url'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 URL 내용 가져오기</h3>
    <label for="payload">테스트할 URL:</label>
    <textarea name="payload" id="payload" placeholder="여기에 테스트할 URL을 입력하거나 위의 버튼을 클릭하세요">{$url}</textarea>
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">요청 보내기</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $url = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($url)) {
        $error = 'URL을 입력해주세요.';
        return ['result' => '', 'error' => $error];
    }

    $result .= "<div class='vulnerable-output'>";
    $result .= "<h4>🚨 취약한 SSRF 실행 결과</h4>";
    
    // 실제 SSRF 공격 실행 (교육 목적)
    try {
        $context = stream_context_create([
            'http' => [
                'timeout' => 10,
                'user_agent' => 'Mozilla/5.0 (Vulnerable SSRF Test)',
                'follow_location' => 1,
                'max_redirects' => 3
            ]
        ]);
        
        $response = @file_get_contents($url, false, $context);
        
        if ($response !== false) {
            $response_length = strlen($response);
            $result .= "<p><strong>요청 성공!</strong> 응답 크기: {$response_length} bytes</p>";
            
            // 응답 내용 분석
            if (strpos($response, 'root:x:') !== false || strpos($response, '/bin/') !== false) {
                $result .= "<p class='danger'>🔥 <strong>로컬 파일 읽기 성공!</strong> /etc/passwd 내용이 노출되었습니다.</p>";
            } elseif (strpos($response, 'ami-') !== false || strpos($response, 'instance-id') !== false) {
                $result .= "<p class='danger'>🔥 <strong>클라우드 메타데이터 접근 성공!</strong> AWS 인스턴스 정보가 노출되었습니다.</p>";
            } elseif (strpos($response, '<html') !== false || strpos($response, '<!DOCTYPE') !== false) {
                $result .= "<p class='warning'>⚠️ <strong>웹페이지 접근 성공!</strong> 내부/외부 웹 리소스에 접근했습니다.</p>";
            }
            
            // 응답 내용 표시 (처음 500자만)
            $preview = htmlspecialchars(substr($response, 0, 500));
            if (strlen($response) > 500) {
                $preview .= "\n... (추가 " . (strlen($response) - 500) . " bytes 생략)";
            }
            $result .= "<p><strong>응답 내용 미리보기:</strong></p>";
            $result .= "<pre class='attack-result'>" . $preview . "</pre>";
            
        } else {
            $result .= "<p class='error'>❌ 요청 실패: URL에 접근할 수 없습니다.</p>";
            $last_error = error_get_last();
            if ($last_error) {
                $result .= "<p class='error'>오류 세부사항: " . htmlspecialchars($last_error['message']) . "</p>";
            }
        }
        
    } catch (Exception $e) {
        $result .= "<p class='error'>❌ SSRF 실행 중 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    $result .= "</div>";
    
    // 안전한 구현 비교
    $result .= "<div class='safe-comparison'>";
    $result .= "<h4>✅ 안전한 SSRF 방어 구현</h4>";
    
    $parsed_url = parse_url($url);
    if ($parsed_url === false || !isset($parsed_url['host'])) {
        $result .= "<p class='error'>🛡️ 차단됨: 유효하지 않은 URL 형식</p>";
    } else {
        $host = $parsed_url['host'];
        $scheme = $parsed_url['scheme'] ?? '';
        
        // 프로토콜 검증
        if (!in_array($scheme, ['http', 'https'])) {
            $result .= "<p class='success'>🛡️ 차단됨: 허용되지 않은 프로토콜 '{$scheme}'</p>";
        } else {
            // IP 주소 해석
            $ip = gethostbyname($host);
            
            // 내부 IP 대역 체크
            $is_private = !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
            
            if ($is_private) {
                $result .= "<p class='success'>🛡️ 차단됨: 내부 네트워크 IP 주소 ({$ip})</p>";
            } else {
                // Whitelist 검증 (예시)
                $allowed_domains = ['httpbin.org', 'example.com', 'jsonplaceholder.typicode.com'];
                if (!in_array($host, $allowed_domains)) {
                    $result .= "<p class='success'>🛡️ 차단됨: 허용되지 않은 도메인 '{$host}'</p>";
                } else {
                    $result .= "<p class='success'>✅ 안전한 요청: 허용된 도메인으로의 요청입니다.</p>";
                    // 실제로는 안전한 요청을 수행할 수 있음
                }
            }
        }
    }
    
    $result .= "</div>";
    
    // 보안 권장사항
    $result .= "<div class='security-recommendations'>";
    $result .= "<h4>🔒 SSRF 방어 권장사항</h4>";
    $result .= "<ul>";
    $result .= "<li><strong>화이트리스트 기반 검증:</strong> 허용된 도메인/IP/포트만 접근 허용</li>";
    $result .= "<li><strong>내부 IP 차단:</strong> RFC 1918 사설 IP 대역(10.x, 192.168.x, 172.16-31.x) 차단</li>";
    $result .= "<li><strong>프로토콜 제한:</strong> HTTP/HTTPS 외 프로토콜(file://, gopher://) 차단</li>";
    $result .= "<li><strong>리다이렉트 제한:</strong> 자동 리다이렉트 비활성화 또는 제한</li>";
    $result .= "<li><strong>응답 크기 제한:</strong> 응답 데이터 크기 및 시간 제한 설정</li>";
    $result .= "<li><strong>네트워크 분리:</strong> 웹 애플리케이션을 내부망과 분리</li>";
    $result .= "</ul>";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "SSRF_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();