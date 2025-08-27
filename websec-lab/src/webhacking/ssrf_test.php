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

    if (!empty($url)) {
        // SSRF 방어 로직 (주석 처리하여 취약점 활성화)
        /*
        $parsed_url = parse_url($url);
        if ($parsed_url === false || !isset($parsed_url['host'])) {
            $error = '유효하지 않은 URL입니다.';
        } else {
            $ip = gethostbyname($parsed_url['host']);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                // 안전한 경우에만 요청
                $result = @file_get_contents($url);
            } else {
                $error = '허용되지 않은 IP 주소입니다. (내부 IP 접근 불가)';
            }
        }
        */

        // 취약한 코드: 사용자 입력을 검증 없이 그대로 사용
        $response = @file_get_contents($url);
        if ($response === false) {
            $error = '요청한 URL의 내용을 가져올 수 없습니다.';
        } else {
            $result = "<pre><code>" . htmlspecialchars($response) . "</code></pre>";
        }
    } else {
        $error = 'URL을 입력해주세요.';
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "SSRF_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();