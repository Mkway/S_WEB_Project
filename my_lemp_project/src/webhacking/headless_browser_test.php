<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Headless Browser Vulnerabilities';
$description = '<p><strong>Headless Browser Vulnerabilities</strong>는 서버 측에서 웹 페이지 렌더링, 스크린샷 생성, PDF 변환 등을 위해 헤드리스 브라우저(예: Puppeteer, Selenium)를 사용할 때 발생할 수 있는 취약점입니다.</p>
<p>공격자는 헤드리스 브라우저가 로드하는 URL을 조작하여 내부 네트워크에 접근하거나, 로컬 파일을 읽거나, 악성 JavaScript를 실행시킬 수 있습니다.</p>
<p>이 페이지에서는 헤드리스 브라우저를 이용한 공격의 개념과 원리를 시뮬레이션합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 헤드리스 브라우저 익스플로잇 시뮬레이션',
        'description' => '아래 입력 필드에 헤드리스 브라우저가 로드할 가상의 URL을 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 값 검증:</strong> 헤드리스 브라우저가 로드할 URL에 대해 엄격한 화이트리스트 기반의 검증을 수행합니다. 내부 IP 주소, `file://`, `data://` 등 위험한 스키마를 차단합니다.",
    "<strong>샌드박스 환경:</strong> 헤드리스 브라우저를 격리된 샌드박스 환경에서 실행하여 시스템 자원에 대한 접근을 제한합니다.",
    "<strong>최소 권한 원칙:</strong> 헤드리스 브라우저 프로세스에 필요한 최소한의 권한만 부여합니다.",
    "<strong>보안 헤더 설정:</strong> 로드되는 페이지에 `Content-Security-Policy (CSP)`, `X-Frame-Options` 등 보안 헤더를 적용하여 공격을 완화합니다.",
    "<strong>정기적인 업데이트:</strong> 헤드리스 브라우저 및 관련 라이브러리를 항상 최신 버전으로 유지하여 알려진 취약점을 패치합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Server Side Request Forgery (SSRF) (관련)" => "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    "PortSwigger - Server-side request forgery (SSRF) (관련)" => "https://portswigger.net/web-security/ssrf"
];

// 5. 테스트 폼 UI 정의
$target_url = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 헤드리스 브라우저 익스플로잇 시뮬레이션</h3>
    <p>아래 입력 필드에 헤드리스 브라우저가 로드할 가상의 URL을 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="payload">헤드리스 브라우저 로드 URL (가상):</label>
    <input type="text" id="payload" name="payload" value="{$target_url}" placeholder="예: http://localhost/admin 또는 file:///etc/passwd" required>
    <br><br>
    <button type="submit" name="action" value="simulate_headless_exploit" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $target_url = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($target_url)) {
        $error = "URL을 입력해주세요.";
        return ['result' => $result, 'error' => $error];
    }

    $result = "헤드리스 브라우저 익스플로잇 시뮬레이션이 시작되었습니다.<br>";
    $result .= "서버가 <code>" . htmlspecialchars($target_url) . "</code>을(를) 헤드리스 브라우저로 로드한다고 가정합니다.<br>";
    $result .= "공격자는 <code>file:///etc/passwd</code> 또는 <code>http://localhost/internal_admin</code>과 같은 URL을 주입하여 내부 파일에 접근하거나 내부 서비스에 요청을 보낼 수 있습니다.<br>";
    $result .= "또한, 로드된 페이지의 JavaScript를 통해 추가적인 공격(예: XSS, SSRF)을 수행할 수도 있습니다.<br><br>";
    $result .= "<strong>참고:</strong> 이 시뮬레이션은 실제 헤드리스 브라우저를 실행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();