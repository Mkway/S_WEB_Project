<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'SSI Injection';
$description = '<p><strong>SSI (Server Side Include) Injection</strong>은 웹 서버가 HTML 페이지를 클라이언트에 전송하기 전에 서버 측에서 동적으로 콘텐츠를 포함시키는 SSI 지시어를 처리하는 과정에서 발생하는 취약점입니다.</p>
<p>공격자는 사용자 입력에 SSI 지시어를 주입하여 웹 서버에서 임의의 명령을 실행하거나, 로컬 파일을 읽거나, 서버 변수를 출력하는 등의 공격을 수행할 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 SSI Injection 시뮬레이션',
        'description' => '아래 입력 필드에 SSI 지시어를 포함한 문자열을 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>사용자 입력 필터링:</strong> 사용자 입력에서 SSI 지시어(예: `<!--#`) 및 관련 특수 문자를 제거하거나 인코딩합니다.",
    "<strong>SSI 비활성화:</strong> 웹 서버 설정에서 불필요한 경우 SSI 기능을 완전히 비활성화합니다.",
    "<strong>최소 권한 원칙:</strong> SSI를 사용하는 경우, `exec`와 같은 위험한 지시어의 사용을 제한하거나, SSI가 실행되는 프로세스의 권한을 최소화합니다.",
    "<strong>웹 애플리케이션 방화벽 (WAF):</strong> SSI Injection 패턴을 탐지하고 차단하는 WAF를 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Server-Side Includes (SSI) Injection" => "https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection",
    "PortSwigger - SSI injection" => "https://portswigger.net/web-security/ssi"
];

// 5. 테스트 폼 UI 정의
$user_input = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 SSI Injection 시뮬레이션</h3>
    <p>아래 입력 필드에 SSI 지시어를 포함한 문자열을 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="payload">사용자 입력:</label>
    <textarea id="payload" name="payload" placeholder="예: &lt;!--#exec cmd=\"id\" --&gt; 또는 &lt;!--#include virtual=\"/etc/passwd\" --&gt;" required>{$user_input}</textarea>
    <br><br>
    <button type="submit" name="action" value="simulate_ssi_injection" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $user_input = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($user_input)) {
        $error = "사용자 입력을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $result = "SSI Injection 시뮬레이션이 실행되었습니다.<br>";
    $result .= "사용자 입력: <code>" . htmlspecialchars($user_input) . "</code><br>";
    $result .= "<br>만약 웹 서버가 사용자 입력에 포함된 SSI 지시어를 필터링 없이 처리한다면, 공격자는 다음과 같은 명령을 실행할 수 있습니다:";
    $result .= "<ul>";
    $result .= "<li><code>&lt;!--#exec cmd=\"ls -la\" --&gt;</code>: 서버에서 임의의 명령 실행</li>";
    $result .= "<li><code>&lt;!--#include virtual=\"/etc/passwd\" --&gt;</code>: 로컬 파일 읽기</li>";
    $result .= "<li><code>&lt;!--#echo var=\"DATE_LOCAL\" --&gt;</code>: 서버 변수 출력</li>";
    $result .= "</ul>";
    $result .= "<br><strong>참고:</strong> 이 시뮬레이션은 실제 SSI 명령을 실행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();