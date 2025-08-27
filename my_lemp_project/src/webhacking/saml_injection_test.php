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
$page_title = 'SAML Injection';
$description = '<p><strong>SAML (Security Assertion Markup Language) Injection</strong>은 SAML 기반의 싱글 사인온(SSO) 시스템에서 공격자가 SAML 어설션(Assertion)을 조작하여 인증을 우회하거나, 다른 사용자를 가장하거나, 권한을 상승시키는 취약점입니다.</p>
<p>이는 SAML 응답의 디지털 서명 검증이 미흡하거나, 어설션 내의 사용자 식별 정보(NameID)나 속성(Attribute)을 제대로 검증하지 않을 때 발생합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 SAML Injection 시뮬레이션',
        'description' => '아래 입력 필드에 조작된 SAML 어설션을 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>디지털 서명 검증:</strong> SAML 응답의 디지털 서명을 항상 철저히 검증하여 어설션의 무결성과 신뢰성을 확인합니다.",
    "<strong>NameID 및 속성 검증:</strong> SAML 어설션 내의 사용자 식별 정보(NameID) 및 속성(Attribute) 값을 신뢰하기 전에 적절히 검증하고, 예상된 형식과 값만 허용합니다.",
    "<strong>재전송 공격 방지:</strong> `NotOnOrAfter`, `IssueInstant` 등 시간 관련 속성을 검증하여 오래된 어설션의 재사용을 방지합니다.",
    "<strong>대상 검증:</strong> `AudienceRestriction`을 통해 SAML 어설션이 올바른 서비스 제공자(SP)를 대상으로 하는지 확인합니다.",
    "<strong>최소 권한 원칙:</strong> SAML 어설션에서 제공되는 권한을 최소화하고, 애플리케이션 내부에서 추가적인 권한 검증을 수행합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - SAML Injection" => "https://owasp.org/www-community/attacks/SAML_Injection",
    "PortSwigger - SAML vulnerabilities" => "https://portswigger.net/web-security/saml"
];

// 5. 테스트 폼 UI 정의
$saml_assertion = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 SAML Injection 시뮬레이션</h3>
    <p>아래 입력 필드에 조작된 SAML 어설션을 입력하여 시뮬레이션을 시작하세요.</p>
    <p><strong>예시 페이로드:</strong></p>
    <pre><code>&lt;saml:Assertion ...&gt;
  &lt;saml:Subject&gt;
    &lt;saml:NameID&gt;admin&lt;/saml:NameID&gt;
    ...
  &lt;/saml:Subject&gt;
  &lt;saml:AttributeStatement&gt;
    &lt;saml:Attribute Name="Role"&gt;
      &lt;saml:AttributeValue&gt;admin&lt;/saml:AttributeValue&gt;
    &lt;/saml:Attribute&gt;
  &lt;/saml:AttributeStatement&gt;
  ...
&lt;/saml:Assertion&gt;</code></pre>
    <label for="payload">조작된 SAML 어설션:</label>
    <textarea id="payload" name="payload" required>{$saml_assertion}</textarea>
    <br><br>
    <button type="submit" name="action" value="simulate_saml_injection" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $saml_assertion = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($saml_assertion)) {
        $error = "SAML 어설션을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    // 매우 단순화된 파싱 (실제 SAML 파서는 훨씬 복잡합니다)
    $username = 'unknown';
    $role = 'user';

    if (strpos($saml_assertion, '<saml:NameID') !== false) {
        preg_match('/<saml:NameID[^>]*>(.*?)<\/saml:NameID>/s', $saml_assertion, $matches);
        $username = $matches[1] ?? 'unknown';
    }

    if (strpos($saml_assertion, '<saml:Attribute Name="Role">') !== false) {
        preg_match('/<saml:Attribute Name="Role">\s*<saml:AttributeValue[^>]*>(.*?)<\/saml:AttributeValue>/s', $saml_assertion, $matches);
        $role = $matches[1] ?? 'user';
    }

    $result = "SAML Injection 시뮬레이션이 실행되었습니다.<br>";
    $result .= "제출된 SAML 어설션에서 추출된 정보:<br>";
    $result .= "사용자 이름: <strong>" . htmlspecialchars($username) . "</strong><br>";
    $result .= "역할: <strong>" . htmlspecialchars($role) . "</strong><br>";
    $result .= "<br>만약 애플리케이션이 SAML 어설션의 디지털 서명을 제대로 검증하지 않거나, NameID/Attribute 값을 신뢰한다면, 공격자는 임의의 사용자 계정으로 로그인하거나 권한을 상승시킬 수 있습니다.";
    $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 SAML 인증을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();