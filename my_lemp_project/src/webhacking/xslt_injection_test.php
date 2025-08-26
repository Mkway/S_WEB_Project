<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'XSLT Injection';
$description = '<p><strong>XSLT (Extensible Stylesheet Language Transformations) Injection</strong>은 웹 애플리케이션이 사용자 입력으로 받은 XSLT 스타일시트를 XML 문서에 적용할 때 발생하는 취약점입니다.</p>
<p>공격자는 악의적인 XSLT를 주입하여 임의의 파일을 읽거나, 임의 코드를 실행하거나, SSRF 공격을 수행하는 등 다양한 공격을 수행할 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 XSLT Injection 시뮬레이션',
        'description' => '아래 입력 필드에 XML 문서와 조작된 XSLT를 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>사용자 입력 검증:</strong> 사용자로부터 XSLT를 직접 받지 않거나, 받는 경우 엄격한 화이트리스트 기반의 검증을 수행합니다.",
    "<strong>외부 엔티티 및 확장 함수 비활성화:</strong> XSLT 프로세서에서 외부 엔티티(`document()` 함수 등) 및 임의 코드 실행을 허용하는 확장 함수를 비활성화합니다.",
    "<strong>최소 권한 원칙:</strong> XSLT 프로세서가 실행되는 환경의 권한을 최소화하여 공격의 영향을 줄입니다.",
    "<strong>웹 애플리케이션 방화벽 (WAF):</strong> XSLT Injection 패턴을 탐지하고 차단하는 WAF를 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - XSLT Injection" => "https://owasp.org/www-community/attacks/XSLT_Injection",
    "PortSwigger - XSLT injection" => "https://portswigger.net/web-security/xxe/xslt-injection"
];

// 5. 테스트 폼 UI 정의
$xml_input = htmlspecialchars($_POST['xml_input'] ?? '');
$xslt_input = htmlspecialchars($_POST['xslt_input'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 XSLT Injection 시뮬레이션</h3>
    <p>아래 입력 필드에 XML 문서와 조작된 XSLT를 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="xml_input">XML 문서 (가상):</label>
    <textarea id="xml_input" name="xml_input" placeholder="예: <data><user>test</user></data>" required>{$xml_input}</textarea>
    <br>
    <label for="xslt_input">XSLT 스타일시트 (가상):</label>
    <textarea id="xslt_input" name="xslt_input" placeholder="예: <xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">	<xsl:template match="//">	<xsl:value-of select="document('file:///etc/passwd')"/>	</xsl:template>
</xsl:stylesheet>" required>{$xslt_input}</textarea>
    <br><br>
    <button type="submit" name="action" value="simulate_xslt_injection" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $xml_input = $form_data['xml_input'] ?? '';
    $xslt_input = $form_data['xslt_input'] ?? '';
    $result = '';
    $error = '';

    if (empty($xml_input) || empty($xslt_input)) {
        $error = "XML 문서와 XSLT 스타일시트를 모두 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $result = "XSLT Injection 시뮬레이션이 시작되었습니다.<br>";
    $result .= "제출된 XML: <code>" . htmlspecialchars($xml_input) . "</code><br>";
    $result .= "제출된 XSLT: <code>" . htmlspecialchars($xslt_input) . "</code><br>";
    $result .= "<br>만약 애플리케이션이 사용자 입력으로 받은 XSLT를 검증 없이 XML 문서에 적용한다면, 공격자는 다음과 같은 공격을 수행할 수 있습니다:";
    $result .= "<ul>";
    $result .= "<li>임의 파일 읽기: <code>&lt;xsl:value-of select=\"document('file:///etc/passwd')\"/&gt;</code></li>";
    $result .= "<li>임의 코드 실행: XSLT 프로세서의 확장 함수를 통해 시스템 명령 실행 (PHP의 `php:function` 등)</li>";
    $result .= "<li>SSRF: <code>document('http://internal-service/admin')</code></li>";
    $result .= "</ul>";
    $result .= "<br><strong>참고:</strong> 이 시뮬레이션은 실제 XSLT 변환을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
