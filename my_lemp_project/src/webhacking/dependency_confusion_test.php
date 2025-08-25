<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Dependency Confusion';
$description = '<p><strong>Dependency Confusion</strong>은 패키지 관리 시스템(npm, pip, Composer 등)이 비공개(private) 패키지보다 공개(public) 패키지를 우선적으로 선택하는 취약점을 악용하는 공격입니다.</p>
<p>공격자는 내부에서 사용되는 비공개 패키지와 동일한 이름의 악성 패키지를 공개 저장소에 업로드하여, 개발 시스템에 악성 코드를 주입할 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 Dependency Confusion 시뮬레이션',
        'description' => '아래 입력 필드에 공격자가 사용할 가상의 패키지 이름을 입력하여 시뮬레이션을 시작하세요.',
        'payloads' => [
            'internal-lib',
            'my-private-package',
            'company-utils'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>스코프(Scope) 사용:</strong> 비공개 패키지에 스코프(예: `@mycompany/package`)를 사용하여 공개 패키지와 이름 충돌을 방지합니다.",
    "<strong>내부 저장소 우선 설정:</strong> 패키지 관리자가 항상 내부 저장소를 먼저 확인하도록 설정합니다.",
    "<strong>패키지 서명 및 무결성 검증:</strong> 패키지 설치 시 서명을 확인하고, 해시 값을 통해 무결성을 검증합니다.",
    "<strong>빌드 시스템 보안 강화:</strong> 빌드 환경에서 외부 네트워크 접근을 제한하고, 신뢰할 수 있는 소스에서만 패키지를 다운로드하도록 합니다.",
    "<strong>정기적인 의존성 감사:</strong> 사용 중인 모든 의존성에 대해 정기적으로 보안 감사를 수행합니다."
];

// 4. 참고 자료 정의
$references = [
    "Snyk - What is Dependency Confusion?" => "https://snyk.io/blog/what-is-dependency-confusion/",
    "Trend Micro - Dependency Confusion Supply Chain Attack" => "https://www.trendmicro.com/en_us/research/21/a/dependency-confusion-supply-chain-attack.html"
];

// 5. 테스트 폼 UI 정의
$package_name_input = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 Dependency Confusion 시뮬레이션</h3>
    <p>아래 입력 필드에 공격자가 사용할 가상의 패키지 이름을 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="payload">가상의 패키지 이름:</label>
    <input type="text" id="payload" name="payload" value="{$package_name_input}" placeholder="예: internal-lib" required>
    <br><br>
    <button type="submit" name="action" value="simulate_confusion" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $package_name = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($package_name)) {
        $error = "패키지 이름을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $result = "Dependency Confusion 공격 시뮬레이션이 시작되었습니다.<br>";
    $result .= "공격자는 <code>" . htmlspecialchars($package_name) . "</code>과 같은 이름의 악성 패키지를 공개 저장소에 업로드합니다.<br>";
    $result .= "개발 환경에서 이 패키지를 설치할 때, 패키지 관리자는 비공개 저장소보다 공개 저장소의 패키지를 우선적으로 선택할 수 있습니다.<br>";
    $result .= "이로 인해 개발 시스템에 악성 코드가 실행될 수 있습니다.<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 Dependency Confusion 공격을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();