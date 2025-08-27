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
$page_title = 'Type Juggling';
$description = '<p><strong>Type Juggling</strong>은 PHP와 같은 일부 프로그래밍 언어에서 발생하는 취약점으로, 느슨한 타입 비교(loose type comparison, `==`)를 사용할 때 서로 다른 타입의 값이 예상치 못하게 `true`로 평가되어 인증 우회 등의 문제가 발생할 수 있습니다.</p>
<p>특히 `0e`로 시작하는 문자열이 숫자형으로 변환될 때 `0`으로 평가되는 특성을 악용할 수 있습니다.</p>
<p>이 페이지에서는 `0e` 문자열을 이용한 비밀번호 비교 우회 시나리오를 시뮬레이션합니다.</p>
<p><strong>예상 비밀번호 (내부):</strong> <code>0e123456789</code></p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 비밀번호 비교 시뮬레이션',
        'description' => '아래 입력 필드에 `0e`로 시작하는 문자열을 입력하여 비밀번호 비교를 우회해보세요.',
        'payloads' => [
            '0e123456789', // 정확한 값
            '0e123', // 0e로 시작하는 다른 문자열
            '0e987654321', // 0e로 시작하는 또 다른 문자열
            '0', // 숫자 0
            'abc' // 일반 문자열
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>엄격한 타입 비교 사용:</strong> PHP에서 값을 비교할 때는 항상 `===` (strict comparison)를 사용하여 값과 타입 모두를 비교합니다.",
    "<strong>입력 값 검증:</strong> 사용자 입력에 대해 예상되는 타입과 형식에 맞는지 철저히 검증합니다.",
    "<strong>해시 함수 사용:</strong> 비밀번호와 같은 민감한 정보는 비교 전에 항상 강력한 해시 함수(예: `password_hash()`)를 사용하여 해시 값을 비교합니다."
];

// 4. 참고 자료 정의
$references = [
    "PHP Manual - Type Juggling" => "https://www.php.net/manual/en/language.types.type-juggling.php",
    "OWASP - Type Juggling" => "https://owasp.org/www-community/attacks/Type_Juggling"
];

// 5. 테스트 폼 UI 정의
$input_password = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 비밀번호 비교 시뮬레이션</h3>
    <p>아래 입력 필드에 `0e`로 시작하는 문자열을 입력하여 비밀번호 비교를 우회해보세요.</p>
    <label for="payload">비밀번호 입력:</label>
    <input type="text" id="payload" name="payload" value="{$input_password}" placeholder="예: 0e123" required>
    <br><br>
    <button type="submit" name="action" value="check_password" class="btn" style="background: #dc3545;">비밀번호 확인</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $input_password = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    // 시뮬레이션: 취약한 비밀번호 비교 로직
    $expected_password = '0e123456789'; // 숫자형 문자열로 시작하는 해시 값 (MD5 등)

    // === (strict comparison) 대신 == (loose comparison) 사용 시 취약
    if ($input_password == $expected_password) {
        $result = "<span style=\"color: red; font-weight: bold;\">비밀번호 비교 성공!</span><br>";
        $result .= "입력된 값: <code>" . htmlspecialchars($input_password) . "</code><br>";
        $result .= "예상된 값: <code>" . htmlspecialchars($expected_password) . "</code><br>";
        $result .= "PHP의 느슨한 타입 비교(==)로 인해 <code>0e</code>로 시작하는 문자열이 <code>0</code>으로 평가되어 비교가 성공했습니다.";
    } else {
        $result = "비밀번호 비교 실패: 입력된 값이 일치하지 않습니다.";
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Type_Juggling_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>