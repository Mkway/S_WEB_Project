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
$page_title = 'Mass Assignment';
$description = '<p><strong>Mass Assignment</strong>는 사용자로부터 입력받은 데이터를 검증 없이 데이터베이스 모델에 대량으로 할당할 때 발생하는 취약점입니다.</p>
<p>공격자는 사용자가 수정해서는 안 되는 필드(예: `is_admin`, `balance`)를 조작하여 권한 상승이나 데이터 변조를 시도할 수 있습니다.</p>';

// 2. 페이로드 정의 (공격 시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🎯 공격 시나리오',
        'description' => '아래 폼은 사용자 프로필을 업데이트하는 기능을 시뮬레이션합니다. 개발자 도구를 사용하여 숨겨진 필드를 추가하여 `is_admin` 값을 `true`로 변경해 보세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>화이트리스트(Whitelist) 기반 할당:</strong> 모델에 할당할 수 있는 필드를 명시적으로 지정합니다. (예: Laravel의 `$fillable` 속성)",
    "<strong>블랙리스트(Blacklist) 기반 할당:</strong> 할당을 금지할 필드를 명시적으로 지정합니다. (화이트리스트가 더 안전)",
    "<strong>사용자 입력 검증:</strong> 모든 사용자 입력에 대해 엄격한 유효성 검증을 수행합니다.",
    "<strong>민감한 필드 분리:</strong> `is_admin`과 같은 민감한 필드는 별도의 로직으로 처리하고, 사용자 입력으로 직접 변경되지 않도록 합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Mass Assignment" => "https://owasp.org/www-community/attacks/Mass_Assignment",
    "PortSwigger - Logic flaws (관련)" => "https://portswigger.net/web-security/logic-flaws"
];

// 5. 테스트 폼 UI 정의
$user_data = [
    'username' => $_SESSION['username'] ?? 'guest',
    'email' => 'user@example.com',
    'is_admin' => false // 이 필드를 조작하는 것이 목표
];

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 프로필 업데이트 시뮬레이션</h3>
    <p>아래 폼은 사용자 프로필을 업데이트하는 기능을 시뮬레이션합니다. 개발자 도구를 사용하여 숨겨진 필드를 추가하여 <code>is_admin</code> 값을 <code>true</code>로 변경해 보세요.</p>
    <label for="username">사용자 이름:</label>
    <input type="text" id="username" name="username" value="{$user_data['username']}" required><br>
    
    <label for="email">이메일:</label>
    <input type="email" id="email" name="email" value="{$user_data['email']}" required><br>
    
    <!-- 공격자는 개발자 도구를 사용하여 아래와 같은 숨겨진 필드를 추가할 수 있습니다. -->
    <!-- <input type="hidden" name="is_admin" value="true"> -->
    
    <button type="submit" class="btn">프로필 업데이트</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($user_data) {
    $message = '';
    $result_user_data = $user_data; // 초기 데이터 복사

    // 취약한 로직: 모든 POST 데이터를 $result_user_data에 병합
    foreach ($form_data as $key => $value) {
        if (array_key_exists($key, $result_user_data)) {
            $result_user_data[$key] = $value;
        }
    }

    $message .= "프로필 업데이트 시도됨. 결과 확인:\n";
    $message .= "Username: " . htmlspecialchars($result_user_data['username']) . "\n";
    $message .= "Email: " . htmlspecialchars($result_user_data['email']) . "\n";
    $message .= "Is Admin: " . ($result_user_data['is_admin'] ? 'true' : 'false') . "\n";
    $message .= "\n(실제 DB 업데이트는 시뮬레이션되지 않습니다.)";

    return ['result' => "<pre><code>" . htmlspecialchars($message) . "</code></pre>", 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();