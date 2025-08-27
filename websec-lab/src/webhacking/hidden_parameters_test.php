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
$page_title = 'Hidden Parameters';
$description = '<p><strong>Hidden Parameters</strong>는 웹 애플리케이션에서 사용자에게 보이지 않지만, 애플리케이션 로직에 영향을 미치는 매개변수(예: 숨겨진 폼 필드, URL 파라미터, 쿠키)를 의미합니다.</p>
<p>공격자는 이러한 숨겨진 매개변수를 조작하여 가격 변경, 권한 상승, 데이터 변조 등 다양한 공격을 수행할 수 있습니다.</p>
<p>이 페이지에서는 숨겨진 가격 필드와 사용자 유형 필드를 조작하는 시나리오를 시뮬레이션합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 숨겨진 매개변수 조작 시뮬레이션',
        'description' => '아래는 상품 구매 폼을 시뮬레이션합니다. 개발자 도구(F12)를 열어 숨겨진 `price` 필드와 `user_type` 필드를 찾아 값을 조작해보세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>서버 측 검증:</strong> 클라이언트 측에서 전송되는 모든 매개변수는 신뢰할 수 없으므로, 서버 측에서 가격, 권한 등 중요한 값들을 반드시 재검증해야 합니다.",
    "<strong>중요 정보는 서버에서 관리:</strong> 가격, 재고, 사용자 권한 등 민감한 정보는 클라이언트 측에 숨겨진 필드로 전송하지 않고, 서버 측 세션이나 데이터베이스에서 관리합니다.",
    "<strong>토큰 사용:</strong> 중요한 폼 제출 시 CSRF 토큰과 유사하게, 일회성 토큰을 사용하여 폼의 무결성을 검증합니다.",
    "<strong>최소 권한 원칙:</strong> 애플리케이션이 외부 변수를 통해 접근할 수 있는 권한을 최소화합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Mass Assignment (관련)" => "https://owasp.org/www-community/attacks/Mass_Assignment",
    "PortSwigger - Logic flaws (관련)" => "https://portswigger.net/web-security/logic-flaws"
];

// 5. 테스트 폼 UI 정의
$item_price = 100; // 기본 상품 가격
$is_admin = false; // 기본 관리자 권한

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 숨겨진 매개변수 조작 시뮬레이션</h3>
    <p>아래는 상품 구매 폼을 시뮬레이션합니다. 개발자 도구(F12)를 열어 숨겨진 <code>price</code> 필드와 <code>user_type</code> 필드를 찾아 값을 조작해보세요.</p>
    <p><strong>원래 상품 가격:</strong> <code>{$item_price}</code>원</p>
    <p><strong>현재 사용자 유형:</strong> <code>guest</code></p>
    
    <!-- 숨겨진 필드 (공격자가 조작할 수 있는 대상) -->
    <input type="hidden" name="price" value="{$item_price}">
    <input type="hidden" name="user_type" value="guest">

    <br>
    <button type="submit" name="action" value="check_role" class="btn" style="background: #dc3545;">구매 시도 / 역할 확인</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $result = '';
    $error = '';
    $item_price = 100; // 서버 측에서 정의된 원래 가격

    // 가격 조작 시뮬레이션
    if (isset($form_data['price'])) {
        $submitted_price = (int)$form_data['price'];
        if ($submitted_price < $item_price) {
            $result .= "<span style=\"color: red; font-weight: bold;\">가격 조작 시도 감지!</span><br>";
            $result .= "제출된 가격: " . htmlspecialchars($submitted_price) . "원 (원래 가격: " . $item_price . "원)<br>";
            $result .= "만약 서버에서 검증하지 않았다면, 공격자는 더 낮은 가격으로 상품을 구매할 수 있었을 것입니다.";
        } else {
            $result .= "제출된 가격: " . htmlspecialchars($submitted_price) . "원 (정상 처리)<br>";
        }
    }

    // 관리자 권한 조작 시뮬레이션
    if (isset($form_data['user_type']) && $form_data['user_type'] === 'admin') {
        $result .= "<br><span style=\"color: red; font-weight: bold;\">관리자 권한 획득 시도 감지!</span><br>";
        $result .= "만약 서버에서 검증하지 않았다면, 공격자는 관리자 페이지에 접근할 수 있었을 것입니다.";
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();