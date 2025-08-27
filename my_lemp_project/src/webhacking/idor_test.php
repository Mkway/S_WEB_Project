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

// 현재 사용자 ID (세션에서)
$current_user_id = $_SESSION['user_id'] ?? 1; // 로그인되지 않은 경우 기본값 1

// 모의 데이터베이스 (테스트용)
$mock_data = [
    'users' => [
        1 => ['name' => 'Alice', 'email' => 'alice@example.com', 'role' => 'user'],
        2 => ['name' => 'Bob', 'email' => 'bob@example.com', 'role' => 'admin'],
        3 => ['name' => 'Charlie', 'email' => 'charlie@example.com', 'role' => 'user']
    ],
    'documents' => [
        1 => ['title' => 'My Personal Notes', 'owner_id' => 1, 'content' => 'Private notes...'],
        2 => ['title' => 'Admin Report', 'owner_id' => 2, 'content' => 'Confidential admin data...'],
        3 => ['title' => 'Project Plan', 'owner_id' => 3, 'content' => 'Project details...']
    ],
    'orders' => [
        100 => ['product' => 'Laptop', 'customer_id' => 1, 'amount' => 1200],
        101 => ['product' => 'Phone', 'customer_id' => 3, 'amount' => 800],
        102 => ['product' => 'Tablet', 'customer_id' => 1, 'amount' => 500]
    ]
];

// 1. 페이지 설정
$page_title = 'IDOR (Insecure Direct Object References)';
$description = '<p><strong>IDOR</strong>는 애플리케이션이 사용자 입력을 직접 객체 참조로 사용하여 적절한 권한 검사 없이 데이터에 접근을 허용하는 취약점입니다.</p>
<p>공격자가 URL 파라미터나 폼 필드의 값을 변경하여 다른 사용자의 데이터에 접근할 수 있습니다.</p>
<p><strong>참고:</strong> 이 페이지에서는 모의 데이터를 사용하여 안전한 환경에서 테스트합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'numeric_id' => [
        'title' => '🔢 Numeric ID Enumeration',
        'description' => '순차적인 숫자 ID를 이용한 기본적인 IDOR 공격입니다.',
        'payloads' => [
            '1', '2', '3', '10', '100'
        ]
    ],
    'encoded_payloads' => [
        'title' => '🔄 Encoded Parameter Manipulation',
        'description' => 'URL 인코딩이나 다른 인코딩을 통한 필터 우회 시도입니다.',
        'payloads' => [
            '%31', '%32', '%33' // URL encoded 1,2,3
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>인증 및 권한 검사:</strong> 모든 요청에서 사용자 권한 확인",
    "<strong>간접 참조 사용:</strong> 직접적인 객체 ID 대신 매핑 테이블 사용",
    "<strong>UUID 사용:</strong> 예측 가능한 순차 ID 대신 UUID 사용",
    "<strong>세션 기반 검증:</strong> 세션 정보와 요청 객체의 소유권 확인",
    "<strong>접근 제어 목록 (ACL):</strong> 각 객체별 접근 권한 정의"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - IDOR Testing" => "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    "PortSwigger - IDOR" => "https://portswigger.net/web-security/access-control/idor"
];

// 5. 테스트 폼 UI 정의
$resource_id = htmlspecialchars($_POST["payload"] ?? '');
$test_type = htmlspecialchars($_POST['test_type'] ?? 'user_id');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #d4edda; border-color: #c3e6cb; color: #155724;">
    <strong>현재 세션 정보:</strong><br>
    사용자 ID: {$current_user_id}<br>
    사용자명: {$_SESSION['username'] ?? 'Guest'}<br>
    <small>이 정보를 기준으로 권한 검사가 수행됩니다.</small>
</div>

<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7; color: #856404;">
    <h3>💡 IDOR 공격 시나리오</h3>
    <p><strong>시나리오 1:</strong> 사용자 프로필 페이지</p>
    <code>profile.php?user_id=1</code> → <code>profile.php?user_id=2</code> (다른 사용자 정보 열람)
    <br><br>
    <p><strong>시나리오 2:</strong> 문서 다운로드</p>
    <code>download.php?doc_id=123</code> → <code>download.php?doc_id=124</code> (타인의 文서 다운로드)
</div>

<form method="post" class="test-form">
    <h3>🧪 IDOR 테스트</h3>
    
    <div class="test-type-selector">
        <label><input type="radio" name="test_type" value="user_id" {$test_type === 'user_id' ? 'checked' : ''}> 사용자 정보 (User ID)</label>
        <label><input type="radio" name="test_type" value="document" {$test_type === 'document' ? 'checked' : ''}> 문서 접근 (Document ID)</label>
        <label><input type="radio" name="test_type" value="order" {$test_type === 'order' ? 'checked' : ''}> 주문 정보 (Order ID)</label>
    </div>
    
    <label for="payload">리소스 ID:</label>
    <input type="text" name="payload" id="payload" placeholder="예: 1, 2, 3, %31, etc." value="{$resource_id}">
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">IDOR 테스트 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($mock_data, $current_user_id) {
    $id = $form_data['payload'] ?? '';
    $test_type = $form_data['test_type'] ?? 'user_id';
    $result = '';
    $error = '';

    $decoded_id = urldecode($id);
    $numeric_id = (int)filter_var($decoded_id, FILTER_SANITIZE_NUMBER_INT);

    $result_html = "<pre>🔍 IDOR 테스트 결과\n\n";
    $result_html .= "원본 입력: " . htmlspecialchars($id) . "\n";
    $result_html .= "디코드된 값: " . htmlspecialchars($decoded_id) . "\n";
    $result_html .= "정규화된 ID: " . htmlspecialchars($numeric_id) . "\n\n";

    switch ($test_type) {
        case 'user_id':
            if (isset($mock_data['users'][$numeric_id])) {
                $user = $mock_data['users'][$numeric_id];
                if ($numeric_id == $current_user_id) {
                    $result_html .= "✅ 사용자 정보 접근 성공 (본인):\n";
                } else {
                    $result_html .= "⚠️ IDOR 취약점 감지! (다른 사용자 정보 접근 시도)\n";
                }
                $result_html .= "이름: " . htmlspecialchars($user['name']) . "\n";
                $result_html .= "이메일: " . htmlspecialchars($user['email']) . "\n";
                $result_html .= "역할: " . htmlspecialchars($user['role']) . "\n";
            } else {
                $result_html .= "❌ 사용자 ID " . htmlspecialchars($numeric_id) . "를 찾을 수 없습니다.\n";
            }
            break;
        case 'document':
            if (isset($mock_data['documents'][$numeric_id])) {
                $doc = $mock_data['documents'][$numeric_id];
                if ($doc['owner_id'] == $current_user_id) {
                    $result_html .= "✅ 문서 접근 성공 (본인 소유):\n";
                } else {
                    $result_html .= "⚠️ IDOR 취약점 감지! (다른 사용자 문서 접근 시도)\n";
                }
                $result_html .= "제목: " . htmlspecialchars($doc['title']) . "\n";
                $result_html .= "내용: " . htmlspecialchars($doc['content']) . "\n";
            } else {
                $result_html .= "❌ 문서 ID " . htmlspecialchars($numeric_id) . "를 찾을 수 없습니다.\n";
            }
            break;
        case 'order':
            if (isset($mock_data['orders'][$numeric_id])) {
                $order = $mock_data['orders'][$numeric_id];
                if ($order['customer_id'] == $current_user_id) {
                    $result_html .= "✅ 주문 정보 접근 성공 (본인 주문):\n";
                } else {
                    $result_html .= "⚠️ IDOR 취약점 감지! (다른 고객 주문 접근 시도)\n";
                }
                $result_html .= "상품: " . htmlspecialchars($order['product']) . "\n";
                $result_html .= "금액: $" . htmlspecialchars($order['amount']) . "\n";
            } else {
                $result_html .= "❌ 주문 ID " . htmlspecialchars($numeric_id) . "를 찾을 수 없습니다.\n";
            }
            break;
    }
    $result_html .= "</pre>";

    return ['result' => $result_html, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
