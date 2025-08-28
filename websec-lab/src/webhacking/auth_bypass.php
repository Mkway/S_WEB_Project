<?php
// 출력 버퍼링 시작 (헤더 전송 문제 방지)
ob_start();

// 세션 시작 (TestPage 전에)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

require_once 'TestPage.php';

// 모의 사용자 데이터베이스
$mock_users = [
    'admin' => ['password' => 'admin123', 'role' => 'administrator'],
    'user' => ['password' => 'user123', 'role' => 'user'],
    'guest' => ['password' => 'guest123', 'role' => 'guest']
];

// 1. 페이지 설정
$page_title = 'Authentication Bypass';
$description = '<p><strong>Authentication Bypass</strong>는 정상적인 인증 과정을 우회하여 시스템에 무단으로 접근하는 공격 기법입니다.</p>
<p>SQL Injection, NoSQL Injection, LDAP Injection 등 다양한 방법으로 인증을 우회할 수 있습니다.</p>
<p><strong>참고:</strong> 이 페이지에서는 모의 인증 시스템을 사용하여 안전한 환경에서 테스트합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'sql_injection_auth' => [
        'title' => '💉 SQL Injection Authentication Bypass',
        'description' => 'SQL 주입을 통한 인증 우회 공격입니다. 가장 일반적이고 효과적인 방법입니다.',
        'payloads' => [
            "admin'--",
            "admin' OR '1'='1'--",
            "' OR '1'='1'--",
            "' UNION SELECT 1,'admin','password'--"
        ]
    ],
    'nosql_injection' => [
        'title' => '🍃 NoSQL Injection Authentication Bypass',
        'description' => 'MongoDB 등 NoSQL 데이터베이스의 연산자를 악용한 인증 우회입니다.',
        'payloads' => [
            '{\"$ne\": \"\"}',
            '{\"$gt\": \"\"}',
            '{\"$regex\": \"(.*)\"}'
        ]
    ],
    'ldap_injection' => [
        'title' => '📁 LDAP Injection Authentication Bypass',
        'description' => 'LDAP 디렉토리 서비스의 필터 구조를 조작하여 인증을 우회하는 공격입니다.',
        'payloads' => [
            'admin)(&))',
            '*)(uid=*))(|(uid=*',
            '*))(|(objectClass=*'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>준비된 문 사용:</strong> SQL Injection 방지를 위한 Prepared Statements",
    "<strong>입력 검증:</strong> 모든 사용자 입력에 대한 엄격한 검증",
    "<strong>최소 권한 원칙:</strong> 데이터베이스 사용자 권한 최소화",
    "<strong>강력한 인증:</strong> 2FA, 생체 인식 등 다중 인증 방식",
    "<strong>세션 관리:</strong> 안전한 세션 토큰 및 만료 시간 설정",
    "<strong>로깅 및 모니터링:</strong> 로그인 시도 및 실패 모니터링",
    "<strong>Rate Limiting:</strong> 무차별 대입 공격 방지",
    "<strong>암호화:</strong> 비밀번호 해시 및 전송 구간 암호화"
];

// 4. 참고 자료 정의
$references = [
    "PayloadsAllTheThings - Authentication Bypass" => "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass",
    "OWASP - Authentication Testing" => "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/",
    "PortSwigger - Authentication vulnerabilities" => "https://portswigger.net/web-security/authentication"
];

// 5. 테스트 폼 UI 정의
$username_input = htmlspecialchars($_POST['username'] ?? '');
$password_input = htmlspecialchars($_POST['password'] ?? '');
$test_type_selected = htmlspecialchars($_POST['test_type'] ?? 'sql_auth');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #d4edda; border-color: #c3e6cb; color: #155724;">
    <h3>🔑 테스트 계정 정보</h3>
    <p>정상적인 로그인 테스트를 위한 계정들:</p>
    <ul>
        <li><strong>admin</strong> / admin123 (관리자)</li>
        <li><strong>user</strong> / user123 (일반 사용자)</li>
        <li><strong>guest</strong> / guest123 (게스트)</li>
    </ul>
</div>

<form method="post" class="test-form">
    <h3>🧪 Authentication Bypass 테스트</h3>
    
    <div class="test-type-selector">
        <label><input type="radio" name="test_type" value="sql_auth" <?= $test_type_selected === 'sql_auth' ? 'checked' : '' ?>> SQL Injection Auth</label>
        <label><input type="radio" name="test_type" value="nosql_auth" <?= $test_type_selected === 'nosql_auth' ? 'checked' : '' ?>> NoSQL Injection Auth</label>
        <label><input type="radio" name="test_type" value="ldap_auth" <?= $test_type_selected === 'ldap_auth' ? 'checked' : '' ?>> LDAP Injection Auth</label>
    </div>
    
    <label for="username">사용자명:</label>
    <input type="text" name="username" id="username" placeholder="사용자명 또는 페이로드 입력" value="{$username_input}">
    
    <label for="password">비밀번호:</label>
    <input type="password" name="password" id="password" placeholder="비밀번호 또는 페이로드 입력" value="{$password_input}">
    
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">인증 테스트 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($mock_users) {
    $result_html = '';
    $error = '';
    $username = $form_data['username'] ?? '';
    $password = $form_data['password'] ?? '';
    $test_type = $form_data['test_type'] ?? 'sql_auth';

    // 취약한 인증 우회 실행
    $result_html .= "<div class='info-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result_html .= "<strong>⚠️ 취약한 인증 시스템 실행:</strong><br>";
    $result_html .= "사용자명: <code>" . htmlspecialchars($username) . "</code><br>";
    $result_html .= "비밀번호: <code>" . htmlspecialchars($password) . "</code>";
    $result_html .= "</div>";

    $result_html .= "<div class='vulnerable-output' style='background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 15px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result_html .= "<strong>Authentication Bypass 테스트 결과:</strong><br>";

    // 취약한 인증 구현 시뮬레이션
    switch ($test_type) {
        case 'sql_auth':
            // SQL 인젝션 기반 인증 우회
            $vulnerable_query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
            $result_html .= "<strong>취약한 SQL 쿼리:</strong><br>";
            $result_html .= "<code>" . htmlspecialchars($vulnerable_query) . "</code><br><br>";
            
            // SQL 인젝션 패턴 체크
            if (preg_match("/'/", $username) || preg_match("/--/", $username) || 
                preg_match("/ OR /i", $username) || preg_match("/ UNION /i", $username)) {
                $result_html .= "<strong>✅ SQL 인젝션 공격 성공!</strong><br>";
                $result_html .= "🎯 <strong>관리자 권한으로 로그인 성공</strong><br>";
                $result_html .= "사용자: admin<br>";
                $result_html .= "역할: administrator<br>";
                $result_html .= "<em>SQL 쿼리가 조작되어 인증이 우회되었습니다!</em><br>";
            } else {
                // 정상 로그인 시도
                $clean_username = strtolower(trim($username));
                if (isset($mock_users[$clean_username]) && $mock_users[$clean_username]['password'] === $password) {
                    $result_html .= "<strong>✅ 정상 로그인 성공</strong><br>";
                    $result_html .= "사용자: " . htmlspecialchars($clean_username) . "<br>";
                    $result_html .= "역할: " . htmlspecialchars($mock_users[$clean_username]['role']);
                } else {
                    $result_html .= "<strong>❌ 로그인 실패</strong><br>";
                    $result_html .= "유효하지 않은 자격증명입니다.";
                }
            }
            break;
            
        case 'nosql_auth':
            $result_html .= "<strong>취약한 NoSQL 쿼리:</strong><br>";
            $result_html .= "<code>db.users.find({username: \"$username\", password: \"$password\"})</code><br><br>";
            
            // NoSQL 인젝션 패턴 체크
            if (preg_match("/\{.*\\\$ne.*\}/", $username) || preg_match("/\{.*\\\$gt.*\}/", $username) ||
                preg_match("/\{.*\\\$regex.*\}/", $username)) {
                $result_html .= "<strong>✅ NoSQL 인젝션 공격 성공!</strong><br>";
                $result_html .= "🎯 <strong>관리자 권한으로 로그인 성공</strong><br>";
                $result_html .= "사용자: admin<br>";
                $result_html .= "역할: administrator<br>";
                $result_html .= "<em>NoSQL 연산자가 악용되어 인증이 우회되었습니다!</em><br>";
            } else {
                $result_html .= "<strong>❌ NoSQL 인젝션 실패</strong><br>";
                $result_html .= "올바른 NoSQL 인젝션 페이로드를 사용하세요.";
            }
            break;
            
        case 'ldap_auth':
            $vulnerable_ldap = "(&(uid=$username)(password=$password))";
            $result_html .= "<strong>취약한 LDAP 필터:</strong><br>";
            $result_html .= "<code>" . htmlspecialchars($vulnerable_ldap) . "</code><br><br>";
            
            // LDAP 인젝션 패턴 체크
            if (preg_match("/\)\(/", $username) || preg_match("/\*\)/", $username)) {
                $result_html .= "<strong>✅ LDAP 인젝션 공격 성공!</strong><br>";
                $result_html .= "🎯 <strong>관리자 권한으로 로그인 성공</strong><br>";
                $result_html .= "사용자: admin<br>";
                $result_html .= "역할: administrator<br>";
                $result_html .= "<em>LDAP 필터가 조작되어 인증이 우회되었습니다!</em><br>";
            } else {
                $result_html .= "<strong>❌ LDAP 인젝션 실패</strong><br>";
                $result_html .= "올바른 LDAP 인젝션 페이로드를 사용하세요.";
            }
            break;
    }
    $result_html .= "</div>";

    // 안전한 구현과 비교
    $result_html .= "<div class='info-box' style='background: #d4edda; border-color: #c3e6cb; color: #155724; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result_html .= "<strong>✅ 안전한 구현이었다면:</strong><br>";
    
    switch ($test_type) {
        case 'sql_auth':
            $result_html .= "준비된 문(Prepared Statement) 사용:<br>";
            $result_html .= "<code>SELECT * FROM users WHERE username = ? AND password = ?</code>";
            break;
        case 'nosql_auth':
            $result_html .= "적절한 타입 검증과 쿼리 빌더 사용:<br>";
            $result_html .= "<code>db.users.find({username: {\$type: 'string'}, password: {\$type: 'string'}})</code>";
            break;
        case 'ldap_auth':
            $result_html .= "LDAP 이스케이프 함수 사용:<br>";
            $result_html .= "<code>ldap_escape($username) 및 ldap_escape($password)</code>";
            break;
    }
    $result_html .= "</div>";

    // 보안 권장사항
    $result_html .= "<div class='info-box' style='background: #d1ecf1; border-color: #bee5eb; color: #0c5460; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
    $result_html .= "<strong>🛡️ 보안 권장사항:</strong><br>";
    $result_html .= "- 준비된 문(Prepared Statement) 사용<br>";
    $result_html .= "- 입력 검증 및 타입 체크<br>";
    $result_html .= "- 강력한 비밀번호 정책<br>";
    $result_html .= "- 다중 인증(MFA) 구현<br>";
    $result_html .= "- 로그인 시도 제한 및 모니터링";
    $result_html .= "</div>";

    return ['result' => $result_html, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Authentication_Bypass_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>