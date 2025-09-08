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
$page_title = 'NoSQL Injection (MongoDB)';
$description = '<p><strong>NoSQL Injection</strong>은 NoSQL 데이터베이스에서 발생하는 인젝션 공격입니다.</p>
<p>MongoDB Operator 조작, JavaScript Expression Injection, Authentication Bypass 등이 가능합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'operator_bypass' => [
        'title' => '연산자 인젝션 ($ne, $gt 등)',
        'description' => 'MongoDB 연산자를 이용한 인증 우회 공격입니다.',
        'payloads' => [
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": "admin", "password": {"$gt": ""}}',
            '{"$or": [{"username": "admin"}, {"role": "administrator"}]}'
        ]
    ],
    'javascript_injection' => [
        'title' => 'JavaScript 표현식 인젝션',
        'description' => '$where 절에서 JavaScript 코드를 실행하는 공격입니다.',
        'payloads' => [
            "'; return true; var dummy='",
            "'; sleep(5000); return true; //",
            "'; db.users.drop(); return true; //"
        ]
    ],
    'regex_injection' => [
        'title' => '정규식 인젝션',
        'description' => '정규식을 이용한 데이터 추출 공격입니다.',
        'payloads' => [
            '{"username": {"$regex": ".*"}}',
            '{"password": {"$regex": "^a"}}',
            '{"email": {"$regex": "admin.*", "$options": "i"}}'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>타입 검증:</strong> 입력값이 문자열인지 검증 (`is_string()` 사용)",
    "<strong>화이트리스트:</strong> 허용된 필드와 값만 사용",
    "<strong>$where 절 금지:</strong> JavaScript 실행 가능한 연산자 사용 금지",
    "<strong>입력 길이 제한:</strong> 과도하게 긴 입력값 차단",
    "<strong>MongoDB ODM 사용:</strong> Doctrine ODM 등으로 안전한 쿼리 구성",
    "<strong>최소 권한:</strong> 데이터베이스 사용자 권한 최소화"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - NoSQL Injection" => "https://owasp.org/www-community/attacks/NoSQL_injection",
    "MongoDB Security Checklist" => "https://docs.mongodb.com/manual/administration/security-checklist/"
];

// 5. 테스트 폼 UI 정의
$test_type = htmlspecialchars($_POST['test_type'] ?? 'login');
$username = htmlspecialchars($_POST['username'] ?? '');
$password = htmlspecialchars($_POST['password'] ?? '');
$search_term = htmlspecialchars($_POST['search_term'] ?? '');
$json_payload = htmlspecialchars($_POST['json_payload'] ?? '');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 NoSQL Injection 테스트</h3>
    
    <label for="test_type">🎯 테스트 유형 선택:</label>
    <select id="test_type" name="test_type" onchange="toggleInputs()">
        <option value="login" {$test_type === 'login' ? 'selected' : ''}>로그인 우회 (Operator Injection)</option>
        <option value="search" {$test_type === 'search' ? 'selected' : ''}>제품 검색 (JavaScript Injection)</option>
        <option value="json" {$test_type === 'json' ? 'selected' : ''}>JSON 페이로드 (Direct Query)</option>
    </select><br><br>
    
    <div id="login-inputs" style="display: {$test_type === 'login' ? 'block' : 'none'}">
        <label for="username">👤 사용자명:</label>
        <input type="text" id="username" name="username" value="{$username}" placeholder="admin 또는 {'$ne': null}"><br><br>
        
        <label for="password">🔒 패스워드:</label>
        <input type="text" id="password" name="password" value="{$password}" placeholder="password 또는 {'$gt': ''}"><br><br>
    </div>
    
    <div id="search-inputs" style="display: {$test_type === 'search' ? 'block' : 'none'}">
        <label for="search_term">🔍 검색어:</label>
        <input type="text" id="search_term" name="search_term" value="{$search_term}" placeholder="laptop 또는 '; sleep(5000); //"><br><br>
    </div>
    
    <div id="json-inputs" style="display: {$test_type === 'json' ? 'block' : 'none'}">
        <label for="json_payload">📝 JSON 페이로드:</label><br>
        <textarea id="json_payload" name="json_payload" placeholder='{"username": {"$ne": null}}'>{$json_payload}</textarea><br><br>
    </div>
    
    <button type="submit" class="btn">NoSQL 쿼리 실행</button>
</form>

<script>
function toggleInputs() {
    const testType = document.getElementById('test_type').value;
    document.getElementById('login-inputs').style.display = testType === 'login' ? 'block' : 'none';
    document.getElementById('search-inputs').style.display = testType === 'search' ? 'block' : 'none';
    document.getElementById('json-inputs').style.display = testType === 'json' ? 'block' : 'none';
}
</script>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $test_type = $form_data['test_type'] ?? 'login';
    $result = '';
    $error = '';

    try {
        require_once __DIR__ . '/../database/MongoDBConnection.php';
        $mongo = new MongoDBConnection();
        
        if (!$mongo->isConnected()) {
            $error = "MongoDB 연결에 실패했습니다.";
            return ['result' => '', 'error' => $error];
        }

        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 NoSQL 쿼리 실행 결과</h4>";
        $result .= "<p><strong>테스트 유형:</strong> " . strtoupper($test_type) . "</p>";
        
        switch ($test_type) {
            case 'login':
                $username = $form_data['username'] ?? '';
                $password = $form_data['password'] ?? '';
                
                // JSON 형태 입력 처리 시도
                if (strpos($username, '{') === 0 || strpos($password, '{') === 0) {
                    $username_obj = json_decode($username, true) ?? $username;
                    $password_obj = json_decode($password, true) ?? $password;
                    
                    if (is_array($username_obj) || is_array($password_obj)) {
                        $result .= "<p class='danger'>🔥 <strong>MongoDB Operator Injection 감지!</strong></p>";
                        $result .= "<p><strong>입력 데이터:</strong></p>";
                        $result .= "<pre class='attack-result'>Username: " . htmlspecialchars($username) . "\nPassword: " . htmlspecialchars($password) . "</pre>";
                    }
                } else {
                    $username_obj = $username;
                    $password_obj = $password;
                }
                
                $login_result = $mongo->vulnerableLogin($username_obj, $password_obj);
                
                if ($login_result) {
                    $result .= "<p class='danger'>🔥 <strong>로그인 우회 성공!</strong> 인증 없이 사용자 정보 획득</p>";
                    $result .= "<p><strong>노출된 사용자 정보:</strong></p>";
                    $result .= "<pre class='attack-result'>" . htmlspecialchars(json_encode($login_result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) . "</pre>";
                } else {
                    $result .= "<p class='warning'>⚠️ 로그인 실패 또는 사용자 없음</p>";
                }
                break;
                
            case 'search':
                $search_term = $form_data['search_term'] ?? '';
                
                if (strpos($search_term, ';') !== false || strpos($search_term, 'sleep') !== false) {
                    $result .= "<p class='danger'>🔥 <strong>JavaScript Injection 시도 감지!</strong></p>";
                }
                
                $result .= "<p><strong>검색어:</strong> " . htmlspecialchars($search_term) . "</p>";
                
                try {
                    $search_results = $mongo->vulnerableProductSearch($search_term);
                    
                    if (!empty($search_results)) {
                        $result .= "<p class='warning'>⚠️ <strong>검색 결과:</strong> " . count($search_results) . "개 제품 발견</p>";
                        $result .= "<pre class='attack-result'>";
                        foreach (array_slice($search_results, 0, 3) as $product) {
                            $result .= htmlspecialchars(json_encode($product, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) . "\n---\n";
                        }
                        $result .= "</pre>";
                    } else {
                        $result .= "<p class='success'>✅ 검색 결과 없음</p>";
                    }
                } catch (Exception $e) {
                    $result .= "<p class='error'>❌ JavaScript 실행 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
                }
                break;
                
            case 'json':
                $json_payload = $form_data['json_payload'] ?? '';
                
                if (empty($json_payload)) {
                    $error = "JSON 페이로드를 입력해주세요.";
                    return ['result' => '', 'error' => $error];
                }
                
                $query = json_decode($json_payload, true);
                if ($query === null) {
                    $result .= "<p class='error'>❌ 유효하지 않은 JSON 형식</p>";
                } else {
                    $result .= "<p class='danger'>🔥 <strong>직접 쿼리 실행!</strong></p>";
                    $result .= "<p><strong>실행된 쿼리:</strong></p>";
                    $result .= "<pre class='attack-result'>" . htmlspecialchars($json_payload) . "</pre>";
                    
                    try {
                        $data_results = $mongo->vulnerableDataCollection($query);
                        
                        if (!empty($data_results)) {
                            $result .= "<p class='danger'>🔥 <strong>데이터 노출!</strong> " . count($data_results) . "개 레코드 발견</p>";
                            $result .= "<pre class='attack-result'>";
                            foreach (array_slice($data_results, 0, 2) as $record) {
                                $result .= htmlspecialchars(json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) . "\n---\n";
                            }
                            $result .= "</pre>";
                        } else {
                            $result .= "<p class='success'>✅ 쿼리 결과 없음</p>";
                        }
                    } catch (Exception $e) {
                        $result .= "<p class='error'>❌ 쿼리 실행 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
                    }
                }
                break;
        }
        
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 NoSQL 쿼리 구현</h4>";
        
        switch ($test_type) {
            case 'login':
                $username = $form_data['username'] ?? '';
                $password = $form_data['password'] ?? '';
                
                // 타입 검증
                if (!is_string($username) || !is_string($password)) {
                    $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 비문자열 입력 감지</p>";
                } elseif (strlen($username) > 50 || strlen($password) > 100) {
                    $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 입력 길이 제한 초과</p>";
                } else {
                    $safe_result = $mongo->safeLogin($username, $password);
                    if ($safe_result) {
                        $result .= "<p class='success'>✅ <strong>안전한 로그인 성공</strong></p>";
                    } else {
                        $result .= "<p class='success'>✅ <strong>안전한 로그인 실패</strong> - 올바른 인증 필요</p>";
                    }
                }
                break;
                
            case 'search':
                $search_term = $form_data['search_term'] ?? '';
                
                if (strpos($search_term, ';') !== false || strpos($search_term, 'sleep') !== false) {
                    $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 위험한 JavaScript 패턴 감지</p>";
                } else {
                    $safe_results = $mongo->safeProductSearch($search_term);
                    $result .= "<p class='success'>✅ <strong>안전한 검색 완료:</strong> " . count($safe_results) . "개 결과</p>";
                }
                break;
                
            case 'json':
                $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 직접 JSON 쿼리는 보안상 허용되지 않습니다.</p>";
                $result .= "<p><strong>대안:</strong> 미리 정의된 안전한 쿼리 메서드 사용</p>";
                break;
        }
        
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🔒 NoSQL Injection 방어 권장사항</h4>";
        $result .= "<ul>";
        $result .= "<li><strong>타입 검증:</strong> 입력값이 예상된 타입(문자열)인지 확인</li>";
        $result .= "<li><strong>화이트리스트:</strong> 허용된 필드와 연산자만 사용</li>";
        $result .= "<li><strong>\$where 절 금지:</strong> JavaScript 실행 가능한 연산자 사용 금지</li>";
        $result .= "<li><strong>입력 길이 제한:</strong> 과도하게 긴 입력값 차단</li>";
        $result .= "<li><strong>ODM 사용:</strong> Object-Document Mapping 라이브러리 사용</li>";
        $result .= "<li><strong>최소 권한:</strong> 데이터베이스 사용자 권한 최소화</li>";
        $result .= "<li><strong>로그 모니터링:</strong> 비정상적인 쿼리 패턴 감지</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $error = "MongoDB 연결 또는 쿼리 실행 중 오류: " . $e->getMessage();
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "NoSQL_Injection_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();