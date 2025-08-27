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
$page_title = 'Insecure Randomness';
$description = '<p><strong>Insecure Randomness</strong>는 예측 가능한 의사난수 생성기를 사용하여 보안에 중요한 값들을 생성할 때 발생하는 취약점입니다.</p>
<p>이는 세션 ID, 비밀번호 재설정 토큰, 암호화 키 등 민감한 정보의 예측 가능성을 높여 공격자가 이를 악용할 수 있게 합니다.</p>';

// 2. 페이로드 정의 (테스트 유형 설명)
$payloads = [
    'password' => [
        'title' => '패스워드 생성',
        'description' => '임시 패스워드나 초기 패스워드 생성 시 랜덤성 테스트',
        'payloads' => []
    ],
    'token' => [
        'title' => '토큰 생성',
        'description' => 'API 토큰, 인증 토큰 등의 랜덤성 테스트',
        'payloads' => []
    ],
    'session_id' => [
        'title' => '세션 ID 생성',
        'description' => '세션 식별자의 예측 가능성 테스트',
        'payloads' => []
    ],
    'random_numbers' => [
        'title' => '난수 생성',
        'description' => '일반적인 난수 생성 함수의 품질 테스트',
        'payloads' => []
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>암호학적으로 안전한 난수 생성기 사용:</strong> PHP의 `random_bytes()`, `random_int()`와 같은 함수를 사용하여 예측 불가능한 난수를 생성합니다.",
    "<strong>예측 가능한 시드 사용 금지:</strong> `time()`, `microtime()` 등 예측 가능한 값을 난수 생성기의 시드로 사용하지 않습니다.",
    "<strong>난수 품질 검증:</strong> 생성된 난수의 엔트로피를 주기적으로 검증하고, 통계적 테스트를 수행합니다.",
    "<strong>민감한 정보에 난수 적용:</strong> 세션 ID, CSRF 토큰, 비밀번호 재설정 토큰 등 보안에 중요한 모든 값에 강력한 난수를 적용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Insecure Randomness" => "https://owasp.org/www-community/attacks/Insecure_Randomness",
    "PHP Manual - Cryptographically Secure Pseudo-random Number Generator" => "https://www.php.net/manual/en/function.random-bytes.php"
];

// 5. 테스트 폼 UI 정의
$sample_count_input = htmlspecialchars($_POST['sample_count'] ?? 20);
$test_type_selected = htmlspecialchars($_POST['test_type'] ?? 'password');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 난수 품질 분석기</h3>
    <div class="form-group">
        <label for="test_type">테스트 유형:</label>
        <select name="test_type" id="test_type">
            <option value="password" {$test_type_selected === 'password' ? 'selected' : ''}>패스워드 생성</option>
            <option value="token" {$test_type_selected === 'token' ? 'selected' : ''}>토큰 생성</option>
            <option value="session_id" {$test_type_selected === 'session_id' ? 'selected' : ''}>세션 ID 생성</option>
            <option value="random_numbers" {$test_type_selected === 'random_numbers' ? 'selected' : ''}>난수 생성</option>
        </select>
    </div>
    
    <div class="form-group">
        <label for="sample_count">샘플 개수 (최대 100개):</label>
        <input type="number" name="sample_count" id="sample_count" min="5" max="100" value="{$sample_count_input}">
    </div>
    
    <button type="submit" class="btn">난수 생성 및 분석</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $result_html = '';
    $error = '';
    $test_type = $form_data['test_type'] ?? 'password';
    $sample_count = min((int)($form_data['sample_count'] ?? 20), 100);

    $generated_data = [];

    // 취약한 난수 생성 함수 (시뮬레이션용)
    function generateInsecurePassword($length = 8) {
        srand(time());
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $password = '';
        for ($i = 0; $i < $length; $i++) { $password .= $chars[rand(0, strlen($chars) - 1)]; } return $password;
    }
    function generateInsecureToken($length = 16) {
        mt_srand(microtime(true) * 1000);
        $token = '';
        for ($i = 0; $i < $length; $i++) { $token .= dechex(mt_rand(0, 15)); } return $token;
    }
    function generateInsecureSessionId() {
        $user_id = $_SESSION['user_id'] ?? 1; $time = time(); return md5($user_id . $time);
    }

    // 안전한 난수 생성 함수
    function generateSecurePassword($length = 8) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        $password = '';
        for ($i = 0; $i < $length; $i++) { $password .= $chars[random_int(0, strlen($chars) - 1)]; } return $password;
    }
    function generateSecureToken($length = 32) {
        return bin2hex(random_bytes($length / 2));
    }
    function generateSecureSessionId() {
        return bin2hex(random_bytes(32));
    }

    // 분석 함수
    function analyzeRandomness($data_array) {
        $analysis = ['count' => count($data_array), 'unique_count' => count(array_unique($data_array)), 'uniqueness_ratio' => 0, 'patterns' => [], 'entropy' => 0];
        if ($analysis['count'] > 0) {
            $analysis['uniqueness_ratio'] = $analysis['unique_count'] / $analysis['count'];
            for ($i = 0; $i < count($data_array) - 1; $i++) {
                $current = $data_array[$i]; $next = $data_array[$i + 1];
                if (is_numeric($current) && is_numeric($next) && abs($next - $current) <= 1) { $analysis['patterns'][] = "Sequential values detected: $current -> $next"; }
                if ($current === $next) { $analysis['patterns'][] = "Duplicate values: $current"; }
            }
            $value_counts = array_count_values($data_array); $total = count($data_array);
            foreach ($value_counts as $count) { $probability = $count / $total; $analysis['entropy'] -= $probability * log($probability, 2); }
        } return $analysis;
    }

    // VULNERABILITY_MODE는 config.php에서 정의됨
    $vulnerability_enabled = defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true;

    for ($i = 0; $i < $sample_count; $i++) {
        switch ($test_type) {
            case 'password': $generated_data[] = $vulnerability_enabled ? generateInsecurePassword() : generateSecurePassword(); break;
            case 'token': $generated_data[] = $vulnerability_enabled ? generateInsecureToken() : generateSecureToken(); break;
            case 'session_id': $generated_data[] = $vulnerability_enabled ? generateInsecureSessionId() : generateSecureSessionId(); break;
            case 'random_numbers': $generated_data[] = $vulnerability_enabled ? rand(1, 100) : random_int(1, 100); break;
        }
    }
    
    $analysis = analyzeRandomness($generated_data);

    $result_html .= "<h3>분석 결과 - " . htmlspecialchars($test_type) . "</h3>";
    $result_html .= "<p>상태: " . ($vulnerability_enabled ? '취약한 난수 생성 (예측 가능)' : '안전한 난수 생성 (암호학적 보안)') . "</p>";
    $result_html .= "<p>생성된 샘플 수: " . $analysis['count'] . "개</p>";
    $result_html .= "<p>고유값 개수: " . $analysis['unique_count'] . "개</p>";
    $result_html .= "<p>고유성 비율: " . number_format($analysis['uniqueness_ratio'] * 100, 1) . "%</p>";
    $result_html .= "<p>엔트로피: " . number_format($analysis['entropy'], 2) . " bits</p>";

    if (!empty($analysis['patterns'])) {
        $result_html .= "<div class=\"info-box\" style=\"background: #ffebee; border-color: #f44336; color: #d32f2f;\"><strong>⚠️ 발견된 패턴:</strong><ul>";
        foreach ($analysis['patterns'] as $pattern) { $result_html .= "<li>" . htmlspecialchars($pattern) . "</li>"; } $result_html .= "</ul></div>";
    }

    $result_html .= "<details><summary><strong>생성된 데이터 보기</strong></summary><pre><code>";
    foreach ($generated_data as $index => $item) { $result_html .= ($index + 1) . ': ' . htmlspecialchars($item) . "\n"; } $result_html .= "</code></pre></details>";

    return ['result' => $result_html, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
