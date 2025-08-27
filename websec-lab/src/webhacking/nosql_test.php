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
$page_title = 'NoSQL Injection';
$description = '<p><strong>NoSQL Injection</strong>은 NoSQL 데이터베이스에서 사용자 입력을 안전하게 처리하지 않을 때 발생하는 취약점입니다.</p>
<p>MongoDB, CouchDB, Redis 등 다양한 NoSQL DB에서 인증 우회, 데이터 추출, 코드 실행이 가능합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'mongodb' => [
        'title' => '📋 MongoDB 테스트 페이로드',
        'description' => 'MongoDB의 쿼리 연산자를 악용하여 인증 우회, 데이터 추출, 코드 실행을 시도합니다.',
        'payloads' => [
            '{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}', // 인증 우회
            '{\"username\": {\"$regex\": \"^admin\"}}', // 데이터 추출
            '{\"$where\": \"this.username == \\\"admin\\\"\"}' // 코드 실행
        ]
    ],
    'couchdb' => [
        'title' => '📋 CouchDB 테스트 페이로드',
        'description' => 'CouchDB의 뷰(View)나 JavaScript 함수를 악용하여 데이터를 조작하거나 정보를 노출합니다.',
        'payloads' => [
            '_design/malicious/_view/users', // 뷰 조작
            'function(doc){emit(doc._id, eval(\"malicious_code\"))}' // JavaScript 실행
        ]
    ],
    'redis' => [
        'title' => '📋 Redis 테스트 페이로드',
        'description' => 'Redis의 명령어를 악용하여 데이터 삭제, 설정 변경, 임의 코드 실행을 시도합니다.',
        'payloads' => [
            'EVAL "redis.call(\"flushall\")" 0', // Lua 스크립트 실행
            'CONFIG SET dir /var/www/html/', // 설정 변경
            'FLUSHALL' // 데이터 삭제
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 검증:</strong> 모든 사용자 입력에 대한 엄격한 검증",
    "<strong>화이트리스트:</strong> 허용된 연산자와 함수만 사용 허용",
    "<strong>매개변수화:</strong> 쿼리와 데이터 분리 (Prepared Statements 개념)",
    "<strong>최소 권한:</strong> 데이터베이스 사용자 권한 최소화",
    "<strong>스키마 검증:</strong> 입력 데이터의 스키마 검증",
    "<strong>특수 문자 이스케이프:</strong> NoSQL 연산자 문자 이스케이프"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - NoSQL Injection" => "https://owasp.org/www-community/attacks/NoSQL_Injection",
    "PortSwigger - NoSQL injection" => "https://portswigger.net/web-security/nosql-injection"
];

// 5. 테스트 폼 UI 정의
$query_input = htmlspecialchars($_POST['payload'] ?? '');
$db_type = htmlspecialchars($_POST['db_type'] ?? 'mongodb');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 NoSQL 쿼리/명령 테스트</h3>
    <label for="db_type">🗄️ 데이터베이스 유형 선택:</label><br>
    <select id="db_type" name="db_type">
        <option value="mongodb" {$db_type === 'mongodb' ? 'selected' : ''}>MongoDB</option>
        <option value="couchdb" {$db_type === 'couchdb' ? 'selected' : ''}>CouchDB</option>
        <option value="redis" {$db_type === 'redis' ? 'selected' : ''}>Redis</option>
        <option value="elasticsearch" {$db_type === 'elasticsearch' ? 'selected' : ''}>Elasticsearch</option>
        <option value="cassandra" {$db_type === 'cassandra' ? 'selected' : ''}>Cassandra</option>
    </select><br><br>
    
    <label for="payload">🎯 NoSQL 쿼리/명령 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="NoSQL 쿼리나 명령을 입력하세요...">{$query_input}</textarea><br><br>
    <button type="submit" class="btn">쿼리 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $query_input = $form_data['payload'] ?? '';
    $db_type = $form_data['db_type'] ?? 'mongodb';
    $result = '';
    $error = '';

    if (empty($query_input)) {
        $error = "NoSQL 쿼리를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] NoSQL Injection 공격 분석\n";
    $response_sim .= "데이터베이스 유형: " . strtoupper($db_type) . "\n";
    $response_sim .= "입력 쿼리: " . htmlspecialchars($query_input) . "\n\n";

    // 위험한 패턴 검사
    $dangerous_patterns = [
        'mongodb' => ['$where', '$regex', '$ne', '$gt', '$lt', '$in', '$or', '$and', '$not'],
        'couchdb' => ['_design', '_view', 'emit', 'function', 'eval'],
        'redis' => ['EVAL', 'SCRIPT', 'CONFIG', 'FLUSHALL', 'SHUTDOWN'],
        'elasticsearch' => ['script', '_source', 'query', 'bool', 'must'],
        'cassandra' => ['DROP', 'TRUNCATE', 'ALTER', 'CREATE', 'ALLOW FILTERING']
    ];

    $payload_detected = false;
    $detected_patterns = [];
    if (isset($dangerous_patterns[$db_type])) {
        foreach ($dangerous_patterns[$db_type] as $pattern) {
            if (stripos($query_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
            }
        }
    }

    if ($payload_detected) {
        $response_sim .= "🚨 공격 감지됨!\n";
        $response_sim .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n";
        $response_sim .= "예상 공격 유형: " . strtoupper($db_type) . " Injection\n\n";
        $response_sim .= "이러한 패턴들은 인증 우회, 데이터 추출, 코드 실행 등에 사용될 수 있습니다.\n";
        $response_sim .= "실제 환경에서는 심각한 보안 문제를 야기할 수 있습니다.";
    } else {
        $response_sim .= "✅ 안전한 NoSQL 쿼리입니다.\n";
        $response_sim .= "위험한 패턴이 감지되지 않았습니다.\n";
        $response_sim .= "쿼리가 정상적으로 처리될 것으로 예상됩니다.";
    }

    return ['result' => "<pre>{"$response_sim"}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "NoSQL_Injection_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>