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

// 선택된 옵션 처리를 위한 변수들
$mongodb_selected = ($db_type === 'mongodb') ? 'selected' : '';
$couchdb_selected = ($db_type === 'couchdb') ? 'selected' : '';
$redis_selected = ($db_type === 'redis') ? 'selected' : '';
$elasticsearch_selected = ($db_type === 'elasticsearch') ? 'selected' : '';
$cassandra_selected = ($db_type === 'cassandra') ? 'selected' : '';

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 NoSQL 쿼리/명령 테스트</h3>
    <label for="db_type">🗄️ 데이터베이스 유형 선택:</label><br>
    <select id="db_type" name="db_type">
        <option value="mongodb" $mongodb_selected>MongoDB</option>
        <option value="couchdb" $couchdb_selected>CouchDB</option>
        <option value="redis" $redis_selected>Redis</option>
        <option value="elasticsearch" $elasticsearch_selected>Elasticsearch</option>
        <option value="cassandra" $cassandra_selected>Cassandra</option>
    </select><br><br>
    
    <label for="payload">🎯 NoSQL 쿼리/명령 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="NoSQL 쿼리나 명령을 입력하세요...">{$query_input}</textarea><br><br>
    <button type="submit" class="btn">쿼리 실행</button>
</form>
HTML;

// MongoDB 연결 함수
function connectToMongoDB() {
    try {
        // Docker 컨테이너 내에서 MongoDB 연결
        $mongoHost = 'security_mongo'; // Docker 서비스명
        $mongoPort = 27017;
        $mongoUser = 'admin';
        $mongoPass = 'admin123';
        $mongoDatabase = 'security_test';
        
        // MongoDB 연결 문자열
        $connectionString = "mongodb://{$mongoUser}:{$mongoPass}@{$mongoHost}:{$mongoPort}/{$mongoDatabase}?authSource=admin";
        
        // mongosh 명령어로 연결 테스트
        $testCommand = "docker exec security_mongo mongosh --quiet --eval 'db.adminCommand(\"ping\")' 2>&1";
        $testResult = shell_exec($testCommand);
        
        if (strpos($testResult, 'ok') !== false) {
            return true;
        }
        
        return false;
    } catch (Exception $e) {
        return false;
    }
}

// MongoDB 쿼리 실행 함수
function executeMongoQuery($query, $db_type = 'mongodb') {
    $result = [];
    
    try {
        if ($db_type === 'mongodb') {
            // JSON 쿼리를 mongosh 명령어로 변환
            $jsonQuery = json_decode($query, true);
            
            if ($jsonQuery === null) {
                return ['error' => 'Invalid JSON format', 'data' => []];
            }
            
            // 샘플 데이터 초기화 (실제 환경에서는 이미 존재)
            $initCommand = "docker exec security_mongo mongosh security_test --quiet --eval '
                db.users.deleteMany({});
                db.users.insertMany([
                    {\"_id\": ObjectId(), \"username\": \"admin\", \"password\": \"admin123\", \"role\": \"administrator\", \"email\": \"admin@test.com\"},
                    {\"_id\": ObjectId(), \"username\": \"user1\", \"password\": \"user123\", \"role\": \"user\", \"email\": \"user1@test.com\"},
                    {\"_id\": ObjectId(), \"username\": \"guest\", \"password\": \"guest\", \"role\": \"guest\", \"email\": \"guest@test.com\"}
                ]);
            ' 2>&1";
            
            shell_exec($initCommand);
            
            // 실제 MongoDB 쿼리 실행
            $mongoQuery = json_encode($jsonQuery);
            $findCommand = "docker exec security_mongo mongosh security_test --quiet --eval 'JSON.stringify(db.users.find(" . addslashes($mongoQuery) . ").toArray())' 2>&1";
            
            $output = shell_exec($findCommand);
            
            if ($output) {
                $cleanOutput = trim($output);
                $data = json_decode($cleanOutput, true);
                
                if ($data !== null) {
                    return ['error' => null, 'data' => $data, 'raw_output' => $cleanOutput];
                } else {
                    return ['error' => 'Query execution failed: ' . $cleanOutput, 'data' => []];
                }
            }
        }
        
        return ['error' => 'Unsupported database type', 'data' => []];
        
    } catch (Exception $e) {
        return ['error' => $e->getMessage(), 'data' => []];
    }
}

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

    $result .= "<div class='vulnerable-output'>";
    $result .= "<h4>🚨 취약한 NoSQL 쿼리 실행 결과</h4>";
    $result .= "<p><strong>데이터베이스 유형:</strong> " . strtoupper($db_type) . "</p>";
    $result .= "<p><strong>입력 쿼리:</strong> " . htmlspecialchars($query_input) . "</p>";

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
    $attack_type = '';
    
    if (isset($dangerous_patterns[$db_type])) {
        foreach ($dangerous_patterns[$db_type] as $pattern) {
            if (stripos($query_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
            }
        }
    }

    if ($payload_detected) {
        $result .= "<p class='danger'>🔥 <strong>NoSQL Injection 공격 감지!</strong></p>";
        $result .= "<p><strong>감지된 패턴:</strong> " . implode(', ', $detected_patterns) . "</p>";
        
        // 공격 유형 분석
        if (in_array('$ne', $detected_patterns) || in_array('$or', $detected_patterns)) {
            $attack_type = "Authentication Bypass Attack";
        } elseif (in_array('$regex', $detected_patterns)) {
            $attack_type = "Data Extraction Attack";
        } elseif (in_array('$where', $detected_patterns)) {
            $attack_type = "Code Injection Attack";
        } else {
            $attack_type = "NoSQL Injection Attack";
        }
        
        $result .= "<p><strong>공격 유형:</strong> {$attack_type}</p>";
    }

    // 실제 MongoDB 연결 및 쿼리 실행
    if ($db_type === 'mongodb') {
        $mongoConnected = connectToMongoDB();
        
        if ($mongoConnected) {
            $result .= "<p class='success'>✅ <strong>MongoDB 연결 성공!</strong> 실제 쿼리를 실행합니다.</p>";
            
            $queryResult = executeMongoQuery($query_input, $db_type);
            
            if ($queryResult['error'] === null) {
                $result .= "<p><strong>실행 결과:</strong> " . count($queryResult['data']) . "개 문서 조회됨</p>";
                
                if (!empty($queryResult['data'])) {
                    $result .= "<p><strong>조회된 데이터:</strong></p>";
                    $data_preview = "";
                    foreach ($queryResult['data'] as $index => $doc) {
                        $data_preview .= "문서 " . ($index + 1) . ":\n";
                        foreach ($doc as $field => $value) {
                            if ($field === '_id' && is_array($value)) {
                                $data_preview .= "  - {$field}: " . ($value['$oid'] ?? 'ObjectId') . "\n";
                            } else {
                                $data_preview .= "  - {$field}: " . $value . "\n";
                            }
                        }
                        $data_preview .= "\n";
                        
                        // 최대 3개 문서만 표시
                        if ($index >= 2) {
                            if (count($queryResult['data']) > 3) {
                                $data_preview .= "... (추가 " . (count($queryResult['data']) - 3) . "개 문서 생략)\n";
                            }
                            break;
                        }
                    }
                    $result .= "<pre class='attack-result'>" . htmlspecialchars($data_preview) . "</pre>";
                    
                    // 보안 위험 경고
                    if (count($queryResult['data']) > 1 && $payload_detected) {
                        $result .= "<p class='danger'>🔥 <strong>다중 사용자 데이터 노출!</strong> 인증 우회로 여러 계정 정보가 노출되었습니다.</p>";
                    }
                    
                    // 민감한 정보 포함 확인
                    $has_sensitive = false;
                    foreach ($queryResult['data'] as $doc) {
                        if (isset($doc['password']) || isset($doc['email'])) {
                            $has_sensitive = true;
                            break;
                        }
                    }
                    
                    if ($has_sensitive) {
                        $result .= "<p class='danger'>🔥 <strong>민감한 정보 노출!</strong> 비밀번호나 이메일 정보가 포함되어 있습니다.</p>";
                    }
                } else {
                    $result .= "<p class='warning'>⚠️ 쿼리는 성공했지만 조건에 맞는 문서가 없습니다.</p>";
                }
            } else {
                $result .= "<p class='error'>❌ <strong>쿼리 실행 오류:</strong> " . htmlspecialchars($queryResult['error']) . "</p>";
                
                if ($payload_detected) {
                    $result .= "<p class='warning'>💡 쿼리 실행에 실패했지만, 실제 환경에서는 이러한 패턴이 성공할 수 있습니다.</p>";
                }
            }
        } else {
            $result .= "<p class='error'>❌ <strong>MongoDB 연결 실패:</strong> Docker 컨테이너에 접근할 수 없습니다.</p>";
            $result .= "<p class='warning'>⚠️ 시뮬레이션 모드로 전환하여 분석을 계속합니다.</p>";
            
            // 시뮬레이션 결과 표시
            if ($payload_detected) {
                $result .= "<p class='danger'>🔥 실제 환경에서는 {$attack_type}이 성공할 수 있습니다.</p>";
            }
        }
    } else {
        // 다른 NoSQL DB는 시뮬레이션으로 처리
        $result .= "<p class='warning'>⚠️ <strong>{$db_type} 시뮬레이션 모드:</strong> 실제 연결은 MongoDB만 지원됩니다.</p>";
        
        if ($payload_detected) {
            $result .= "<p class='danger'>🔥 실제 환경에서는 " . strtoupper($db_type) . " Injection 공격이 성공할 수 있습니다.</p>";
        }
    }
    
    $result .= "</div>";

    // 안전한 구현 비교
    $result .= "<div class='safe-comparison'>";
    $result .= "<h4>✅ 안전한 NoSQL 쿼리 구현</h4>";
    
    if ($payload_detected) {
        $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 위험한 NoSQL 연산자가 감지되어 쿼리가 거부되었습니다.</p>";
        $result .= "<p><strong>감지된 위험 요소:</strong> " . implode(', ', $detected_patterns) . "</p>";
        $result .= "<p><strong>권장 대안:</strong></p>";
        $result .= "<ul>";
        $result .= "<li>입력 값 타입 검증 (문자열만 허용)</li>";
        $result .= "<li>화이트리스트 기반 필드 검증</li>";
        $result .= "<li>매개변수화된 쿼리 사용</li>";
        $result .= "</ul>";
    } else {
        $result .= "<p class='success'>✅ <strong>안전한 쿼리:</strong> 위험한 패턴이 감지되지 않았습니다.</p>";
        
        // 안전한 MongoDB 쿼리 예시 실행
        if ($db_type === 'mongodb' && connectToMongoDB()) {
            try {
                $parsed = json_decode($query_input, true);
                if ($parsed && !array_intersect_key($parsed, array_flip(['$where', '$regex', '$ne', '$gt', '$lt', '$in', '$or', '$and', '$not']))) {
                    $result .= "<p><strong>안전한 실행 결과:</strong> 제한된 필드 조회가 허용됩니다.</p>";
                }
            } catch (Exception $e) {
                $result .= "<p class='success'>🛡️ 안전한 파싱 처리</p>";
            }
        }
    }
    
    $result .= "</div>";

    // 보안 권장사항
    $result .= "<div class='security-recommendations'>";
    $result .= "<h4>🔒 NoSQL Injection 방어 권장사항</h4>";
    $result .= "<ul>";
    $result .= "<li><strong>입력 검증:</strong> 사용자 입력의 타입과 형식을 엄격히 검증</li>";
    $result .= "<li><strong>화이트리스트:</strong> 허용된 연산자와 필드만 사용 허용</li>";
    $result .= "<li><strong>매개변수화:</strong> 직접적인 객체 병합 대신 안전한 쿼리 빌더 사용</li>";
    $result .= "<li><strong>최소 권한:</strong> 데이터베이스 계정 권한 최소화</li>";
    $result .= "<li><strong>모니터링:</strong> 비정상적인 쿼리 패턴 감지 및 로깅</li>";
    $result .= "<li><strong>스키마 검증:</strong> 입력 데이터의 스키마 검증</li>";
    $result .= "</ul>";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "NoSQL_Injection_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>