<?php
/**
 * SQL Injection 테스트 페이지
 * PayloadsAllTheThings의 SQL Injection 페이로드를 기반으로 구성
 */

session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$result = '';
$error = '';
$test_type = $_POST['test_type'] ?? '';
$payload = $_POST['payload'] ?? '';

// SQL Injection 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'union' => [
        "' UNION SELECT null,username,password FROM users--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION ALL SELECT null,null,null--",
        "1' UNION SELECT database(),user(),version()--",
        "' UNION SELECT table_name FROM information_schema.tables--"
    ],
    'boolean' => [
        "1' AND '1'='1",
        "1' AND '1'='2", 
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "1' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>64--",
        "1' OR 1=1--"
    ],
    'time' => [
        "1'; WAITFOR DELAY '00:00:05'--",
        "1' AND (SELECT SLEEP(5))--",
        "1'; SELECT pg_sleep(5)--",
        "1' AND BENCHMARK(5000000,MD5(1))--"
    ],
    'error' => [
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "1' AND EXP(~(SELECT * FROM (SELECT version())a))--"
    ],
    'basic' => [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "admin'/*",
        "' OR 'x'='x",
        "') OR ('1'='1"
    ]
];

// 테스트 실행
if ($_POST && isset($_POST['payload'])) {
    try {
        // 안전한 방식으로 쿼리 실행 (실제로는 취약한 쿼리를 시뮬레이션)
        $safe_query = "SELECT id, username FROM users WHERE id = ?";
        $stmt = $pdo->prepare($safe_query);
        $stmt->execute([$payload]);
        $results = $stmt->fetchAll();
        
        if ($results) {
            $result = "쿼리가 실행되었지만 준비된 문(Prepared Statement)으로 인해 안전하게 처리되었습니다.<br>";
            $result .= "결과: " . count($results) . "개의 레코드가 발견되었습니다.";
        } else {
            $result = "쿼리가 실행되었지만 결과가 없습니다. 준비된 문이 SQL Injection을 방지했습니다.";
        }
        
        // 시연 목적으로 취약한 쿼리가 어떻게 작동하는지 보여주기 (실제 실행 X)
        $vulnerable_query = "SELECT id, username FROM users WHERE id = '$payload'";
        $result .= "<br><br><strong>만약 취약한 쿼리였다면:</strong><br>";
        $result .= "<code>" . htmlspecialchars($vulnerable_query) . "</code><br>";
        $result .= "<em>이 쿼리는 실제로 실행되지 않았습니다.</em>";
        
    } catch (Exception $e) {
        $error = "테스트 중 오류가 발생했습니다: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .payload-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .payload-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 10px 0;
        }
        
        .payload-btn {
            background: #6c757d;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .payload-btn:hover {
            background: #5a6268;
        }
        
        .test-form {
            background: white;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .result-box {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #155724;
        }
        
        .error-box {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #721c24;
        }
        
        .info-box {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #0c5460;
        }
        
        textarea {
            width: 100%;
            min-height: 100px;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>SQL Injection 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>SQL Injection</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🗃️ SQL Injection 테스트</h3>
            <p><strong>SQL Injection</strong>은 애플리케이션의 데이터베이스 쿼리에 악의적인 SQL 코드를 삽입하는 공격입니다.</p>
            <p>이 페이지에서는 다양한 SQL Injection 기법을 안전한 환경에서 테스트할 수 있습니다.</p>
            <p><strong>참고:</strong> 실제 쿼리는 준비된 문(Prepared Statement)으로 보호되어 있어 안전합니다.</p>
        </div>

        <!-- UNION-based SQL Injection -->
        <div class="payload-section">
            <h3>🔗 UNION-based SQL Injection</h3>
            <p>UNION 연산자를 사용하여 다른 테이블의 데이터를 조회하는 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['union'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars(substr($p, 0, 30)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Boolean-based SQL Injection -->
        <div class="payload-section">
            <h3>✅ Boolean-based SQL Injection</h3>
            <p>조건문의 참/거짓 결과를 이용하여 데이터를 추출하는 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['boolean'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars(substr($p, 0, 30)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Time-based SQL Injection -->
        <div class="payload-section">
            <h3>⏱️ Time-based SQL Injection</h3>
            <p>시간 지연을 이용하여 정보를 추출하는 블라인드 SQL Injection 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['time'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars(substr($p, 0, 30)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Error-based SQL Injection -->
        <div class="payload-section">
            <h3>❌ Error-based SQL Injection</h3>
            <p>의도적으로 오류를 발생시켜 데이터베이스 정보를 노출시키는 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['error'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars(substr($p, 0, 30)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Basic SQL Injection -->
        <div class="payload-section">
            <h3>🔧 Basic SQL Injection</h3>
            <p>기본적인 SQL Injection 페이로드들입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['basic'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 페이로드 테스트</h3>
            <label for="payload">SQL Injection 페이로드:</label>
            <textarea name="payload" id="payload" placeholder="여기에 테스트할 페이로드를 입력하거나 위의 버튼을 클릭하세요"><?php echo htmlspecialchars($payload); ?></textarea>
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">테스트 실행</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error-box">
                <h3>❌ 오류</h3>
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ SQL Injection 방어 방법</h3>
            <ul>
                <li><strong>준비된 문(Prepared Statements) 사용:</strong> 가장 효과적인 방어 방법</li>
                <li><strong>입력 값 검증:</strong> 사용자 입력을 철저히 검증</li>
                <li><strong>저장 프로시저 사용:</strong> 동적 SQL 구문 대신 저장 프로시저 활용</li>
                <li><strong>최소 권한 원칙:</strong> 데이터베이스 사용자에게 필요한 최소한의 권한만 부여</li>
                <li><strong>에러 메시지 숨김:</strong> 데이터베이스 오류 정보를 사용자에게 노출하지 않음</li>
                <li><strong>웹 애플리케이션 방화벽(WAF) 사용:</strong> SQL Injection 패턴 탐지 및 차단</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" target="_blank">PayloadsAllTheThings - SQL Injection</a></li>
                <li><a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP - SQL Injection</a></li>
                <li><a href="https://portswigger.net/web-security/sql-injection" target="_blank">PortSwigger - SQL Injection</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setPayload(payload) {
            document.getElementById('payload').value = payload;
        }

        // 폼 제출 시 확인
        document.querySelector('form').addEventListener('submit', function(e) {
            const confirmed = confirm(
                'SQL Injection 테스트를 실행하시겠습니까?\n' +
                '이 테스트는 교육 목적으로만 사용하세요.'
            );
            
            if (!confirmed) {
                e.preventDefault();
            }
        });
    </script>
</body>
</html>