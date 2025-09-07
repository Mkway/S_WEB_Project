<?php
/**
 * PostgreSQL Injection 테스트 페이지
 * PL/pgSQL 저장 프로시저 인젝션 및 PostgreSQL 특화 취약점 테스트
 */
require_once '../database/PostgreSQLConnection.php';

$title = "PostgreSQL Injection Test";
$vulnerability = "PostgreSQL PL/pgSQL Injection";
$testResult = '';
$attackSuccess = false;

// 취약점 테스트 실행
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $testType = $_POST['test_type'] ?? '';
    $searchTerm = $_POST['search_term'] ?? '';
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $command = $_POST['command'] ?? '';
    
    try {
        $pgConn = new PostgreSQLConnection();
        
        switch ($testType) {
            case 'plpgsql_search':
                $testResult = testPlpgsqlSearchInjection($pgConn, $searchTerm);
                break;
            case 'plpgsql_login':
                $testResult = testPlpgsqlLoginInjection($pgConn, $username, $password);
                break;
            case 'copy_program':
                $testResult = testCopyFromProgram($pgConn, $command);
                break;
            case 'info_gathering':
                $testResult = testInformationGathering($pgConn);
                break;
        }
        
    } catch (Exception $e) {
        $testResult = '<div class="result-box error">연결 오류: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
}

/**
 * PL/pgSQL 검색 인젝션 테스트
 */
function testPlpgsqlSearchInjection($pgConn, $searchTerm) {
    global $attackSuccess;
    
    $result = '<h3>🔍 PL/pgSQL 저장 프로시저 인젝션 테스트</h3>';
    
    // 취약한 실행
    $vulnResult = $pgConn->testVulnerablePlpgsqlInjection($searchTerm);
    
    if ($vulnResult['success']) {
        $attackSuccess = true;
        $result .= '<div class="result-box vulnerable">';
        $result .= '<h4>🚨 취약한 실행 결과 (실제 공격 성공!)</h4>';
        $result .= '<p><strong>실행된 쿼리:</strong> <code>' . htmlspecialchars($vulnResult['query']) . '</code></p>';
        
        if (!empty($vulnResult['data'])) {
            $result .= '<p><strong>추출된 데이터:</strong></p><pre>';
            foreach ($vulnResult['data'] as $row) {
                $result .= print_r($row, true) . "\n";
            }
            $result .= '</pre>';
        } else {
            $result .= '<p>쿼리가 실행되었지만 반환된 데이터가 없습니다.</p>';
        }
        $result .= '</div>';
    } else {
        $result .= '<div class="result-box error">';
        $result .= '<h4>⚠️ 공격 실행 중 오류</h4>';
        $result .= '<p><strong>오류:</strong> ' . htmlspecialchars($vulnResult['error']) . '</p>';
        $result .= '</div>';
    }
    
    // 안전한 구현과 비교
    $safeResult = $pgConn->testSafeSearch($searchTerm);
    
    $result .= '<div class="result-box safe">';
    $result .= '<h4>✅ 안전한 구현 (파라미터화된 쿼리)</h4>';
    if ($safeResult['success']) {
        $result .= '<p><strong>안전한 쿼리:</strong> <code>' . htmlspecialchars($safeResult['query']) . '</code></p>';
        $result .= '<p>파라미터화된 쿼리로 SQL 인젝션이 방지됩니다.</p>';
    } else {
        $result .= '<p>입력값 검증으로 인해 실행이 차단되었습니다: ' . htmlspecialchars($safeResult['error']) . '</p>';
    }
    $result .= '</div>';
    
    return $result;
}

/**
 * PL/pgSQL 로그인 인젝션 테스트
 */
function testPlpgsqlLoginInjection($pgConn, $username, $password) {
    global $attackSuccess;
    
    $result = '<h3>🔐 PL/pgSQL 인증 우회 인젝션 테스트</h3>';
    
    // 취약한 실행
    $vulnResult = $pgConn->testVulnerableLogin($username, $password);
    
    if ($vulnResult['success']) {
        $result .= '<div class="result-box vulnerable">';
        $result .= '<h4>🚨 취약한 로그인 (인증 우회 성공!)</h4>';
        $result .= '<p><strong>실행된 쿼리:</strong> <code>' . htmlspecialchars($vulnResult['query']) . '</code></p>';
        
        if (!empty($vulnResult['data'])) {
            $attackSuccess = true;
            $result .= '<p><strong>우회된 사용자 정보:</strong></p><pre>';
            foreach ($vulnResult['data'] as $user) {
                $result .= "ID: {$user['user_id']}, Username: {$user['username']}, Role: {$user['role']}, Admin: " . ($user['is_admin'] ? 'Yes' : 'No') . "\n";
            }
            $result .= '</pre>';
        } else {
            $result .= '<p>인증에 실패했습니다.</p>';
        }
        $result .= '</div>';
    } else {
        $result .= '<div class="result-box error">';
        $result .= '<h4>⚠️ 로그인 공격 실행 중 오류</h4>';
        $result .= '<p><strong>오류:</strong> ' . htmlspecialchars($vulnResult['error']) . '</p>';
        $result .= '</div>';
    }
    
    // 안전한 구현과 비교
    $safeResult = $pgConn->testSafeLogin($username, $password);
    
    $result .= '<div class="result-box safe">';
    $result .= '<h4>✅ 안전한 로그인 구현</h4>';
    if ($safeResult['success'] && !empty($safeResult['data'])) {
        $result .= '<p>정상적인 인증이 성공했습니다.</p>';
    } else {
        $result .= '<p>안전한 구현: 입력값 검증, 계정 잠금, 감사 로깅 등으로 보호됩니다.</p>';
        if (isset($safeResult['error'])) {
            $result .= '<p>' . htmlspecialchars($safeResult['error']) . '</p>';
        }
    }
    $result .= '</div>';
    
    return $result;
}

/**
 * COPY FROM PROGRAM 공격 테스트
 */
function testCopyFromProgram($pgConn, $command) {
    global $attackSuccess;
    
    $result = '<h3>💻 PostgreSQL COPY FROM PROGRAM 공격 테스트</h3>';
    $result .= '<div class="warning-box">⚠️ 이 테스트는 실제 시스템 명령어를 실행할 수 있습니다!</div>';
    
    // 취약한 실행
    $vulnResult = $pgConn->testVulnerableCopyFromProgram($command);
    
    if ($vulnResult['success']) {
        $attackSuccess = true;
        $result .= '<div class="result-box vulnerable">';
        $result .= '<h4>🚨 COPY FROM PROGRAM 실행 성공!</h4>';
        $result .= '<p><strong>실행된 쿼리:</strong> <code>' . htmlspecialchars($vulnResult['query']) . '</code></p>';
        $result .= '<p>' . htmlspecialchars($vulnResult['message']) . '</p>';
        $result .= '<p><strong>위험성:</strong> 시스템 명령어가 데이터베이스 권한으로 실행되었습니다!</p>';
        $result .= '</div>';
    } else {
        $result .= '<div class="result-box error">';
        $result .= '<h4>⚠️ COPY FROM PROGRAM 실행 중 오류</h4>';
        $result .= '<p><strong>오류:</strong> ' . htmlspecialchars($vulnResult['error']) . '</p>';
        $result .= '</div>';
    }
    
    // 안전한 구현 설명
    $result .= '<div class="result-box safe">';
    $result .= '<h4>✅ 안전한 구현 방법</h4>';
    $result .= '<ul>';
    $result .= '<li>COPY FROM PROGRAM 권한 제거</li>';
    $result .= '<li>사용자 입력값을 COPY 명령에 직접 사용 금지</li>';
    $result .= '<li>화이트리스트 기반 명령어 필터링</li>';
    $result .= '<li>최소 권한 원칙 적용</li>';
    $result .= '</ul>';
    $result .= '</div>';
    
    return $result;
}

/**
 * PostgreSQL 정보 수집 테스트
 */
function testInformationGathering($pgConn) {
    $result = '<h3>📊 PostgreSQL 정보 수집 테스트</h3>';
    
    // 버전 정보
    $version = $pgConn->getPostgreSQLVersion();
    $result .= '<div class="result-box info">';
    $result .= '<h4>🔍 시스템 정보 수집</h4>';
    $result .= '<p><strong>PostgreSQL 버전:</strong> ' . htmlspecialchars($version) . '</p>';
    
    // 데이터베이스 목록
    $databases = $pgConn->getDatabaseList();
    $result .= '<p><strong>데이터베이스 목록:</strong> ' . implode(', ', $databases) . '</p>';
    
    // 테이블 목록
    $tables = $pgConn->getTableList();
    $result .= '<p><strong>취약한 DB 테이블:</strong> ' . implode(', ', $tables) . '</p>';
    
    $result .= '</div>';
    
    return $result;
}

// 공격 페이로드 예시
$payloads = [
    'plpgsql_search' => [
        "test'; DROP TABLE users; --",
        "test'; SELECT version(); --",
        "test' UNION SELECT id, username, password FROM users --"
    ],
    'plpgsql_login' => [
        "admin'; --",
        "admin' OR '1'='1'; --",
        "'; SELECT * FROM users WHERE role='admin'; --"
    ],
    'copy_program' => [
        "echo 'Command executed' > /tmp/test.txt",
        "whoami",
        "cat /etc/passwd"
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?></title>
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .test-form { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .payload-examples { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .payload-examples h5 { margin: 0 0 10px 0; }
        .payload-item { margin: 5px 0; font-family: monospace; font-size: 12px; }
        .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .result-box.vulnerable { background: #f8d7da; border-color: #f5c6cb; color: #721c24; }
        .result-box.safe { background: #d4edda; border-color: #c3e6cb; color: #155724; }
        .result-box.error { background: #f8d7da; border-color: #f5c6cb; color: #721c24; }
        .result-box.info { background: #e2e3e5; border-color: #d6d8db; color: #383d41; }
        .attack-indicator { text-align: center; padding: 15px; margin: 20px 0; border-radius: 8px; font-weight: bold; }
        .attack-success { background: #dc3545; color: white; }
        .attack-failed { background: #6c757d; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><?= htmlspecialchars($title) ?></h1>
            <p class="description">PostgreSQL PL/pgSQL 저장 프로시저 인젝션 및 특화 취약점 테스트</p>
        </header>

        <?php if ($testResult): ?>
            <div class="attack-indicator <?= $attackSuccess ? 'attack-success' : 'attack-failed' ?>">
                <?= $attackSuccess ? '🚨 공격 성공! 실제 PostgreSQL 인젝션 실행됨' : '⚠️ 공격 실패 또는 차단됨' ?>
            </div>
            <div class="results">
                <?= $testResult ?>
            </div>
        <?php endif; ?>

        <!-- PL/pgSQL 검색 인젝션 테스트 -->
        <div class="test-form">
            <h3>🔍 PL/pgSQL 저장 프로시저 검색 인젝션</h3>
            <form method="POST">
                <input type="hidden" name="test_type" value="plpgsql_search">
                <div class="form-group">
                    <label for="search_term">검색어:</label>
                    <input type="text" id="search_term" name="search_term" 
                           value="<?= htmlspecialchars($_POST['search_term'] ?? '') ?>" 
                           placeholder="제품명을 입력하세요">
                </div>
                <button type="submit">PL/pgSQL 검색 테스트 실행</button>
            </form>
            
            <div class="payload-examples">
                <h5>💉 공격 페이로드 예시:</h5>
                <?php foreach ($payloads['plpgsql_search'] as $payload): ?>
                    <div class="payload-item"><?= htmlspecialchars($payload) ?></div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- PL/pgSQL 로그인 인젝션 테스트 -->
        <div class="test-form">
            <h3>🔐 PL/pgSQL 인증 우회 인젝션</h3>
            <form method="POST">
                <input type="hidden" name="test_type" value="plpgsql_login">
                <div class="form-group">
                    <label for="username">사용자명:</label>
                    <input type="text" id="username" name="username" 
                           value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" 
                           placeholder="사용자명">
                </div>
                <div class="form-group">
                    <label for="password">비밀번호:</label>
                    <input type="text" id="password" name="password" 
                           value="<?= htmlspecialchars($_POST['password'] ?? '') ?>" 
                           placeholder="비밀번호">
                </div>
                <button type="submit">PL/pgSQL 로그인 테스트 실행</button>
            </form>
            
            <div class="payload-examples">
                <h5>💉 인증 우회 페이로드 예시:</h5>
                <?php foreach ($payloads['plpgsql_login'] as $payload): ?>
                    <div class="payload-item"><?= htmlspecialchars($payload) ?></div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- COPY FROM PROGRAM 테스트 -->
        <div class="test-form">
            <h3>💻 PostgreSQL COPY FROM PROGRAM 공격</h3>
            <div class="warning-box">
                ⚠️ <strong>위험:</strong> 이 테스트는 실제 시스템 명령어를 실행할 수 있습니다!
            </div>
            <form method="POST">
                <input type="hidden" name="test_type" value="copy_program">
                <div class="form-group">
                    <label for="command">명령어:</label>
                    <input type="text" id="command" name="command" 
                           value="<?= htmlspecialchars($_POST['command'] ?? '') ?>" 
                           placeholder="실행할 명령어">
                </div>
                <button type="submit" onclick="return confirm('정말로 명령어를 실행하시겠습니까?')">
                    COPY FROM PROGRAM 테스트 실행
                </button>
            </form>
            
            <div class="payload-examples">
                <h5>💥 시스템 명령어 예시:</h5>
                <?php foreach ($payloads['copy_program'] as $payload): ?>
                    <div class="payload-item"><?= htmlspecialchars($payload) ?></div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 정보 수집 테스트 -->
        <div class="test-form">
            <h3>📊 PostgreSQL 정보 수집</h3>
            <form method="POST">
                <input type="hidden" name="test_type" value="info_gathering">
                <button type="submit">정보 수집 테스트 실행</button>
            </form>
        </div>

        <div class="security-info">
            <h3>🛡️ 보안 권장사항</h3>
            <ul>
                <li><strong>파라미터화된 쿼리 사용:</strong> 사용자 입력을 직접 쿼리에 삽입하지 않기</li>
                <li><strong>최소 권한 원칙:</strong> 데이터베이스 사용자에게 필요한 최소한의 권한만 부여</li>
                <li><strong>COPY FROM PROGRAM 비활성화:</strong> 불필요한 시스템 명령 실행 권한 제거</li>
                <li><strong>입력값 검증:</strong> 모든 사용자 입력에 대한 엄격한 검증</li>
                <li><strong>에러 메시지 제한:</strong> 데이터베이스 구조 정보 노출 방지</li>
                <li><strong>감사 로깅:</strong> 모든 데이터베이스 접근 로그 기록</li>
            </ul>
        </div>

        <div class="navigation">
            <a href="../index.php" class="btn-back">← 메인으로 돌아가기</a>
            <a href="sql_injection.php" class="btn-nav">MySQL 인젝션 테스트 →</a>
        </div>
    </div>
</body>
</html>