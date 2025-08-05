<?php
/**
 * Authentication Bypass 테스트 페이지
 * PayloadsAllTheThings의 Authentication Bypass 페이로드를 기반으로 구성
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
$test_type = $_POST['test_type'] ?? 'sql_auth';
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// Authentication Bypass 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'sql_injection_auth' => [
        "admin'--",
        "admin'/*",
        "admin' OR '1'='1'--",
        "admin' OR 1=1--",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "') OR ('1'='1'--",
        "') OR 1=1--",
        "admin' OR 'x'='x'--",
        "' UNION SELECT 1,'admin','password'--"
    ],
    'nosql_injection' => [
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "this.username"}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$in": ["admin", "administrator"]}}',
        '{"$or": [{"username": "admin"}, {"username": "administrator"}]}'
    ],
    'ldap_injection' => [
        'admin)(&))',
        'admin)(|(password=*))',
        'admin)(&(password=*))',
        '*)(uid=*))(|(uid=*',
        '*)(|(password=*))',
        '*))(|(objectClass=*'
    ],
    'xpath_injection' => [
        "' or '1'='1",
        "' or 1=1 or ''='",
        "admin' or '1'='1' or '1'='1",
        "x' or name()='username' or 'x'='y",
        "' or position()=1 or ''='"
    ],
    'session_manipulation' => [
        'admin=true',
        'authenticated=1',
        'user_role=admin',
        'is_admin=true',
        'login_status=success',
        'user_id=1',
        'session_valid=1'
    ],
    'header_manipulation' => [
        'X-Forwarded-For: 127.0.0.1',
        'X-Real-IP: 127.0.0.1',
        'X-Originating-IP: 127.0.0.1',
        'X-Remote-IP: 127.0.0.1',
        'X-Client-IP: 127.0.0.1',
        'X-Original-URL: /admin',
        'X-Rewrite-URL: /admin',
        'X-Override-URL: /admin'
    ],
    'parameter_pollution' => [
        'user=guest&user=admin',
        'role=user&role=admin',
        'authenticated=false&authenticated=true',
        'permission=read&permission=write&permission=admin'
    ]
];

// 모의 사용자 데이터베이스
$mock_users = [
    'admin' => ['password' => 'admin123', 'role' => 'administrator'],
    'user' => ['password' => 'user123', 'role' => 'user'],
    'guest' => ['password' => 'guest123', 'role' => 'guest'],
    'test' => ['password' => 'test123', 'role' => 'user']
];

// 테스트 실행
if ($_POST && isset($_POST['username']) && isset($_POST['password'])) {
    $result = "🔐 Authentication Bypass 테스트 결과\n\n";
    $result .= "입력된 사용자명: " . htmlspecialchars($username) . "\n";
    $result .= "입력된 비밀번호: " . htmlspecialchars($password) . "\n\n";
    
    // 위험한 패턴 감지
    $dangerous_patterns = [
        '/\'/',               // Single quotes
        '/--/',               // SQL comments
        '/\/\*/',             // SQL comments
        '/union/i',           // UNION queries
        '/select/i',          // SELECT queries
        '/or\s+1=1/i',        // OR 1=1
        '/or\s+\'1\'=\'1\'/i', // OR '1'='1'
        '/\$ne/',             // NoSQL operators
        '/\$gt/',             // NoSQL operators
        '/\$regex/',          // NoSQL operators
        '/\)\(&\)\)/',        // LDAP injection
        '/\*\)\(/',           // LDAP injection
    ];
    
    $detected_attacks = [];
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $username) || preg_match($pattern, $password)) {
            $detected_attacks[] = $pattern;
        }
    }
    
    if (!empty($detected_attacks)) {
        $result .= "⚠️ 위험한 Authentication Bypass 공격 패턴이 감지되었습니다!\n\n";
        
        switch ($test_type) {
            case 'sql_auth':
                $result .= "🎯 SQL Injection Authentication Bypass 시도:\n";
                $result .= "- 사용자가 SQL 주입을 통해 인증을 우회하려고 시도했습니다.\n";
                $result .= "- 일반적인 패턴: ' OR '1'='1'--, admin'--, UNION SELECT 등\n";
                $result .= "- 취약한 쿼리 예: SELECT * FROM users WHERE username='$username' AND password='$password'\n\n";
                
                // 시뮬레이션: 취약한 쿼리가 어떻게 변조되는지 보여주기
                $vulnerable_query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
                $result .= "변조된 쿼리:\n" . htmlspecialchars($vulnerable_query) . "\n\n";
                
                if (preg_match('/or\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1[\'"]?/i', $username . ' ' . $password)) {
                    $result .= "🚨 이 패턴은 항상 TRUE가 되어 모든 사용자 레코드를 반환할 수 있습니다!\n";
                }
                break;
                
            case 'nosql_auth':
                $result .= "🎯 NoSQL Injection Authentication Bypass 시도:\n";
                $result .= "- MongoDB 등 NoSQL 데이터베이스의 연산자를 악용한 공격입니다.\n";
                $result .= "- 일반적인 패턴: {\$ne: \"\"}, {\$gt: \"\"}, {\$regex: \".*\"} 등\n";
                $result .= "- 이러한 연산자는 항상 참이 되어 인증을 우회할 수 있습니다.\n\n";
                break;
                
            case 'ldap_auth':
                $result .= "🎯 LDAP Injection Authentication Bypass 시도:\n";
                $result .= "- LDAP 쿼리 구조를 조작하여 인증을 우회하는 공격입니다.\n";
                $result .= "- 일반적인 패턴: )(&)), )(|(password=*)), *)(uid=*)) 등\n";
                $result .= "- LDAP 필터 구조를 변조하여 항상 참이 되도록 만듭니다.\n\n";
                break;
        }
        
        $result .= "🛡️ 다행히 이 시스템은 다음과 같은 보안 조치로 보호되고 있습니다:\n";
        $result .= "- 준비된 문(Prepared Statements) 사용\n";
        $result .= "- 입력값 검증 및 필터링\n";
        $result .= "- 적절한 인코딩 및 이스케이프 처리\n";
        $result .= "- 최소 권한 원칙 적용\n\n";
        
    } else {
        // 정상적인 인증 시뮬레이션
        $clean_username = strtolower(trim($username));
        $clean_password = trim($password);
        
        if (isset($mock_users[$clean_username]) && $mock_users[$clean_username]['password'] === $clean_password) {
            $result .= "✅ 정상적인 인증 성공!\n";
            $result .= "사용자: " . htmlspecialchars($clean_username) . "\n";
            $result .= "역할: " . $mock_users[$clean_username]['role'] . "\n";
            $result .= "인증이 안전하게 처리되었습니다.\n";
        } else {
            $result .= "❌ 인증 실패\n";
            $result .= "유효하지 않은 사용자명 또는 비밀번호입니다.\n";
            $result .= "사용 가능한 테스트 계정: admin/admin123, user/user123, guest/guest123, test/test123";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Bypass 테스트 - 보안 테스트</title>
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
            font-family: monospace;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .payload-btn:hover {
            background: #5a6268;
        }
        
        .payload-btn.dangerous {
            background: #dc3545;
        }
        
        .payload-btn.dangerous:hover {
            background: #c82333;
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
            font-family: monospace;
            white-space: pre-wrap;
        }
        
        .danger-box {
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
        
        .test-accounts {
            background: #d4edda;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }
        
        .test-type-selector {
            margin: 15px 0;
        }
        
        .test-type-selector label {
            margin-right: 15px;
            display: inline-block;
            margin-bottom: 10px;
        }
        
        input[type="text"], input[type="password"] {
            width: 100%;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
            margin: 5px 0;
        }
        
        .examples {
            background: #fff3cd;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: monospace;
        }
        
        .severity-critical {
            color: #721c24;
            font-weight: bold;
            background: #f8d7da;
            padding: 2px 4px;
            border-radius: 3px;
        }
        
        .attack-demo {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>Authentication Bypass 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Authentication Bypass</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🔓 Authentication Bypass 테스트</h3>
            <p><strong>Authentication Bypass</strong>는 정상적인 인증 과정을 우회하여 시스템에 무단으로 접근하는 공격 기법입니다.</p>
            <p>SQL Injection, NoSQL Injection, LDAP Injection 등 다양한 방법으로 인증을 우회할 수 있습니다.</p>
            <p><strong>참고:</strong> 이 페이지에서는 모의 인증 시스템을 사용하여 안전한 환경에서 테스트합니다.</p>
        </div>

        <!-- 경고 -->
        <div class="danger-box">
            <h3>⚠️ <span class="severity-critical">CRITICAL</span> 보안 위험</h3>
            <p>Authentication Bypass 취약점은 다음과 같은 심각한 결과를 초래할 수 있습니다:</p>
            <ul>
                <li>관리자 계정으로 무단 접근</li>
                <li>전체 시스템 권한 탈취</li>
                <li>민감한 데이터 및 개인정보 노출</li>
                <li>시스템 설정 변경 및 파괴</li>
                <li>다른 사용자 계정 탈취</li>
                <li>백도어 설치 및 지속적 침투</li>
            </ul>
        </div>

        <!-- 테스트 계정 정보 -->
        <div class="test-accounts">
            <h3>🔑 테스트 계정 정보</h3>
            <p>정상적인 로그인 테스트를 위한 계정들:</p>
            <ul>
                <li><strong>admin</strong> / admin123 (관리자)</li>
                <li><strong>user</strong> / user123 (일반 사용자)</li>
                <li><strong>guest</strong> / guest123 (게스트)</li>
                <li><strong>test</strong> / test123 (테스트 사용자)</li>
            </ul>
        </div>

        <!-- SQL Injection Auth Bypass -->
        <div class="payload-section">
            <h3>💉 SQL Injection Authentication Bypass</h3>
            <p>SQL 주입을 통한 인증 우회 공격입니다. 가장 일반적이고 효과적인 방법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['sql_injection_auth'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setUsernamePayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- NoSQL Injection -->
        <div class="payload-section">
            <h3>🍃 NoSQL Injection Authentication Bypass</h3>
            <p>MongoDB 등 NoSQL 데이터베이스에서 사용되는 연산자를 악용한 인증 우회입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['nosql_injection'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setUsernamePayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        NoSQL Operator
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- LDAP Injection -->
        <div class="payload-section">
            <h3>📁 LDAP Injection Authentication Bypass</h3>
            <p>LDAP 디렉토리 서비스의 필터 구조를 조작하여 인증을 우회하는 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['ldap_injection'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setUsernamePayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 15)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- XPath Injection -->
        <div class="payload-section">
            <h3>🛤️ XPath Injection Authentication Bypass</h3>
            <p>XML 문서를 쿼리하는 XPath 표현식을 조작하여 인증을 우회하는 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['xpath_injection'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setUsernamePayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 20)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Session Manipulation -->
        <div class="payload-section">
            <h3>🍪 Session/Cookie Manipulation</h3>
            <p>세션 변수나 쿠키 값을 조작하여 인증 상태를 변경하는 공격입니다.</p>
            <div class="attack-demo">
                <?php foreach ($payloads['session_manipulation'] as $p): ?>
                    Cookie: <?php echo htmlspecialchars($p); ?><br>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Header Manipulation -->
        <div class="payload-section">
            <h3>📋 HTTP Header Manipulation</h3>
            <p>HTTP 헤더를 조작하여 인증을 우회하거나 권한을 상승시키는 공격입니다.</p>
            <div class="attack-demo">
                <?php foreach ($payloads['header_manipulation'] as $p): ?>
                    <?php echo htmlspecialchars($p); ?><br>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Parameter Pollution -->
        <div class="payload-section">
            <h3>🔄 HTTP Parameter Pollution</h3>
            <p>같은 이름의 매개변수를 여러 번 전송하여 서버의 처리 로직을 혼란시키는 공격입니다.</p>
            <div class="attack-demo">
                <?php foreach ($payloads['parameter_pollution'] as $p): ?>
                    POST: <?php echo htmlspecialchars($p); ?><br>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 Authentication Bypass 테스트</h3>
            
            <div class="test-type-selector">
                <label><input type="radio" name="test_type" value="sql_auth" <?php echo $test_type === 'sql_auth' ? 'checked' : ''; ?>> SQL Injection Auth</label>
                <label><input type="radio" name="test_type" value="nosql_auth" <?php echo $test_type === 'nosql_auth' ? 'checked' : ''; ?>> NoSQL Injection Auth</label>
                <label><input type="radio" name="test_type" value="ldap_auth" <?php echo $test_type === 'ldap_auth' ? 'checked' : ''; ?>> LDAP Injection Auth</label>
            </div>
            
            <label for="username">사용자명:</label>
            <input type="text" name="username" id="username" placeholder="사용자명 또는 페이로드 입력" value="<?php echo htmlspecialchars($username); ?>">
            
            <label for="password">비밀번호:</label>
            <input type="password" name="password" id="password" placeholder="비밀번호 또는 페이로드 입력" value="<?php echo htmlspecialchars($password); ?>">
            
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">인증 테스트 실행</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- 공격 시나리오 -->
        <div class="examples">
            <h3>💡 Authentication Bypass 공격 시나리오</h3>
            <p><strong>시나리오 1:</strong> 로그인 폼 SQL Injection</p>
            <code>Username: admin'-- Password: anything</code> → 비밀번호 확인 우회
            <br><br>
            <p><strong>시나리오 2:</strong> 항상 참인 조건</p>
            <code>Username: ' OR '1'='1'-- Password: anything</code> → 모든 사용자 인증 통과
            <br><br>
            <p><strong>시나리오 3:</strong> UNION을 통한 관리자 인증</p>
            <code>Username: ' UNION SELECT 1,'admin','password'-- Password: password</code>
            <br><br>
            <p><strong>시나리오 4:</strong> NoSQL 연산자 악용</p>
            <code>Username: {"$ne": ""} Password: {"$ne": ""}</code> → 빈 값이 아닌 모든 계정 매치
        </div>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ Authentication Bypass 방어 방법</h3>
            <ul>
                <li><strong>준비된 문 사용:</strong> SQL Injection 방지를 위한 Prepared Statements</li>
                <li><strong>입력 검증:</strong> 모든 사용자 입력에 대한 엄격한 검증</li>
                <li><strong>최소 권한 원칙:</strong> 데이터베이스 사용자 권한 최소화</li>
                <li><strong>강력한 인증:</strong> 2FA, 생체 인식 등 다중 인증 방식</li>
                <li><strong>세션 관리:</strong> 안전한 세션 토큰 및 만료 시간 설정</li>
                <li><strong>로깅 및 모니터링:</strong> 로그인 시도 및 실패 모니터링</li>
                <li><strong>Rate Limiting:</strong> 무차별 대입 공격 방지</li>
                <li><strong>암호화:</strong> 비밀번호 해시 및 전송 구간 암호화</li>
            </ul>
        </div>

        <!-- 코드 예제 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>🔧 안전한 인증 구현 예제</h3>
            <h4>취약한 코드:</h4>
            <div class="attack-demo">// 취약한 코드 - SQL Injection 가능
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $sql);
if (mysqli_num_rows($result) > 0) {
    // 로그인 성공
}</div>

            <h4>안전한 코드:</h4>
            <div class="attack-demo">// 안전한 코드 - Prepared Statement 사용
$sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";
$stmt = $pdo->prepare($sql);
$hashed_password = hash('sha256', $password);
$stmt->execute([$username, $hashed_password]);

if ($user = $stmt->fetch()) {
    // 추가 검증
    if (password_verify($password, $user['hashed_password'])) {
        // 로그인 성공
    }
}</div>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass" target="_blank">PayloadsAllTheThings - Authentication Bypass</a></li>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/" target="_blank">OWASP - Authentication Testing</a></li>
                <li><a href="https://portswigger.net/web-security/authentication" target="_blank">PortSwigger - Authentication vulnerabilities</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/287.html" target="_blank">CWE-287: Improper Authentication</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setUsernamePayload(payload) {
            document.getElementById('username').value = payload;
            document.getElementById('password').value = 'anything';
        }

        function setPasswordPayload(payload) {
            document.getElementById('password').value = payload;
        }

        // 실시간 위험 입력 감지
        function checkDangerousInput(element) {
            const value = element.value;
            const dangerousPatterns = [
                /'/,               // Single quotes
                /--/,              // SQL comments
                /\/\*/,            // SQL comments
                /union/i,          // UNION queries
                /select/i,         // SELECT queries
                /or\s+1=1/i,       // OR 1=1
                /or\s+'1'='1'/i,   // OR '1'='1'
                /\$ne/,            // NoSQL operators
                /\$gt/,            // NoSQL operators
                /\)\(&\)\)/,       // LDAP injection
                /\*\)\(/           // LDAP injection
            ];
            
            let isDangerous = false;
            for (let pattern of dangerousPatterns) {
                if (pattern.test(value)) {
                    isDangerous = true;
                    break;
                }
            }
            
            if (isDangerous) {
                element.style.borderColor = '#dc3545';
                element.style.backgroundColor = '#fff5f5';
            } else {
                element.style.borderColor = '#ced4da';
                element.style.backgroundColor = '#ffffff';
            }
        }

        document.getElementById('username').addEventListener('input', function() {
            checkDangerousInput(this);
        });

        document.getElementById('password').addEventListener('input', function() {
            checkDangerousInput(this);
        });

        // 폼 제출 시 확인
        document.querySelector('form').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            const dangerousChars = /['"\-\-\/\*\$\(\)\|\&]/;
            
            if (dangerousChars.test(username) || dangerousChars.test(password)) {
                const confirmed = confirm(
                    '⚠️ 입력된 값에 위험한 문자가 포함되어 있습니다.\n' +
                    '이는 Authentication Bypass 공격에 사용될 수 있습니다.\n\n' +
                    '교육 목적으로 계속 진행하시겠습니까?'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            } else {
                const confirmed = confirm(
                    'Authentication Bypass 테스트를 실행하시겠습니까?\n' +
                    '이 테스트는 교육 목적으로만 사용하세요.'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            }
        });
    </script>
</body>
</html>