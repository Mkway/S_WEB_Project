<?php
/**
 * LDAP Injection 취약점 테스트 페이지
 * 교육 목적으로만 사용하시기 바랍니다.
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
$ldap_input = '';
$query_type = 'search';

// LDAP Injection 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ldap_query'])) {
    $ldap_input = $_POST['ldap_query'];
    $query_type = $_POST['query_type'] ?? 'search';
    
    if (empty($ldap_input)) {
        $result = "LDAP 쿼리를 입력해주세요.";
    } else {
        // 교육 목적의 LDAP Injection 시뮬레이션
        $dangerous_patterns = [
            // LDAP 메타문자
            'metacharacters' => ['*', '(', ')', '\\', '/', '|', '&', '!', '=', '<', '>', '~'],
            // 논리 연산자
            'operators' => ['&', '|', '!'],
            // 인증 우회 패턴
            'auth_bypass' => ['*)(uid=*', '*)(cn=*', '*)(&', '*))%00'],
            // 블라인드 공격 패턴
            'blind' => ['*)(objectClass=*', '*)(description=*'],
            // 정보 수집 패턴
            'enumeration' => ['objectClass=*', 'cn=admin*', 'uid=*']
        ];
        
        $payload_detected = false;
        $detected_patterns = [];
        $attack_type = '';
        
        // 패턴 매칭 검사
        foreach ($dangerous_patterns as $type => $patterns) {
            foreach ($patterns as $pattern) {
                if (stripos($ldap_input, $pattern) !== false) {
                    $payload_detected = true;
                    $detected_patterns[] = $pattern;
                    $attack_type = $type;
                    break 2;
                }
            }
        }
        
        if ($payload_detected) {
            $result = "[시뮬레이션] LDAP Injection 공격 감지됨\n";
            $result .= "쿼리 유형: " . strtoupper($query_type) . "\n";
            $result .= "공격 유형: " . $attack_type . "\n";
            $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
            
            // 공격 유형별 상세 설명
            switch ($attack_type) {
                case 'auth_bypass':
                    $result .= "인증 우회 공격 시나리오:\n";
                    $result .= "- 원본 쿼리: (uid=user)(password=pass)\n";
                    $result .= "- 공격 쿼리: (uid=*)(uid=admin)(password=*)\n";
                    $result .= "- 결과: 비밀번호 검증 없이 관리자 계정 접근\n";
                    $result .= "- 영향: 전체 사용자 계정 정보 노출 가능";
                    break;
                    
                case 'blind':
                    $result .= "블라인드 LDAP Injection 시나리오:\n";
                    $result .= "- True 조건: (objectClass=*) - 모든 객체 반환\n";
                    $result .= "- False 조건: (objectClass=invalid) - 결과 없음\n";
                    $result .= "- 정보 추출: (cn=a*) → (cn=ad*) → (cn=admin*)\n";
                    $result .= "- 영향: 숨겨진 사용자 정보 단계별 추출";
                    break;
                    
                case 'enumeration':
                    $result .= "LDAP 디렉토리 열거 시나리오:\n";
                    $result .= "- 모든 사용자: (uid=*)\n";
                    $result .= "- 관리자 계정: (cn=admin*)\n";
                    $result .= "- 서비스 계정: (objectClass=serviceAccount)\n";
                    $result .= "- 그룹 정보: (objectClass=groupOfNames)";
                    break;
                    
                case 'operators':
                    $result .= "LDAP 논리 연산자 악용:\n";
                    $result .= "- OR 주입: (|(uid=user)(uid=admin))\n";
                    $result .= "- AND 무력화: (&(uid=user)(!(password=*)))\n";
                    $result .= "- NOT 연산: (!(uid=disabled))\n";
                    $result .= "- 복합 조건: (&(|(cn=*)(uid=*))(objectClass=*))";
                    break;
                    
                default:
                    $result .= "일반적인 LDAP Injection 패턴 감지됨\n";
                    $result .= "잠재적 위험: 디렉토리 정보 노출, 인증 우회";
            }
            
        } else {
            // 안전한 LDAP 쿼리 처리 시뮬레이션
            $result = "안전한 LDAP 쿼리 처리 완료:\n";
            $result .= "쿼리 유형: " . strtoupper($query_type) . "\n";
            $result .= "입력된 쿼리가 정상적으로 처리되었습니다.\n";
            $result .= "위험한 패턴이 감지되지 않았습니다.\n\n";
            
            // 예상 LDAP 쿼리 결과 시뮬레이션
            switch ($query_type) {
                case 'search':
                    $result .= "LDAP 검색 결과 시뮬레이션:\n";
                    $result .= "검색 쿼리: " . htmlspecialchars($ldap_input) . "\n";
                    $result .= "→ 매칭된 항목: 3개\n";
                    $result .= "→ cn=testuser,ou=users,dc=example,dc=com\n";
                    $result .= "→ cn=normaluser,ou=users,dc=example,dc=com";
                    break;
                    
                case 'bind':
                    $result .= "LDAP 바인드 결과 시뮬레이션:\n";
                    $result .= "인증 시도: " . htmlspecialchars($ldap_input) . "\n";
                    $result .= "→ 바인드 성공\n";
                    $result .= "→ 사용자 인증 완료";
                    break;
                    
                case 'modify':
                    $result .= "LDAP 수정 결과 시뮬레이션:\n";
                    $result .= "수정 대상: " . htmlspecialchars($ldap_input) . "\n";
                    $result .= "→ 속성 수정 완료\n";
                    $result .= "→ 변경 사항 저장됨";
                    break;
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LDAP Injection 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .vulnerability-description, .mitigation-guide {
            background-color: #f9f9f9;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .mitigation-guide {
            border-color: #28a745;
        }
        textarea {
            width: 100%;
            height: 120px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin: 10px 0;
            width: 200px;
        }
        .payload-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .payload-btn:hover {
            background: #138496;
        }
        .nav {
            background: #343a40;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav h1 {
            margin: 0;
            color: white;
        }
        .nav-links .btn {
            margin-left: 10px;
            background: #007bff;
            color: white;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 4px;
        }
        .ldap-example {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .attack-vector {
            background: #ffebee;
            border: 1px solid #ef5350;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>LDAP Injection 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🏢 LDAP Injection 취약점</h2>
            <p><strong>설명:</strong> LDAP (Lightweight Directory Access Protocol) 쿼리에서 사용자 입력을 
            적절히 검증하지 않을 때 발생하는 취약점입니다. 인증 우회, 디렉토리 정보 노출, 권한 상승이 가능합니다.</p>
            
            <div class="ldap-example">
                <h4>📖 LDAP 쿼리 구조</h4>
                <p><strong>기본 구조:</strong> <code>(attribute=value)</code></p>
                <p><strong>논리 연산자:</strong></p>
                <ul>
                    <li><code>&</code> - AND 연산: <code>(&(uid=user)(password=pass))</code></li>
                    <li><code>|</code> - OR 연산: <code>(|(uid=admin)(cn=admin))</code></li>
                    <li><code>!</code> - NOT 연산: <code>(!(uid=disabled))</code></li>
                    <li><code>*</code> - 와일드카드: <code>(cn=admin*)</code></li>
                </ul>
            </div>
            
            <h3>📋 테스트 페이로드:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testPayload('auth_bypass')" class="payload-btn">인증 우회</button>
                <button onclick="testPayload('blind')" class="payload-btn">블라인드 주입</button>
                <button onclick="testPayload('enumeration')" class="payload-btn">정보 열거</button>
                <button onclick="testPayload('wildcard')" class="payload-btn">와일드카드</button>
                <button onclick="testPayload('safe')" class="payload-btn">안전한 쿼리</button>
            </div>
        </div>

        <form method="POST">
            <label for="query_type">🔍 LDAP 작업 유형:</label><br>
            <select id="query_type" name="query_type">
                <option value="search" <?php echo ($query_type == 'search') ? 'selected' : ''; ?>>Search (검색)</option>
                <option value="bind" <?php echo ($query_type == 'bind') ? 'selected' : ''; ?>>Bind (인증)</option>
                <option value="modify" <?php echo ($query_type == 'modify') ? 'selected' : ''; ?>>Modify (수정)</option>
            </select><br><br>
            
            <label for="ldap_query">🎯 LDAP 쿼리 입력:</label><br>
            <textarea id="ldap_query" name="ldap_query" placeholder="LDAP 쿼리를 입력하세요... 예: (uid=testuser)"><?php echo htmlspecialchars($ldap_input); ?></textarea><br><br>
            <input type="submit" value="LDAP 쿼리 실행" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="attack-vector">
            <h4>⚠️ 주요 공격 벡터</h4>
            <p><strong>1. 인증 우회:</strong> <code>(uid=*)(uid=admin)</code></p>
            <p><strong>2. 정보 노출:</strong> <code>(|(uid=*)(cn=*))</code></p>
            <p><strong>3. 블라인드 공격:</strong> <code>(uid=admin*)</code> → <code>(uid=adminuser*)</code></p>
            <p><strong>4. 논리 우회:</strong> <code>(&(uid=user)(!(password=*)))</code></p>
        </div>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>입력 검증:</strong> LDAP 메타문자 (, ), *, \, /, |, &, ! 필터링</li>
                <li><strong>이스케이프 처리:</strong> 특수 문자를 적절히 이스케이프</li>
                <li><strong>화이트리스트:</strong> 허용된 문자와 패턴만 허용</li>
                <li><strong>최소 권한:</strong> LDAP 서비스 계정 권한 최소화</li>
                <li><strong>바인드 DN 검증:</strong> 인증 시 DN(Distinguished Name) 형식 검증</li>
                <li><strong>로깅 및 모니터링:</strong> 비정상적인 LDAP 쿼리 패턴 감지</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        const payloads = {
            search: {
                auth_bypass: '*)(uid=*',
                blind: '(uid=admin*)',
                enumeration: '(objectClass=*)',
                wildcard: '(cn=*admin*)',
                safe: '(uid=testuser)'
            },
            bind: {
                auth_bypass: 'cn=*,ou=users,dc=example,dc=com',
                blind: 'cn=admin*,ou=users,dc=example,dc=com',
                enumeration: 'cn=*,ou=*,dc=*',
                wildcard: 'uid=*admin*,ou=users,dc=example,dc=com',
                safe: 'cn=testuser,ou=users,dc=example,dc=com'
            },
            modify: {
                auth_bypass: 'cn=*,ou=users,dc=example,dc=com',
                blind: 'cn=admin*,ou=users,dc=example,dc=com',
                enumeration: 'cn=*,ou=*,dc=*',
                wildcard: 'uid=*admin*,ou=users,dc=example,dc=com',
                safe: 'cn=testuser,ou=users,dc=example,dc=com'
            }
        };

        function testPayload(type) {
            const queryType = document.getElementById('query_type').value;
            const payload = payloads[queryType][type];
            
            if (confirm('⚠️ 교육 목적의 LDAP Injection 테스트를 실행하시겠습니까?\n\n작업 유형: ' + queryType + '\n공격 유형: ' + type)) {
                document.getElementById('ldap_query').value = payload;
            }
        }

        // 위험 패턴 경고
        document.getElementById('ldap_query').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['*)(', '|(', '&(', '!(', '*)', 'objectclass=*', 'cn=*', 'uid=*'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // 쿼리 유형 변경 시 예제 업데이트
        document.getElementById('query_type').addEventListener('change', function() {
            const type = this.value;
            const examples = {
                search: '(uid=testuser)',
                bind: 'cn=testuser,ou=users,dc=example,dc=com',
                modify: 'cn=testuser,ou=users,dc=example,dc=com'
            };
            
            document.getElementById('ldap_query').placeholder = 'LDAP ' + type + ' 쿼리를 입력하세요... 예: ' + examples[type];
        });
    </script>
</body>
</html>