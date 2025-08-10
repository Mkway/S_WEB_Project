<?php
/**
 * XPath Injection 취약점 테스트 페이지
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
$xpath_input = '';

// 샘플 XML 데이터 (시뮬레이션용)
$sample_xml = '<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user id="1">
        <username>admin</username>
        <password>admin123</password>
        <role>administrator</role>
        <email>admin@example.com</email>
    </user>
    <user id="2">
        <username>user1</username>
        <password>user123</password>
        <role>user</role>
        <email>user1@example.com</email>
    </user>
    <user id="3">
        <username>guest</username>
        <password>guest</password>
        <role>guest</role>
        <email>guest@example.com</email>
    </user>
</users>';

// XPath Injection 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xpath_query'])) {
    $xpath_input = $_POST['xpath_query'];
    
    if (empty($xpath_input)) {
        $result = "XPath 쿼리를 입력해주세요.";
    } else {
        // 교육 목적의 XPath Injection 시뮬레이션
        $dangerous_patterns = [
            // 논리 연산자
            'operators' => ['or', 'and', 'not()'],
            // 함수 호출
            'functions' => ['count()', 'string-length()', 'substring()', 'contains()', 'starts-with()'],
            // 축 (Axes)
            'axes' => ['ancestor::', 'descendant::', 'following::', 'preceding::', 'parent::', 'child::'],
            // 인증 우회 패턴
            'auth_bypass' => ["'='", "' or '1'='1", "' or 1=1 or '", "'] | //user[position()=1] | //user['"],
            // 블라인드 공격
            'blind' => ['string-length()', 'substring(', 'position()='],
            // 데이터 추출
            'extraction' => ['//*', '//user', '//password', '//text()']
        ];
        
        $payload_detected = false;
        $detected_patterns = [];
        $attack_type = '';
        
        // 패턴 매칭 검사
        foreach ($dangerous_patterns as $type => $patterns) {
            foreach ($patterns as $pattern) {
                if (stripos($xpath_input, $pattern) !== false) {
                    $payload_detected = true;
                    $detected_patterns[] = $pattern;
                    $attack_type = $type;
                    break 2;
                }
            }
        }
        
        if ($payload_detected) {
            $result = "[시뮬레이션] XPath Injection 공격 감지됨\n";
            $result .= "공격 유형: " . $attack_type . "\n";
            $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
            
            // 공격 유형별 상세 설명
            switch ($attack_type) {
                case 'auth_bypass':
                    $result .= "XPath 인증 우회 공격 시나리오:\n";
                    $result .= "- 원본 쿼리: //user[username='user' and password='pass']\n";
                    $result .= "- 공격 쿼리: //user[username='' or '1'='1' and password='pass']\n";
                    $result .= "- 결과: 모든 사용자 노드 반환 (첫 번째 사용자로 인증)\n";
                    $result .= "- 실제 결과 시뮬레이션:\n";
                    $result .= "  → admin 계정으로 로그인 성공\n";
                    $result .= "  → 관리자 권한 획득";
                    break;
                    
                case 'blind':
                    $result .= "블라인드 XPath Injection 시나리오:\n";
                    $result .= "- 문자열 길이 추출: string-length(//user[1]/password)\n";
                    $result .= "- 문자별 추출: substring(//user[1]/password,1,1)='a'\n";
                    $result .= "- 노드 개수: count(//user)\n";
                    $result .= "- 단계별 데이터 추출 가능:\n";
                    $result .= "  → 비밀번호 길이: 8자\n";
                    $result .= "  → 첫 번째 문자: 'a'\n";
                    $result .= "  → 완전한 비밀번호: 'admin123'";
                    break;
                    
                case 'extraction':
                    $result .= "데이터 추출 공격 시나리오:\n";
                    $result .= "- 전체 노드: //* - 모든 XML 노드 반환\n";
                    $result .= "- 사용자 정보: //user - 모든 사용자 노드\n";
                    $result .= "- 민감한 데이터: //password - 모든 비밀번호\n";
                    $result .= "- 추출 가능한 정보:\n";
                    $result .= "  → 모든 사용자명: admin, user1, guest\n";
                    $result .= "  → 모든 비밀번호: admin123, user123, guest\n";
                    $result .= "  → 이메일 주소: admin@example.com, user1@example.com";
                    break;
                    
                case 'functions':
                    $result .= "XPath 함수 악용 시나리오:\n";
                    $result .= "- contains() 함수: //user[contains(username,'admin')]\n";
                    $result .= "- starts-with() 함수: //user[starts-with(password,'admin')]\n";
                    $result .= "- string-length() 함수: //user[string-length(password)>5]\n";
                    $result .= "- 정보 수집 결과:\n";
                    $result .= "  → 관리자 계정 존재 확인\n";
                    $result .= "  → 비밀번호 패턴 분석\n";
                    $result .= "  → 계정 구조 파악";
                    break;
                    
                case 'axes':
                    $result .= "XPath 축(Axes) 활용 시나리오:\n";
                    $result .= "- ancestor:: 상위 노드 탐색\n";
                    $result .= "- descendant:: 하위 모든 노드 탐색\n";
                    $result .= "- following:: 다음 노드들 탐색\n";
                    $result .= "- 탐색 결과: XML 구조 전체 파악 가능";
                    break;
                    
                default:
                    $result .= "일반적인 XPath Injection 패턴:\n";
                    $result .= "- 논리 연산자를 통한 조건 우회\n";
                    $result .= "- XPath 함수를 통한 정보 수집\n";
                    $result .= "- 잠재적 위험: 전체 XML 데이터 노출";
            }
            
        } else {
            // 안전한 XPath 쿼리 처리 시뮬레이션
            try {
                $dom = new DOMDocument();
                $dom->loadXML($sample_xml);
                $xpath = new DOMXPath($dom);
                
                // 간단한 XPath 쿼리 실행 (안전한 경우만)
                if (preg_match('/^\/\/\w+(\[\w+=[\'"][^\'"\[\]]*[\'"]\])?$/', $xpath_input)) {
                    $nodes = $xpath->query($xpath_input);
                    
                    $result = "안전한 XPath 쿼리 처리 완료:\n";
                    $result .= "쿼리: " . htmlspecialchars($xpath_input) . "\n";
                    $result .= "결과 노드 수: " . $nodes->length . "\n\n";
                    
                    if ($nodes->length > 0) {
                        $result .= "매칭된 노드:\n";
                        foreach ($nodes as $i => $node) {
                            if ($i < 3) { // 최대 3개만 표시
                                $result .= "- " . $node->nodeName . ": " . $node->textContent . "\n";
                            }
                        }
                    } else {
                        $result .= "매칭된 노드가 없습니다.";
                    }
                } else {
                    $result = "안전한 XPath 쿼리 형식이 아닙니다.\n";
                    $result .= "기본 형식을 사용해주세요: //nodename 또는 //nodename[attribute='value']";
                }
                
            } catch (Exception $e) {
                $result = "XPath 쿼리 처리 중 오류 발생:\n";
                $result .= "올바른 XPath 문법을 사용해주세요.";
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
    <title>XPath Injection 테스트 - <?php echo SITE_NAME; ?></title>
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
        input[type="text"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
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
        .xml-sample {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            overflow-x: auto;
        }
        .xpath-syntax {
            background: #e8f5e8;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>XPath Injection 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>📍 XPath Injection 취약점</h2>
            <p><strong>설명:</strong> XPath 표현식에서 사용자 입력을 적절히 검증하지 않을 때 발생하는 취약점입니다. 
            XML 데이터의 전체 구조 노출, 인증 우회, 민감한 정보 추출이 가능합니다.</p>
            
            <div class="xpath-syntax">
                <h4>📖 XPath 기본 문법</h4>
                <p><strong>노드 선택:</strong></p>
                <ul>
                    <li><code>//user</code> - 모든 user 노드</li>
                    <li><code>//user[1]</code> - 첫 번째 user 노드</li>
                    <li><code>//user[@id='1']</code> - id가 1인 user 노드</li>
                    <li><code>//user[username='admin']</code> - username이 admin인 노드</li>
                </ul>
                <p><strong>조건 연산자:</strong></p>
                <ul>
                    <li><code>and</code>, <code>or</code>, <code>not()</code> - 논리 연산</li>
                    <li><code>=</code>, <code>!=</code>, <code>&lt;</code>, <code>&gt;</code> - 비교 연산</li>
                </ul>
            </div>
            
            <h3>📋 테스트 페이로드:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testPayload('auth_bypass')" class="payload-btn">인증 우회</button>
                <button onclick="testPayload('blind')" class="payload-btn">블라인드 주입</button>
                <button onclick="testPayload('extraction')" class="payload-btn">데이터 추출</button>
                <button onclick="testPayload('functions')" class="payload-btn">함수 활용</button>
                <button onclick="testPayload('safe')" class="payload-btn">안전한 쿼리</button>
            </div>
        </div>

        <div class="xml-sample">
            <h4>📄 테스트용 XML 데이터 구조:</h4>
            <pre><?php echo htmlspecialchars($sample_xml); ?></pre>
        </div>

        <form method="POST">
            <label for="xpath_query">🎯 XPath 쿼리 입력:</label><br>
            <input type="text" id="xpath_query" name="xpath_query" value="<?php echo htmlspecialchars($xpath_input); ?>" placeholder="예: //user[username='admin']"><br><br>
            <input type="submit" value="XPath 쿼리 실행" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>입력 검증:</strong> XPath 메타문자 ', ", [, ], (, ), / 필터링</li>
                <li><strong>매개변수화:</strong> XPath 변수를 사용한 쿼리 구성</li>
                <li><strong>화이트리스트:</strong> 허용된 문자와 패턴만 허용</li>
                <li><strong>이스케이프 처리:</strong> 특수 문자를 적절히 이스케이프</li>
                <li><strong>최소 권한:</strong> XML 문서 접근 권한 최소화</li>
                <li><strong>스키마 검증:</strong> XML 스키마를 통한 구조 제한</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        const payloads = {
            auth_bypass: "//user[username='' or '1'='1' and password='']",
            blind: "//user[string-length(password)>5]",
            extraction: "//password/text()",
            functions: "//user[contains(username,'admin')]",
            safe: "//user[username='testuser']"
        };

        function testPayload(type) {
            const payload = payloads[type];
            
            if (confirm('⚠️ 교육 목적의 XPath Injection 테스트를 실행하시겠습니까?\n\n공격 유형: ' + type + '\n쿼리: ' + payload)) {
                document.getElementById('xpath_query').value = payload;
            }
        }

        // 위험 패턴 경고
        document.getElementById('xpath_query').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ["'='", 'or ', 'and ', 'count(', 'string-length(', 'contains(', '//', 'text()'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // XPath 문법 도움말 표시
        document.getElementById('xpath_query').addEventListener('focus', function() {
            this.title = 'XPath 문법 예제:\n//user - 모든 user 노드\n//user[1] - 첫 번째 user\n//user[username="admin"] - 조건 검색\n//user[contains(username,"admin")] - 부분 매칭';
        });
    </script>
</body>
</html>