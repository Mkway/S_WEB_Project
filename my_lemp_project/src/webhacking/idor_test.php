<?php
/**
 * IDOR (Insecure Direct Object References) 테스트 페이지
 * PayloadsAllTheThings의 IDOR 페이로드를 기반으로 구성
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
$test_type = $_POST['test_type'] ?? 'user_id';
$resource_id = $_POST['resource_id'] ?? '';

// 현재 사용자 ID (세션에서)
$current_user_id = $_SESSION['user_id'];

// 모의 데이터베이스 (테스트용)
$mock_data = [
    'users' => [
        1 => ['name' => 'Alice', 'email' => 'alice@example.com', 'role' => 'user'],
        2 => ['name' => 'Bob', 'email' => 'bob@example.com', 'role' => 'admin'],
        3 => ['name' => 'Charlie', 'email' => 'charlie@example.com', 'role' => 'user'],
        4 => ['name' => 'David', 'email' => 'david@example.com', 'role' => 'user'],
        5 => ['name' => 'Eve', 'email' => 'eve@example.com', 'role' => 'user']
    ],
    'documents' => [
        1 => ['title' => 'My Personal Notes', 'owner_id' => 1, 'content' => 'Private notes...'],
        2 => ['title' => 'Admin Report', 'owner_id' => 2, 'content' => 'Confidential admin data...'],
        3 => ['title' => 'Project Plan', 'owner_id' => 3, 'content' => 'Project details...'],
        4 => ['title' => 'Financial Data', 'owner_id' => 2, 'content' => 'Sensitive financial info...'],
        5 => ['title' => 'User Manual', 'owner_id' => 1, 'content' => 'Public documentation...']
    ],
    'orders' => [
        100 => ['product' => 'Laptop', 'customer_id' => 1, 'amount' => 1200],
        101 => ['product' => 'Phone', 'customer_id' => 3, 'amount' => 800],
        102 => ['product' => 'Tablet', 'customer_id' => 4, 'amount' => 500],
        103 => ['product' => 'Monitor', 'customer_id' => 1, 'amount' => 300],
        104 => ['product' => 'Keyboard', 'customer_id' => 5, 'amount' => 100]
    ]
];

// IDOR 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'numeric_id' => [
        '1', '2', '3', '4', '5', '10', '100', '999', '1000',
        '-1', '-2', '0', '00', '01', '001'
    ],
    'guid_bruteforce' => [
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000002',
        '11111111-1111-1111-1111-111111111111',
        'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        '12345678-1234-1234-1234-123456789abc'
    ],
    'encoded_payloads' => [
        '%31', '%32', '%33', '%34', '%35',  // URL encoded 1,2,3,4,5
        '%2E%2E%2F1', '%2E%2E%2F2',       // ../1, ../2
        '..%2F1', '..%2F2',               // ../1, ../2
        '%252E%252E%252F1'                // Double encoded ../1
    ],
    'hash_manipulation' => [
        'md5(' . md5('1') . ')',
        'sha1(' . sha1('1') . ')',
        base64_encode('1'),
        base64_encode('2'),
        bin2hex('1'),
        bin2hex('2')
    ],
    'bypass_techniques' => [
        '1.json', '2.json', '3.json',
        '1.xml', '2.xml', '3.xml',
        '1?format=json', '2?format=xml',
        '1#', '2#', '3#',
        '1/', '2/', '3/',
        '1..', '2..', '3..'
    ]
];

// 테스트 실행
if ($_POST && isset($_POST['resource_id'])) {
    $id = $resource_id;
    
    // ID 정규화 (인코딩 디코드 등)
    $decoded_id = urldecode($id);
    $clean_id = filter_var($decoded_id, FILTER_SANITIZE_NUMBER_INT);
    $numeric_id = (int)$clean_id;
    
    $result = "🔍 IDOR 테스트 결과\n\n";
    $result .= "원본 입력: " . htmlspecialchars($id) . "\n";
    $result .= "디코드된 값: " . htmlspecialchars($decoded_id) . "\n";
    $result .= "정규화된 ID: " . htmlspecialchars($numeric_id) . "\n\n";
    
    switch ($test_type) {
        case 'user_id':
            if (isset($mock_data['users'][$numeric_id])) {
                $user = $mock_data['users'][$numeric_id];
                
                // 접근 권한 체크 (현재 사용자 ID와 비교)
                if ($numeric_id == $current_user_id || $numeric_id == 1) {  // 1번은 테스트용으로 허용
                    $result .= "✅ 사용자 정보 접근 성공:\n";
                    $result .= "이름: " . $user['name'] . "\n";
                    $result .= "이메일: " . $user['email'] . "\n";
                    $result .= "역할: " . $user['role'] . "\n";
                } else {
                    $result .= "⚠️ IDOR 취약점 감지!\n\n";
                    $result .= "다른 사용자의 정보에 접근을 시도했습니다:\n";
                    $result .= "타겟 사용자: " . $user['name'] . "\n";
                    $result .= "이메일: " . $user['email'] . "\n";
                    $result .= "역할: " . $user['role'] . "\n\n";
                    $result .= "🛡️ 실제 시스템에서는 이러한 접근이 차단되어야 합니다.";
                }
            } else {
                $result .= "❌ 사용자 ID " . $numeric_id . "를 찾을 수 없습니다.";
            }
            break;
            
        case 'document':
            if (isset($mock_data['documents'][$numeric_id])) {
                $doc = $mock_data['documents'][$numeric_id];
                
                // 문서 소유자 체크
                if ($doc['owner_id'] == $current_user_id || $doc['owner_id'] == 1) {  // 1번 소유 문서는 테스트용으로 허용
                    $result .= "✅ 문서 접근 성공:\n";
                    $result .= "제목: " . $doc['title'] . "\n";
                    $result .= "내용: " . $doc['content'] . "\n";
                } else {
                    $result .= "⚠️ IDOR 취약점 감지!\n\n";
                    $result .= "다른 사용자의 문서에 접근을 시도했습니다:\n";
                    $result .= "제목: " . $doc['title'] . "\n";
                    $result .= "소유자 ID: " . $doc['owner_id'] . "\n";
                    $result .= "내용: " . substr($doc['content'], 0, 50) . "...\n\n";
                    $result .= "🛡️ 실제 시스템에서는 이러한 접근이 차단되어야 합니다.";
                }
            } else {
                $result .= "❌ 문서 ID " . $numeric_id . "를 찾을 수 없습니다.";
            }
            break;
            
        case 'order':
            if (isset($mock_data['orders'][$numeric_id])) {
                $order = $mock_data['orders'][$numeric_id];
                
                // 주문 고객 체크
                if ($order['customer_id'] == $current_user_id || $order['customer_id'] == 1) {  // 1번 고객 주문은 테스트용으로 허용
                    $result .= "✅ 주문 정보 접근 성공:\n";
                    $result .= "상품: " . $order['product'] . "\n";
                    $result .= "금액: $" . $order['amount'] . "\n";
                } else {
                    $result .= "⚠️ IDOR 취약점 감지!\n\n";
                    $result .= "다른 고객의 주문 정보에 접근을 시도했습니다:\n";
                    $result .= "주문 ID: " . $numeric_id . "\n";
                    $result .= "상품: " . $order['product'] . "\n";
                    $result .= "고객 ID: " . $order['customer_id'] . "\n";
                    $result .= "금액: $" . $order['amount'] . "\n\n";
                    $result .= "🛡️ 실제 시스템에서는 이러한 접근이 차단되어야 합니다.";
                }
            } else {
                $result .= "❌ 주문 ID " . $numeric_id . "를 찾을 수 없습니다.";
            }
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDOR 테스트 - 보안 테스트</title>
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
        
        .mock-data {
            background: #e9ecef;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 12px;
        }
        
        .test-type-selector {
            margin: 15px 0;
        }
        
        .test-type-selector label {
            margin-right: 15px;
            display: inline-block;
            margin-bottom: 10px;
        }
        
        input[type="text"] {
            width: 100%;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
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
        
        .current-user {
            background: #d4edda;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>IDOR (Insecure Direct Object References) 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>IDOR 테스트</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🔑 Insecure Direct Object References (IDOR) 테스트</h3>
            <p><strong>IDOR</strong>는 애플리케이션이 사용자 입력을 직접 객체 참조로 사용하여 적절한 권한 검사 없이 데이터에 접근을 허용하는 취약점입니다.</p>
            <p>공격자가 URL 파라미터나 폼 필드의 값을 변경하여 다른 사용자의 데이터에 접근할 수 있습니다.</p>
            <p><strong>참고:</strong> 이 페이지에서는 모의 데이터를 사용하여 안전한 환경에서 테스트합니다.</p>
        </div>

        <!-- 현재 사용자 정보 -->
        <div class="current-user">
            <strong>현재 세션 정보:</strong><br>
            사용자 ID: <?php echo $current_user_id; ?><br>
            사용자명: <?php echo htmlspecialchars($_SESSION['username']); ?><br>
            <small>이 정보를 기준으로 권한 검사가 수행됩니다.</small>
        </div>

        <!-- 경고 -->
        <div class="danger-box">
            <h3>⚠️ <span class="severity-critical">HIGH RISK</span> 보안 위험</h3>
            <p>IDOR 취약점은 다음과 같은 심각한 결과를 초래할 수 있습니다:</p>
            <ul>
                <li>다른 사용자의 개인정보 열람</li>
                <li>타인의 계정 정보 수정</li>
                <li>기밀 문서 및 파일 접근</li>
                <li>금융 거래 내역 노출</li>
                <li>관리자 권한 데이터 접근</li>
                <li>시스템 전체 데이터 유출</li>
            </ul>
        </div>

        <!-- 모의 데이터 구조 -->
        <div class="mock-data">
            <h3>📊 테스트용 모의 데이터 구조</h3>
            <strong>사용자 (users):</strong> ID 1-5 (Alice, Bob, Charlie, David, Eve)<br>
            <strong>문서 (documents):</strong> ID 1-5 (각각 다른 소유자)<br>
            <strong>주문 (orders):</strong> ID 100-104 (각각 다른 고객)<br>
            <small>실제 데이터베이스는 사용하지 않으며, 모든 데이터는 시뮬레이션입니다.</small>
        </div>

        <!-- Numeric ID Enumeration -->
        <div class="payload-section">
            <h3>🔢 Numeric ID Enumeration</h3>
            <p>순차적인 숫자 ID를 이용한 기본적인 IDOR 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['numeric_id'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- GUID Bruteforce -->
        <div class="payload-section">
            <h3>🔤 GUID/UUID Bruteforce</h3>
            <p>GUID나 UUID를 사용하는 시스템에서의 추측 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['guid_bruteforce'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 8)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Encoded Payloads -->
        <div class="payload-section">
            <h3>🔄 Encoded Parameter Manipulation</h3>
            <p>URL 인코딩이나 다른 인코딩을 통한 필터 우회 시도입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['encoded_payloads'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Hash Manipulation -->
        <div class="payload-section">
            <h3>🔐 Hash/Token Manipulation</h3>
            <p>해시값이나 인코딩된 토큰을 조작하는 고급 IDOR 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['hash_manipulation'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        Hash/Encoded
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Bypass Techniques -->
        <div class="payload-section">
            <h3>🚫 Bypass Techniques</h3>
            <p>다양한 파라미터 형태와 확장자를 사용한 우회 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['bypass_techniques'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 IDOR 테스트</h3>
            
            <div class="test-type-selector">
                <label><input type="radio" name="test_type" value="user_id" <?php echo $test_type === 'user_id' ? 'checked' : ''; ?>> 사용자 정보 (User ID)</label>
                <label><input type="radio" name="test_type" value="document" <?php echo $test_type === 'document' ? 'checked' : ''; ?>> 문서 접근 (Document ID)</label>
                <label><input type="radio" name="test_type" value="order" <?php echo $test_type === 'order' ? 'checked' : ''; ?>> 주문 정보 (Order ID)</label>
            </div>
            
            <label for="resource_id">리소스 ID:</label>
            <input type="text" name="resource_id" id="resource_id" placeholder="예: 1, 2, 3, %31, etc." value="<?php echo htmlspecialchars($resource_id); ?>">
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">IDOR 테스트 실행</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- IDOR 공격 시나리오 -->
        <div class="examples">
            <h3>💡 IDOR 공격 시나리오</h3>
            <p><strong>시나리오 1:</strong> 사용자 프로필 페이지</p>
            <code>profile.php?user_id=1</code> → <code>profile.php?user_id=2</code> (다른 사용자 정보 열람)
            <br><br>
            <p><strong>시나리오 2:</strong> 문서 다운로드</p>
            <code>download.php?doc_id=123</code> → <code>download.php?doc_id=124</code> (타인의 文서 다운로드)
            <br><br>
            <p><strong>시나리오 3:</strong> 계좌 거래 내역</p>
            <code>transactions.php?account=12345</code> → <code>transactions.php?account=12346</code> (타인의 거래 내역 열람)
            <br><br>
            <p><strong>시나리오 4:</strong> API 엔드포인트</p>
            <code>api/user/1</code> → <code>api/user/2</code> (API를 통한 정보 수집)
        </div>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ IDOR 방어 방법</h3>
            <ul>
                <li><strong>인증 및 권한 검사:</strong> 모든 요청에서 사용자 권한 확인</li>
                <li><strong>간접 참조 사용:</strong> 직접적인 객체 ID 대신 매핑 테이블 사용</li>
                <li><strong>UUID 사용:</strong> 예측 가능한 순차 ID 대신 UUID 사용</li>
                <li><strong>세션 기반 검증:</strong> 세션 정보와 요청 객체의 소유권 확인</li>
                <li><strong>접근 제어 목록 (ACL):</strong> 각 객체별 접근 권한 정의</li>
                <li><strong>파라미터 암호화:</strong> 중요한 ID는 암호화하여 전송</li>
                <li><strong>로깅 및 모니터링:</strong> 의심스러운 접근 패턴 탐지</li>
            </ul>
        </div>

        <!-- 코드 예제 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>🔧 IDOR 방어 구현 예제</h3>
            <h4>취약한 코드:</h4>
            <div class="mock-data">// 취약한 코드 - 권한 검사 없음
$user_id = $_GET['user_id'];
$sql = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($conn, $sql);</div>

            <h4>안전한 코드:</h4>
            <div class="mock-data">// 안전한 코드 - 권한 검사 포함
$user_id = $_GET['user_id'];
$current_user_id = $_SESSION['user_id'];

// 자신의 정보만 접근 가능
if ($user_id != $current_user_id && !is_admin()) {
    die('Unauthorized access');
}

$sql = "SELECT * FROM users WHERE id = ? AND id = ?";
$stmt = $pdo->prepare($sql);
$stmt->execute([$user_id, $current_user_id]);</div>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References" target="_blank">PayloadsAllTheThings - IDOR</a></li>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References" target="_blank">OWASP - IDOR Testing</a></li>
                <li><a href="https://portswigger.net/web-security/access-control/idor" target="_blank">PortSwigger - IDOR</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/639.html" target="_blank">CWE-639: Authorization Bypass</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setPayload(payload) {
            document.getElementById('resource_id').value = payload;
        }

        // 실시간 위험 입력 감지
        document.getElementById('resource_id').addEventListener('input', function() {
            const value = this.value;
            const currentUserId = <?php echo $current_user_id; ?>;
            
            // 현재 사용자 ID가 아닌 다른 값들은 위험으로 표시
            if (value && value != currentUserId.toString() && value != '1') {  // 1은 테스트용으로 허용
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#28a745';
                this.style.backgroundColor = '#f8fff8';
            }
        });

        // 폼 제출 시 확인
        document.querySelector('form').addEventListener('submit', function(e) {
            const resourceId = document.getElementById('resource_id').value;
            const currentUserId = <?php echo $current_user_id; ?>;
            
            if (resourceId && resourceId != currentUserId.toString() && resourceId != '1') {
                const confirmed = confirm(
                    '⚠️ 다른 사용자의 리소스에 접근을 시도하고 있습니다.\n' +
                    '이는 IDOR (Insecure Direct Object References) 공격입니다.\n\n' +
                    '교육 목적으로 계속 진행하시겠습니까?'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            } else {
                const confirmed = confirm(
                    'IDOR 테스트를 실행하시겠습니까?\n' +
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