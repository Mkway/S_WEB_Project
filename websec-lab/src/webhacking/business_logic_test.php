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

// 시뮬레이션용 사용자 데이터
$current_user = [
    'id' => 123,
    'username' => $_SESSION['username'] ?? 'guest',
    'balance' => 1000,
    'role' => 'user',
    'subscription_expires' => '2025-12-31',
    'failed_login_attempts' => 0
];

// 1. 페이지 설정
$page_title = 'Business Logic Errors';
$description = '<p><strong>Business Logic Errors</strong>는 애플리케이션의 비즈니스 로직 구현 오류로 인해 발생하는 취약점입니다.</p>
<p>기술적 보안은 완벽해도 업무 흐름의 논리적 결함을 악용하여 시스템을 우회하거나 부정한 이익을 얻을 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'price_manipulation' => [
        'title' => '가격 조작 (Price Manipulation)',
        'description' => '상품 가격을 음수나 0으로 조작하여 무료 구매 또는 잔액 증가를 시도합니다.',
        'payloads' => [
            '-1000', '0', '0.01'
        ]
    ],
    'quantity_manipulation' => [
        'title' => '수량 조작 (Quantity Manipulation)',
        'description' => '주문 수량을 음수나 매우 큰 값으로 조작하여 재고 조작 또는 오버플로우를 유발합니다.',
        'payloads' => [
            '-50', '0', '999999999'
        ]
    ],
    'workflow_bypass' => [
        'title' => '워크플로우 우회 (Workflow Bypass)',
        'description' => '정상적인 비즈니스 프로세스의 단계를 건너뛰거나 순서를 변경하여 로직을 우회합니다.',
        'payloads' => [
            'activate,register', // 이메일 인증 없이 활성화
            'complete_profile,register' // 회원가입 없이 프로필 생성
        ]
    ],
    'time_manipulation' => [
        'title' => '시간 조작 (Time Manipulation)',
        'description' => '시간 관련 로직(예: 쿠폰 유효 기간, 경매 마감)을 조작하여 부당한 이득을 얻습니다.',
        'payloads' => [
            '2030-12-31 23:59:59', // 미래 시간
            '1999-01-01 00:00:00' // 과거 시간
        ]
    ],
    'state_manipulation' => [
        'title' => '상태 조작 (State Manipulation)',
        'description' => '주문, 계정 등의 상태를 비정상적으로 변경하여 로직을 우회합니다.',
        'payloads' => [
            'pending -> completed', // 결제 없이 주문 완료
            'cancelled -> shipped' // 취소된 주문 배송
        ]
    ],
    'rate_limit_bypass' => [
        'title' => 'Rate Limit 우회',
        'description' => '요청 빈도 제한을 우회하여 무차별 대입 공격이나 DoS 공격을 시도합니다.',
        'payloads' => [
            '1.1.1.1,1.1.1.1,1.1.1.1,2.2.2.2,2.2.2.2', // 분산 IP
            'user1,user1,user1,user2,user2' // 사용자명 반복
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 검증 강화:</strong> 모든 입력값의 범위, 타입, 형식 검증",
    "<strong>서버 사이드 검증:</strong> 클라이언트 검증에 의존하지 않고 서버에서 재검증",
    "<strong>상태 머신 구현:</strong> 명확한 상태 전환 규칙 정의 및 강제",
    "<strong>트랜잭션 관리:</strong> ACID 속성을 보장하는 데이터베이스 트랜잭션",
    "<strong>시간 검증:</strong> 서버 시간 기준으로 모든 시간 관련 로직 처리",
    "<strong>Rate Limiting:</strong> IP, 사용자, 세션별 요청 빈도 제한",
    "<strong>워크플로우 검증:</strong> 각 단계별 전제 조건 확인",
    "<strong>로깅 및 모니터링:</strong> 비정상적인 패턴 감지 및 알림",
    "<strong>코드 리뷰:</strong> 비즈니스 로직에 대한 철저한 검토"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Business Logic Flaws" => "https://owasp.org/www-community/attacks/Business_Logic_Flaws",
    "PortSwigger - Logic flaws" => "https://portswigger.net/web-security/logic-flaws"
];

// 5. 테스트 폼 UI 정의
$test_scenario_selected = htmlspecialchars($_POST['scenario'] ?? '');
$test_data_input = htmlspecialchars($_POST['payload'] ?? '');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #e3f2fd; border-color: #2196f3;">
    <h4>👤 현재 사용자 정보 (시뮬레이션)</h4>
    <p><strong>사용자:</strong> {$current_user['username']} (ID: {$current_user['id']})</p>
    <p><strong>잔액:</strong> {$current_user['balance']}원</p>
    <p><strong>권한:</strong> {$current_user['role']}</p>
    <p><strong>구독 만료:</strong> {$current_user['subscription_expires']}</p>
    <p><strong>로그인 실패:</strong> {$current_user['failed_login_attempts']}회</p>
</div>

<form method="post" class="test-form">
    <h3>🧪 Business Logic 테스트</h3>
    <label for="scenario">테스트 시나리오 선택:</label>
    <select id="scenario" name="scenario">
        <option value="">-- 시나리오 선택 --</option>
        <option value="price_manipulation" {$test_scenario_selected === 'price_manipulation' ? 'selected' : ''}>가격 조작 (Price Manipulation)</option>
        <option value="quantity_manipulation" {$test_scenario_selected === 'quantity_manipulation' ? 'selected' : ''}>수량 조작 (Quantity Manipulation)</option>
        <option value="workflow_bypass" {$test_scenario_selected === 'workflow_bypass' ? 'selected' : ''}>워크플로우 우회 (Workflow Bypass)</option>
        <option value="time_manipulation" {$test_scenario_selected === 'time_manipulation' ? 'selected' : ''}>시간 조작 (Time Manipulation)</option>
        <option value="state_manipulation" {$test_scenario_selected === 'state_manipulation' ? 'selected' : ''}>상태 조작 (State Manipulation)</option>
        <option value="rate_limit_bypass" {$test_scenario_selected === 'rate_limit_bypass' ? 'selected' : ''}>Rate Limit 우회</option>
    </select><br><br>
    
    <label for="payload">테스트 데이터 입력:</label>
    <input type="text" id="payload" name="payload" value="{$test_data_input}" placeholder="시나리오별 테스트 데이터를 입력하세요">
    <br><br>
    <button type="submit" class="btn">Business Logic 테스트</button>
</form>
HTML; 

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($current_user) {
    $result_html = '';
    $error = '';
    $scenario = $form_data['scenario'] ?? '';
    $data = $form_data['payload'] ?? '';

    if (empty($scenario)) {
        $error = "테스트 시나리오를 선택해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response = "[시뮬레이션] Business Logic 테스트 결과\n";
    $response .= "사용자: {$current_user['username']} (ID: {$current_user['id']})\n";
    $response .= "현재 잔액: {$current_user['balance']}원\n";
    $response .= "테스트 시나리오: {$scenario}\n\n";
    
    switch ($scenario) {
        case 'price_manipulation':
            $price = floatval($data);
            if ($price < 0) {
                $response .= "🚨 취약점 발견: 음수 가격 허용\n";
                $response .= "공격 결과: 결제 시 잔액 증가: " . ($current_user['balance'] + abs($price)) . "원\n";
            } elseif ($price == 0) {
                $response .= "🚨 취약점 발견: 0원 가격 허용\n";
            } else {
                $response .= "✅ 정상 가격: {$price}원\n";
            }
            break;
            
        case 'quantity_manipulation':
            $quantity = intval($data);
            if ($quantity < 0) {
                $response .= "🚨 취약점 발견: 음수 수량 허용\n";
                $response .= "공격 결과: 재고 증가 및 잔액 환불\n";
            } elseif ($quantity == 0) {
                $response .= "⚠️ 의심: 0개 주문\n";
            } else {
                $response .= "✅ 정상 수량: {$quantity}개\n";
            }
            break;
            
        case 'workflow_bypass':
            $steps = explode(',', $data);
            $expected_flow = ['register', 'verify_email', 'complete_profile', 'activate'];
            if ($steps !== $expected_flow) {
                $response .= "🚨 취약점 발견: 워크플로우 우회\n";
                $response .= "예상 순서: " . implode(' → ', $expected_flow) . "\n";
                $response .= "실제 순서: " . implode(' → ', $steps) . "\n";
            } else {
                $response .= "✅ 정상적인 워크플로우 진행\n";
            }
            break;
            
        case 'time_manipulation':
            $submitted_time = strtotime($data);
            $current_time = time();
            $time_diff = $submitted_time - $current_time;
            if ($submitted_time === false) {
                $response .= "⚠️ 잘못된 시간 형식\n";
            } elseif ($time_diff > 86400) {
                $response .= "🚨 취약점 발견: 미래 시간 조작\n";
            } elseif ($time_diff < -86400 * 365) {
                $response .= "🚨 취약점 발견: 과거 시간 조작\n";
            } else {
                $response .= "✅ 정상적인 시간 범위\n";
            }
            break;
            
        case 'state_manipulation':
            $states = explode(' -> ', $data);
            if (count($states) !== 2) {
                $response .= "⚠️ 잘못된 상태 변경 형식\n";
                break;
            }
            $from_state = $states[0];
            $to_state = $states[1];
            $forbidden_transitions = [
                'pending' => ['completed', 'refunded'],
                'cancelled' => ['completed', 'shipped']
            ];
            if (isset($forbidden_transitions[$from_state]) && in_array($to_state, $forbidden_transitions[$from_state])) {
                $response .= "🚨 취약점 발견: 비정상적 상태 변경\n";
            } else {
                $response .= "✅ 정상적인 상태 변경: {$from_state} → {$to_state}\n";
            }
            break;
            
        case 'rate_limit_bypass':
            $requests = explode(',', $data);
            $request_count = count($requests);
            if ($request_count > 100) {
                $response .= "🚨 취약점 발견: 과도한 요청 빈도\n";
            } else {
                $response .= "✅ 정상적인 요청 빈도: {$request_count}회\n";
            }
            break;
    }
    
    return ['result' => "<pre>{$response}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Business_Logic_Errors_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Business Logic Errors 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 1000px;
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
        input[type="text"], select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin: 5px 0;
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
        .scenario-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
        }
        .user-info {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .logic-example {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
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
            <h1>Business Logic Errors 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>💼 Business Logic Errors 취약점</h2>
            <p><strong>설명:</strong> 애플리케이션의 비즈니스 로직 구현 오류로 인해 발생하는 취약점입니다. 
            기술적 보안은 완벽해도 업무 흐름의 논리적 결함을 악용하여 시스템을 우회하거나 부정한 이익을 얻을 수 있습니다.</p>
            
            <div class="user-info">
                <h4>👤 현재 사용자 정보 (시뮬레이션)</h4>
                <p><strong>사용자:</strong> <?php echo $current_user['username']; ?> (ID: <?php echo $current_user['id']; ?>)</p>
                <p><strong>잔액:</strong> <?php echo number_format($current_user['balance']); ?>원</p>
                <p><strong>권한:</strong> <?php echo $current_user['role']; ?></p>
                <p><strong>구독 만료:</strong> <?php echo $current_user['subscription_expires']; ?></p>
                <p><strong>로그인 실패:</strong> <?php echo $current_user['failed_login_attempts']; ?>회</p>
            </div>
            
            <h3>📋 Business Logic 공격 시나리오:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testScenario('price_manipulation', '-1000')" class="payload-btn">가격 조작</button>
                <button onclick="testScenario('quantity_manipulation', '-50')" class="payload-btn">수량 조작</button>
                <button onclick="testScenario('workflow_bypass', 'activate,register')" class="payload-btn">워크플로우 우회</button>
                <button onclick="testScenario('time_manipulation', '2030-12-31 23:59:59')" class="payload-btn">시간 조작</button>
                <button onclick="testScenario('state_manipulation', 'cancelled -> completed')" class="payload-btn">상태 조작</button>
                <button onclick="testScenario('rate_limit_bypass', '많은 요청')" class="payload-btn">제한 우회</button>
            </div>
        </div>

        <div class="scenario-card">
            <h3>🧪 Business Logic 테스트</h3>
            <form method="POST">
                <label for="scenario">테스트 시나리오 선택:</label>
                <select id="scenario" name="scenario">
                    <option value="">-- 시나리오 선택 --</option>
                    <option value="price_manipulation" <?php echo ($test_scenario == 'price_manipulation') ? 'selected' : ''; ?>>가격 조작 (Price Manipulation)</option>
                    <option value="quantity_manipulation" <?php echo ($test_scenario == 'quantity_manipulation') ? 'selected' : ''; ?>>수량 조작 (Quantity Manipulation)</option>
                    <option value="workflow_bypass" <?php echo ($test_scenario == 'workflow_bypass') ? 'selected' : ''; ?>>워크플로우 우회 (Workflow Bypass)</option>
                    <option value="time_manipulation" <?php echo ($test_scenario == 'time_manipulation') ? 'selected' : ''; ?>>시간 조작 (Time Manipulation)</option>
                    <option value="state_manipulation" <?php echo ($test_scenario == 'state_manipulation') ? 'selected' : ''; ?>>상태 조작 (State Manipulation)</option>
                    <option value="rate_limit_bypass" <?php echo ($test_scenario == 'rate_limit_bypass') ? 'selected' : ''; ?>>Rate Limit 우회</option>
                </select><br><br>
                
                <label for="test_data">테스트 데이터 입력:</label>
                <input type="text" id="test_data" name="test_data" value="<?php echo htmlspecialchars($test_data); ?>" 
                       placeholder="시나리오별 테스트 데이터를 입력하세요"><br><br>
                
                <input type="hidden" name="test_logic" value="1">
                <input type="submit" value="Business Logic 테스트" class="btn">
            </form>
        </div>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="logic-example">
            <h4>⚠️ 주요 Business Logic 취약점 유형</h4>
            <p><strong>1. 가격 조작:</strong> 음수 가격, 0원, 소수점 오류</p>
            <p><strong>2. 수량 조작:</strong> 음수 수량, 정수 오버플로우</p>
            <p><strong>3. 워크플로우 우회:</strong> 필수 단계 생략, 순서 변경</p>
            <p><strong>4. 시간 조작:</strong> 과거/미래 타임스탬프 조작</p>
            <p><strong>5. 상태 조작:</strong> 비정상적 상태 전환</p>
            <p><strong>6. Rate Limit 우회:</strong> IP 분산, 시간 조작</p>
            <p><strong>7. 권한 상승:</strong> 역할 변경, 권한 체크 우회</p>
            <p><strong>8. 경쟁 조건:</strong> 동시 요청으로 로직 우회</p>
        </div>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>입력 검증 강화:</strong> 모든 입력값의 범위, 타입, 형식 검증</li>
                <li><strong>서버 사이드 검증:</strong> 클라이언트 검증에 의존하지 않고 서버에서 재검증</li>
                <li><strong>상태 머신 구현:</strong> 명확한 상태 전환 규칙 정의 및 강제</li>
                <li><strong>트랜잭션 관리:</strong> ACID 속성을 보장하는 데이터베이스 트랜잭션</li>
                <li><strong>시간 검증:</strong> 서버 시간 기준으로 모든 시간 관련 로직 처리</li>
                <li><strong>Rate Limiting:</strong> IP, 사용자, 세션별 요청 빈도 제한</li>
                <li><strong>워크플로우 검증:</strong> 각 단계별 전제 조건 확인</li>
                <li><strong>로깅 및 모니터링:</strong> 비정상적인 패턴 감지 및 알림</li>
                <li><strong>코드 리뷰:</strong> 비즈니스 로직에 대한 철저한 검토</li>
            </ul>
            
            <h4>🔧 안전한 Business Logic 구현 예제:</h4>
            <pre style="background: #e8f5e8; padding: 10px; border-radius: 4px; font-size: 12px;">
// 가격 검증 예제
function validatePrice($price) {
    if (!is_numeric($price)) return false;
    if ($price <= 0) return false;
    if ($price > 999999) return false;
    return true;
}

// 상태 전환 검증
function canTransitionState($from, $to) {
    $allowed_transitions = [
        'pending' => ['processing', 'cancelled'],
        'processing' => ['shipped', 'cancelled'],
        'shipped' => ['delivered'],
        'delivered' => ['completed'],
        'cancelled' => [], // 최종 상태
        'completed' => []  // 최종 상태
    ];
    
    return isset($allowed_transitions[$from]) && 
           in_array($to, $allowed_transitions[$from]);
}
            </pre>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        function testScenario(scenario, testData) {
            if (confirm('⚠️ 교육 목적의 Business Logic 테스트를 실행하시겠습니까?\n\n시나리오: ' + scenario + '\n데이터: ' + testData)) {
                document.getElementById('scenario').value = scenario;
                document.getElementById('test_data').value = testData;
            }
        }

        // 시나리오별 예제 데이터 업데이트
        document.getElementById('scenario').addEventListener('change', function() {
            const scenario = this.value;
            const testDataInput = document.getElementById('test_data');
            
            const examples = {
                'price_manipulation': '-1000',
                'quantity_manipulation': '-50',
                'workflow_bypass': 'activate,register', // 이메일 인증 없이 활성화
                'time_manipulation': '2030-12-31 23:59:59', // 미래 시간
                'state_manipulation': 'cancelled -> completed', // 결제 없이 주문 완료
                'rate_limit_bypass': '1.1.1.1,1.1.1.1,1.1.1.1,2.2.2.2,2.2.2.2' // 분산 IP
            };
            
            const placeholders = {
                'price_manipulation': '예: -1000, 0, 0.01',
                'quantity_manipulation': '예: -50, 0, 999999999',
                'workflow_bypass': '예: activate,register (순서 바뀜)',
                'time_manipulation': '예: 2030-12-31 23:59:59 (미래)',
                'state_manipulation': '예: cancelled -> completed',
                'rate_limit_bypass': '예: IP1,IP1,IP2,IP2... (다중 요청)'
            };
            
            if (examples[scenario]) {
                testDataInput.value = examples[scenario];
                testDataInput.placeholder = placeholders[scenario];
            } else {
                testDataInput.value = '';
                testDataInput.placeholder = '테스트 데이터를 입력하세요';
            }
        });

        // 위험 패턴 경고
        document.getElementById('test_data').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const scenario = document.getElementById('scenario').value;
            
            let isRisky = false;
            
            if (scenario === 'price_manipulation' && (value.includes('-') || value === '0')) {
                isRisky = true;
            } else if (scenario === 'quantity_manipulation' && value.includes('-')) {
                isRisky = true;
            } else if (scenario === 'time_manipulation' && (value.includes('2030') || value.includes('1900'))) {
                isRisky = true;
            }
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });
    </script>
</body>
</html>