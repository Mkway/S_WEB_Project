<?php
/**
 * Business Logic Errors 취약점 테스트 페이지
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
$test_scenario = '';
$test_data = '';

// 시뮬레이션용 사용자 데이터
$current_user = [
    'id' => 123,
    'username' => $_SESSION['username'],
    'balance' => 1000,
    'role' => 'user',
    'subscription_expires' => '2025-12-31',
    'failed_login_attempts' => 0
];

// Business Logic 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['test_logic'])) {
    $test_scenario = $_POST['scenario'] ?? '';
    $test_data = $_POST['test_data'] ?? '';
    
    if (empty($test_scenario)) {
        $result = "테스트 시나리오를 선택해주세요.";
    } else {
        $result = simulateBusinessLogicAttack($test_scenario, $test_data, $current_user);
    }
}

function simulateBusinessLogicAttack($scenario, $data, $user) {
    $response = "[시뮬레이션] Business Logic 테스트 결과\n";
    $response .= "사용자: {$user['username']} (ID: {$user['id']})\n";
    $response .= "현재 잔액: {$user['balance']}원\n";
    $response .= "테스트 시나리오: {$scenario}\n\n";
    
    switch ($scenario) {
        case 'price_manipulation':
            $response .= "가격 조작 공격 테스트:\n";
            $response .= "입력 데이터: {$data}\n\n";
            
            $price = floatval($data);
            if ($price < 0) {
                $response .= "🚨 취약점 발견: 음수 가격 허용\n";
                $response .= "공격 결과: \n";
                $response .= "- 상품 가격: {$price}원 (음수!)\n";
                $response .= "- 결제 시 잔액 증가: " . ($user['balance'] + abs($price)) . "원\n";
                $response .= "- 공격자 이익: " . abs($price) . "원 획득\n\n";
                $response .= "실제 피해 시나리오:\n";
                $response .= "1. 공격자가 -1000원 상품 '구매'\n";
                $response .= "2. 시스템이 잔액에서 -1000원을 차감 (실제로는 +1000원)\n";
                $response .= "3. 공격자 계정 잔액 무한 증가 가능";
            } elseif ($price == 0) {
                $response .= "🚨 취약점 발견: 0원 가격 허용\n";
                $response .= "공격 결과: 모든 상품을 무료로 구매 가능";
            } elseif ($price > 0 && $price < 1) {
                $response .= "⚠️ 위험: 소수점 가격 조작\n";
                $response .= "0.01원으로 고가 상품 구매 시도 가능";
            } else {
                $response .= "✅ 정상 가격: {$price}원\n";
                $response .= "취약점이 발견되지 않았습니다.";
            }
            break;
            
        case 'quantity_manipulation':
            $response .= "수량 조작 공격 테스트:\n";
            $response .= "주문 수량: {$data}\n\n";
            
            $quantity = intval($data);
            if ($quantity < 0) {
                $response .= "🚨 취약점 발견: 음수 수량 허용\n";
                $response .= "공격 결과:\n";
                $response .= "- 주문 수량: {$quantity}개 (음수!)\n";
                $response .= "- 재고 증가: " . abs($quantity) . "개\n";
                $response .= "- 잔액 환불: " . (abs($quantity) * 100) . "원\n\n";
                $response .= "실제 피해:\n";
                $response .= "1. -100개 주문으로 재고 100개 증가\n";
                $response .= "2. 10,000원 환불 받음\n";
                $response .= "3. 재고 조작 + 금전적 이익";
            } elseif ($quantity == 0) {
                $response .= "⚠️ 의심: 0개 주문\n";
                $response .= "무료 배송비나 쿠폰 남용 가능성";
            } elseif ($quantity > 999999) {
                $response .= "🚨 취약점 발견: 정수 오버플로우 위험\n";
                $response .= "매우 큰 수량으로 시스템 오류 유발 가능";
            } else {
                $response .= "✅ 정상 수량: {$quantity}개";
            }
            break;
            
        case 'workflow_bypass':
            $response .= "워크플로우 우회 공격 테스트:\n";
            $response .= "단계 순서: {$data}\n\n";
            
            $steps = explode(',', $data);
            $expected_flow = ['register', 'verify_email', 'complete_profile', 'activate'];
            
            if ($steps !== $expected_flow) {
                $response .= "🚨 취약점 발견: 워크플로우 우회\n";
                $response .= "예상 순서: " . implode(' → ', $expected_flow) . "\n";
                $response .= "실제 순서: " . implode(' → ', $steps) . "\n\n";
                
                if (in_array('activate', $steps) && !in_array('verify_email', $steps)) {
                    $response .= "이메일 인증 없이 계정 활성화 성공!\n";
                    $response .= "→ 무효한 이메일로 계정 생성 가능";
                }
                if (in_array('complete_profile', $steps) && !in_array('register', $steps)) {
                    $response .= "회원가입 없이 프로필 생성 시도!\n";
                    $response .= "→ 시스템 로직 오류 유발 가능";
                }
            } else {
                $response .= "✅ 정상적인 워크플로우 진행";
            }
            break;
            
        case 'time_manipulation':
            $response .= "시간 조작 공격 테스트:\n";
            $response .= "제출 시간: {$data}\n\n";
            
            $submitted_time = strtotime($data);
            $current_time = time();
            $time_diff = $submitted_time - $current_time;
            
            if ($submitted_time === false) {
                $response .= "⚠️ 잘못된 시간 형식";
            } elseif ($time_diff > 86400) { // 24시간 이후
                $response .= "🚨 취약점 발견: 미래 시간 조작\n";
                $response .= "시간 차이: " . round($time_diff / 3600, 2) . "시간 후\n";
                $response .= "공격 시나리오:\n";
                $response .= "- 할인 쿠폰 유효기간 연장\n";
                $response .= "- 경매 마감시간 조작\n";
                $response .= "- 구독 만료일 연장";
            } elseif ($time_diff < -86400 * 365) { // 1년 이전
                $response .= "🚨 취약점 발견: 과거 시간 조작\n";
                $response .= "시간 차이: " . abs(round($time_diff / 86400)) . "일 전\n";
                $response .= "공격 시나리오:\n";
                $response .= "- 포인트 적립 중복 처리\n";
                $response .= "- 로그 조작으로 감사 회피\n";
                $response .= "- 과거 가격으로 상품 구매";
            } else {
                $response .= "✅ 정상적인 시간 범위";
            }
            break;
            
        case 'state_manipulation':
            $response .= "상태 조작 공격 테스트:\n";
            $response .= "상태 변경 요청: {$data}\n\n";
            
            $states = explode(' -> ', $data);
            if (count($states) !== 2) {
                $response .= "⚠️ 잘못된 상태 변경 형식";
                break;
            }
            
            $from_state = $states[0];
            $to_state = $states[1];
            
            // 허용되지 않는 상태 변경 체크
            $forbidden_transitions = [
                'pending' => ['completed', 'refunded'],
                'cancelled' => ['completed', 'shipped'],
                'refunded' => ['pending', 'shipped', 'completed']
            ];
            
            if (isset($forbidden_transitions[$from_state]) && 
                in_array($to_state, $forbidden_transitions[$from_state])) {
                
                $response .= "🚨 취약점 발견: 비정상적 상태 변경\n";
                $response .= "'{$from_state}' → '{$to_state}' 변경은 정책상 불가능\n\n";
                $response .= "공격 효과:\n";
                
                if ($from_state === 'pending' && $to_state === 'completed') {
                    $response .= "- 결제 없이 주문 완료 처리\n";
                    $response .= "- 상품 무료 획득";
                } elseif ($from_state === 'cancelled' && $to_state === 'shipped') {
                    $response .= "- 취소된 주문의 배송 강제 실행\n";
                    $response .= "- 환불 후 상품 수령";
                } elseif ($from_state === 'refunded' && $to_state === 'completed') {
                    $response .= "- 환불 완료 후 재완료 처리\n";
                    $response .= "- 이중 결제 또는 중복 상품 획득";
                }
            } else {
                $response .= "✅ 정상적인 상태 변경: {$from_state} → {$to_state}";
            }
            break;
            
        case 'rate_limit_bypass':
            $response .= "Rate Limiting 우회 공격 테스트:\n";
            $response .= "요청 패턴: {$data}\n\n";
            
            $requests = explode(',', $data);
            $request_count = count($requests);
            $unique_ips = count(array_unique($requests));
            
            if ($request_count > 100) {
                $response .= "🚨 취약점 발견: 과도한 요청 빈도\n";
                $response .= "총 요청 수: {$request_count}회\n";
                $response .= "고유 IP 수: {$unique_ips}개\n\n";
                
                if ($unique_ips > 10) {
                    $response .= "분산 IP를 통한 Rate Limit 우회 시도:\n";
                    $response .= "- Botnet을 통한 분산 공격\n";
                    $response .= "- Proxy/VPN을 통한 IP 변조\n";
                    $response .= "- 각 IP당 제한 회피";
                } else {
                    $response .= "단일/소수 IP를 통한 무차별 요청:\n";
                    $response .= "- 브루트포스 공격\n";
                    $response .= "- DoS 공격\n";
                    $response .= "- 시스템 리소스 고갈";
                }
            } else {
                $response .= "✅ 정상적인 요청 빈도: {$request_count}회";
            }
            break;
    }
    
    return $response;
}
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
                <li><strong>Business Rules Engine:</strong> 복잡한 비즈니스 로직의 중앙화</li>
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
                'workflow_bypass': 'activate,complete_profile,register',
                'time_manipulation': '2030-12-31 23:59:59',
                'state_manipulation': 'cancelled -> completed',
                'rate_limit_bypass': '1.1.1.1,1.1.1.1,1.1.1.1,2.2.2.2,2.2.2.2'
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