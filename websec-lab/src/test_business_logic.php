<?php
/**
 * Business Logic Vulnerability 테스트 스크립트
 */

require_once 'advanced/BusinessLogicVulnerability.php';

echo "<h2>🔧 Business Logic Vulnerability 테스트</h2>\n";

try {
    $businessLogic = new BusinessLogicVulnerability(1, 1000.00); // 사용자 ID 1, 초기 잔액 1000
    
    echo "<p>초기 잔액: <strong>\$" . number_format($businessLogic->getBalance(), 2) . "</strong></p>\n";
    
    // 1. Price Manipulation 테스트
    echo "<h3>🚨 1. Price Manipulation (가격 조작) 테스트:</h3>\n";
    
    // 정상 주문
    echo "<h4>정상 주문:</h4>\n";
    $normalOrder = $businessLogic->safeAddToCart(1, 2); // Premium Software License $299.99 x 2
    if ($normalOrder['success']) {
        echo "<p style='color: green;'>✅ 정상 주문: " . $normalOrder['message'] . "</p>\n";
        echo "<p>장바구니 총액: \$" . number_format($normalOrder['cart_total'], 2) . "</p>\n";
    }
    
    $businessLogic->clearCart();
    
    // 가격 조작 공격
    echo "<h4>가격 조작 공격:</h4>\n";
    $priceAttack = $businessLogic->vulnerableAddToCart(1, 2, 1.00); // $299.99를 $1.00으로 조작
    if ($priceAttack['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Price Manipulation 공격 성공!</p>\n";
        echo "<p><strong>조작된 가격:</strong> \$1.00 (원가: \$299.99)</p>\n";
        echo "<p><strong>총액:</strong> \$" . number_format($priceAttack['cart_total'], 2) . "</p>\n";
        echo "<p><strong>절약 금액:</strong> \$" . number_format((299.99 * 2) - $priceAttack['cart_total'], 2) . "</p>\n";
        echo "</div>\n";
    }
    
    // 2. Discount Abuse 테스트
    echo "<h3>🚨 2. Discount Abuse (할인 남용) 테스트:</h3>\n";
    
    $businessLogic->clearCart();
    $businessLogic->vulnerableAddToCart(2, 1, 99.99); // Cloud Storage $99.99
    
    // 정상 할인 적용
    echo "<h4>정상 할인 적용:</h4>\n";
    $normalDiscount = $businessLogic->safeApplyDiscount('SAVE10');
    if ($normalDiscount['success']) {
        echo "<p style='color: green;'>✅ 정상 할인 적용: \$10 할인</p>\n";
        echo "<p>최종 금액: \$" . number_format($normalDiscount['final_total'], 2) . "</p>\n";
    }
    
    // 할인 남용 공격
    echo "<h4>할인 남용 공격:</h4>\n";
    $discountAbuse = $businessLogic->vulnerableApplyDiscount('CUSTOM', 500.00); // $500 할인 시도
    if ($discountAbuse['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Discount Abuse 공격 성공!</p>\n";
        echo "<p><strong>할인 금액:</strong> \$" . number_format($discountAbuse['discount_amount'], 2) . "</p>\n";
        echo "<p><strong>최종 금액:</strong> \$" . number_format($discountAbuse['final_total'], 2) . "</p>\n";
        if ($discountAbuse['abuse_detected'] === 'NEGATIVE_TOTAL') {
            echo "<p style='color: red;'><strong>⚠️ 음수 총액 발생!</strong></p>\n";
        }
        echo "</div>\n";
    }
    
    // 3. Workflow Bypass 테스트
    echo "<h3>🚨 3. Workflow Bypass (워크플로우 우회) 테스트:</h3>\n";
    
    // 정상 주문 프로세스
    echo "<h4>정상 주문 프로세스:</h4>\n";
    $normalProcess = $businessLogic->vulnerableProcessOrder(['total' => 99.99, 'status' => 'pending']);
    echo "<p style='color: green;'>✅ 정상 주문 생성: " . $normalProcess['message'] . "</p>\n";
    echo "<p>주문 상태: " . $normalProcess['status'] . "</p>\n";
    
    // 워크플로우 우회 공격
    echo "<h4>워크플로우 우회 공격:</h4>\n";
    $workflowBypass = $businessLogic->vulnerableProcessOrder(['total' => 0.01, 'status' => 'completed']);
    if ($workflowBypass['success'] && isset($workflowBypass['bypass_detected'])) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Workflow Bypass 공격 성공!</p>\n";
        echo "<p><strong>결제 없이 주문 완료 처리</strong></p>\n";
        echo "<p>주문 ID: " . $workflowBypass['order_id'] . "</p>\n";
        echo "<p>지불 금액: \$" . number_format($workflowBypass['total'], 2) . "</p>\n";
        echo "<p>남은 잔액: \$" . number_format($workflowBypass['remaining_balance'], 2) . "</p>\n";
        echo "</div>\n";
    }
    
    // 4. Point Manipulation 테스트
    echo "<h3>🚨 4. Point Manipulation (포인트 조작) 테스트:</h3>\n";
    
    // 정상 포인트 적립
    echo "<h4>정상 포인트 적립:</h4>\n";
    $normalPoints = $businessLogic->vulnerableEarnPoints(100.00, 1);
    echo "<p style='color: green;'>✅ 정상 포인트 적립</p>\n";
    echo "<p>구매 금액: \$" . number_format($normalPoints['purchase_amount'], 2) . "</p>\n";
    echo "<p>적립 포인트: " . number_format($normalPoints['earned_points'], 2) . " 점</p>\n";
    
    // 배수 조작 공격
    echo "<h4>배수 조작 공격:</h4>\n";
    $multiplierAttack = $businessLogic->vulnerableEarnPoints(100.00, 100); // 100배 적립
    if ($multiplierAttack['manipulation'] === 'MULTIPLIER_ABUSE') {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Multiplier Abuse 공격 성공!</p>\n";
        echo "<p><strong>조작된 배수:</strong> " . $multiplierAttack['multiplier'] . "배</p>\n";
        echo "<p><strong>비정상 적립:</strong> " . number_format($multiplierAttack['earned_points'], 2) . " 점</p>\n";
        echo "<p><strong>총 포인트:</strong> " . number_format($multiplierAttack['total_points'], 2) . " 점</p>\n";
        echo "</div>\n";
    }
    
    // 음수 구매 공격
    echo "<h4>음수 구매 공격:</h4>\n";
    $negativeAttack = $businessLogic->vulnerableEarnPoints(-1000.00, 50); // 음수 구매로 포인트 증가
    if ($negativeAttack['negative_abuse'] === 'NEGATIVE_PURCHASE') {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Negative Purchase 공격 성공!</p>\n";
        echo "<p><strong>음수 구매 금액:</strong> \$" . number_format($negativeAttack['purchase_amount'], 2) . "</p>\n";
        echo "<p><strong>포인트 증가:</strong> " . number_format($negativeAttack['earned_points'], 2) . " 점</p>\n";
        echo "<p><strong>총 포인트:</strong> " . number_format($negativeAttack['total_points'], 2) . " 점</p>\n";
        echo "</div>\n";
    }
    
    // 5. Race Condition 테스트
    echo "<h3>🚨 5. Race Condition (경쟁 조건) 테스트:</h3>\n";
    
    $businessLogic = new BusinessLogicVulnerability(1, 100.00); // 잔액 $100으로 재설정
    
    echo "<p>초기 잔액: \$" . number_format($businessLogic->getBalance(), 2) . "</p>\n";
    
    // 정상 이체
    echo "<h4>정상 이체:</h4>\n";
    $normalTransfer = $businessLogic->safeTransferBalance(50.00, 2);
    if ($normalTransfer['success']) {
        echo "<p style='color: green;'>✅ 정상 이체 완료: \$50.00</p>\n";
        echo "<p>남은 잔액: \$" . number_format($normalTransfer['remaining_balance'], 2) . "</p>\n";
    }
    
    // Race Condition 시뮬레이션
    echo "<h4>Race Condition 시뮬레이션:</h4>\n";
    echo "<p style='color: orange;'>⚠️ 동시 이체 요청 시뮬레이션...</p>\n";
    
    // 연속된 이체 시도 (Race Condition)
    $raceTransfer1 = $businessLogic->vulnerableTransferBalance(40.00, 3);
    $raceTransfer2 = $businessLogic->vulnerableTransferBalance(40.00, 4); // 잔액 부족하지만 동시 요청
    
    if ($raceTransfer1['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Race Condition 취약점 감지!</p>\n";
        echo "<p>첫 번째 이체: 성공 (\$40.00)</p>\n";
        echo "<p>남은 잔액: \$" . number_format($raceTransfer1['remaining_balance'], 2) . "</p>\n";
        echo "<p><strong>위험도:</strong> " . $raceTransfer1['race_condition_risk'] . "</p>\n";
        echo "</div>\n";
    }
    
    // 6. 안전한 구현과의 비교
    echo "<h3>🛡️ 안전한 구현 결과:</h3>\n";
    
    $safeBusiness = new BusinessLogicVulnerability(2, 500.00);
    
    echo "<h4>안전한 장바구니 추가:</h4>\n";
    $safeCart = $safeBusiness->safeAddToCart(1, 2);
    if ($safeCart['success']) {
        echo "<p style='color: green;'>✅ 서버 고정 가격 사용: \$" . number_format($safeCart['cart_total'], 2) . "</p>\n";
    }
    
    echo "<h4>안전한 할인 적용:</h4>\n";
    $safeDiscount = $safeBusiness->safeApplyDiscount('SAVE10');
    if ($safeDiscount['success']) {
        echo "<p style='color: green;'>✅ 검증된 할인 코드만 허용</p>\n";
        echo "<p>최종 금액: \$" . number_format($safeDiscount['final_total'], 2) . "</p>\n";
    }
    
    echo "<h4>안전한 잔액 이체:</h4>\n";
    $safeTransfer = $safeBusiness->safeTransferBalance(100.00, 5);
    if ($safeTransfer['success']) {
        echo "<p style='color: green;'>✅ 동시성 제어를 통한 안전한 이체</p>\n";
        echo "<p>이체 금액: \$" . number_format($safeTransfer['transferred_amount'], 2) . "</p>\n";
    }
    
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ 오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>\n";
}

echo "<hr>\n";
echo "<h3>🔒 Business Logic 보안 권장사항:</h3>\n";
echo "<ul>\n";
echo "<li><strong>서버 사이드 검증:</strong> 모든 비즈니스 로직을 서버에서 검증</li>\n";
echo "<li><strong>가격 무결성:</strong> 클라이언트에서 가격 정보 수정 불가</li>\n";
echo "<li><strong>워크플로우 강제:</strong> 필수 단계 우회 방지</li>\n";
echo "<li><strong>동시성 제어:</strong> 중요한 연산에 락(Lock) 적용</li>\n";
echo "<li><strong>한도 설정:</strong> 할인, 적립 등에 적절한 상한선 설정</li>\n";
echo "<li><strong>상태 관리:</strong> 주문/결제 상태 변경에 권한 검증</li>\n";
echo "<li><strong>로깅:</strong> 모든 비즈니스 로직 실행 로그 기록</li>\n";
echo "</ul>\n";

echo "<p><a href='webhacking/business_logic_test.php'>🔗 Business Logic 테스트 페이지로 이동</a></p>\n";
?>