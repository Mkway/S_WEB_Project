<?php
/**
 * Race Condition Vulnerability 테스트 스크립트
 */

require_once 'advanced/RaceConditionVulnerability.php';

echo "<h2>⚡ Race Condition Vulnerability 테스트</h2>\n";

try {
    $raceTest = new RaceConditionVulnerability();
    
    echo "<h3>초기 상태:</h3>\n";
    echo "<div style='background: #f0f8ff; padding: 10px; border: 1px solid #4169e1; margin: 10px 0;'>\n";
    echo "<p><strong>계정 잔액:</strong></p>\n";
    foreach ($raceTest->getAccounts() as $account => $data) {
        echo "<p>- {$account}: \$" . number_format($data['balance'], 2) . "</p>\n";
    }
    echo "<p><strong>카운터:</strong></p>\n";
    foreach ($raceTest->getCounters() as $name => $value) {
        echo "<p>- {$name}: " . number_format($value) . "</p>\n";
    }
    echo "</div>\n";
    
    // 1. Bank Transfer Race Condition 테스트
    echo "<h3>🚨 1. Bank Transfer Race Condition 테스트:</h3>\n";
    
    // 정상 이체
    echo "<h4>정상 이체:</h4>\n";
    $normalTransfer = $raceTest->safeBankTransfer('user1', 'user2', 100.00);
    if ($normalTransfer['success']) {
        echo "<p style='color: green;'>✅ 안전한 이체 완료: \$100.00</p>\n";
        echo "<p>user1 잔액: \$" . number_format($normalTransfer['from_balance'], 2) . "</p>\n";
        echo "<p>user2 잔액: \$" . number_format($normalTransfer['to_balance'], 2) . "</p>\n";
    }
    
    // Race Condition 시뮬레이션 (동시 이체)
    echo "<h4>Race Condition 시뮬레이션:</h4>\n";
    echo "<p style='color: orange;'>⚠️ 동시 이체 요청 시뮬레이션 (같은 계정에서)...</p>\n";
    
    // 두 번의 연속 이체 (잔액 900 -> 두 번 400 이체 시도)
    $raceTransfer1 = $raceTest->vulnerableBankTransfer('user1', 'user2', 400.00);
    $raceTransfer2 = $raceTest->vulnerableBankTransfer('user1', 'user3', 400.00);
    
    if ($raceTransfer1['success'] && $raceTransfer2['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Race Condition 취약점 발생!</p>\n";
        echo "<p><strong>첫 번째 이체:</strong> \$400 (user1 → user2)</p>\n";
        echo "<p><strong>두 번째 이체:</strong> \$400 (user1 → user3)</p>\n";
        echo "<p><strong>user1 최종 잔액:</strong> \$" . number_format($raceTransfer2['from_balance'], 2) . " (음수 가능!)</p>\n";
        echo "<p><strong>Race Window:</strong> " . $raceTransfer1['race_condition_window'] . "</p>\n";
        echo "</div>\n";
    }
    
    // 2. File Upload Race Condition 테스트
    echo "<h3>🚨 2. File Upload Race Condition 테스트:</h3>\n";
    
    // 정상 파일 업로드
    echo "<h4>정상 파일 업로드:</h4>\n";
    $normalUpload = $raceTest->vulnerableFileUpload('document.txt', 'This is a safe document content.');
    if ($normalUpload['success']) {
        echo "<p style='color: green;'>✅ 정상 파일 업로드: " . $normalUpload['filename'] . "</p>\n";
        echo "<p>파일 크기: " . $normalUpload['size'] . " bytes</p>\n";
    }
    
    // Race Condition 파일 업로드 시뮬레이션
    echo "<h4>Race Condition 파일 업로드 시뮬레이션:</h4>\n";
    echo "<p style='color: orange;'>⚠️ 검증 후 저장 전 파일 내용 변경 시나리오...</p>\n";
    
    $maliciousUpload = $raceTest->vulnerableFileUpload('script.txt', '<?php system($_GET["cmd"]); ?>');
    if ($maliciousUpload['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 File Upload Race Condition 성공!</p>\n";
        echo "<p><strong>업로드된 파일:</strong> " . $maliciousUpload['filename'] . "</p>\n";
        echo "<p><strong>Race Window:</strong> " . $maliciousUpload['race_window'] . "</p>\n";
        echo "<p><strong>위험:</strong> 검증 후 악성 코드로 변경될 수 있음</p>\n";
        echo "</div>\n";
    }
    
    // 3. Session Race Condition 테스트
    echo "<h3>🚨 3. Session Race Condition 테스트:</h3>\n";
    
    // 정상 세션 관리
    echo "<h4>정상 세션 로그인:</h4>\n";
    $normalLogin = $raceTest->vulnerableSessionManagement('sess_12345', 'login');
    if ($normalLogin['success']) {
        echo "<p style='color: green;'>✅ 정상 로그인: 카운트 " . $normalLogin['login_count'] . "</p>\n";
    }
    
    // 동시 로그인 시뮬레이션
    echo "<h4>동시 로그인 Race Condition:</h4>\n";
    echo "<p style='color: orange;'>⚠️ 동일 세션으로 동시 로그인 요청...</p>\n";
    
    $concurrentLogin1 = $raceTest->vulnerableSessionManagement('sess_67890', 'login');
    $concurrentLogin2 = $raceTest->vulnerableSessionManagement('sess_67890', 'login');
    
    if ($concurrentLogin1['success'] && $concurrentLogin2['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Session Race Condition 발생!</p>\n";
        echo "<p><strong>동시 로그인 요청:</strong> 2개</p>\n";
        echo "<p><strong>최종 로그인 카운트:</strong> " . $concurrentLogin2['login_count'] . "</p>\n";
        echo "<p><strong>Race Window:</strong> " . $concurrentLogin1['race_window'] . "</p>\n";
        echo "<p><strong>예상 문제:</strong> 잘못된 카운트, 중복 세션 생성</p>\n";
        echo "</div>\n";
    }
    
    // 4. Counter Race Condition 테스트
    echo "<h3>🚨 4. Counter Race Condition 테스트:</h3>\n";
    
    // 정상 카운터 증가
    echo "<h4>안전한 카운터 증가:</h4>\n";
    $safeCounter = $raceTest->safeCounterIncrement('api_calls', 10);
    if ($safeCounter['success']) {
        echo "<p style='color: green;'>✅ 안전한 카운터 증가</p>\n";
        echo "<p>이전: " . number_format($safeCounter['previous_value']) . " → 현재: " . number_format($safeCounter['new_value']) . "</p>\n";
    }
    
    // 동시 카운터 증가 시뮬레이션
    echo "<h4>동시 카운터 증가 Race Condition:</h4>\n";
    echo "<p style='color: orange;'>⚠️ 동시에 페이지 뷰 카운터 증가...</p>\n";
    
    $raceCounter1 = $raceTest->vulnerableCounterIncrement('page_views', 5);
    $raceCounter2 = $raceTest->vulnerableCounterIncrement('page_views', 3);
    
    if ($raceCounter1['success'] && $raceCounter2['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Counter Race Condition 발생!</p>\n";
        echo "<p><strong>첫 번째 증가:</strong> +" . $raceCounter1['increment'] . " (결과: " . number_format($raceCounter1['new_value']) . ")</p>\n";
        echo "<p><strong>두 번째 증가:</strong> +" . $raceCounter2['increment'] . " (결과: " . number_format($raceCounter2['new_value']) . ")</p>\n";
        echo "<p><strong>Race Window:</strong> " . $raceCounter1['race_window'] . "</p>\n";
        echo "<p><strong>손실된 업데이트:</strong> 가능성 있음</p>\n";
        echo "</div>\n";
    }
    
    // 5. Database Race Condition 테스트  
    echo "<h3>🚨 5. Database Race Condition 테스트:</h3>\n";
    
    // 안전한 데이터베이스 업데이트 (Optimistic Locking)
    echo "<h4>안전한 데이터베이스 업데이트:</h4>\n";
    $safeDbUpdate = $raceTest->safeDatabaseUpdate(1, ['balance' => 1200], 1);
    if ($safeDbUpdate['success']) {
        echo "<p style='color: green;'>✅ Optimistic Locking으로 안전한 업데이트</p>\n";
        echo "<p>업데이트된 잔액: \$" . number_format($safeDbUpdate['updated_data']['balance'], 2) . "</p>\n";
        echo "<p>새 버전: " . $safeDbUpdate['updated_data']['version'] . "</p>\n";
    }
    
    // 동시 데이터베이스 업데이트 시뮬레이션
    echo "<h4>동시 데이터베이스 업데이트 시뮬레이션:</h4>\n";
    echo "<p style='color: orange;'>⚠️ 같은 레코드에 동시 업데이트...</p>\n";
    
    $raceDbUpdate1 = $raceTest->vulnerableDatabaseUpdate(2, ['balance' => 2500]);
    $raceDbUpdate2 = $raceTest->vulnerableDatabaseUpdate(2, ['name' => 'Jane Updated']);
    
    if ($raceDbUpdate1['success'] && $raceDbUpdate2['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Database Race Condition 발생!</p>\n";
        echo "<p><strong>첫 번째 업데이트:</strong> balance → \$2,500</p>\n";
        echo "<p><strong>두 번째 업데이트:</strong> name → 'Jane Updated'</p>\n";
        echo "<p><strong>Race Window:</strong> " . $raceDbUpdate1['race_window'] . "</p>\n";
        echo "<p><strong>데이터 무결성 위험:</strong> Lost Update, Dirty Read 가능</p>\n";
        echo "</div>\n";
    }
    
    // 6. 최종 상태 확인
    echo "<h3>🔍 최종 상태 확인:</h3>\n";
    echo "<div style='background: #fff8dc; padding: 10px; border: 1px solid #daa520; margin: 10px 0;'>\n";
    echo "<p><strong>최종 계정 잔액:</strong></p>\n";
    foreach ($raceTest->getAccounts() as $account => $data) {
        echo "<p>- {$account}: \$" . number_format($data['balance'], 2) . "</p>\n";
    }
    echo "<p><strong>최종 카운터 값:</strong></p>\n";
    foreach ($raceTest->getCounters() as $name => $value) {
        echo "<p>- {$name}: " . number_format($value) . "</p>\n";
    }
    echo "</div>\n";
    
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ 오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>\n";
}

echo "<hr>\n";
echo "<h3>🔒 Race Condition 방어 권장사항:</h3>\n";
echo "<ul>\n";
echo "<li><strong>Locking:</strong> Pessimistic/Optimistic Locking으로 동시성 제어</li>\n";
echo "<li><strong>Atomic Operations:</strong> 데이터베이스 원자적 연산 사용</li>\n";
echo "<li><strong>Transaction:</strong> ACID 트랜잭션으로 일관성 보장</li>\n";
echo "<li><strong>Mutex/Semaphore:</strong> 동기화 프리미티브 활용</li>\n";
echo "<li><strong>Queue Systems:</strong> 메시지 큐로 순차 처리</li>\n";
echo "<li><strong>Version Control:</strong> 버전 기반 충돌 감지</li>\n";
echo "<li><strong>Retry Logic:</strong> 충돌 시 재시도 메커니즘</li>\n";
echo "<li><strong>Immutable Data:</strong> 불변 데이터 구조 사용</li>\n";
echo "</ul>\n";

echo "<p><a href='webhacking/race_condition_test.php'>🔗 Race Condition 테스트 페이지로 이동</a></p>\n";
?>