<?php
/**
 * Deserialization Vulnerability 테스트 스크립트
 */

require_once 'advanced/DeserializationVulnerability.php';

echo "<h2>🧬 Deserialization Vulnerability 테스트</h2>\n";

try {
    $deserTest = new DeserializationVulnerability();
    
    // 1. PHP Object Injection 테스트
    echo "<h3>🚨 1. PHP Object Injection 테스트:</h3>\n";
    
    // 정상 사용자 데이터 복원
    echo "<h4>정상 사용자 데이터:</h4>\n";
    $normalPayload = $deserTest->createMaliciousPayload('normal');
    $normalResult = $deserTest->safeUserRestore($normalPayload, ['VulnerableUser']);
    if ($normalResult['success']) {
        echo "<p style='color: green;'>✅ 안전한 복원: " . $normalResult['username'] . " (" . $normalResult['role'] . ")</p>\n";
    }
    
    // 권한 상승 공격
    echo "<h4>권한 상승 공격:</h4>\n";
    $adminPayload = $deserTest->createMaliciousPayload('admin_escalation');
    echo "<p style='color: orange;'>⚠️ 악성 직렬화 데이터 주입...</p>\n";
    echo "<div style='background: #f5f5f5; padding: 5px; border: 1px solid #ccc; margin: 5px 0; font-family: monospace; font-size: 12px;'>\n";
    echo htmlspecialchars(substr($adminPayload, 0, 200)) . "...\n";
    echo "</div>\n";
    
    $adminResult = $deserTest->vulnerableUserRestore($adminPayload);
    if ($adminResult['success'] && $adminResult['is_admin']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 PHP Object Injection 성공!</p>\n";
        echo "<p><strong>사용자명:</strong> " . $adminResult['username'] . "</p>\n";
        echo "<p><strong>권한 상승:</strong> " . $adminResult['role'] . " → 관리자 권한 획득</p>\n";
        echo "<p><strong>Magic Method:</strong> " . $adminResult['magic_methods_executed'] . "</p>\n";
        echo "<p><strong>파일 접근:</strong> /tmp/admin_access.log 생성됨</p>\n";
        echo "</div>\n";
    }
    
    // 2. Property Oriented Programming (POP Chain) 테스트
    echo "<h3>🚨 2. POP Chain Exploitation 테스트:</h3>\n";
    
    echo "<h4>파일 읽기 POP Chain:</h4>\n";
    $popPayload = $deserTest->createMaliciousPayload('pop_chain');
    echo "<p style='color: orange;'>⚠️ POP Chain 페이로드 생성...</p>\n";
    
    $popResult = $deserTest->vulnerableCacheLoad('malicious_cache', $popPayload);
    if ($popResult['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 POP Chain 공격 성공!</p>\n";
        echo "<p><strong>공격 체인:</strong> VulnerableCache → VulnerableFile</p>\n";
        echo "<p><strong>실행된 객체:</strong> " . $popResult['result']['object_class'] . "</p>\n";
        echo "<p><strong>Magic Method:</strong> __get, __call 자동 실행</p>\n";
        echo "<p><strong>파일 접근:</strong> /etc/passwd 읽기 시도</p>\n";
        echo "</div>\n";
    }
    
    // 명령 실행 POP Chain
    echo "<h4>명령 실행 POP Chain:</h4>\n";
    $cmdPayload = $deserTest->createMaliciousPayload('command_execution');
    $cmdResult = $deserTest->vulnerableCacheLoad('cmd_cache', $cmdPayload);
    if ($cmdResult['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Command Execution POP Chain 성공!</p>\n";
        echo "<p><strong>실행 모드:</strong> exec</p>\n";
        echo "<p><strong>명령어:</strong> whoami</p>\n";
        echo "<p><strong>Magic Method:</strong> __invoke 자동 실행</p>\n";
        echo "</div>\n";
    }
    
    // 3. Session Deserialization 테스트
    echo "<h3>🚨 3. Session Deserialization 테스트:</h3>\n";
    
    // 안전한 세션 처리
    echo "<h4>안전한 세션 처리 (JSON):</h4>\n";
    $safeSessionData = json_encode([
        'user_id' => 123,
        'username' => 'normal_user',
        'role' => 'user',
        'login_time' => time()
    ]);
    
    $safeSession = $deserTest->safeSessionHandle('safe123', $safeSessionData);
    if ($safeSession['success']) {
        echo "<p style='color: green;'>✅ 안전한 세션 처리: " . $safeSession['username'] . "</p>\n";
        echo "<p>보안 방식: " . $safeSession['security'] . "</p>\n";
    }
    
    // 취약한 세션 공격
    echo "<h4>취약한 세션 역직렬화 공격:</h4>\n";
    $maliciousUser = new VulnerableUser('session_hacker', 'administrator');
    $maliciousSessionData = serialize($maliciousUser);
    
    echo "<p style='color: orange;'>⚠️ 세션에 악성 객체 주입...</p>\n";
    $vulnerableSession = $deserTest->vulnerableSessionHandle('vuln456', $maliciousSessionData);
    if ($vulnerableSession['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Session Deserialization 공격 성공!</p>\n";
        echo "<p><strong>세션 ID:</strong> " . $vulnerableSession['session_id'] . "</p>\n";
        echo "<p><strong>객체 클래스:</strong> " . $vulnerableSession['data_class'] . "</p>\n";
        echo "<p><strong>세션 파일:</strong> " . $vulnerableSession['session_file'] . "</p>\n";
        echo "<p><strong>Magic Method:</strong> __wakeup 자동 실행됨</p>\n";
        echo "</div>\n";
    }
    
    // 4. Cookie Deserialization 테스트
    echo "<h3>🚨 4. Cookie Deserialization 테스트:</h3>\n";
    
    // 악성 쿠키 데이터 생성
    echo "<h4>악성 쿠키 데이터 공격:</h4>\n";
    $cookieUser = new VulnerableUser('cookie_attacker', 'administrator');
    $cookieUser->email = 'delete:/tmp/sensitive_data.txt';
    $maliciousCookieData = base64_encode(serialize($cookieUser));
    
    echo "<p style='color: orange;'>⚠️ Base64 인코딩된 악성 쿠키 주입...</p>\n";
    echo "<div style='background: #f5f5f5; padding: 5px; border: 1px solid #ccc; margin: 5px 0; font-family: monospace; font-size: 12px;'>\n";
    echo htmlspecialchars(substr($maliciousCookieData, 0, 100)) . "...\n";
    echo "</div>\n";
    
    $cookieResult = $deserTest->vulnerableCookieProcess($maliciousCookieData);
    if ($cookieResult['success']) {
        echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
        echo "<p style='color: red;'>🔥 Cookie Deserialization 공격 성공!</p>\n";
        echo "<p><strong>객체 클래스:</strong> " . $cookieResult['object_class'] . "</p>\n";
        echo "<p><strong>Magic Method:</strong> " . $cookieResult['magic_methods'] . "</p>\n";
        echo "<p><strong>위험:</strong> __destruct 실행 시 파일 삭제 가능</p>\n";
        echo "</div>\n";
    }
    
    // 5. 안전한 구현과의 비교
    echo "<h3>🛡️ 안전한 구현 결과:</h3>\n";
    
    echo "<h4>화이트리스트 기반 안전한 역직렬화:</h4>\n";
    $safeResult = $deserTest->safeUserRestore($adminPayload, ['VulnerableUser']);
    if (!$safeResult['success']) {
        echo "<p style='color: green;'>✅ 권한 상승 공격 차단: " . $safeResult['message'] . "</p>\n";
        if (isset($safeResult['security'])) {
            echo "<p>보안 조치: " . $safeResult['security'] . "</p>\n";
        }
    }
    
    echo "<h4>HMAC 서명 기반 안전한 데이터 처리:</h4>\n";
    $safeData = base64_encode(json_encode(['user' => 'safe_user', 'role' => 'user']));
    $signature = hash_hmac('sha256', $safeData, 'secret_key_123');
    
    $signedResult = $deserTest->safeDataWithSignature($safeData, $signature);
    if ($signedResult['success']) {
        echo "<p style='color: green;'>✅ 서명 검증 성공</p>\n";
        echo "<p>보안 방식: " . $signedResult['security'] . "</p>\n";
        echo "<p>처리된 사용자: " . $signedResult['data']['user'] . "</p>\n";
    }
    
    // 잘못된 서명 테스트
    $invalidSignature = 'invalid_signature_12345';
    $invalidResult = $deserTest->safeDataWithSignature($safeData, $invalidSignature);
    if (!$invalidResult['success']) {
        echo "<p style='color: green;'>✅ 잘못된 서명 차단: " . $invalidResult['message'] . "</p>\n";
    }
    
    // 6. 실제 파일 시스템 영향 확인
    echo "<h3>🔍 파일 시스템 영향 확인:</h3>\n";
    
    if (file_exists('/tmp/admin_access.log')) {
        echo "<div style='background: #fff8dc; padding: 10px; border: 1px solid #daa520; margin: 10px 0;'>\n";
        echo "<p style='color: #b8860b;'>⚠️ Magic Method 실행 흔적 발견:</p>\n";
        echo "<p><strong>파일:</strong> /tmp/admin_access.log</p>\n";
        $logContent = file_get_contents('/tmp/admin_access.log');
        echo "<p><strong>내용:</strong> " . htmlspecialchars($logContent) . "</p>\n";
        echo "</div>\n";
    }
    
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ 오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>\n";
}

echo "<hr>\n";
echo "<h3>🔒 Deserialization 보안 권장사항:</h3>\n";
echo "<ul>\n";
echo "<li><strong>입력 검증:</strong> 역직렬화 전 데이터 무결성 검증</li>\n";
echo "<li><strong>화이트리스트:</strong> 허용된 클래스만 역직렬화 허용</li>\n";
echo "<li><strong>대안 형식:</strong> JSON, XML 등 안전한 데이터 형식 사용</li>\n";
echo "<li><strong>서명 검증:</strong> HMAC 등을 통한 데이터 서명 검증</li>\n";
echo "<li><strong>Magic Method:</strong> __wakeup, __destruct 등 주의깊게 구현</li>\n";
echo "<li><strong>권한 검증:</strong> 역직렬화 후 추가 권한 검증</li>\n";
echo "<li><strong>샌드박스:</strong> 역직렬화를 격리된 환경에서 수행</li>\n";
echo "<li><strong>모니터링:</strong> 역직렬화 과정 로깅 및 모니터링</li>\n";
echo "</ul>\n";

echo "<p><a href='webhacking/deserialization_test.php'>🔗 Deserialization 테스트 페이지로 이동</a></p>\n";
?>