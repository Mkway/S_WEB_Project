<?php
/**
 * Redis 연결 및 Cache Injection 테스트 스크립트
 */

require_once 'database/RedisConnection.php';

echo "<h2>🧪 Redis 연결 및 Cache Injection 테스트</h2>\n";

try {
    echo "<p>Redis 연결 시도 중...</p>\n";
    
    // Predis를 사용한 연결 테스트
    $redis = new RedisConnection(false);
    
    if ($redis->isConnected()) {
        echo "<p style='color: green;'>✅ Redis 연결 성공! (Predis 라이브러리)</p>\n";
        
        // 1. 기본 캐시 데이터 확인
        echo "<h3>📋 캐시 데이터 확인:</h3>\n";
        
        $sessionData = $redis->safeGetSession('admin_123');
        if ($sessionData) {
            echo "<p style='color: green;'>✅ 관리자 세션 조회 성공:</p>\n";
            echo "<pre>" . htmlspecialchars($sessionData) . "</pre>\n";
        }
        
        $userProfile = $redis->safeGetUserProfile(1);
        if ($userProfile) {
            echo "<p style='color: green;'>✅ 사용자 프로필 조회 성공:</p>\n";
            echo "<pre>" . json_encode($userProfile, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>\n";
        }
        
        // 2. Cache Injection 취약점 테스트
        echo "<h3>🚨 Cache Injection 취약점 테스트:</h3>\n";
        
        echo "<h4>1. Session Hijacking 테스트:</h4>\n";
        
        // 정상 세션 조회
        $normalSession = $redis->safeGetSession('user1_456');
        if ($normalSession) {
            echo "<p style='color: green;'>✅ 정상 세션 조회 성공</p>\n";
        }
        
        // 취약한 세션 조회 (와일드카드 패턴)
        $maliciousPattern = "session:*";
        $allSessions = $redis->vulnerableCacheSearch($maliciousPattern);
        if (!empty($allSessions)) {
            echo "<p style='color: red;'>🔥 Session Hijacking 공격 성공! 모든 세션 노출:</p>\n";
            echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
            foreach ($allSessions as $key => $session) {
                echo "<strong>{$key}:</strong> " . htmlspecialchars($session) . "<br>\n";
            }
            echo "</div>\n";
        }
        
        echo "<h4>2. Cache Poisoning 테스트:</h4>\n";
        
        // 정상 사용자 프로필 업데이트
        $normalUpdate = $redis->safeUpdateUserProfile(2, [
            'name' => 'Updated User',
            'email' => 'updated@example.com',
            'theme' => 'dark'
        ]);
        if ($normalUpdate) {
            echo "<p style='color: green;'>✅ 정상 프로필 업데이트 성공</p>\n";
        }
        
        // 취약한 사용자 권한 상승 공격
        $maliciousData = [
            'name' => 'Hacker',
            'role' => 'administrator',  // 권한 상승 시도
            'premium' => true,
            'balance' => 999999
        ];
        
        $poisonResult = $redis->vulnerableUpdateUserCache(2, $maliciousData);
        if ($poisonResult) {
            echo "<p style='color: red;'>🔥 Cache Poisoning 공격 성공! 권한 상승:</p>\n";
            
            // 공격 결과 확인
            $poisonedProfile = $redis->safeGetUserProfile(2);
            if ($poisonedProfile) {
                echo "<div style='background: #ffe6e6; padding: 10px; border: 1px solid #ff9999; margin: 10px 0;'>\n";
                echo "<pre>" . json_encode($poisonedProfile, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>\n";
                echo "</div>\n";
            }
        }
        
        echo "<h4>3. Configuration Injection 테스트:</h4>\n";
        
        // 취약한 설정 변경 공격
        $configResult = $redis->vulnerableUpdateConfig('debug_mode', 'true');
        if ($configResult) {
            echo "<p style='color: red;'>🔥 Configuration Injection 공격 성공! 디버그 모드 활성화</p>\n";
        }
        
        $maintenanceResult = $redis->vulnerableUpdateConfig('maintenance', 'false');  
        if ($maintenanceResult) {
            echo "<p style='color: red;'>🔥 유지보수 모드 설정 변경 성공!</p>\n";
        }
        
        echo "<h4>4. Command Injection 테스트:</h4>\n";
        
        // 위험한 명령어 실행 테스트
        echo "<p style='color: orange;'>⚠️ 위험한 Redis 명령어 실행 테스트:</p>\n";
        
        $infoResult = $redis->vulnerableExecuteCommand('INFO', ['server']);
        if ($infoResult && !is_string($infoResult)) {
            echo "<p style='color: red;'>🔥 INFO 명령어 실행 성공 - 서버 정보 노출</p>\n";
        }
        
        // 키 목록 조회 (민감한 정보 노출)
        $keysResult = $redis->vulnerableExecuteCommand('KEYS', ['*']);
        if ($keysResult && is_array($keysResult)) {
            echo "<p style='color: red;'>🔥 KEYS * 명령어 성공 - 모든 캐시 키 노출: " . count($keysResult) . "개</p>\n";
        }
        
        echo "<h4>5. Queue Injection 테스트:</h4>\n";
        
        // 악성 메시지 큐 삽입
        $maliciousMessage = '{"type":"admin_alert","message":"System compromised","execute":"rm -rf /*"}';
        $queueResult = $redis->vulnerableAddToQueue('notifications', $maliciousMessage);
        if ($queueResult) {
            echo "<p style='color: red;'>🔥 Queue Injection 공격 성공! 악성 메시지 삽입</p>\n";
        }
        
        // 3. 안전한 구현과의 비교
        echo "<h3>🛡️ 안전한 구현 결과:</h3>\n";
        
        $safeKeyCount = $redis->safeCountKeys('session:*');
        echo "<p style='color: green;'>✅ 안전한 세션 키 카운트: {$safeKeyCount}개</p>\n";
        
        $safeStats = $redis->safeGetCacheStats('daily');
        if ($safeStats) {
            echo "<p style='color: green;'>✅ 안전한 통계 조회 성공</p>\n";
        }
        
        $safeInfo = $redis->safeGetRedisInfo('memory');
        if ($safeInfo) {
            echo "<p style='color: green;'>✅ 안전한 Redis 정보 조회 (제한된 섹션만)</p>\n";
        }
        
    } else {
        echo "<p style='color: red;'>❌ Redis 연결 실패</p>\n";
    }
    
} catch (Exception $e) {
    echo "<p style='color: red;'>❌ 오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>\n";
}

echo "<hr>\n";
echo "<h3>🔒 보안 권장사항:</h3>\n";
echo "<ul>\n";
echo "<li><strong>입력 검증:</strong> 모든 캐시 키와 값에 대해 엄격한 검증 수행</li>\n";
echo "<li><strong>키 네임스페이싱:</strong> 고정된 접두사 사용으로 키 조작 방지</li>\n";
echo "<li><strong>명령어 제한:</strong> 위험한 Redis 명령어 비활성화</li>\n";
echo "<li><strong>권한 분리:</strong> Redis 사용자별 명령어 권한 제한</li>\n";
echo "<li><strong>TTL 설정:</strong> 모든 캐시 데이터에 적절한 만료 시간 설정</li>\n";
echo "<li><strong>모니터링:</strong> Redis 명령어 실행 로그 모니터링</li>\n";
echo "</ul>\n";

echo "<p><a href='webhacking/redis_injection_test.php'>🔗 Redis Cache Injection 테스트 페이지로 이동</a></p>\n";
?>