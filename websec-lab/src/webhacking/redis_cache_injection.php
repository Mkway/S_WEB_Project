<?php
/**
 * Redis Cache Injection 취약점 테스트 페이지
 * 
 * 캐시 인젝션 및 캐시 포이즈닝 공격 시나리오를 시뮬레이션합니다.
 * 교육 목적으로 실제 Redis 캐시 조작을 보여줍니다.
 */

// Redis 연결 설정
try {
    $redis = new Redis();
    $redis->connect('security_redis', 6379);  // docker-compose에서 정의한 서비스명
} catch (Exception $e) {
    die("❌ Redis 연결 실패: " . $e->getMessage());
}

// 결과 저장 변수
$result = "";
$vulnerability_executed = false;

// POST 요청 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    $user_input = $_POST['user_input'] ?? '';
    
    switch ($test_type) {
        case 'cache_injection':
            $result = testCacheInjection($redis, $user_input);
            break;
            
        case 'cache_poisoning':
            $result = testCachePoisoning($redis, $user_input);
            break;
            
        case 'lua_injection':
            $result = testLuaScriptInjection($redis, $user_input);
            break;
            
        case 'key_manipulation':
            $result = testKeyManipulation($redis, $user_input);
            break;
            
        case 'safe_cache':
            $result = testSafeCacheHandling($redis, $user_input);
            break;
    }
    $vulnerability_executed = true;
}

/**
 * 캐시 인젝션 테스트
 * 사용자 입력을 캐시 키에 직접 사용하여 인젝션 공격 시뮬레이션
 */
function testCacheInjection($redis, $user_input) {
    $result = "<h3>🔥 Cache Injection 테스트</h3>";
    
    // 취약한 구현: 사용자 입력을 필터링 없이 키로 사용
    $vulnerable_key = "user_data:" . $user_input;
    
    try {
        // 실제 캐시 인젝션 실행
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        
        // Redis 명령어 인젝션 시도
        if (strpos($user_input, '*') !== false || strpos($user_input, '?') !== false) {
            $keys = $redis->keys($vulnerable_key);
            $result .= "<p><strong>키 패턴 매칭 결과:</strong></p>";
            $result .= "<pre>" . print_r($keys, true) . "</pre>";
            
            if (!empty($keys)) {
                $result .= "<p><strong>노출된 데이터:</strong></p>";
                foreach (array_slice($keys, 0, 5) as $key) {
                    $value = $redis->get($key);
                    if ($value) {
                        $result .= "<code>$key: $value</code><br>";
                    }
                }
            }
        } else {
            // 단순 키 접근
            $value = $redis->get($vulnerable_key);
            if ($value) {
                $result .= "<p>키 '$vulnerable_key'의 값: <code>$value</code></p>";
            } else {
                $result .= "<p>키 '$vulnerable_key'에서 데이터를 찾을 수 없습니다.</p>";
            }
        }
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $safe_key = "user_data:" . preg_replace('/[^a-zA-Z0-9_]/', '', $user_input);
        $result .= "<p>필터링된 키: <code>$safe_key</code></p>";
        $result .= "<p>와일드카드 문자 제거, 영숫자와 언더스코어만 허용</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>사용자 입력을 캐시 키에 사용할 때는 반드시 검증 및 필터링</li>";
        $result .= "<li>화이트리스트 기반 키 네이밍 규칙 적용</li>";
        $result .= "<li>Redis KEYS 명령어 대신 SCAN 사용 권장</li>";
        $result .= "<li>캐시 키 접근 권한 제한 및 네임스페이스 분리</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * 캐시 포이즈닝 테스트
 * 악의적인 데이터로 캐시를 오염시키는 공격 시뮬레이션
 */
function testCachePoisoning($redis, $user_input) {
    $result = "<h3>☠️ Cache Poisoning 테스트</h3>";
    
    try {
        // 취약한 구현: 사용자 입력을 검증 없이 캐시에 저장
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        
        // 악의적인 데이터로 캐시 포이즈닝
        $cache_key = "api_response:weather";
        $malicious_data = $user_input;
        
        // 실제 캐시 포이즈닝 실행
        $redis->set($cache_key, $malicious_data, 3600); // 1시간 TTL
        
        $result .= "<p><strong>캐시 포이즈닝 성공!</strong></p>";
        $result .= "<p>키: <code>$cache_key</code></p>";
        $result .= "<p>악의적인 데이터: <code>" . htmlspecialchars($malicious_data) . "</code></p>";
        
        // 포이즈닝된 캐시 읽기
        $poisoned_value = $redis->get($cache_key);
        $result .= "<p><strong>포이즈닝된 캐시에서 읽은 값:</strong></p>";
        $result .= "<pre>" . htmlspecialchars($poisoned_value) . "</pre>";
        
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $result .= "<p>입력 검증: JSON 스키마 검증, 데이터 타입 확인</p>";
        $result .= "<p>데이터 무결성: 체크섬 또는 서명 검증</p>";
        $result .= "<p>소스 검증: 신뢰할 수 있는 소스에서만 캐시 업데이트 허용</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>캐시 데이터의 무결성 검증 (체크섬, 디지털 서명)</li>";
        $result .= "<li>캐시 업데이트 권한을 특정 서비스로 제한</li>";
        $result .= "<li>캐시 TTL 적절히 설정하여 포이즈닝 영향 최소화</li>";
        $result .= "<li>캐시 데이터 입력 시 엄격한 검증 수행</li>";
        $result .= "<li>캐시 변조 탐지 시스템 구축</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * Lua 스크립트 인젝션 테스트
 * Redis Lua 스크립트 실행 취약점 시뮬레이션
 */
function testLuaScriptInjection($redis, $user_input) {
    $result = "<h3>🔥 Lua Script Injection 테스트</h3>";
    
    try {
        // 취약한 구현: 사용자 입력을 Lua 스크립트에 직접 삽입
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        
        // 악의적인 Lua 스크립트 구성
        $lua_script = "return redis.call('get', '$user_input')";
        $result .= "<p><strong>실행할 Lua 스크립트:</strong></p>";
        $result .= "<pre>" . htmlspecialchars($lua_script) . "</pre>";
        
        // 실제 Lua 스크립트 실행 (위험한 예제)
        try {
            $script_result = $redis->eval($lua_script, 0);
            $result .= "<p><strong>Lua 스크립트 실행 결과:</strong></p>";
            $result .= "<pre>" . htmlspecialchars(print_r($script_result, true)) . "</pre>";
        } catch (Exception $e) {
            $result .= "<p class='error'>Lua 스크립트 실행 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
        }
        
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $result .= "<p>미리 정의된 Lua 스크립트만 사용 (SHA 해시로 실행)</p>";
        $result .= "<p>사용자 입력은 스크립트 인자로만 전달</p>";
        $result .= "<p>Lua 스크립트 실행 권한 엄격히 제한</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>동적 Lua 스크립트 생성 금지</li>";
        $result .= "<li>사전 승인된 스크립트만 실행 (화이트리스트)</li>";
        $result .= "<li>스크립트 실행 시간 및 리소스 제한</li>";
        $result .= "<li>Redis CONFIG 명령어를 통한 Lua 스크립트 실행 제한</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * 키 조작 공격 테스트
 * 의도되지 않은 Redis 키에 접근하는 공격 시뮬레이션
 */
function testKeyManipulation($redis, $user_input) {
    $result = "<h3>🔓 Key Manipulation 테스트</h3>";
    
    try {
        // 취약한 구현: 사용자 입력으로 키 조작
        $result .= "<div class='vulnerable-output'>";
        $result .= "<h4>🚨 취약한 구현 실행 결과:</h4>";
        
        // 키 조작 공격 시도
        $manipulated_key = $user_input;
        $result .= "<p><strong>조작된 키로 데이터 접근:</strong></p>";
        $result .= "<p>요청된 키: <code>" . htmlspecialchars($manipulated_key) . "</code></p>";
        
        // 실제 키 조작 공격 실행
        if ($redis->exists($manipulated_key)) {
            $value = $redis->get($manipulated_key);
            $type = $redis->type($manipulated_key);
            
            $result .= "<p><strong>⚠️ 접근 성공! 민감한 데이터 노출:</strong></p>";
            $result .= "<p>데이터 타입: <code>$type</code></p>";
            
            if ($type == Redis::REDIS_STRING) {
                $result .= "<p>값: <code>" . htmlspecialchars($value) . "</code></p>";
            } elseif ($type == Redis::REDIS_HASH) {
                $hash_data = $redis->hGetAll($manipulated_key);
                $result .= "<p>해시 데이터:</p>";
                $result .= "<pre>" . print_r($hash_data, true) . "</pre>";
            }
        } else {
            $result .= "<p>키를 찾을 수 없습니다: <code>$manipulated_key</code></p>";
        }
        
        // 패턴 매칭으로 유사한 키 탐색
        if (strpos($user_input, '*') !== false) {
            $matching_keys = $redis->keys($user_input);
            if (!empty($matching_keys)) {
                $result .= "<p><strong>패턴 매칭으로 발견된 키들:</strong></p>";
                $result .= "<ul>";
                foreach (array_slice($matching_keys, 0, 10) as $key) {
                    $result .= "<li><code>" . htmlspecialchars($key) . "</code></li>";
                }
                $result .= "</ul>";
            }
        }
        
        $result .= "</div>";
        
        // 안전한 구현 비교
        $result .= "<div class='safe-comparison'>";
        $result .= "<h4>✅ 안전한 구현이었다면:</h4>";
        $result .= "<p>키 접근 권한을 사용자 세션으로 제한</p>";
        $result .= "<p>키 네임스페이스를 통한 접근 범위 제한</p>";
        $result .= "<p>허용된 키 패턴만 접근 가능하도록 검증</p>";
        $result .= "</div>";
        
        // 보안 권장사항
        $result .= "<div class='security-recommendations'>";
        $result .= "<h4>🛡️ 보안 권장사항:</h4>";
        $result .= "<ul>";
        $result .= "<li>키 접근 권한 모델 구축 (사용자별, 역할별)</li>";
        $result .= "<li>키 네임스페이스를 통한 데이터 격리</li>";
        $result .= "<li>민감한 데이터는 암호화하여 저장</li>";
        $result .= "<li>키 패턴 검증 및 화이트리스트 적용</li>";
        $result .= "<li>Redis ACL(Access Control List) 기능 활용</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

/**
 * 안전한 캐시 처리 구현 예제
 */
function testSafeCacheHandling($redis, $user_input) {
    $result = "<h3>✅ Safe Cache Handling 테스트</h3>";
    
    try {
        $result .= "<div class='safe-implementation'>";
        $result .= "<h4>🛡️ 안전한 구현 실행:</h4>";
        
        // 입력 검증
        $sanitized_input = preg_replace('/[^a-zA-Z0-9_]/', '', $user_input);
        $result .= "<p><strong>1단계 - 입력 검증:</strong></p>";
        $result .= "<p>원본 입력: <code>" . htmlspecialchars($user_input) . "</code></p>";
        $result .= "<p>검증된 입력: <code>$sanitized_input</code></p>";
        
        // 권한 확인 (시뮬레이션)
        $allowed_prefixes = ['user_data', 'public_info', 'temp_cache'];
        $safe_key = "user_data:$sanitized_input";
        
        $result .= "<p><strong>2단계 - 권한 확인:</strong></p>";
        $result .= "<p>허용된 키 접두사: " . implode(', ', $allowed_prefixes) . "</p>";
        $result .= "<p>최종 안전한 키: <code>$safe_key</code></p>";
        
        // 안전한 캐시 접근
        if ($redis->exists($safe_key)) {
            $value = $redis->get($safe_key);
            $result .= "<p><strong>3단계 - 안전한 데이터 접근:</strong></p>";
            $result .= "<p>캐시된 값: <code>" . htmlspecialchars($value) . "</code></p>";
        } else {
            // 안전한 기본값 설정
            $default_data = json_encode(['message' => 'No data found', 'timestamp' => time()]);
            $redis->set($safe_key, $default_data, 300); // 5분 TTL
            
            $result .= "<p><strong>3단계 - 안전한 기본값 설정:</strong></p>";
            $result .= "<p>기본값으로 설정: <code>$default_data</code></p>";
        }
        
        $result .= "</div>";
        
        // 안전한 구현의 장점
        $result .= "<div class='implementation-benefits'>";
        $result .= "<h4>🎯 안전한 구현의 장점:</h4>";
        $result .= "<ul>";
        $result .= "<li><strong>입력 검증:</strong> 악의적인 문자 제거</li>";
        $result .= "<li><strong>권한 제어:</strong> 허용된 범위 내에서만 접근</li>";
        $result .= "<li><strong>네임스페이스:</strong> 데이터 격리 및 충돌 방지</li>";
        $result .= "<li><strong>예외 처리:</strong> 안전한 기본값 제공</li>";
        $result .= "</ul>";
        $result .= "</div>";
        
    } catch (Exception $e) {
        $result .= "<p class='error'>오류 발생: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    return $result;
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redis Cache Injection 취약점 테스트</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }

        .header {
            background: linear-gradient(135deg, #dc2626, #ef4444);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }

        .test-container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
        }

        select, input, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }

        button {
            background: #dc2626;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
        }

        button:hover {
            background: #b91c1c;
        }

        .result {
            margin-top: 30px;
            border-radius: 10px;
            overflow: hidden;
        }

        .vulnerable-output {
            background: #fee2e2;
            border: 2px solid #fca5a5;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .safe-comparison {
            background: #dcfce7;
            border: 2px solid #86efac;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .security-recommendations {
            background: #dbeafe;
            border: 2px solid #93c5fd;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .safe-implementation {
            background: #f0fdf4;
            border: 2px solid #4ade80;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .implementation-benefits {
            background: #fefce8;
            border: 2px solid #facc15;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }

        .error {
            color: #dc2626;
            font-weight: bold;
        }

        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #e9ecef;
            overflow-x: auto;
            font-size: 13px;
        }

        code {
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Menlo', monospace;
        }

        .info-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }

        ul {
            padding-left: 20px;
        }

        li {
            margin-bottom: 8px;
        }

        h3 {
            color: #1f2937;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }

        h4 {
            margin-top: 0;
            color: #374151;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 Redis Cache Injection 취약점 테스트</h1>
        <p>실제 캐시 인젝션 및 포이즈닝 공격을 시뮬레이션하고 안전한 구현과 비교합니다</p>
    </div>

    <div class="test-container">
        <div class="warning">
            ⚠️ <strong>경고:</strong> 이 테스트는 교육 목적으로만 사용되며, 실제 Redis 캐시를 조작합니다. 
            프로덕션 환경에서는 절대 사용하지 마세요.
        </div>

        <form method="POST">
            <div class="form-group">
                <label for="test_type">테스트 유형:</label>
                <select name="test_type" id="test_type" required>
                    <option value="">테스트 유형을 선택하세요</option>
                    <option value="cache_injection" <?= ($_POST['test_type'] ?? '') == 'cache_injection' ? 'selected' : '' ?>>
                        Cache Injection (키 조작 공격)
                    </option>
                    <option value="cache_poisoning" <?= ($_POST['test_type'] ?? '') == 'cache_poisoning' ? 'selected' : '' ?>>
                        Cache Poisoning (캐시 오염 공격)
                    </option>
                    <option value="lua_injection" <?= ($_POST['test_type'] ?? '') == 'lua_injection' ? 'selected' : '' ?>>
                        Lua Script Injection (스크립트 인젝션)
                    </option>
                    <option value="key_manipulation" <?= ($_POST['test_type'] ?? '') == 'key_manipulation' ? 'selected' : '' ?>>
                        Key Manipulation (키 접근 권한 우회)
                    </option>
                    <option value="safe_cache" <?= ($_POST['test_type'] ?? '') == 'safe_cache' ? 'selected' : '' ?>>
                        Safe Cache Handling (안전한 구현)
                    </option>
                </select>
            </div>

            <div class="form-group">
                <label for="user_input">테스트 입력:</label>
                <textarea name="user_input" id="user_input" rows="3" placeholder="테스트할 입력을 입력하세요" required><?= htmlspecialchars($_POST['user_input'] ?? '') ?></textarea>
            </div>

            <button type="submit">🚀 취약점 테스트 실행</button>
        </form>

        <div class="info-box">
            <h3>📖 테스트 예제:</h3>
            <ul>
                <li><strong>Cache Injection:</strong> <code>*</code> 또는 <code>user:*</code> (모든 사용자 키 조회)</li>
                <li><strong>Cache Poisoning:</strong> <code>{"malicious": "data", "xss": "&lt;script&gt;alert('XSS')&lt;/script&gt;"}</code></li>
                <li><strong>Lua Injection:</strong> <code>test') return redis.call('keys', '*') --</code></li>
                <li><strong>Key Manipulation:</strong> <code>config:security</code> 또는 <code>admin:*</code></li>
                <li><strong>Safe Implementation:</strong> <code>testuser123</code></li>
            </ul>
        </div>
    </div>

    <?php if ($vulnerability_executed && $result): ?>
    <div class="test-container">
        <div class="result">
            <?= $result ?>
        </div>
    </div>
    <?php endif; ?>

    <div class="test-container">
        <h3>🎯 Redis Cache Injection 공격 개요</h3>
        <div class="info-box">
            <h4>주요 공격 벡터:</h4>
            <ul>
                <li><strong>키 인젝션:</strong> 사용자 입력을 통한 의도되지 않은 캐시 키 접근</li>
                <li><strong>캐시 포이즈닝:</strong> 악의적인 데이터로 캐시 오염</li>
                <li><strong>Lua 스크립트 인젝션:</strong> Redis Lua 스크립트 실행 권한 악용</li>
                <li><strong>권한 우회:</strong> 다른 사용자의 캐시 데이터 접근</li>
            </ul>
            
            <h4>실제 피해 사례:</h4>
            <ul>
                <li>민감한 사용자 데이터 노출 (세션 토큰, 개인정보)</li>
                <li>캐시를 통한 애플리케이션 로직 우회</li>
                <li>서비스 거부 공격 (DoS)</li>
                <li>데이터 무결성 손상</li>
            </ul>
        </div>
    </div>
</body>
</html>