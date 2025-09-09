<?php
session_start();
include_once '../db_connection.php';

class APISecurityTest {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
        $this->initializeDatabase();
    }
    
    private function initializeDatabase() {
        // API 보안 테스트용 테이블 생성
        $tables = [
            "CREATE TABLE IF NOT EXISTS api_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                email VARCHAR(100) NOT NULL,
                password VARCHAR(255) NOT NULL,
                api_key VARCHAR(100),
                role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            "CREATE TABLE IF NOT EXISTS api_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                token TEXT NOT NULL,
                token_type ENUM('access', 'refresh', 'api_key') DEFAULT 'access',
                expires_at DATETIME,
                is_revoked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES api_users(id) ON DELETE CASCADE
            )",
            "CREATE TABLE IF NOT EXISTS api_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                endpoint VARCHAR(255) NOT NULL,
                method ENUM('GET', 'POST', 'PUT', 'DELETE', 'PATCH') NOT NULL,
                user_id INT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                request_data TEXT,
                response_code INT,
                execution_time DECIMAL(8,3),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_endpoint (endpoint),
                INDEX idx_created_at (created_at)
            )",
            "CREATE TABLE IF NOT EXISTS api_rate_limits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                identifier VARCHAR(100) NOT NULL,
                requests_count INT DEFAULT 0,
                window_start DATETIME NOT NULL,
                window_duration INT DEFAULT 60,
                max_requests INT DEFAULT 100,
                UNIQUE KEY unique_identifier_window (identifier, window_start)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->db->exec($sql);
        }
        
        // 테스트 데이터 삽입
        $this->initializeTestData();
    }
    
    private function initializeTestData() {
        // API 사용자 데이터 삽입
        $users = [
            ['admin', 'admin@test.com', password_hash('admin123', PASSWORD_DEFAULT), $this->generateApiKey(), 'admin'],
            ['testuser', 'user@test.com', password_hash('user123', PASSWORD_DEFAULT), $this->generateApiKey(), 'user'],
            ['moderator', 'mod@test.com', password_hash('mod123', PASSWORD_DEFAULT), $this->generateApiKey(), 'moderator'],
            ['inactive', 'inactive@test.com', password_hash('inactive123', PASSWORD_DEFAULT), $this->generateApiKey(), 'user']
        ];
        
        foreach ($users as $user) {
            $stmt = $this->db->prepare("INSERT IGNORE INTO api_users (username, email, password, api_key, role) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute($user);
        }
        
        // 비활성 사용자 설정
        $stmt = $this->db->prepare("UPDATE api_users SET is_active = FALSE WHERE username = 'inactive'");
        $stmt->execute();
    }
    
    private function generateApiKey() {
        return 'sk-' . bin2hex(random_bytes(20));
    }
    
    private function generateJWT($payload, $secret = 'secret_key') {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode($payload);
        
        $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        
        $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $secret, true);
        $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        
        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }
    
    private function verifyJWT($token, $secret = 'secret_key') {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }
        
        list($header, $payload, $signature) = $parts;
        
        $expectedSignature = hash_hmac('sha256', $header . "." . $payload, $secret, true);
        $expectedSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($expectedSignature));
        
        if (!hash_equals($signature, $expectedSignature)) {
            return false;
        }
        
        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $payload)), true);
        
        // 만료 시간 확인
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return false;
        }
        
        return $payload;
    }
    
    public function testWeakAuthentication($username, $password) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 취약한 API 인증 테스트</h4>";
            
            // SQL Injection이 가능한 취약한 쿼리
            $query = "SELECT * FROM api_users WHERE username = '$username' AND password = '$password' AND is_active = 1";
            $result .= "<p><strong>실행 쿼리:</strong> <code>" . htmlspecialchars($query) . "</code></p>";
            
            $stmt = $this->db->query($query);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                $result .= "<p class='alert-danger'><strong>🚨 인증 성공!</strong> SQL Injection으로 로그인 우회 성공</p>";
                
                // 취약한 JWT 토큰 생성 (약한 서명 키)
                $payload = [
                    'user_id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role'],
                    'exp' => time() + 3600
                ];
                
                $weak_token = $this->generateJWT($payload, 'weak'); // 약한 서명 키
                $result .= "<p><strong>생성된 JWT 토큰:</strong></p>";
                $result .= "<textarea readonly style='width: 100%; height: 60px; font-family: monospace;'>" . $weak_token . "</textarea>";
                
                $result .= "<p class='alert-warning'><strong>⚠️ 취약점:</strong></p>";
                $result .= "<ul>";
                $result .= "<li>SQL Injection을 통한 인증 우회</li>";
                $result .= "<li>약한 JWT 서명 키 사용</li>";
                $result .= "<li>패스워드 해싱 검증 없음</li>";
                $result .= "</ul>";
                
            } else {
                $result .= "<p class='alert-warning'><strong>❌ 인증 실패</strong></p>";
                $result .= "<p>이번에는 SQL Injection이 성공하지 않았습니다.</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function testSecureAuthentication($username, $password) {
        $result = '';
        
        try {
            $result .= "<div class='safe-output'>";
            $result .= "<h4>🔒 안전한 API 인증 구현</h4>";
            
            // Prepared Statement 사용
            $stmt = $this->db->prepare("SELECT * FROM api_users WHERE username = ? AND is_active = 1");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && password_verify($password, $user['password'])) {
                $result .= "<p class='alert-success'><strong>✅ 안전한 인증 성공!</strong></p>";
                
                // 강한 JWT 토큰 생성
                $payload = [
                    'user_id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role'],
                    'iat' => time(),
                    'exp' => time() + 3600,
                    'iss' => 'secure-api'
                ];
                
                $strong_secret = hash('sha256', 'strong_secret_key_' . $user['id']);
                $secure_token = $this->generateJWT($payload, $strong_secret);
                
                $result .= "<p><strong>안전한 JWT 토큰:</strong></p>";
                $result .= "<textarea readonly style='width: 100%; height: 60px; font-family: monospace;'>" . $secure_token . "</textarea>";
                
                $result .= "<p class='alert-success'><strong>✅ 보안 강화 요소:</strong></p>";
                $result .= "<ul>";
                $result .= "<li>Prepared Statement로 SQL Injection 방지</li>";
                $result .= "<li>강한 JWT 서명 키 사용</li>";
                $result .= "<li>패스워드 해싱 검증</li>";
                $result .= "<li>토큰 만료 시간 설정</li>";
                $result .= "</ul>";
                
            } else {
                $result .= "<p class='alert-warning'><strong>❌ 인증 실패</strong></p>";
                $result .= "<p>올바른 사용자명과 패스워드를 입력하세요.</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function testJWTVulnerabilities($token) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 JWT 취약점 분석</h4>";
            
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return "<div class='error-output'>❌ 유효하지 않은 JWT 형식입니다.</div>";
            }
            
            list($header, $payload, $signature) = $parts;
            
            // Header 분석
            $decoded_header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $header)), true);
            $decoded_payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $payload)), true);
            
            $result .= "<h5>📋 JWT 분석 결과:</h5>";
            $result .= "<p><strong>Header:</strong></p>";
            $result .= "<pre>" . htmlspecialchars(json_encode($decoded_header, JSON_PRETTY_PRINT)) . "</pre>";
            $result .= "<p><strong>Payload:</strong></p>";
            $result .= "<pre>" . htmlspecialchars(json_encode($decoded_payload, JSON_PRETTY_PRINT)) . "</pre>";
            
            // 취약점 검사
            $vulnerabilities = [];
            
            // 1. None 알고리즘 취약점
            if (isset($decoded_header['alg']) && strtolower($decoded_header['alg']) === 'none') {
                $vulnerabilities[] = "🚨 None 알고리즘 사용 - 서명 없이 토큰 조작 가능";
            }
            
            // 2. 약한 서명 키 테스트
            $weak_secrets = ['secret', 'weak', 'test', '123456', 'password'];
            foreach ($weak_secrets as $weak_secret) {
                if ($this->verifyJWT($token, $weak_secret)) {
                    $vulnerabilities[] = "🚨 약한 서명 키 사용: '$weak_secret'";
                    break;
                }
            }
            
            // 3. 만료 시간 검사
            if (!isset($decoded_payload['exp'])) {
                $vulnerabilities[] = "⚠️ 만료 시간(exp) 없음 - 토큰이 영구적으로 유효";
            } elseif ($decoded_payload['exp'] < time()) {
                $vulnerabilities[] = "⚠️ 만료된 토큰이지만 검증되지 않을 수 있음";
            }
            
            // 4. 중요 클레임 누락
            $required_claims = ['iss', 'aud', 'exp', 'iat'];
            $missing_claims = array_diff($required_claims, array_keys($decoded_payload));
            if (!empty($missing_claims)) {
                $vulnerabilities[] = "⚠️ 중요 클레임 누락: " . implode(', ', $missing_claims);
            }
            
            // 5. 권한 상승 시도
            if (isset($decoded_payload['role'])) {
                $modified_payload = $decoded_payload;
                $modified_payload['role'] = 'admin';
                
                $modified_token = $this->generateJWT($modified_payload, 'weak');
                $result .= "<h5>🎯 권한 상승 공격 시뮬레이션:</h5>";
                $result .= "<p><strong>조작된 토큰 (role을 admin으로 변경):</strong></p>";
                $result .= "<textarea readonly style='width: 100%; height: 60px; font-family: monospace;'>" . $modified_token . "</textarea>";
            }
            
            if (!empty($vulnerabilities)) {
                $result .= "<h5>🚨 발견된 취약점:</h5>";
                $result .= "<ul>";
                foreach ($vulnerabilities as $vuln) {
                    $result .= "<li>$vuln</li>";
                }
                $result .= "</ul>";
            } else {
                $result .= "<p class='alert-success'><strong>✅ 심각한 취약점이 발견되지 않았습니다.</strong></p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function testRateLimiting($endpoint, $requests_count) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>⚡ Rate Limiting 우회 테스트</h4>";
            
            $identifier = $_SERVER['REMOTE_ADDR'] ?? 'test_ip';
            $current_time = date('Y-m-d H:i:00'); // 1분 단위
            
            // 현재 시간대의 요청 수 확인
            $stmt = $this->db->prepare("SELECT requests_count FROM api_rate_limits WHERE identifier = ? AND window_start = ?");
            $stmt->execute([$identifier, $current_time]);
            $current_requests = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $current_count = $current_requests ? $current_requests['requests_count'] : 0;
            $max_requests = 10; // 분당 10회 제한
            
            $result .= "<p><strong>요청 시도:</strong> {$requests_count}회</p>";
            $result .= "<p><strong>현재 요청 수:</strong> {$current_count}회</p>";
            $result .= "<p><strong>제한:</strong> 분당 {$max_requests}회</p>";
            
            // Rate Limiting 우회 기법들 시뮬레이션
            $bypass_techniques = [
                'X-Forwarded-For' => ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
                'X-Real-IP' => ['8.8.8.8', '9.9.9.9'],
                'X-Originating-IP' => ['10.0.0.1', '10.0.0.2'],
                'User-Agent' => ['Bot1', 'Bot2', 'Crawler']
            ];
            
            $successful_requests = 0;
            $blocked_requests = 0;
            
            for ($i = 1; $i <= $requests_count; $i++) {
                // 취약한 Rate Limiting 구현 - 헤더 기반 우회 가능
                $client_ip = $identifier;
                
                // 헤더 스푸핑 시뮬레이션 (10회 이후부터)
                if ($i > $max_requests) {
                    $techniques = array_keys($bypass_techniques);
                    $technique = $techniques[($i - $max_requests - 1) % count($techniques)];
                    $values = $bypass_techniques[$technique];
                    $value = $values[($i - $max_requests - 1) % count($values)];
                    
                    $client_ip = $value; // 헤더로 IP 스푸핑
                    
                    $result .= "<p><strong>우회 시도 #{$i}:</strong> {$technique}: {$value}</p>";
                }
                
                // Rate Limit 검사 (취약한 구현)
                $stmt = $this->db->prepare("SELECT requests_count FROM api_rate_limits WHERE identifier = ? AND window_start = ?");
                $stmt->execute([$client_ip, $current_time]);
                $limit_record = $stmt->fetch(PDO::FETCH_ASSOC);
                
                $current_requests = $limit_record ? $limit_record['requests_count'] : 0;
                
                if ($current_requests < $max_requests) {
                    // 요청 허용
                    $successful_requests++;
                    
                    if ($limit_record) {
                        $stmt = $this->db->prepare("UPDATE api_rate_limits SET requests_count = requests_count + 1 WHERE identifier = ? AND window_start = ?");
                        $stmt->execute([$client_ip, $current_time]);
                    } else {
                        $stmt = $this->db->prepare("INSERT INTO api_rate_limits (identifier, requests_count, window_start, max_requests) VALUES (?, 1, ?, ?)");
                        $stmt->execute([$client_ip, $current_time, $max_requests]);
                    }
                    
                    // API 요청 기록
                    $stmt = $this->db->prepare("INSERT INTO api_requests (endpoint, method, ip_address, response_code, execution_time) VALUES (?, 'GET', ?, 200, ?)");
                    $stmt->execute([$endpoint, $client_ip, rand(50, 200) / 1000]);
                    
                } else {
                    $blocked_requests++;
                }
            }
            
            $result .= "<h5>📊 테스트 결과:</h5>";
            $result .= "<div class='result-stats'>";
            $result .= "<p><strong>✅ 성공한 요청:</strong> {$successful_requests}회</p>";
            $result .= "<p><strong>🚫 차단된 요청:</strong> {$blocked_requests}회</p>";
            $result .= "<p><strong>🎯 우회율:</strong> " . round(($successful_requests / $requests_count) * 100, 1) . "%</p>";
            $result .= "</div>";
            
            if ($successful_requests > $max_requests) {
                $result .= "<p class='alert-danger'><strong>🚨 Rate Limiting 우회 성공!</strong></p>";
                $result .= "<p>헤더 스푸핑을 통해 제한을 우회할 수 있었습니다.</p>";
                
                $result .= "<h5>🔧 사용된 우회 기법:</h5>";
                $result .= "<ul>";
                foreach ($bypass_techniques as $header => $values) {
                    $result .= "<li><strong>{$header}:</strong> " . implode(', ', $values) . "</li>";
                }
                $result .= "</ul>";
            } else {
                $result .= "<p class='alert-success'><strong>✅ Rate Limiting이 적절히 작동했습니다.</strong></p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function testGraphQLInjection($query) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔍 GraphQL Injection 테스트</h4>";
            
            // GraphQL 쿼리 시뮬레이션
            $result .= "<p><strong>입력된 GraphQL 쿼리:</strong></p>";
            $result .= "<pre>" . htmlspecialchars($query) . "</pre>";
            
            // 취약점 패턴 검사
            $injection_patterns = [
                'union select' => 'SQL Injection 시도 탐지',
                'information_schema' => '스키마 정보 수집 시도',
                'sleep(' => 'Time-based Blind Injection',
                'load_file(' => '파일 읽기 시도',
                'into outfile' => '파일 쓰기 시도',
                '__schema' => 'GraphQL 스키마 탐색 (Introspection)',
                '__type' => '타입 정보 탐색',
                'fragment' => 'Fragment를 이용한 복잡한 쿼리',
                'mutation' => '데이터 변경 시도',
                'subscription' => '실시간 데이터 구독'
            ];
            
            $detected_attacks = [];
            foreach ($injection_patterns as $pattern => $description) {
                if (stripos($query, $pattern) !== false) {
                    $detected_attacks[] = $description;
                }
            }
            
            if (!empty($detected_attacks)) {
                $result .= "<h5>🚨 탐지된 공격 패턴:</h5>";
                $result .= "<ul>";
                foreach ($detected_attacks as $attack) {
                    $result .= "<li class='alert-danger'>$attack</li>";
                }
                $result .= "</ul>";
            }
            
            // GraphQL 취약점 시뮬레이션
            if (stripos($query, '__schema') !== false) {
                $result .= "<h5>🔓 GraphQL Introspection 공격 성공!</h5>";
                $result .= "<p>스키마 정보가 노출되었습니다:</p>";
                $result .= "<pre>{
  \"data\": {
    \"__schema\": {
      \"types\": [
        {
          \"name\": \"User\",
          \"fields\": [
            {\"name\": \"id\", \"type\": \"ID\"},
            {\"name\": \"username\", \"type\": \"String\"},
            {\"name\": \"email\", \"type\": \"String\"},
            {\"name\": \"password\", \"type\": \"String\"},
            {\"name\": \"role\", \"type\": \"String\"}
          ]
        }
      ]
    }
  }
}</pre>";
                
                $result .= "<p class='alert-danger'><strong>⚠️ 보안 위험:</strong> 스키마 정보 노출로 인한 추가 공격 가능</p>";
            }
            
            if (stripos($query, 'user') !== false && stripos($query, 'password') !== false) {
                $result .= "<h5>🔓 민감 정보 접근 시도!</h5>";
                $result .= "<p>패스워드 필드에 접근하려고 시도했습니다:</p>";
                $result .= "<pre>{
  \"data\": {
    \"user\": {
      \"id\": \"1\",
      \"username\": \"admin\",
      \"email\": \"admin@test.com\",
      \"password\": \"$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi\"
    }
  }
}</pre>";
                
                $result .= "<p class='alert-danger'><strong>🚨 심각한 보안 위험!</strong> 해시된 패스워드가 노출되었습니다.</p>";
            }
            
            // DoS 공격 시뮬레이션
            $depth = substr_count($query, '{');
            if ($depth > 5) {
                $result .= "<h5>⚠️ 깊은 중첩 쿼리 탐지!</h5>";
                $result .= "<p>쿼리 깊이: {$depth}단계</p>";
                $result .= "<p class='alert-warning'>DoS 공격 가능성: 서버 리소스 과다 사용</p>";
            }
            
            $result .= "<h5>🛡️ 권장 대응 방안:</h5>";
            $result .= "<ul>";
            $result .= "<li><strong>Introspection 비활성화:</strong> 프로덕션에서 스키마 노출 방지</li>";
            $result .= "<li><strong>쿼리 깊이 제한:</strong> 최대 중첩 깊이 설정</li>";
            $result .= "<li><strong>필드 레벨 권한:</strong> 민감한 필드 접근 제어</li>";
            $result .= "<li><strong>Rate Limiting:</strong> 복잡한 쿼리에 대한 제한</li>";
            $result .= "<li><strong>쿼리 복잡도 분석:</strong> 리소스 사용량 기반 제한</li>";
            $result .= "</ul>";
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function generateSecurityReport() {
        $result = '';
        
        try {
            $result .= "<div class='info-output'>";
            $result .= "<h4>📊 API 보안 테스트 종합 리포트</h4>";
            
            // 최근 24시간 API 요청 통계
            $stmt = $this->db->prepare("SELECT 
                COUNT(*) as total_requests,
                COUNT(DISTINCT ip_address) as unique_ips,
                AVG(execution_time) as avg_response_time,
                COUNT(CASE WHEN response_code >= 400 THEN 1 END) as error_count
                FROM api_requests 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $stmt->execute();
            $stats = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $result .= "<h5>📈 최근 24시간 API 활동:</h5>";
            $result .= "<div class='stats-grid'>";
            $result .= "<div><strong>총 요청:</strong> " . number_format($stats['total_requests']) . "회</div>";
            $result .= "<div><strong>고유 IP:</strong> " . number_format($stats['unique_ips']) . "개</div>";
            $result .= "<div><strong>평균 응답시간:</strong> " . round($stats['avg_response_time'], 3) . "ms</div>";
            $result .= "<div><strong>에러 요청:</strong> " . number_format($stats['error_count']) . "회</div>";
            $result .= "</div>";
            
            // 엔드포인트별 통계
            $stmt = $this->db->prepare("SELECT endpoint, COUNT(*) as count FROM api_requests 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) 
                GROUP BY endpoint ORDER BY count DESC LIMIT 5");
            $stmt->execute();
            $endpoints = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if (!empty($endpoints)) {
                $result .= "<h5>🎯 인기 엔드포인트 TOP 5:</h5>";
                foreach ($endpoints as $endpoint) {
                    $result .= "<div class='endpoint-stat'>";
                    $result .= "<strong>" . htmlspecialchars($endpoint['endpoint']) . "</strong>: " . number_format($endpoint['count']) . "회";
                    $result .= "</div>";
                }
            }
            
            // Rate Limiting 통계
            $stmt = $this->db->prepare("SELECT COUNT(*) as active_limits FROM api_rate_limits 
                WHERE window_start >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
            $stmt->execute();
            $rate_limits = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $result .= "<h5>🚦 Rate Limiting 현황:</h5>";
            $result .= "<div><strong>활성 제한:</strong> " . $rate_limits['active_limits'] . "개 IP</div>";
            
            // 보안 권장사항
            $result .= "<h5>🛡️ API 보안 권장사항:</h5>";
            $result .= "<div class='security-recommendations'>";
            $result .= "<h6>인증 & 인가:</h6>";
            $result .= "<ul>";
            $result .= "<li>강력한 JWT 서명 키 사용</li>";
            $result .= "<li>토큰 만료 시간 적절히 설정</li>";
            $result .= "<li>Refresh Token 별도 관리</li>";
            $result .= "<li>API Key 정기 교체</li>";
            $result .= "</ul>";
            
            $result .= "<h6>입력 검증:</h6>";
            $result .= "<ul>";
            $result .= "<li>모든 입력 데이터 검증</li>";
            $result .= "<li>GraphQL 쿼리 깊이 제한</li>";
            $result .= "<li>SQL Injection 방지</li>";
            $result .= "<li>JSON 스키마 검증</li>";
            $result .= "</ul>";
            
            $result .= "<h6>Rate Limiting:</h6>";
            $result .= "<ul>";
            $result .= "<li>IP 기반 제한 강화</li>";
            $result .= "<li>사용자 기반 제한</li>";
            $result .= "<li>엔드포인트별 차별화</li>";
            $result .= "<li>분산 환경 고려</li>";
            $result .= "</ul>";
            
            $result .= "<h6>모니터링:</h6>";
            $result .= "<ul>";
            $result .= "<li>실시간 로그 분석</li>";
            $result .= "<li>이상 패턴 탐지</li>";
            $result .= "<li>성능 메트릭 수집</li>";
            $result .= "<li>보안 이벤트 알림</li>";
            $result .= "</ul>";
            $result .= "</div>";
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
}

// 메인 처리
$apiTest = new APISecurityTest($pdo);
$result = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'weak_auth':
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            $result = $apiTest->testWeakAuthentication($username, $password);
            break;
            
        case 'secure_auth':
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            $result = $apiTest->testSecureAuthentication($username, $password);
            break;
            
        case 'jwt_test':
            $token = $_POST['jwt_token'] ?? '';
            $result = $apiTest->testJWTVulnerabilities($token);
            break;
            
        case 'rate_limit_test':
            $endpoint = $_POST['endpoint'] ?? '/api/users';
            $requests_count = (int)($_POST['requests_count'] ?? 20);
            $result = $apiTest->testRateLimiting($endpoint, $requests_count);
            break;
            
        case 'graphql_test':
            $query = $_POST['graphql_query'] ?? '';
            $result = $apiTest->testGraphQLInjection($query);
            break;
            
        case 'security_report':
            $result = $apiTest->generateSecurityReport();
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔌 API Security Testing</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        
        .container {
            background-color: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        
        .description {
            background-color: #e8f4fd;
            padding: 20px;
            border-left: 5px solid #2196F3;
            margin-bottom: 30px;
            border-radius: 5px;
        }
        
        .test-section {
            margin-bottom: 40px;
            padding: 25px;
            border: 2px solid #ddd;
            border-radius: 10px;
            background-color: #fafafa;
        }
        
        .test-section h3 {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        
        input, select, textarea, button {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }
        
        textarea {
            resize: vertical;
            min-height: 100px;
            font-family: 'Courier New', monospace;
        }
        
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
            font-weight: bold;
            margin-top: 10px;
            transition: background-color 0.3s;
        }
        
        button:hover {
            background-color: #45a049;
        }
        
        .dangerous-btn {
            background-color: #f44336;
        }
        
        .dangerous-btn:hover {
            background-color: #da190b;
        }
        
        .safe-btn {
            background-color: #2196F3;
        }
        
        .safe-btn:hover {
            background-color: #1976D2;
        }
        
        .info-btn {
            background-color: #FF9800;
        }
        
        .info-btn:hover {
            background-color: #F57C00;
        }
        
        .vulnerable-output {
            background-color: #ffebee;
            border: 2px solid #f44336;
            color: #c62828;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .safe-output {
            background-color: #e8f5e8;
            border: 2px solid #4caf50;
            color: #2e7d32;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .info-output {
            background-color: #e3f2fd;
            border: 2px solid #2196f3;
            color: #1565c0;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .error-output {
            background-color: #fff3e0;
            border: 2px solid #ff9800;
            color: #ef6c00;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .alert-danger {
            color: #d32f2f !important;
            font-weight: bold;
        }
        
        .alert-success {
            color: #2e7d32 !important;
            font-weight: bold;
        }
        
        .alert-warning {
            color: #f57c00 !important;
            font-weight: bold;
        }
        
        .two-column {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .three-column {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        
        .stats-grid > div {
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 5px;
            text-align: center;
        }
        
        .endpoint-stat {
            padding: 8px;
            margin: 5px 0;
            background-color: #f8f9fa;
            border-radius: 4px;
            border-left: 4px solid #2196F3;
        }
        
        .security-recommendations h6 {
            margin-top: 15px;
            margin-bottom: 5px;
            color: #333;
        }
        
        .security-recommendations ul {
            margin-bottom: 15px;
        }
        
        .result-stats {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        
        pre {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            font-size: 13px;
        }
        
        code {
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        @media (max-width: 768px) {
            .two-column, .three-column {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔌 API Security Testing</h1>
        
        <div class="description">
            <h3>🎯 API 보안 테스트란?</h3>
            <p><strong>API (Application Programming Interface) 보안 테스트</strong>는 웹 API의 다양한 보안 취약점을 식별하고 테스트하는 과정입니다. REST API, GraphQL, JWT 인증 등 현대 웹 애플리케이션의 핵심 구성요소들에 대한 보안 검증을 수행합니다.</p>
            
            <h4>🔍 주요 테스트 영역:</h4>
            <ul>
                <li><strong>인증 & 인가:</strong> JWT 취약점, 약한 인증 우회</li>
                <li><strong>입력 검증:</strong> SQL Injection, NoSQL Injection</li>
                <li><strong>Rate Limiting:</strong> 요청 제한 우회, DDoS 방지</li>
                <li><strong>GraphQL 보안:</strong> Introspection, 복잡한 쿼리 공격</li>
                <li><strong>API 설계:</strong> 정보 노출, 권한 상승</li>
            </ul>
            
            <p><strong>⚠️ 교육 목적:</strong> 이 테스트들은 실제 API 공격을 시뮬레이션하여 취약점을 이해하고 방어 방법을 학습하기 위한 것입니다.</p>
        </div>

        <div class="two-column">
            <!-- API 인증 테스트 -->
            <div class="test-section">
                <h3>🔐 API 인증 취약점 테스트</h3>
                <p>SQL Injection을 통한 API 인증 우회를 테스트합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="username">사용자명:</label>
                        <input type="text" name="username" id="username" placeholder="admin' OR '1'='1" value="<?php echo htmlspecialchars($_POST['username'] ?? 'admin'); ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="password">패스워드:</label>
                        <input type="text" name="password" id="password" placeholder="' OR '1'='1" value="<?php echo htmlspecialchars($_POST['password'] ?? 'admin123'); ?>">
                    </div>
                    
                    <input type="hidden" name="action" value="weak_auth">
                    <button type="submit" class="dangerous-btn">🔓 취약한 인증 테스트</button>
                </form>
                
                <form method="post" style="margin-top: 10px;">
                    <input type="hidden" name="username" value="admin">
                    <input type="hidden" name="password" value="admin123">
                    <input type="hidden" name="action" value="secure_auth">
                    <button type="submit" class="safe-btn">🔒 안전한 인증 비교</button>
                </form>
            </div>

            <!-- JWT 취약점 테스트 -->
            <div class="test-section">
                <h3>🎫 JWT 토큰 취약점 분석</h3>
                <p>JWT 토큰의 다양한 보안 취약점을 분석합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="jwt_token">JWT 토큰:</label>
                        <textarea name="jwt_token" id="jwt_token" placeholder="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."><?php echo htmlspecialchars($_POST['jwt_token'] ?? ''); ?></textarea>
                    </div>
                    
                    <input type="hidden" name="action" value="jwt_test">
                    <button type="submit" class="dangerous-btn">🔍 JWT 취약점 분석</button>
                </form>
                
                <div style="margin-top: 15px;">
                    <h5>💡 테스트용 JWT 토큰 예제:</h5>
                    <div style="font-size: 12px; background-color: #f8f9fa; padding: 10px; border-radius: 5px;">
                        <strong>약한 키:</strong> eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzMxNTMzMzI1fQ.YfnPRnQpHHtTzqx_8FMKZZCgzIXLFBCCHmm1ot4mBbg
                    </div>
                </div>
            </div>
        </div>

        <div class="two-column">
            <!-- Rate Limiting 테스트 -->
            <div class="test-section">
                <h3>⚡ Rate Limiting 우회 테스트</h3>
                <p>API Rate Limiting을 우회하는 다양한 기법을 테스트합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="endpoint">테스트 엔드포인트:</label>
                        <select name="endpoint" id="endpoint">
                            <option value="/api/users">GET /api/users</option>
                            <option value="/api/login">POST /api/login</option>
                            <option value="/api/search">GET /api/search</option>
                            <option value="/api/upload">POST /api/upload</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="requests_count">요청 횟수:</label>
                        <input type="number" name="requests_count" id="requests_count" value="25" min="1" max="100">
                    </div>
                    
                    <input type="hidden" name="action" value="rate_limit_test">
                    <button type="submit" class="dangerous-btn">⚡ Rate Limiting 우회 시도</button>
                </form>
                
                <div style="margin-top: 15px; font-size: 13px; color: #666;">
                    <strong>참고:</strong> 분당 10회 제한, 헤더 스푸핑으로 우회 시도
                </div>
            </div>

            <!-- GraphQL Injection 테스트 -->
            <div class="test-section">
                <h3>🔍 GraphQL Injection 테스트</h3>
                <p>GraphQL 쿼리를 통한 다양한 공격 패턴을 테스트합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="graphql_query">GraphQL 쿼리:</label>
                        <textarea name="graphql_query" id="graphql_query" placeholder="query { __schema { types { name fields { name type } } } }"><?php echo htmlspecialchars($_POST['graphql_query'] ?? ''); ?></textarea>
                    </div>
                    
                    <input type="hidden" name="action" value="graphql_test">
                    <button type="submit" class="dangerous-btn">🔍 GraphQL 공격 테스트</button>
                </form>
                
                <div style="margin-top: 15px;">
                    <h5>💡 테스트 쿼리 예제:</h5>
                    <button type="button" onclick="fillGraphQLQuery('introspection')" style="width: auto; margin: 5px;">Introspection</button>
                    <button type="button" onclick="fillGraphQLQuery('deep')" style="width: auto; margin: 5px;">Deep Query</button>
                    <button type="button" onclick="fillGraphQLQuery('sensitive')" style="width: auto; margin: 5px;">Sensitive Data</button>
                </div>
            </div>
        </div>

        <!-- 보안 리포트 생성 -->
        <div class="test-section">
            <h3>📊 API 보안 종합 리포트</h3>
            <p>전체 API 보안 테스트 결과를 종합하여 리포트를 생성합니다.</p>
            
            <form method="post">
                <input type="hidden" name="action" value="security_report">
                <button type="submit" class="info-btn">📊 보안 리포트 생성</button>
            </form>
        </div>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="test-section">
                <h3>📋 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- 보안 권장사항 -->
        <div class="test-section">
            <h3>🛡️ API 보안 권장사항</h3>
            <div class="safe-output">
                <h4>🔒 종합 보안 가이드:</h4>
                
                <div class="three-column">
                    <div>
                        <h5>🔐 인증 & 인가</h5>
                        <ul>
                            <li>강력한 JWT 서명 키 사용</li>
                            <li>토큰 만료 시간 적절 설정</li>
                            <li>Refresh Token 별도 관리</li>
                            <li>Multi-factor Authentication</li>
                            <li>API Key 정기 교체</li>
                        </ul>
                    </div>
                    
                    <div>
                        <h5>🛡️ 입력 검증</h5>
                        <ul>
                            <li>모든 입력 데이터 검증</li>
                            <li>SQL/NoSQL Injection 방지</li>
                            <li>JSON 스키마 검증</li>
                            <li>파라미터 타입 검사</li>
                            <li>입력 길이 제한</li>
                        </ul>
                    </div>
                    
                    <div>
                        <h5>📊 모니터링</h5>
                        <ul>
                            <li>실시간 로그 분석</li>
                            <li>이상 패턴 탐지</li>
                            <li>Rate Limiting 모니터링</li>
                            <li>보안 이벤트 알림</li>
                            <li>성능 메트릭 수집</li>
                        </ul>
                    </div>
                </div>
                
                <h5>🚀 GraphQL 특화 보안:</h5>
                <ul>
                    <li><strong>Introspection 비활성화:</strong> 프로덕션 환경에서 스키마 노출 방지</li>
                    <li><strong>쿼리 깊이 제한:</strong> 최대 중첩 깊이 설정 (권장: 7-10단계)</li>
                    <li><strong>쿼리 복잡도 분석:</strong> 리소스 사용량 기반 제한</li>
                    <li><strong>필드 레벨 권한:</strong> 민감한 필드 접근 제어</li>
                    <li><strong>Query Whitelist:</strong> 허용된 쿼리만 실행</li>
                </ul>
                
                <h5>⚡ Rate Limiting 강화:</h5>
                <ul>
                    <li><strong>다층 제한:</strong> IP, 사용자, API Key 기반</li>
                    <li><strong>적응형 제한:</strong> 사용자 행동에 따른 동적 조절</li>
                    <li><strong>분산 환경 고려:</strong> Redis 등 중앙화된 카운터</li>
                    <li><strong>헤더 검증:</strong> X-Forwarded-For 등 신뢰할 수 있는 헤더만 사용</li>
                    <li><strong>Graceful Degradation:</strong> 제한 초과 시 부분 서비스 제공</li>
                </ul>
                
                <p class='alert-success'><strong>💡 핵심 원칙:</strong> 최소 권한, 심층 방어, 지속적 모니터링을 통해 API 보안을 강화하세요.</p>
            </div>
        </div>
    </div>

    <script>
        // GraphQL 쿼리 예제 채우기
        function fillGraphQLQuery(type) {
            const textarea = document.getElementById('graphql_query');
            let query = '';
            
            switch(type) {
                case 'introspection':
                    query = `query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}`;
                    break;
                case 'deep':
                    query = `query DeepQuery {
  user {
    profile {
      settings {
        preferences {
          notifications {
            email {
              marketing {
                enabled
              }
            }
          }
        }
      }
    }
  }
}`;
                    break;
                case 'sensitive':
                    query = `query SensitiveData {
  user(id: 1) {
    username
    email
    password
    api_key
    role
  }
}`;
                    break;
            }
            
            textarea.value = query;
        }
        
        // JWT 토큰 예제 채우기
        function fillJWTExample(type) {
            const textarea = document.getElementById('jwt_token');
            let token = '';
            
            switch(type) {
                case 'weak':
                    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzMxNTMzMzI1fQ.YfnPRnQpHHtTzqx_8FMKZZCgzIXLFBCCHmm1ot4mBbg';
                    break;
                case 'none':
                    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.';
                    break;
            }
            
            textarea.value = token;
        }
        
        // 폼 제출 확인
        document.querySelectorAll('.dangerous-btn').forEach(button => {
            button.addEventListener('click', function(e) {
                const action = this.closest('form').querySelector('input[name="action"]').value;
                if (action.includes('rate_limit') && document.getElementById('requests_count').value > 50) {
                    if (!confirm('⚠️ 많은 수의 요청을 보내려고 합니다. 계속하시겠습니까?')) {
                        e.preventDefault();
                    }
                }
            });
        });
    </script>
</body>
</html>