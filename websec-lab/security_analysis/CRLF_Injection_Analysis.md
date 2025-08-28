# CRLF Injection 취약점 분석

## 📋 취약점 개요

**CRLF Injection**은 웹 애플리케이션이 사용자 입력을 HTTP 헤더에 삽입할 때 Carriage Return(`\r`) 및 Line Feed(`\n`) 문자를 적절히 필터링하지 않아 발생하는 취약점입니다. 공격자는 이를 통해 HTTP 응답을 분할하고 추가 헤더를 삽입하거나 응답 본문을 조작할 수 있습니다.

### 🎯 공격 원리

1. **헤더 삽입**: CRLF 문자로 기존 헤더 라인을 종료
2. **새 헤더 추가**: 악의적인 새 HTTP 헤더 삽입
3. **응답 분할**: HTTP 응답을 완전히 분할하여 새로운 응답 생성
4. **클라이언트 조작**: 브라우저의 동작 조작 및 보안 우회

### 🔍 주요 위험성

- **CVSS 점수**: 6.5 (Medium)
- **HTTP 응답 분할**: 완전히 새로운 HTTP 응답 생성
- **세션 하이재킹**: 쿠키 및 세션 정보 조작
- **캐시 독성**: 웹 캐시 서버에 악성 콘텐츠 저장

## 🚨 공격 시나리오

### 시나리오 1: 기본 CRLF Injection

```php
<?php
// 취약한 리다이렉션 코드
$redirect_url = $_GET['url'];
header("Location: " . $redirect_url);
?>
```

```http
# 공격 요청
GET /redirect.php?url=http://example.com%0D%0ASet-Cookie:%20admin=true HTTP/1.1
Host: victim.com

# 결과적인 응답 헤더
HTTP/1.1 302 Found
Location: http://example.com
Set-Cookie: admin=true
```

### 시나리오 2: HTTP Response Splitting

```php
<?php
// 취약한 쿠키 설정
$username = $_GET['user'];
setcookie('last_user', $username);
echo "Welcome back!";
?>
```

```http
# 공격 페이로드
GET /welcome.php?user=admin%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert('XSS')</script> HTTP/1.1

# 분할된 응답 결과
HTTP/1.1 200 OK
Set-Cookie: last_user=admin
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html

<script>alert('XSS')</script>
```

### 시나리오 3: 웹 캐시 독성

```http
# 캐시 독성 공격 페이로드
GET /page.php?param=value%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0AContent-Length:%2023%0D%0A%0D%0A<h1>Hacked%20Page</h1> HTTP/1.1
Host: victim.com

# 캐시 서버에 저장될 악성 응답
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 23

<h1>Hacked Page</h1>
```

### 시나리오 4: 세션 및 보안 헤더 우회

```php
<?php
// 취약한 보안 헤더 설정
$theme = $_GET['theme'];
header("X-Theme: " . $theme);
header("X-Frame-Options: DENY");
?>
```

```http
# 보안 헤더 우회 공격
GET /settheme.php?theme=dark%0D%0AX-Frame-Options:%20ALLOWALL%0D%0ASet-Cookie:%20admin=true HTTP/1.1

# 결과 헤더 (보안 헤더가 덮어씌워짐)
HTTP/1.1 200 OK
X-Theme: dark
X-Frame-Options: ALLOWALL
Set-Cookie: admin=true
X-Frame-Options: DENY
```

## 🛡️ 방어 방법

### 1. 기본적인 CRLF 필터링

```php
<?php
class CRLFSanitizer {
    public static function sanitizeHeader($value) {
        // CRLF 문자 제거
        $value = str_replace(["\r", "\n", "\r\n"], '', $value);
        
        // NULL 바이트 제거
        $value = str_replace("\0", '', $value);
        
        // 연속된 공백 정규화
        $value = preg_replace('/\s+/', ' ', $value);
        
        // 앞뒤 공백 제거
        $value = trim($value);
        
        return $value;
    }
    
    public static function safeRedirect($url) {
        $sanitized_url = self::sanitizeHeader($url);
        
        // URL 유효성 검증
        if (!filter_var($sanitized_url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('Invalid URL provided');
        }
        
        // 허용된 도메인 확인
        $allowed_domains = ['example.com', 'trusted.com'];
        $parsed_url = parse_url($sanitized_url);
        
        if (!in_array($parsed_url['host'], $allowed_domains)) {
            throw new SecurityException('Unauthorized redirect domain');
        }
        
        header('Location: ' . $sanitized_url);
        exit;
    }
    
    public static function setCookie($name, $value, $options = []) {
        $safe_name = self::sanitizeHeader($name);
        $safe_value = self::sanitizeHeader($value);
        
        // 기본 보안 옵션
        $default_options = [
            'httponly' => true,
            'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'samesite' => 'Strict'
        ];
        
        $options = array_merge($default_options, $options);
        
        setcookie($safe_name, $safe_value, $options);
    }
}

// 사용 예제
try {
    CRLFSanitizer::safeRedirect($_GET['url'] ?? '/');
} catch (Exception $e) {
    error_log('CRLF Attack attempted: ' . $e->getMessage());
    header('Location: /error.php');
    exit;
}
?>
```

### 2. 고급 HTTP 헤더 보안

```php
<?php
class SecureHeaderManager {
    private $allowed_headers;
    private $security_headers;
    
    public function __construct() {
        $this->allowed_headers = [
            'Content-Type', 'Cache-Control', 'Expires', 
            'Last-Modified', 'ETag', 'Location'
        ];
        
        $this->security_headers = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-XSS-Protection' => '1; mode=block',
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy' => "default-src 'self'",
            'Referrer-Policy' => 'strict-origin-when-cross-origin'
        ];
    }
    
    public function setSecureHeader($name, $value) {
        // 헤더명 검증
        if (!$this->isAllowedHeader($name)) {
            throw new SecurityException('Header not allowed: ' . $name);
        }
        
        // 헤더값 정화
        $safe_value = $this->sanitizeHeaderValue($value);
        
        // CRLF 인젝션 탐지
        if ($this->detectCRLFInjection($name . ': ' . $safe_value)) {
            $this->logSecurityEvent('CRLF injection attempt', [
                'header' => $name,
                'value' => $value,
                'sanitized' => $safe_value
            ]);
            throw new SecurityException('CRLF injection detected');
        }
        
        header($name . ': ' . $safe_value);
    }
    
    public function setSecurityHeaders() {
        foreach ($this->security_headers as $name => $value) {
            if (!headers_sent()) {
                header($name . ': ' . $value);
            }
        }
    }
    
    public function safeRedirect($url, $status_code = 302) {
        $sanitized_url = $this->validateAndSanitizeURL($url);
        
        if (!headers_sent()) {
            http_response_code($status_code);
            $this->setSecureHeader('Location', $sanitized_url);
        }
        
        exit;
    }
    
    private function isAllowedHeader($name) {
        return in_array($name, $this->allowed_headers, true);
    }
    
    private function sanitizeHeaderValue($value) {
        // CRLF 문자 완전 제거
        $value = preg_replace('/[\r\n\x0b\x0c]/', '', $value);
        
        // NULL 바이트 제거
        $value = str_replace("\0", '', $value);
        
        // 제어 문자 제거 (탭 제외)
        $value = preg_replace('/[\x00-\x08\x0e-\x1f\x7f]/', '', $value);
        
        // 연속된 공백 정규화
        $value = preg_replace('/\s+/', ' ', trim($value));
        
        return $value;
    }
    
    private function detectCRLFInjection($header_line) {
        $dangerous_patterns = [
            '/\r\n|\r|\n/',           // CRLF 문자
            '/\x0d\x0a|\x0d|\x0a/',   // 헥스 표현
            '/%0d%0a|%0d|%0a/i',      // URL 인코딩
            '/\\\r\\\n|\\\r|\\\n/',   // 이스케이프된 문자
            '/&#13;&#10;|&#13;|&#10;/', // HTML 엔티티
        ];
        
        foreach ($dangerous_patterns as $pattern) {
            if (preg_match($pattern, $header_line)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function validateAndSanitizeURL($url) {
        $sanitized_url = $this->sanitizeHeaderValue($url);
        
        // 기본 URL 형식 검증
        if (!filter_var($sanitized_url, FILTER_VALIDATE_URL)) {
            // 상대 URL 처리
            if (strpos($sanitized_url, '/') === 0) {
                $sanitized_url = $this->validateRelativeURL($sanitized_url);
            } else {
                throw new InvalidArgumentException('Invalid URL format');
            }
        } else {
            // 절대 URL 도메인 검증
            $sanitized_url = $this->validateAbsoluteURL($sanitized_url);
        }
        
        return $sanitized_url;
    }
    
    private function validateRelativeURL($url) {
        // 상위 디렉토리 탐색 방지
        if (strpos($url, '../') !== false || strpos($url, '..\\') !== false) {
            throw new SecurityException('Directory traversal attempt in URL');
        }
        
        // 스크립트 실행 방지
        if (preg_match('/javascript:|data:|vbscript:/i', $url)) {
            throw new SecurityException('Script execution attempt in URL');
        }
        
        return $url;
    }
    
    private function validateAbsoluteURL($url) {
        $parsed = parse_url($url);
        
        if (!$parsed || !isset($parsed['host'])) {
            throw new InvalidArgumentException('Invalid URL structure');
        }
        
        // 허용된 도메인 확인
        $allowed_domains = $this->getAllowedDomains();
        
        if (!in_array($parsed['host'], $allowed_domains)) {
            throw new SecurityException('Unauthorized redirect domain: ' . $parsed['host']);
        }
        
        // HTTPS 강제 (보안 도메인의 경우)
        if (in_array($parsed['host'], $this->getSecureDomains()) && 
            $parsed['scheme'] !== 'https') {
            throw new SecurityException('HTTPS required for secure domain');
        }
        
        return $url;
    }
    
    private function getAllowedDomains() {
        return [
            $_SERVER['HTTP_HOST'] ?? 'localhost',
            'trusted-partner.com',
            'api.example.com'
        ];
    }
    
    private function getSecureDomains() {
        return [
            'payment.example.com',
            'secure.example.com'
        ];
    }
    
    private function logSecurityEvent($event, $data) {
        $log_entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'data' => $data,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        error_log('SECURITY_EVENT: ' . json_encode($log_entry));
    }
}

// 사용 예제
$headerManager = new SecureHeaderManager();

// 보안 헤더 설정
$headerManager->setSecurityHeaders();

// 안전한 리다이렉션
try {
    $headerManager->safeRedirect($_GET['redirect'] ?? '/dashboard');
} catch (Exception $e) {
    $headerManager->logSecurityEvent('Redirect blocked', [
        'reason' => $e->getMessage(),
        'attempted_url' => $_GET['redirect'] ?? ''
    ]);
    
    $headerManager->safeRedirect('/error?code=invalid_redirect');
}
?>
```

### 3. CRLF 주입 탐지 시스템

```php
<?php
class CRLFDetectionSystem {
    private $detection_patterns;
    private $log_file;
    
    public function __construct($log_file = '/var/log/crlf_attacks.log') {
        $this->log_file = $log_file;
        $this->detection_patterns = [
            'basic_crlf' => '/\r\n|\r|\n/',
            'encoded_crlf' => '/%0d%0a|%0a|%0d/i',
            'unicode_crlf' => '/\u000d\u000a|\u000d|\u000a/i',
            'hex_crlf' => '/\x0d\x0a|\x0d|\x0a/',
            'escaped_crlf' => '/\\\\r\\\\n|\\\\r|\\\\n/',
            'html_entity_crlf' => '/&#13;&#10;|&#13;|&#10;/',
            'response_splitting' => '/HTTP\/1\.[01]\s+\d{3}/i'
        ];
    }
    
    public function scanRequest() {
        $suspicious_inputs = [];
        
        // GET 파라미터 검사
        foreach ($_GET as $key => $value) {
            if ($this->containsCRLFInjection($value)) {
                $suspicious_inputs[] = [
                    'type' => 'GET',
                    'parameter' => $key,
                    'value' => $value,
                    'pattern_matched' => $this->getMatchedPattern($value)
                ];
            }
        }
        
        // POST 파라미터 검사
        foreach ($_POST as $key => $value) {
            if ($this->containsCRLFInjection($value)) {
                $suspicious_inputs[] = [
                    'type' => 'POST',
                    'parameter' => $key,
                    'value' => $value,
                    'pattern_matched' => $this->getMatchedPattern($value)
                ];
            }
        }
        
        // 헤더 검사
        foreach (getallheaders() as $name => $value) {
            if ($this->containsCRLFInjection($value)) {
                $suspicious_inputs[] = [
                    'type' => 'HEADER',
                    'parameter' => $name,
                    'value' => $value,
                    'pattern_matched' => $this->getMatchedPattern($value)
                ];
            }
        }
        
        if (!empty($suspicious_inputs)) {
            $this->logAttackAttempt($suspicious_inputs);
            $this->triggerSecurityResponse($suspicious_inputs);
        }
        
        return $suspicious_inputs;
    }
    
    public function containsCRLFInjection($input) {
        foreach ($this->detection_patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }
    
    public function getMatchedPattern($input) {
        foreach ($this->detection_patterns as $name => $pattern) {
            if (preg_match($pattern, $input)) {
                return $name;
            }
        }
        return 'none';
    }
    
    public function analyzeRequestHeaders() {
        $analysis = [
            'total_headers' => 0,
            'suspicious_headers' => [],
            'risk_level' => 'LOW'
        ];
        
        $headers = getallheaders();
        $analysis['total_headers'] = count($headers);
        
        foreach ($headers as $name => $value) {
            if ($this->containsCRLFInjection($value)) {
                $analysis['suspicious_headers'][] = [
                    'name' => $name,
                    'value' => $value,
                    'risk_factors' => $this->assessRiskFactors($value)
                ];
            }
        }
        
        // 위험도 평가
        if (count($analysis['suspicious_headers']) > 0) {
            $analysis['risk_level'] = 'HIGH';
            
            // Response Splitting 시도 탐지
            foreach ($analysis['suspicious_headers'] as $header) {
                if (in_array('response_splitting', $header['risk_factors'])) {
                    $analysis['risk_level'] = 'CRITICAL';
                    break;
                }
            }
        }
        
        return $analysis;
    }
    
    private function assessRiskFactors($value) {
        $risk_factors = [];
        
        if (preg_match('/HTTP\/1\.[01]/i', $value)) {
            $risk_factors[] = 'response_splitting';
        }
        
        if (preg_match('/Set-Cookie:/i', $value)) {
            $risk_factors[] = 'cookie_injection';
        }
        
        if (preg_match('/Location:/i', $value)) {
            $risk_factors[] = 'redirect_manipulation';
        }
        
        if (preg_match('/Content-Type:|Content-Length:/i', $value)) {
            $risk_factors[] = 'content_manipulation';
        }
        
        return $risk_factors;
    }
    
    private function logAttackAttempt($suspicious_inputs) {
        $log_entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
            'suspicious_inputs' => $suspicious_inputs
        ];
        
        file_put_contents($this->log_file, 
                         json_encode($log_entry) . "\n", 
                         FILE_APPEND | LOCK_EX);
    }
    
    private function triggerSecurityResponse($suspicious_inputs) {
        // 높은 위험도 공격에 대한 즉시 차단
        $high_risk_patterns = ['response_splitting', 'cookie_injection'];
        
        foreach ($suspicious_inputs as $input) {
            if (in_array($input['pattern_matched'], $high_risk_patterns)) {
                $this->blockRequest('High risk CRLF injection detected');
                break;
            }
        }
        
        // 알림 전송 (슬랙, 이메일 등)
        $this->sendSecurityAlert($suspicious_inputs);
    }
    
    private function blockRequest($reason) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'Request blocked for security reasons',
            'reason' => $reason,
            'timestamp' => time()
        ]);
        exit;
    }
    
    private function sendSecurityAlert($suspicious_inputs) {
        // 실제 구현에서는 이메일이나 슬랙 알림 등을 보냄
        error_log('CRLF_INJECTION_ALERT: ' . json_encode($suspicious_inputs));
    }
}

// 미들웨어로 사용
$crlfDetector = new CRLFDetectionSystem();
$suspicious_activity = $crlfDetector->scanRequest();

if (!empty($suspicious_activity)) {
    // 공격 시도가 탐지됨 - 추가 보안 조치
    $analysis = $crlfDetector->analyzeRequestHeaders();
    
    if ($analysis['risk_level'] === 'CRITICAL') {
        header('HTTP/1.1 403 Forbidden');
        exit('Security violation detected');
    }
}
?>
```

## 🧪 테스트 방법

### 1. 기본 CRLF Injection 테스트

```python
import requests
import urllib.parse

def test_crlf_injection():
    base_url = "http://target.com"
    
    # 테스트 페이로드들
    payloads = [
        # 기본 CRLF
        "%0D%0ASet-Cookie:%20admin=true",
        
        # Response Splitting
        "%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<h1>Injected</h1>",
        
        # 다양한 인코딩
        "%0d%0a",  # 소문자
        "%0D%0a",  # 혼합
        "%0d%0A",  # 혼합
        "\r\n",    # 직접
        "\u000d\u000a",  # 유니코드
        
        # 헤더 주입
        "%0D%0AX-Injected-Header:%20true",
        "%0D%0ALocation:%20http://evil.com"
    ]
    
    endpoints = [
        "/redirect.php?url=http://example.com",
        "/setcookie.php?value=test",
        "/header.php?custom="
    ]
    
    for endpoint in endpoints:
        for payload in payloads:
            test_url = base_url + endpoint + payload
            
            try:
                response = requests.get(test_url, allow_redirects=False)
                
                # 응답 헤더에서 주입된 내용 확인
                if any('injected' in str(v).lower() for v in response.headers.values()):
                    print(f"VULNERABLE: {endpoint} with payload: {payload}")
                    print(f"Injected headers: {response.headers}")
                
                # Set-Cookie 헤더 확인
                if 'admin=true' in response.headers.get('Set-Cookie', ''):
                    print(f"COOKIE INJECTION: {endpoint}")
                
            except Exception as e:
                print(f"Error testing {endpoint}: {e}")

test_crlf_injection()
```

### 2. 자동화된 CRLF 스캐너

```python
import requests
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

class CRLFScanner:
    def __init__(self):
        self.payloads = [
            "%0D%0ASet-Cookie:%20admin=true",
            "%0D%0AContent-Type:%20text/html",
            "%0D%0ALocation:%20http://evil.com",
            "%0D%0AX-XSS-Protection:%20disabled",
            "\r\nSet-Cookie: session=hijacked",
            "%0d%0aCache-Control: no-cache",
            "%0A%0DLocation: javascript:alert(1)"
        ]
        
        self.detection_patterns = [
            r'Set-Cookie:\s*admin=true',
            r'Location:\s*http://evil\.com',
            r'X-.*?:\s*.*',
            r'Content-Type:\s*text/html'
        ]
    
    def scan_endpoint(self, base_url, endpoint, params):
        results = []
        
        for param in params:
            for payload in self.payloads:
                test_url = f"{base_url}{endpoint}?{param}={payload}"
                
                try:
                    response = requests.get(test_url, 
                                         allow_redirects=False, 
                                         timeout=10)
                    
                    vulnerability = self.analyze_response(response, payload)
                    if vulnerability:
                        results.append({
                            'url': test_url,
                            'payload': payload,
                            'vulnerability': vulnerability,
                            'headers': dict(response.headers)
                        })
                        
                except Exception as e:
                    continue
        
        return results
    
    def analyze_response(self, response, payload):
        # 헤더에서 페이로드 확인
        for header_name, header_value in response.headers.items():
            if any(pattern in payload for pattern in ['Set-Cookie', 'Location', 'Content-Type']):
                for pattern in self.detection_patterns:
                    if re.search(pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        return {
                            'type': 'header_injection',
                            'injected_header': f"{header_name}: {header_value}",
                            'severity': 'HIGH'
                        }
        
        # Response Splitting 확인
        if 'HTTP/1.1' in str(response.headers) or 'HTTP/1.0' in str(response.headers):
            return {
                'type': 'response_splitting',
                'severity': 'CRITICAL'
            }
        
        # 상태 코드 조작 확인
        if response.status_code != 200 and 'Location' in response.headers:
            parsed_location = urllib.parse.urlparse(response.headers['Location'])
            if parsed_location.netloc == 'evil.com':
                return {
                    'type': 'malicious_redirect',
                    'severity': 'HIGH'
                }
        
        return None
    
    def generate_report(self, results):
        if not results:
            return "No CRLF injection vulnerabilities found."
        
        report = "CRLF Injection Vulnerability Report\n"
        report += "=" * 40 + "\n\n"
        
        for i, result in enumerate(results, 1):
            report += f"{i}. Vulnerability Found\n"
            report += f"   URL: {result['url']}\n"
            report += f"   Payload: {result['payload']}\n"
            report += f"   Type: {result['vulnerability']['type']}\n"
            report += f"   Severity: {result['vulnerability']['severity']}\n"
            
            if 'injected_header' in result['vulnerability']:
                report += f"   Injected: {result['vulnerability']['injected_header']}\n"
            
            report += "\n"
        
        return report

# 사용 예제
scanner = CRLFScanner()

# 테스트할 엔드포인트들
test_cases = [
    ("http://target.com", "/redirect.php", ["url"]),
    ("http://target.com", "/setcookie.php", ["name", "value"]),
    ("http://target.com", "/header.php", ["custom", "theme"])
]

all_results = []

for base_url, endpoint, params in test_cases:
    results = scanner.scan_endpoint(base_url, endpoint, params)
    all_results.extend(results)

# 보고서 생성
report = scanner.generate_report(all_results)
print(report)
```

## 📚 참고 자료

### 공식 문서
- [OWASP CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)

### 보안 가이드
- [PortSwigger CRLF Injection](https://portswigger.net/web-security/request-smuggling)
- [NIST HTTP Security Guidelines](https://csrc.nist.gov/publications)

### 도구 및 리소스
- [Burp Suite CRLF Tests](https://portswigger.net/burp)
- [OWASP ZAP CRLF Scanner](https://owasp.org/www-project-zap/)

---

## 🎯 핵심 요약

1. **입력 정화**: 모든 사용자 입력에서 CRLF 문자 완전 제거
2. **헤더 검증**: HTTP 헤더 설정 전 엄격한 유효성 검사
3. **허용 목록**: 안전한 헤더와 값만 허용하는 화이트리스트 방식
4. **모니터링**: CRLF 주입 시도에 대한 실시간 탐지 및 차단

**⚠️ 주의**: CRLF Injection은 HTTP 프로토콜의 특성을 악용하므로 모든 HTTP 헤더 조작 지점에서 방어해야 합니다.