# Web Cache Deception 취약점 상세 분석

## 📋 개요

**Web Cache Deception**은 공격자가 웹 캐시 시스템(CDN, 리버스 프록시 등)을 속여 민감한 동적 콘텐츠를 정적 파일로 오인하여 캐싱하도록 유도하는 취약점입니다. 이를 통해 개인정보, 인증 정보 등 민감한 데이터가 공개적으로 접근 가능한 캐시에 저장되어 무단으로 탈취될 수 있습니다.

## 🎯 취약점 정보

- **CVSS 3.1 점수**: 7.5 (High)
- **공격 복잡성**: Low
- **필요 권한**: None
- **사용자 상호작용**: Required
- **영향 범위**: Confidentiality, Integrity

## 🔍 취약점 원리

### 핵심 개념

Web Cache Deception은 다음과 같은 상황에서 발생합니다:

1. **경로 정규화 불일치**: 웹 서버와 캐시 시스템 간의 URL 해석 차이
2. **파일 확장자 기반 캐싱**: 캐시 시스템이 파일 확장자만으로 캐싱 여부 결정
3. **인증 상태 미고려**: 캐시 시스템이 인증된 사용자의 요청도 캐싱
4. **적절한 헤더 부재**: 민감한 콘텐츠에 대한 캐싱 방지 헤더 미설정

### 공격 메커니즘

```
사용자 요청: /profile/sensitive.php/fake.css
             ↓
캐시 시스템: ".css 파일이니까 캐싱하자!"
             ↓
웹 서버: "/profile/sensitive.php"의 내용 반환 (민감한 정보 포함)
         ↓
캐시에 저장: 누구나 접근 가능한 공개 캐시에 민감한 정보 저장
            ↓
공격자: 나중에 같은 URL로 접근하여 캐시된 민감한 정보 탈취
```

## 🚨 공격 시나리오

### 1. 개인 프로필 정보 탈취

**공격 과정**:
```bash
# 1. 공격자가 피해자에게 악의적인 링크 전송
https://victim-site.com/profile/user.php/nonexistent.css

# 2. 피해자가 로그인 상태로 링크 클릭
# 웹 서버: /profile/user.php의 민감한 내용 반환
# CDN: ".css 파일"이라고 판단하여 캐싱

# 3. 공격자가 나중에 같은 URL 접근
curl https://victim-site.com/profile/user.php/nonexistent.css
# 결과: 캐시에서 피해자의 개인정보 획득
```

### 2. API 키 및 토큰 탈취

**취약한 API 엔드포인트**:
```php
// /api/user/settings.php
if (!isLoggedIn()) {
    http_response_code(401);
    exit('Unauthorized');
}

echo json_encode([
    'user_id' => $_SESSION['user_id'],
    'api_key' => $_SESSION['api_key'],  // 민감한 정보!
    'settings' => getUserSettings($_SESSION['user_id'])
]);
```

**공격 벡터**:
```bash
# 피해자가 접근하는 URL
https://api.example.com/user/settings.php/fake.js

# 캐시 시스템: JavaScript 파일로 인식하여 캐싱
# 공격자: 나중에 접근하여 API 키 획득
```

### 3. 관리자 패널 정보 노출

**공격 시나리오**:
```html
<!-- 공격자가 관리자에게 보낸 피싱 이메일 -->
<a href="https://admin.company.com/dashboard/admin.php/logo.png">
    회사 로고 확인이 필요합니다
</a>
```

```bash
# 관리자가 링크 클릭 시
# 웹 서버: 관리자 대시보드 내용 반환
# CDN: PNG 파일로 오인하여 캐싱

# 공격자가 나중에 접근
curl https://admin.company.com/dashboard/admin.php/logo.png
# 결과: 관리자 대시보드 정보 획득
```

### 4. 결제 정보 탈취

```php
// /payment/history.php - 결제 내역 페이지
session_start();
if (!isLoggedIn()) {
    header('Location: /login.php');
    exit;
}

$payments = getPaymentHistory($_SESSION['user_id']);
?>
<div class="payment-history">
    <?php foreach ($payments as $payment): ?>
        <div>결제금액: <?= $payment['amount'] ?></div>
        <div>카드번호: **** **** **** <?= $payment['last4'] ?></div>
    <?php endforeach; ?>
</div>
```

**공격 벡터**:
```bash
# 소셜 엔지니어링을 통한 링크 유도
https://shop.example.com/payment/history.php/receipt.pdf

# 캐시 시스템이 PDF로 인식하여 캐싱
# 공격자가 결제 정보 탈취
```

## 🛡️ 방어 방법

### 1. 적절한 캐시 제어 헤더 설정

```php
<?php
// 민감한 페이지에 대한 캐싱 방지
function setNoCacheHeaders() {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Cache-Control: post-check=0, pre-check=0', false);
    header('Pragma: no-cache');
    header('Expires: Mon, 01 Jan 1990 00:00:00 GMT');
}

// 사용자별 콘텐츠 캐싱 방지
function setPrivateCache() {
    header('Cache-Control: private, no-cache, no-store, must-revalidate');
    header('Vary: Authorization, Cookie');
}

// 인증된 페이지에서 사용
if (isLoggedIn()) {
    setNoCacheHeaders();
    // 또는
    setPrivateCache();
}
?>
```

### 2. URL 정규화 및 라우팅 강화

```php
<?php
class SecureRouter {
    private $routes = [];
    
    public function addRoute($pattern, $handler) {
        $this->routes[$pattern] = $handler;
    }
    
    public function route($uri) {
        // URL 정규화
        $normalizedUri = $this->normalizeUri($uri);
        
        // 정확한 라우트 매칭만 허용
        foreach ($this->routes as $pattern => $handler) {
            if ($normalizedUri === $pattern) {
                return $handler;
            }
        }
        
        // 매칭되지 않으면 404
        http_response_code(404);
        exit('Not Found');
    }
    
    private function normalizeUri($uri) {
        // 쿼리 스트링 제거
        $uri = strtok($uri, '?');
        
        // 불필요한 경로 세그먼트 제거
        $parts = explode('/', trim($uri, '/'));
        $cleanParts = [];
        
        foreach ($parts as $part) {
            if ($part !== '' && $part !== '.' && $part !== '..') {
                $cleanParts[] = $part;
            }
        }
        
        return '/' . implode('/', $cleanParts);
    }
}

// 사용 예
$router = new SecureRouter();
$router->addRoute('/profile/user.php', 'handleUserProfile');
$router->addRoute('/api/user/settings.php', 'handleUserSettings');

$currentUri = $_SERVER['REQUEST_URI'];
$handler = $router->route($currentUri);
?>
```

### 3. 미들웨어를 통한 보호

```php
<?php
class CacheDeceptionProtectionMiddleware {
    private $sensitivePatterns = [
        '/profile/',
        '/admin/',
        '/api/',
        '/dashboard/',
        '/settings/'
    ];
    
    private $staticExtensions = [
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', 
        '.ico', '.svg', '.woff', '.woff2', '.ttf'
    ];
    
    public function process($request, $next) {
        $uri = $request->getUri();
        
        // 민감한 경로인지 확인
        if ($this->isSensitivePath($uri)) {
            // 정적 파일 확장자가 붙어있는지 확인
            if ($this->hasStaticExtension($uri)) {
                // Web Cache Deception 공격 시도로 판단
                $this->logSuspiciousActivity($uri);
                
                // 캐싱 방지 헤더 강제 설정
                header('Cache-Control: no-store, no-cache, must-revalidate');
                header('X-Cache-Deception-Protection: active');
                
                // 또는 요청 차단
                if ($this->shouldBlock($uri)) {
                    http_response_code(403);
                    exit('Suspicious request detected');
                }
            }
        }
        
        return $next($request);
    }
    
    private function isSensitivePath($uri) {
        foreach ($this->sensitivePatterns as $pattern) {
            if (strpos($uri, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }
    
    private function hasStaticExtension($uri) {
        foreach ($this->staticExtensions as $ext) {
            if (strpos($uri, $ext) !== false) {
                return true;
            }
        }
        return false;
    }
    
    private function logSuspiciousActivity($uri) {
        error_log("Potential Web Cache Deception: $uri from " . $_SERVER['REMOTE_ADDR']);
    }
    
    private function shouldBlock($uri) {
        // 정책에 따라 차단 여부 결정
        return true; // 보수적 접근
    }
}
?>
```

### 4. CDN/프록시 설정 강화

#### Nginx 설정
```nginx
# nginx.conf
location ~* ^(/profile/|/admin/|/api/) {
    # 동적 콘텐츠는 캐싱하지 않음
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    add_header Pragma "no-cache";
    
    # 의심스러운 요청 차단
    location ~* ^(/profile/|/admin/|/api/).*\.(css|js|png|jpg|gif|ico)$ {
        return 403;
    }
    
    proxy_pass http://backend;
}

# 정적 파일만 캐싱
location ~* \.(css|js|png|jpg|gif|ico|svg|woff|woff2|ttf)$ {
    # 실제 파일이 존재하는 경우만
    try_files $uri =404;
    
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

#### Apache .htaccess 설정
```apache
# .htaccess
<IfModule mod_rewrite.c>
    RewriteEngine On
    
    # 민감한 경로에 정적 파일 확장자가 있는 요청 차단
    RewriteRule ^(profile/|admin/|api/).*\.(css|js|png|jpg|gif|ico)$ - [F,L]
</IfModule>

<IfModule mod_headers.c>
    # 동적 콘텐츠 캐싱 방지
    <LocationMatch "^/(profile|admin|api)/">
        Header always set Cache-Control "no-store, no-cache, must-revalidate"
        Header always set Pragma "no-cache"
        Header always set X-Cache-Deception-Protection "active"
    </LocationMatch>
</IfModule>
```

### 5. Content-Type 기반 캐싱

```php
<?php
class ContentTypeBasedCaching {
    public static function setCacheHeaders($contentType) {
        switch ($contentType) {
            case 'text/html':
                if (isLoggedIn()) {
                    // 인증된 사용자의 HTML은 캐싱하지 않음
                    header('Cache-Control: no-store, no-cache, must-revalidate');
                } else {
                    // 공개 HTML은 짧게 캐싱
                    header('Cache-Control: public, max-age=300'); // 5분
                }
                break;
                
            case 'application/json':
                // API 응답은 기본적으로 캐싱하지 않음
                header('Cache-Control: no-store, no-cache, must-revalidate');
                header('Vary: Authorization');
                break;
                
            case 'text/css':
            case 'application/javascript':
            case 'image/png':
            case 'image/jpeg':
                // 정적 파일은 길게 캐싱
                header('Cache-Control: public, max-age=31536000'); // 1년
                header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 31536000) . ' GMT');
                break;
                
            default:
                // 기본적으로 캐싱하지 않음
                header('Cache-Control: no-store, no-cache, must-revalidate');
        }
    }
}

// 사용 예
ContentTypeBasedCaching::setCacheHeaders('text/html');
?>
```

## 🔍 취약점 탐지 방법

### 1. 자동화된 스캐닝 도구

```python
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import time

class WebCacheDeceptionScanner:
    def __init__(self, base_url, session_cookies=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if session_cookies:
            self.session.cookies.update(session_cookies)
        
        self.static_extensions = [
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
            '.ico', '.svg', '.pdf', '.txt', '.xml'
        ]
        
        self.sensitive_paths = [
            '/profile/', '/user/', '/account/', '/settings/',
            '/admin/', '/dashboard/', '/api/', '/private/'
        ]
    
    def generate_test_urls(self, path):
        """테스트할 URL 변형들 생성"""
        test_urls = []
        
        for ext in self.static_extensions:
            # 경로 끝에 가짜 파일 추가
            test_urls.append(f"{path}/nonexistent{ext}")
            test_urls.append(f"{path}/fake{ext}")
            
            # 경로 중간에 가짜 파일 추가
            parts = path.strip('/').split('/')
            if len(parts) > 1:
                fake_path = '/'.join(parts[:-1]) + f'/fake{ext}/' + parts[-1]
                test_urls.append('/' + fake_path)
        
        return test_urls
    
    def test_cache_deception(self, original_path):
        """Web Cache Deception 테스트"""
        results = []
        
        try:
            # 원본 요청
            original_response = self.session.get(f"{self.base_url}{original_path}")
            if original_response.status_code != 200:
                return results
            
            original_content = original_response.text
            original_length = len(original_content)
            
            # 테스트 URL들 생성 및 테스트
            test_urls = self.generate_test_urls(original_path)
            
            for test_url in test_urls:
                try:
                    response = self.session.get(f"{self.base_url}{test_url}")
                    
                    if response.status_code == 200:
                        # 컨텐츠가 유사한지 확인
                        similarity = self.calculate_similarity(
                            original_content, response.text)
                        
                        if similarity > 0.8:  # 80% 이상 유사
                            cache_headers = self.check_cache_headers(response)
                            
                            results.append({
                                'original_url': original_path,
                                'test_url': test_url,
                                'vulnerable': True,
                                'similarity': similarity,
                                'cache_headers': cache_headers,
                                'response_length': len(response.text)
                            })
                
                except Exception as e:
                    print(f"Error testing {test_url}: {e}")
                
                # 요청 간격 조절
                time.sleep(0.1)
        
        except Exception as e:
            print(f"Error with original path {original_path}: {e}")
        
        return results
    
    def calculate_similarity(self, text1, text2):
        """텍스트 유사도 계산 (간단한 방식)"""
        if not text1 or not text2:
            return 0
        
        # 길이 비교
        len_ratio = min(len(text1), len(text2)) / max(len(text1), len(text2))
        
        # 키워드 매칭 (더 정교한 방식으로 개선 가능)
        words1 = set(text1.split())
        words2 = set(text2.split())
        
        if not words1 or not words2:
            return len_ratio
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        word_similarity = intersection / union if union > 0 else 0
        
        return (len_ratio + word_similarity) / 2
    
    def check_cache_headers(self, response):
        """캐시 관련 헤더 확인"""
        cache_headers = {}
        
        headers_to_check = [
            'Cache-Control', 'Expires', 'Pragma', 'ETag',
            'Last-Modified', 'Vary', 'Age'
        ]
        
        for header in headers_to_check:
            if header in response.headers:
                cache_headers[header] = response.headers[header]
        
        return cache_headers
    
    def scan_site(self, test_paths=None):
        """전체 사이트 스캔"""
        if not test_paths:
            test_paths = [
                '/profile/user.php',
                '/admin/dashboard.php',
                '/api/user/info.php',
                '/settings/account.php'
            ]
        
        all_results = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.test_cache_deception, path) 
                      for path in test_paths]
            
            for future in futures:
                results = future.result()
                all_results.extend(results)
        
        return all_results

# 사용 예
scanner = WebCacheDeceptionScanner(
    'https://target.com',
    session_cookies={'PHPSESSID': 'authenticated_session_id'}
)

results = scanner.scan_site([
    '/profile.php',
    '/api/user/settings.php',
    '/admin/users.php'
])

for result in results:
    if result['vulnerable']:
        print(f"VULNERABLE: {result['test_url']}")
        print(f"Similarity: {result['similarity']:.2f}")
        print(f"Cache Headers: {result['cache_headers']}")
        print("-" * 50)
```

### 2. 수동 테스트 방법론

```bash
#!/bin/bash
# Web Cache Deception 수동 테스트 스크립트

BASE_URL="https://target.com"
COOKIE="PHPSESSID=your_session_cookie"

# 테스트할 민감한 경로들
PATHS=(
    "/profile.php"
    "/settings.php"
    "/api/user/info.php"
    "/admin/dashboard.php"
)

# 정적 파일 확장자들
EXTENSIONS=(
    ".css"
    ".js"
    ".png"
    ".jpg"
    ".gif"
    ".ico"
    ".pdf"
    ".txt"
)

echo "Web Cache Deception 테스트 시작..."
echo "================================="

for path in "${PATHS[@]}"; do
    echo "Testing path: $path"
    
    # 원본 페이지 요청
    original_response=$(curl -s -H "Cookie: $COOKIE" "$BASE_URL$path")
    original_size=${#original_response}
    
    if [ $original_size -gt 0 ]; then
        for ext in "${EXTENSIONS[@]}"; do
            test_url="$path/nonexistent$ext"
            
            echo "  Testing: $test_url"
            
            # 테스트 요청
            test_response=$(curl -s -H "Cookie: $COOKIE" "$BASE_URL$test_url")
            test_size=${#test_response}
            
            # 응답 크기 비교 (간단한 유사도 측정)
            if [ $test_size -gt 0 ] && [ $test_size -ge $((original_size * 80 / 100)) ]; then
                echo "    ⚠️  POTENTIAL VULNERABILITY FOUND!"
                echo "    Original size: $original_size"
                echo "    Test size: $test_size"
                
                # 캐시 헤더 확인
                cache_headers=$(curl -s -I -H "Cookie: $COOKIE" "$BASE_URL$test_url" | grep -i cache)
                if [ -n "$cache_headers" ]; then
                    echo "    Cache headers: $cache_headers"
                fi
                echo ""
            fi
        done
    fi
    echo ""
done

echo "테스트 완료!"
```

### 3. Burp Suite 확장

```javascript
// Burp Suite Web Cache Deception 탐지 확장
function processHttpMessage(toolFlag, messageIsRequest, messageInfo) {
    if (messageIsRequest) {
        return; // 요청은 처리하지 않음
    }
    
    var response = messageInfo.getResponse();
    var url = messageInfo.getUrl().toString();
    var responseStr = helpers.bytesToString(response);
    
    // 캐시 가능한 확장자 패턴
    var staticExtensions = /\.(css|js|png|jpg|jpeg|gif|ico|svg|pdf|txt|xml)(\?|$)/i;
    
    // 민감한 경로 패턴
    var sensitivePaths = /\/(profile|admin|api|user|settings|dashboard|private)\//i;
    
    if (staticExtensions.test(url) && sensitivePaths.test(url)) {
        // 응답이 실제로 정적 파일 내용인지 확인
        var isDynamic = checkIfDynamicContent(responseStr);
        
        if (isDynamic) {
            var cacheHeaders = extractCacheHeaders(response);
            
            // 취약점 보고
            callbacks.addScanIssue({
                url: messageInfo.getUrl(),
                name: "Web Cache Deception Vulnerability",
                detail: `동적 콘텐츠가 정적 파일 URL로 제공됨: ${url}\n` +
                       `캐시 헤더: ${JSON.stringify(cacheHeaders)}`,
                severity: "High",
                confidence: "Firm"
            });
        }
    }
}

function checkIfDynamicContent(responseStr) {
    // 동적 콘텐츠 지표들
    var dynamicIndicators = [
        /sessionid/i,
        /csrf[_-]?token/i,
        /user[_-]?id/i,
        /logged[_-]?in/i,
        /<form/i,
        /php|asp|jsp/i
    ];
    
    return dynamicIndicators.some(pattern => pattern.test(responseStr));
}

function extractCacheHeaders(response) {
    var headers = {};
    var headerLines = helpers.bytesToString(response).split('\n');
    
    var cacheHeaderNames = [
        'cache-control', 'expires', 'pragma', 'etag', 
        'last-modified', 'vary', 'age'
    ];
    
    headerLines.forEach(line => {
        var colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            var name = line.substring(0, colonIndex).toLowerCase().trim();
            var value = line.substring(colonIndex + 1).trim();
            
            if (cacheHeaderNames.includes(name)) {
                headers[name] = value;
            }
        }
    });
    
    return headers;
}
```

## 🧪 테스트 시나리오

### 시나리오 1: E-commerce 사이트 테스트

```python
import requests
import json
import time

def test_ecommerce_cache_deception():
    base_url = "https://shop.example.com"
    
    # 로그인하여 세션 얻기
    login_data = {
        'username': 'testuser',
        'password': 'testpass'
    }
    
    session = requests.Session()
    login_response = session.post(f"{base_url}/login", data=login_data)
    
    if "dashboard" not in login_response.text:
        print("로그인 실패")
        return
    
    # 테스트할 민감한 페이지들
    sensitive_pages = [
        '/account/profile.php',
        '/order/history.php',
        '/payment/methods.php',
        '/api/user/details.json'
    ]
    
    results = []
    
    for page in sensitive_pages:
        print(f"Testing {page}...")
        
        # 원본 페이지 요청
        original = session.get(f"{base_url}{page}")
        if original.status_code != 200:
            continue
        
        # Web Cache Deception 테스트
        test_urls = [
            f"{page}/style.css",
            f"{page}/script.js",
            f"{page}/image.png",
            f"{page}/document.pdf"
        ]
        
        for test_url in test_urls:
            test_response = session.get(f"{base_url}{test_url}")
            
            if (test_response.status_code == 200 and 
                len(test_response.text) > len(original.text) * 0.7):
                
                # 잠재적 취약점 발견
                results.append({
                    'original': page,
                    'vulnerable_url': test_url,
                    'content_similarity': calculate_similarity(
                        original.text, test_response.text),
                    'cache_control': test_response.headers.get('Cache-Control', ''),
                    'expires': test_response.headers.get('Expires', '')
                })
        
        time.sleep(1)  # 요청 간격
    
    return results

def calculate_similarity(text1, text2):
    # 간단한 유사도 계산
    words1 = set(text1.split())
    words2 = set(text2.split())
    
    if not words1 or not words2:
        return 0
    
    intersection = len(words1 & words2)
    union = len(words1 | words2)
    
    return intersection / union if union else 0

# 테스트 실행
results = test_ecommerce_cache_deception()

print("\n=== 테스트 결과 ===")
for result in results:
    if result['content_similarity'] > 0.8:
        print(f"🚨 취약점 발견!")
        print(f"  원본: {result['original']}")
        print(f"  취약 URL: {result['vulnerable_url']}")
        print(f"  유사도: {result['content_similarity']:.2f}")
        print(f"  Cache-Control: {result['cache_control']}")
        print(f"  Expires: {result['expires']}")
        print()
```

### 시나리오 2: API 엔드포인트 테스트

```bash
#!/bin/bash
# API Web Cache Deception 테스트

API_BASE="https://api.example.com"
AUTH_TOKEN="your_jwt_token_here"

# API 엔드포인트들
API_ENDPOINTS=(
    "/v1/user/profile"
    "/v1/user/settings"
    "/v1/account/billing"
    "/v1/admin/users"
)

# 테스트 확장자들
TEST_EXTENSIONS=(
    ".json"
    ".xml"
    ".js"
    ".css"
    ".txt"
)

echo "API Web Cache Deception 테스트 시작..."

for endpoint in "${API_ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    
    # 원본 API 호출
    original=$(curl -s -H "Authorization: Bearer $AUTH_TOKEN" "$API_BASE$endpoint")
    
    if [ -n "$original" ] && [ "$original" != "null" ]; then
        for ext in "${TEST_EXTENSIONS[@]}"; do
            test_endpoint="$endpoint/fake$ext"
            
            echo "  Testing: $test_endpoint"
            
            response=$(curl -s -w "%{http_code}" \
                      -H "Authorization: Bearer $AUTH_TOKEN" \
                      "$API_BASE$test_endpoint")
            
            http_code="${response: -3}"
            body="${response%???}"
            
            if [ "$http_code" = "200" ] && [ -n "$body" ]; then
                # JSON 구조 비교
                if echo "$body" | jq . >/dev/null 2>&1 && 
                   echo "$original" | jq . >/dev/null 2>&1; then
                    
                    # 키 개수 비교
                    original_keys=$(echo "$original" | jq 'keys | length')
                    test_keys=$(echo "$body" | jq 'keys | length')
                    
                    if [ "$original_keys" -eq "$test_keys" ]; then
                        echo "    ⚠️  잠재적 취약점!"
                        echo "    HTTP 상태: $http_code"
                        echo "    응답 크기: ${#body}"
                        
                        # 캐시 헤더 확인
                        curl -s -I -H "Authorization: Bearer $AUTH_TOKEN" \
                             "$API_BASE$test_endpoint" | grep -i "cache\|expires"
                        echo ""
                    fi
                fi
            fi
        done
    fi
    echo ""
done
```

## 📊 영향 평가

### 비즈니스 영향

- **개인정보 유출**: 사용자 프로필, 결제 정보 등 민감한 개인정보 노출
- **인증 정보 탈취**: 세션 토큰, API 키 등 인증 정보 유출
- **경쟁 정보 노출**: 관리자 대시보드, 내부 데이터 등 비즈니스 정보 노출
- **규정 위반**: GDPR, CCPA 등 개인정보보호 규정 위반

### 기술적 영향

- **캐시 오염**: CDN 캐시에 민감한 정보가 장기간 저장
- **대규모 데이터 유출**: 캐시된 정보로 인한 지속적 정보 노출
- **인증 우회**: 캐시된 인증 정보를 통한 무단 접근
- **API 보안 우회**: API 키 탈취를 통한 서비스 남용

## 🔧 수정 가이드

### 즉시 적용할 수정사항

1. **캐시 제어 헤더 설정**
2. **URL 라우팅 강화**
3. **정적 파일 확장자 차단**
4. **인증된 요청 캐싱 금지**

### 장기적 개선사항

1. **CDN 설정 재검토**
2. **Content-Type 기반 캐싱**
3. **캐시 정책 표준화**
4. **모니터링 시스템 구축**

## 📚 참고 자료

- [PortSwigger - Web Cache Deception](https://portswigger.net/web-security/web-cache-poisoning/web-cache-deception)
- [OWASP - Web Cache Deception](https://owasp.org/www-community/attacks/Web_Cache_Deception)
- [CWE-524: Use of Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/524.html)
- [RFC 7234 - HTTP/1.1 Caching](https://tools.ietf.org/html/rfc7234)

## 🎯 결론

Web Cache Deception은 웹 캐시 시스템의 URL 해석과 캐싱 정책의 불일치를 악용하는 교묘한 공격입니다. 민감한 콘텐츠에 대한 적절한 캐시 제어 헤더 설정과 URL 정규화를 통해 효과적으로 방어할 수 있으며, 특히 인증된 사용자의 콘텐츠는 절대 공개 캐시에 저장되지 않도록 하는 것이 중요합니다.