# API Key Leak 취약점 상세 분석

## 📋 개요

**API Key Leak**은 민감한 API 키가 의도하지 않게 노출되어 공격자에게 발견되는 보안 취약점입니다. 이는 소스코드 하드코딩, 버전 관리 시스템 유출, 클라이언트 측 노출, 로그 파일 유출 등 다양한 경로를 통해 발생할 수 있으며, 서비스 오용, 금전적 손실, 데이터 유출 등 심각한 결과를 초래할 수 있습니다.

## 🎯 취약점 정보

- **CVSS 3.1 점수**: 8.8 (High)
- **공격 복잡성**: Low
- **필요 권한**: None
- **사용자 상호작용**: None
- **영향 범위**: Confidentiality, Integrity, Availability

## 🔍 취약점 원리

### 핵심 개념

API Key Leak은 다음과 같은 상황에서 발생합니다:

1. **하드코딩**: 소스코드에 API 키를 직접 문자열로 포함
2. **버전 관리 유출**: Git, SVN 등 저장소에 API 키 커밋
3. **클라이언트 측 노출**: 프론트엔드 코드나 JavaScript에 API 키 포함
4. **설정 파일 노출**: 공개 디렉토리의 설정 파일에 API 키 저장
5. **로그 유출**: 애플리케이션 로그에 API 키 기록

### 일반적인 노출 경로

```
1. GitHub/GitLab 공개 저장소 → 자동화된 크롤러 → API 키 발견
2. 클라이언트 측 코드 → 개발자 도구 → API 키 확인
3. 설정 파일 노출 → 웹 크롤링 → API 키 탈취
4. 로그 파일 유출 → 로그 분석 → API 키 추출
5. 메모리 덤프 → 포렌식 분석 → API 키 복구
```

## 🚨 공격 시나리오

### 1. GitHub 저장소 하드코딩

**취약한 코드**:
```javascript
// config.js - GitHub에 업로드된 파일
const config = {
    openai_api_key: "sk-proj-EXAMPLE123456789012345678901234567890",
    aws_access_key: "AKIAIOSFODNN7EXAMPLE",
    aws_secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    stripe_secret: "sk_live_FAKE_EXAMPLE_KEY_ABCDEFGHIJK"
};

export default config;
```

**공격 과정**:
```bash
# 1. GitHub 자동 크롤링
curl "https://api.github.com/search/code?q=sk-proj+extension:js"

# 2. API 키 패턴 매칭
grep -r "sk-proj-[a-zA-Z0-9]" ./cloned-repos/

# 3. 발견된 키로 무단 사용
curl -H "Authorization: Bearer sk-proj-EXAMPLE123..." https://api.openai.com/v1/chat/completions
```

### 2. 클라이언트 측 JavaScript 노출

**취약한 프론트엔드 코드**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Weather App</title>
</head>
<body>
    <script>
        const API_KEY = "EXAMPLE1234567890abcdef1234567890ab"; // 취약!
        
        fetch(`https://api.openweathermap.org/data/2.5/weather?q=Seoul&appid=${API_KEY}`)
            .then(response => response.json())
            .then(data => console.log(data));
    </script>
</body>
</html>
```

**공격 벡터**:
```javascript
// 개발자 도구 콘솔에서
console.log(API_KEY); // API 키 즉시 확인 가능

// 소스코드 검사로도 확인 가능
// View Page Source → API_KEY 검색
```

### 3. 환경 파일 노출

**취약한 설정**:
```bash
# .env 파일이 웹 루트에 노출된 경우
https://vulnerable-site.com/.env

# .env 파일 내용
DB_PASSWORD=EXAMPLE_PASSWORD
OPENAI_API_KEY=sk-proj-EXAMPLE789abc123def456
STRIPE_SECRET_KEY=sk_live_FAKE_EXAMPLE_KEY_123456
AWS_ACCESS_KEY_ID=AKIA12345EXAMPLE
```

**자동화된 탐지**:
```python
import requests
import re

def scan_env_files(target_urls):
    env_patterns = [
        r'[A-Z_]+_API_KEY\s*=\s*["\']?([a-zA-Z0-9\-_]+)["\']?',
        r'sk-[a-zA-Z0-9\-_]{20,}',
        r'AKIA[0-9A-Z]{16}',
        r'AIza[0-9A-Za-z\-_]{35}'
    ]
    
    for url in target_urls:
        try:
            response = requests.get(f"{url}/.env", timeout=5)
            if response.status_code == 200:
                for pattern in env_patterns:
                    matches = re.findall(pattern, response.text)
                    if matches:
                        print(f"API Keys found at {url}: {matches}")
        except:
            continue

# 사용 예
target_sites = ["https://example.com", "https://test.com"]
scan_env_files(target_sites)
```

### 4. Git 히스토리 유출

**문제 상황**:
```bash
# 개발자가 실수로 API 키 커밋
git add config.js
git commit -m "Add API configuration"
git push origin main

# 나중에 API 키 제거
git rm config.js
git commit -m "Remove API key"
git push origin main

# 하지만 Git 히스토리에는 여전히 존재
git log --all --full-history -- config.js
git show <commit-hash>:config.js  # API 키 여전히 확인 가능
```

**공격 기법**:
```bash
# GitHub 고급 검색으로 커밋 히스토리 탐색
site:github.com "removed api key" OR "remove secret"

# Git 히스토리 크롤링
git clone https://github.com/target/repo.git
cd repo
git log --all --grep="api\|key\|secret" --oneline
git show --name-only <suspicious-commit>
```

## 🛡️ 방어 방법

### 1. 환경 변수 기반 관리

```php
<?php
// 안전한 API 키 관리
class SecureConfig {
    private static $instance = null;
    private $config = [];
    
    private function __construct() {
        // 환경 변수에서 안전하게 로드
        $this->config = [
            'openai_api_key' => $_ENV['OPENAI_API_KEY'] ?? null,
            'stripe_secret' => $_ENV['STRIPE_SECRET_KEY'] ?? null,
            'aws_access_key' => $_ENV['AWS_ACCESS_KEY_ID'] ?? null,
        ];
        
        // 필수 키 검증
        $this->validateRequiredKeys();
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function get($key) {
        return $this->config[$key] ?? null;
    }
    
    private function validateRequiredKeys() {
        $required = ['openai_api_key', 'stripe_secret'];
        
        foreach ($required as $key) {
            if (empty($this->config[$key])) {
                throw new Exception("Required API key missing: $key");
            }
        }
    }
}

// 사용 방법
$config = SecureConfig::getInstance();
$api_key = $config->get('openai_api_key');
?>
```

### 2. 클라우드 비밀 관리 서비스

```php
<?php
// AWS Secrets Manager 사용 예시
use Aws\SecretsManager\SecretsManagerClient;

class AWSSecretManager {
    private $client;
    private $cache = [];
    private $cache_ttl = 3600; // 1시간
    
    public function __construct($region = 'us-east-1') {
        $this->client = new SecretsManagerClient([
            'version' => 'latest',
            'region' => $region
        ]);
    }
    
    public function getSecret($secret_name) {
        // 캐시 확인
        if (isset($this->cache[$secret_name])) {
            $cached = $this->cache[$secret_name];
            if (time() - $cached['timestamp'] < $this->cache_ttl) {
                return $cached['value'];
            }
        }
        
        try {
            $result = $this->client->getSecretValue([
                'SecretId' => $secret_name
            ]);
            
            $secret_value = $result['SecretString'];
            
            // 캐싱
            $this->cache[$secret_name] = [
                'value' => $secret_value,
                'timestamp' => time()
            ];
            
            return $secret_value;
            
        } catch (Exception $e) {
            error_log("Failed to retrieve secret $secret_name: " . $e->getMessage());
            return null;
        }
    }
    
    public function getApiKey($service) {
        $secret = $this->getSecret("api-keys/$service");
        if ($secret) {
            $decoded = json_decode($secret, true);
            return $decoded['api_key'] ?? null;
        }
        return null;
    }
}

// 사용 예
$secretManager = new AWSSecretManager();
$openai_key = $secretManager->getApiKey('openai');
?>
```

### 3. 클라이언트-서버 프록시 패턴

```javascript
// 안전한 프론트엔드 구현
class SecureAPIClient {
    constructor(baseURL = '/api/proxy') {
        this.baseURL = baseURL;
    }
    
    // API 키를 직접 사용하지 않고 백엔드 프록시를 통해 요청
    async makeRequest(service, endpoint, data = null) {
        const response = await fetch(`${this.baseURL}/${service}`, {
            method: data ? 'POST' : 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: data ? JSON.stringify({
                endpoint: endpoint,
                data: data
            }) : null
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return response.json();
    }
    
    // 사용 예시
    async getWeather(city) {
        return this.makeRequest('weather', '/current', { city: city });
    }
    
    async chatCompletion(messages) {
        return this.makeRequest('openai', '/chat/completions', { messages: messages });
    }
}
```

```php
<?php
// 백엔드 프록시 구현
class APIProxyController {
    private $config;
    
    public function __construct() {
        $this->config = SecureConfig::getInstance();
    }
    
    public function handleWeatherRequest($request) {
        $api_key = $this->config->get('openweather_api_key');
        $city = $request->input('data.city');
        
        // 입력 검증
        if (!$this->validateCity($city)) {
            return response()->json(['error' => 'Invalid city name'], 400);
        }
        
        // 외부 API 호출
        $url = "https://api.openweathermap.org/data/2.5/weather?q={$city}&appid={$api_key}";
        $response = file_get_contents($url);
        
        // API 키 제거하고 응답
        return response()->json(json_decode($response, true));
    }
    
    public function handleOpenAIRequest($request) {
        $api_key = $this->config->get('openai_api_key');
        $messages = $request->input('data.messages');
        
        // 요청 제한 및 검증
        if (!$this->validateOpenAIRequest($messages)) {
            return response()->json(['error' => 'Invalid request'], 400);
        }
        
        // 외부 API 호출
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://api.openai.com/v1/chat/completions',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $api_key,
                'Content-Type: application/json'
            ],
            CURLOPT_POSTFIELDS => json_encode([
                'model' => 'gpt-3.5-turbo',
                'messages' => $messages,
                'max_tokens' => 1000
            ])
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return response()->json(json_decode($response, true));
    }
    
    private function validateCity($city) {
        return preg_match('/^[a-zA-Z\s\-,]{1,50}$/', $city);
    }
    
    private function validateOpenAIRequest($messages) {
        return is_array($messages) && count($messages) <= 10;
    }
}
?>
```

### 4. Git 보안 강화

```bash
#!/bin/bash
# pre-commit 훅 스크립트 (.git/hooks/pre-commit)

# API 키 패턴 정의
API_KEY_PATTERNS=(
    "sk-[a-zA-Z0-9]{48}"                    # OpenAI
    "AKIA[0-9A-Z]{16}"                      # AWS Access Key
    "AIza[0-9A-Za-z\\-_]{35}"               # Google API
    "[0-9a-zA-Z]{32}"                       # Generic 32-char key
    "sk_live_[0-9a-zA-Z]{24,}"             # Stripe Live Key
    "sk_test_[0-9a-zA-Z]{24,}"             # Stripe Test Key
)

# 변경된 파일들 확인
changed_files=$(git diff --cached --name-only)

echo "🔍 Checking for API keys in commit..."

found_secrets=0

for file in $changed_files; do
    if [[ -f "$file" ]]; then
        for pattern in "${API_KEY_PATTERNS[@]}"; do
            if grep -qE "$pattern" "$file"; then
                echo "❌ Potential API key found in $file"
                echo "   Pattern: $pattern"
                found_secrets=1
            fi
        done
    fi
done

if [ $found_secrets -eq 1 ]; then
    echo ""
    echo "🚫 Commit blocked! Potential API keys detected."
    echo "Please review and remove any hardcoded API keys."
    echo ""
    echo "Safe alternatives:"
    echo "- Use environment variables"
    echo "- Use cloud secret management services"
    echo "- Store keys in separate config files (add to .gitignore)"
    exit 1
fi

echo "✅ No API keys detected. Commit allowed."
exit 0
```

### 5. API 키 제한 및 모니터링

```php
<?php
class APIKeySecurityManager {
    private $redis;
    
    public function __construct() {
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }
    
    // API 키 사용량 제한
    public function checkRateLimit($api_key, $limit_per_hour = 1000) {
        $key = "api_usage:" . hash('sha256', $api_key) . ":" . date('Y-m-d-H');
        $current_usage = $this->redis->get($key) ?: 0;
        
        if ($current_usage >= $limit_per_hour) {
            throw new Exception('API rate limit exceeded');
        }
        
        // 사용량 증가
        $this->redis->incr($key);
        $this->redis->expire($key, 3600); // 1시간 후 만료
        
        return true;
    }
    
    // IP 주소 제한
    public function checkIPRestriction($api_key, $client_ip) {
        $allowed_ips_key = "api_allowed_ips:" . hash('sha256', $api_key);
        $allowed_ips = $this->redis->smembers($allowed_ips_key);
        
        if (!empty($allowed_ips) && !in_array($client_ip, $allowed_ips)) {
            $this->logSuspiciousActivity($api_key, $client_ip, 'IP_RESTRICTION_VIOLATION');
            throw new Exception('IP address not allowed');
        }
        
        return true;
    }
    
    // 의심스러운 활동 탐지
    public function detectAnomalousUsage($api_key, $request_data) {
        $anomalies = [];
        
        // 1. 비정상적인 요청 빈도
        $recent_requests = $this->getRecentRequestCount($api_key, 300); // 5분
        if ($recent_requests > 100) {
            $anomalies[] = 'HIGH_FREQUENCY_REQUESTS';
        }
        
        // 2. 새로운 IP에서의 접근
        if ($this->isNewIP($api_key, $_SERVER['REMOTE_ADDR'])) {
            $anomalies[] = 'NEW_IP_ACCESS';
        }
        
        // 3. 비정상적인 시간대 접근
        $hour = date('H');
        if ($hour < 6 || $hour > 23) { // 새벽 시간대
            $anomalies[] = 'UNUSUAL_TIME_ACCESS';
        }
        
        if (!empty($anomalies)) {
            $this->logSuspiciousActivity($api_key, $_SERVER['REMOTE_ADDR'], implode(',', $anomalies));
            
            // 심각한 경우 일시적 차단
            if (count($anomalies) >= 2) {
                $this->temporaryBlock($api_key, 1800); // 30분 차단
            }
        }
        
        return $anomalies;
    }
    
    private function logSuspiciousActivity($api_key, $ip, $reason) {
        $log_data = [
            'timestamp' => time(),
            'api_key_hash' => hash('sha256', $api_key),
            'ip_address' => $ip,
            'reason' => $reason,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'referer' => $_SERVER['HTTP_REFERER'] ?? ''
        ];
        
        error_log("API_SECURITY_ALERT: " . json_encode($log_data));
        
        // 알림 시스템 연동
        $this->sendSecurityAlert($log_data);
    }
    
    private function sendSecurityAlert($log_data) {
        // Slack, 이메일 등으로 보안 알림 전송
        $webhook_url = $_ENV['SECURITY_ALERT_WEBHOOK'];
        if ($webhook_url) {
            $payload = json_encode([
                'text' => "🚨 API Security Alert: {$log_data['reason']} from IP {$log_data['ip_address']}"
            ]);
            
            $ch = curl_init($webhook_url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_exec($ch);
            curl_close($ch);
        }
    }
}
?>
```

## 🔍 취약점 탐지 방법

### 1. 자동화된 GitHub 스캐닝

```python
import requests
import re
import base64
from concurrent.futures import ThreadPoolExecutor
import time

class GitHubAPIKeyScanner:
    def __init__(self, github_token=None):
        self.session = requests.Session()
        if github_token:
            self.session.headers.update({
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            })
        
        self.api_patterns = {
            'openai': r'sk-[a-zA-Z0-9]{48}',
            'aws_access': r'AKIA[0-9A-Z]{16}',
            'aws_secret': r'[A-Za-z0-9/+=]{40}',
            'google': r'AIza[0-9A-Za-z\-_]{35}',
            'stripe_live': r'sk_live_[0-9a-zA-Z]{24,}',
            'stripe_test': r'sk_test_[0-9a-zA-Z]{24,}',
            'github_token': r'ghp_[A-Za-z0-9]{36}',
            'discord': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            'slack': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
        }
    
    def search_repositories(self, query, max_results=100):
        """GitHub에서 저장소 검색"""
        results = []
        page = 1
        per_page = min(max_results, 100)
        
        while len(results) < max_results:
            url = "https://api.github.com/search/repositories"
            params = {
                'q': query,
                'page': page,
                'per_page': per_page,
                'sort': 'updated'
            }
            
            response = self.session.get(url, params=params)
            if response.status_code != 200:
                break
            
            data = response.json()
            if not data.get('items'):
                break
            
            results.extend(data['items'])
            page += 1
            
            # GitHub API 속도 제한 고려
            time.sleep(1)
        
        return results[:max_results]
    
    def search_code(self, query, language=None):
        """GitHub에서 코드 검색"""
        url = "https://api.github.com/search/code"
        params = {'q': query}
        
        if language:
            params['q'] += f' language:{language}'
        
        response = self.session.get(url, params=params)
        if response.status_code == 200:
            return response.json().get('items', [])
        
        return []
    
    def get_file_content(self, repo_full_name, file_path):
        """파일 내용 가져오기"""
        url = f"https://api.github.com/repos/{repo_full_name}/contents/{file_path}"
        response = self.session.get(url)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('encoding') == 'base64':
                return base64.b64decode(data['content']).decode('utf-8')
        
        return None
    
    def scan_for_api_keys(self, content):
        """콘텐츠에서 API 키 패턴 검색"""
        found_keys = {}
        
        for key_type, pattern in self.api_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                found_keys[key_type] = matches
        
        return found_keys
    
    def scan_repository(self, repo_full_name):
        """저장소 전체 스캔"""
        print(f"Scanning repository: {repo_full_name}")
        
        # 주요 파일들 확인
        suspicious_files = [
            '.env', 'config.js', 'config.py', 'settings.py',
            'app.js', 'index.js', 'main.py', 'config.json',
            'docker-compose.yml', 'Dockerfile'
        ]
        
        findings = []
        
        for file_path in suspicious_files:
            content = self.get_file_content(repo_full_name, file_path)
            if content:
                api_keys = self.scan_for_api_keys(content)
                if api_keys:
                    findings.append({
                        'file': file_path,
                        'repository': repo_full_name,
                        'api_keys': api_keys
                    })
            
            time.sleep(0.5)  # API 호출 제한
        
        return findings
    
    def mass_scan(self, search_queries, max_repos_per_query=50):
        """대량 스캔 수행"""
        all_findings = []
        
        for query in search_queries:
            print(f"Searching for: {query}")
            repos = self.search_repositories(query, max_repos_per_query)
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.scan_repository, repo['full_name']) 
                          for repo in repos]
                
                for future in futures:
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        print(f"Error scanning repository: {e}")
        
        return all_findings

# 사용 예시
scanner = GitHubAPIKeyScanner(github_token="your_github_token")

# 의심스러운 키워드로 검색
search_queries = [
    'openai api key',
    'stripe secret key', 
    'aws secret key',
    'google api key',
    'config api'
]

findings = scanner.mass_scan(search_queries)

print(f"\n=== SCAN RESULTS ===")
print(f"Total repositories with API keys found: {len(findings)}")

for finding in findings:
    print(f"\n🚨 Repository: {finding['repository']}")
    print(f"📁 File: {finding['file']}")
    for key_type, keys in finding['api_keys'].items():
        print(f"🔑 {key_type.upper()}: {len(keys)} keys found")
```

### 2. 웹 크롤링 기반 탐지

```python
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import time

class WebAPIKeyScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.api_patterns = {
            'openai': r'sk-[a-zA-Z0-9]{48}',
            'aws_access': r'AKIA[0-9A-Z]{16}',
            'google': r'AIza[0-9A-Za-z\-_]{35}',
            'stripe': r'sk_(live|test)_[0-9a-zA-Z]{24,}',
            'generic_32': r'[a-zA-Z0-9]{32}',
            'jwt': r'eyJ[A-Za-z0-9_/+\-]{50,}'
        }
        
        # 의심스러운 파일 확장자
        self.suspicious_extensions = [
            '.env', '.config', '.json', '.js', '.py', '.php',
            '.yml', '.yaml', '.xml', '.txt', '.log'
        ]
    
    def crawl_website(self, base_url, max_depth=2):
        """웹사이트 크롤링"""
        visited = set()
        to_visit = [(base_url, 0)]
        found_keys = []
        
        while to_visit:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            print(f"Crawling: {url} (depth: {depth})")
            
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # API 키 검색
                    keys = self.scan_for_api_keys(response.text)
                    if keys:
                        found_keys.append({
                            'url': url,
                            'keys': keys
                        })
                    
                    # 추가 링크 찾기
                    if depth < max_depth:
                        new_links = self.extract_links(response.text, url)
                        for link in new_links:
                            if link not in visited:
                                to_visit.append((link, depth + 1))
            
            except Exception as e:
                print(f"Error crawling {url}: {e}")
            
            time.sleep(1)  # 정중한 크롤링
        
        return found_keys
    
    def scan_common_files(self, base_url):
        """일반적인 노출 파일들 확인"""
        common_files = [
            '.env',
            'config.json',
            'config.js',
            'settings.json',
            'app-config.json',
            'firebase-config.js',
            'api-keys.json',
            'secrets.json',
            '.env.local',
            '.env.production',
            'config/database.yml',
            'config/app.php',
            'wp-config.php',
            'configuration.php'
        ]
        
        findings = []
        
        for file_path in common_files:
            test_url = urljoin(base_url, file_path)
            
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    keys = self.scan_for_api_keys(response.text)
                    if keys:
                        findings.append({
                            'url': test_url,
                            'file': file_path,
                            'keys': keys
                        })
                        print(f"🚨 API keys found in {test_url}")
            
            except Exception:
                continue
            
            time.sleep(0.5)
        
        return findings
    
    def scan_javascript_files(self, base_url):
        """JavaScript 파일에서 API 키 검색"""
        try:
            response = self.session.get(base_url)
            if response.status_code != 200:
                return []
            
            soup = BeautifulSoup(response.text, 'html.parser')
            js_files = []
            
            # <script src="..."> 태그에서 외부 JS 파일 찾기
            for script in soup.find_all('script', src=True):
                js_url = urljoin(base_url, script['src'])
                js_files.append(js_url)
            
            # 인라인 스크립트도 확인
            for script in soup.find_all('script'):
                if script.string:
                    keys = self.scan_for_api_keys(script.string)
                    if keys:
                        js_files.append({
                            'url': base_url,
                            'type': 'inline_script',
                            'keys': keys
                        })
            
            # 외부 JS 파일들 스캔
            findings = []
            for js_url in js_files:
                if isinstance(js_url, str):
                    try:
                        js_response = self.session.get(js_url, timeout=5)
                        if js_response.status_code == 200:
                            keys = self.scan_for_api_keys(js_response.text)
                            if keys:
                                findings.append({
                                    'url': js_url,
                                    'type': 'external_js',
                                    'keys': keys
                                })
                    except Exception:
                        continue
                    
                    time.sleep(0.5)
                else:
                    findings.append(js_url)  # 인라인 스크립트 결과
            
            return findings
            
        except Exception as e:
            print(f"Error scanning JS files: {e}")
            return []
    
    def scan_for_api_keys(self, content):
        """콘텐츠에서 API 키 패턴 검색"""
        found_keys = {}
        
        for key_type, pattern in self.api_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # 중복 제거
                unique_matches = list(set(matches))
                found_keys[key_type] = unique_matches
        
        return found_keys
    
    def extract_links(self, html_content, base_url):
        """HTML에서 링크 추출"""
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        
        for tag in soup.find_all(['a', 'link'], href=True):
            link = urljoin(base_url, tag['href'])
            
            # 같은 도메인의 링크만 수집
            if urlparse(link).netloc == urlparse(base_url).netloc:
                # 의심스러운 확장자만 수집
                if any(link.endswith(ext) for ext in self.suspicious_extensions):
                    links.add(link)
        
        return links

# 사용 예시
scanner = WebAPIKeyScanner()

# 웹사이트 전체 스캔
target_site = "https://example.com"
print(f"Scanning {target_site} for API keys...")

# 1. 일반적인 설정 파일 확인
common_findings = scanner.scan_common_files(target_site)

# 2. JavaScript 파일 확인  
js_findings = scanner.scan_javascript_files(target_site)

# 3. 전체 사이트 크롤링
crawl_findings = scanner.crawl_website(target_site, max_depth=2)

print(f"\n=== SCAN RESULTS ===")
print(f"Common files with API keys: {len(common_findings)}")
print(f"JavaScript files with API keys: {len(js_findings)}")
print(f"Crawling findings: {len(crawl_findings)}")

all_findings = common_findings + js_findings + crawl_findings
for finding in all_findings:
    print(f"\n🚨 URL: {finding['url']}")
    if 'keys' in finding:
        for key_type, keys in finding['keys'].items():
            print(f"🔑 {key_type.upper()}: {keys}")
```

### 3. 메모리 덤프 분석

```python
import re
import mmap
import os

class MemoryAPIKeyScanner:
    def __init__(self):
        self.api_patterns = {
            'openai': rb'sk-[a-zA-Z0-9]{48}',
            'aws_access': rb'AKIA[0-9A-Z]{16}',
            'aws_secret': rb'[A-Za-z0-9/+=]{40}',
            'google': rb'AIza[0-9A-Za-z\-_]{35}',
            'stripe_live': rb'sk_live_[0-9a-zA-Z]{24,}',
            'github_token': rb'ghp_[A-Za-z0-9]{36}',
        }
    
    def scan_memory_dump(self, dump_file_path):
        """메모리 덤프 파일에서 API 키 검색"""
        findings = {}
        
        try:
            with open(dump_file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    print(f"Scanning memory dump: {dump_file_path}")
                    print(f"File size: {len(mm)} bytes")
                    
                    for key_type, pattern in self.api_patterns.items():
                        matches = re.findall(pattern, mm)
                        if matches:
                            # 바이트를 문자열로 변환
                            string_matches = [match.decode('utf-8', errors='ignore') 
                                            for match in matches]
                            findings[key_type] = list(set(string_matches))
                            print(f"Found {len(findings[key_type])} {key_type} keys")
        
        except Exception as e:
            print(f"Error scanning memory dump: {e}")
        
        return findings
    
    def scan_process_memory(self, pid):
        """실행 중인 프로세스 메모리 스캔 (Linux)"""
        mem_file = f"/proc/{pid}/mem"
        maps_file = f"/proc/{pid}/maps"
        
        if not os.path.exists(mem_file) or not os.path.exists(maps_file):
            print(f"Process {pid} not found or not accessible")
            return {}
        
        findings = {}
        
        try:
            with open(maps_file, 'r') as maps:
                memory_regions = maps.readlines()
            
            with open(mem_file, 'rb') as mem:
                for region in memory_regions:
                    # 읽기 가능한 메모리 영역만 스캔
                    if 'r' not in region.split()[1]:
                        continue
                    
                    # 주소 범위 파싱
                    addr_range = region.split()[0]
                    start, end = addr_range.split('-')
                    start_addr = int(start, 16)
                    end_addr = int(end, 16)
                    
                    try:
                        mem.seek(start_addr)
                        data = mem.read(end_addr - start_addr)
                        
                        # API 키 패턴 검색
                        for key_type, pattern in self.api_patterns.items():
                            matches = re.findall(pattern, data)
                            if matches:
                                if key_type not in findings:
                                    findings[key_type] = []
                                
                                string_matches = [match.decode('utf-8', errors='ignore') 
                                                for match in matches]
                                findings[key_type].extend(string_matches)
                    
                    except (OSError, IOError):
                        continue  # 접근할 수 없는 메모리 영역
        
        except Exception as e:
            print(f"Error scanning process memory: {e}")
        
        # 중복 제거
        for key_type in findings:
            findings[key_type] = list(set(findings[key_type]))
        
        return findings

# 사용 예시
scanner = MemoryAPIKeyScanner()

# 메모리 덤프 파일 스캔
dump_findings = scanner.scan_memory_dump('/path/to/memory.dump')

# 실행 중인 프로세스 스캔 (Linux만 지원)
import psutil

for proc in psutil.process_iter(['pid', 'name']):
    try:
        if 'node' in proc.info['name'] or 'python' in proc.info['name']:
            print(f"Scanning process: {proc.info['name']} (PID: {proc.info['pid']})")
            proc_findings = scanner.scan_process_memory(proc.info['pid'])
            
            if proc_findings:
                print(f"API keys found in process {proc.info['pid']}:")
                for key_type, keys in proc_findings.items():
                    print(f"  {key_type}: {len(keys)} keys")
    
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue
```

## 🧪 테스트 시나리오

### 시나리오 1: GitHub Repository 스캔

```bash
#!/bin/bash
# GitHub API 키 탐지 스크립트

# GitHub Token (선택적)
GITHUB_TOKEN=""

# 검색할 API 키 패턴들
declare -A API_PATTERNS=(
    ["openai"]="sk-[a-zA-Z0-9]{48}"
    ["aws_access"]="AKIA[0-9A-Z]{16}" 
    ["aws_secret"]="[A-Za-z0-9/+=]{40}"
    ["google"]="AIza[0-9A-Za-z\-_]{35}"
    ["stripe_live"]="sk_live_[0-9a-zA-Z]{24,}"
    ["github"]="ghp_[A-Za-z0-9]{36}"
)

# GitHub API 호출 함수
github_api() {
    local endpoint="$1"
    local auth_header=""
    
    if [[ -n "$GITHUB_TOKEN" ]]; then
        auth_header="-H \"Authorization: token $GITHUB_TOKEN\""
    fi
    
    eval "curl -s $auth_header \"https://api.github.com$endpoint\""
}

# 코드 검색
search_code_for_pattern() {
    local pattern="$1"
    local query="$2"
    
    echo "Searching for $pattern..."
    
    # GitHub 코드 검색
    response=$(github_api "/search/code?q=$query")
    
    # 결과 파싱
    echo "$response" | jq -r '.items[]? | "\(.repository.full_name):\(.path):\(.html_url)"' 2>/dev/null
}

echo "🔍 GitHub API Key Scanner Started"
echo "=================================="

# 각 패턴별로 검색 수행
for key_type in "${!API_PATTERNS[@]}"; do
    pattern="${API_PATTERNS[$key_type]}"
    
    # 쿼리 생성 (정규식을 GitHub 검색 쿼리로 변환)
    case $key_type in
        "openai")
            query="sk- extension:js OR extension:py OR extension:php OR extension:env"
            ;;
        "aws_access")
            query="AKIA extension:js OR extension:py OR extension:php OR extension:env"
            ;;
        "google") 
            query="AIza extension:js OR extension:py OR extension:php OR extension:env"
            ;;
        *)
            query="$key_type extension:js OR extension:py OR extension:php"
            ;;
    esac
    
    results=$(search_code_for_pattern "$pattern" "$query")
    
    if [[ -n "$results" ]]; then
        echo "🚨 Found $key_type API keys:"
        echo "$results"
        echo ""
    fi
    
    # GitHub API 속도 제한 고려
    sleep 2
done

echo "Scan completed!"
```

### 시나리오 2: 웹 애플리케이션 테스트

```python
import requests
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import re

class WebAppAPIKeyTest:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
        # Selenium WebDriver 설정
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(options=chrome_options)
        
        self.api_patterns = {
            'openai': r'sk-[a-zA-Z0-9]{48}',
            'aws_access': r'AKIA[0-9A-Z]{16}',
            'google': r'AIza[0-9A-Za-z\-_]{35}',
            'stripe': r'sk_(live|test)_[0-9a-zA-Z]{24,}'
        }
    
    def test_client_side_exposure(self):
        """클라이언트 측 API 키 노출 테스트"""
        print(f"Testing client-side exposure: {self.target_url}")
        
        findings = []
        
        try:
            # 페이지 로드
            self.driver.get(self.target_url)
            time.sleep(3)
            
            # 1. 페이지 소스에서 검색
            page_source = self.driver.page_source
            source_keys = self.scan_for_keys(page_source)
            if source_keys:
                findings.append({
                    'location': 'page_source',
                    'keys': source_keys
                })
            
            # 2. JavaScript 변수에서 검색
            js_vars = self.driver.execute_script("""
                var vars = {};
                for (var prop in window) {
                    if (typeof window[prop] === 'string' && window[prop].length > 20) {
                        vars[prop] = window[prop];
                    }
                }
                return vars;
            """)
            
            for var_name, var_value in js_vars.items():
                var_keys = self.scan_for_keys(var_value)
                if var_keys:
                    findings.append({
                        'location': f'js_variable_{var_name}',
                        'keys': var_keys
                    })
            
            # 3. localStorage 검사
            local_storage = self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
            
            for key, value in local_storage.items():
                storage_keys = self.scan_for_keys(str(value))
                if storage_keys:
                    findings.append({
                        'location': f'localStorage_{key}',
                        'keys': storage_keys
                    })
            
            # 4. sessionStorage 검사
            session_storage = self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
            
            for key, value in session_storage.items():
                storage_keys = self.scan_for_keys(str(value))
                if storage_keys:
                    findings.append({
                        'location': f'sessionStorage_{key}',
                        'keys': storage_keys
                    })
        
        except Exception as e:
            print(f"Error during client-side testing: {e}")
        
        return findings
    
    def test_network_requests(self):
        """네트워크 요청에서 API 키 노출 테스트"""
        print("Testing network requests...")
        
        # Chrome DevTools Protocol 사용하여 네트워크 모니터링
        self.driver.execute_cdp_cmd('Network.enable', {})
        
        # 페이지 로드
        self.driver.get(self.target_url)
        time.sleep(5)
        
        # 네트워크 로그 수집
        logs = self.driver.get_log('performance')
        
        findings = []
        
        for log in logs:
            message = json.loads(log['message'])
            
            if message['message']['method'] == 'Network.requestWillBeSent':
                request = message['message']['params']['request']
                
                # URL에서 API 키 검색
                url_keys = self.scan_for_keys(request['url'])
                if url_keys:
                    findings.append({
                        'location': 'request_url',
                        'url': request['url'],
                        'keys': url_keys
                    })
                
                # 헤더에서 API 키 검색
                for header_name, header_value in request.get('headers', {}).items():
                    header_keys = self.scan_for_keys(str(header_value))
                    if header_keys:
                        findings.append({
                            'location': f'request_header_{header_name}',
                            'url': request['url'],
                            'keys': header_keys
                        })
                
                # POST 데이터에서 API 키 검색
                if 'postData' in request:
                    post_keys = self.scan_for_keys(request['postData'])
                    if post_keys:
                        findings.append({
                            'location': 'request_body',
                            'url': request['url'],
                            'keys': post_keys
                        })
        
        return findings
    
    def test_common_endpoints(self):
        """일반적인 API 키 노출 엔드포인트 테스트"""
        common_endpoints = [
            '/.env',
            '/config.json',
            '/config.js',
            '/settings.json',
            '/api/config',
            '/admin/config',
            '/.env.local',
            '/.env.production',
            '/firebase-config.js',
            '/app-config.json'
        ]
        
        findings = []
        
        for endpoint in common_endpoints:
            test_url = self.target_url.rstrip('/') + endpoint
            
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    keys = self.scan_for_keys(response.text)
                    if keys:
                        findings.append({
                            'location': 'exposed_endpoint',
                            'url': test_url,
                            'keys': keys
                        })
            
            except Exception:
                continue
        
        return findings
    
    def scan_for_keys(self, content):
        """텍스트에서 API 키 패턴 검색"""
        found_keys = {}
        
        for key_type, pattern in self.api_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_keys[key_type] = list(set(matches))
        
        return found_keys
    
    def run_full_test(self):
        """전체 테스트 수행"""
        print(f"🔍 Starting comprehensive API key leak test for {self.target_url}")
        print("=" * 60)
        
        all_findings = []
        
        # 1. 클라이언트 측 노출 테스트
        client_findings = self.test_client_side_exposure()
        all_findings.extend(client_findings)
        
        # 2. 네트워크 요청 테스트
        network_findings = self.test_network_requests()
        all_findings.extend(network_findings)
        
        # 3. 일반적인 엔드포인트 테스트
        endpoint_findings = self.test_common_endpoints()
        all_findings.extend(endpoint_findings)
        
        # 결과 출력
        print(f"\n📊 Test Results:")
        print(f"Total findings: {len(all_findings)}")
        
        for finding in all_findings:
            print(f"\n🚨 Location: {finding['location']}")
            if 'url' in finding:
                print(f"   URL: {finding['url']}")
            
            for key_type, keys in finding['keys'].items():
                print(f"   🔑 {key_type.upper()}: {len(keys)} keys")
                for key in keys[:3]:  # 처음 3개만 표시
                    masked_key = key[:10] + "*" * (len(key) - 10)
                    print(f"      - {masked_key}")
                
                if len(keys) > 3:
                    print(f"      ... and {len(keys) - 3} more")
        
        # 정리
        self.driver.quit()
        
        return all_findings

# 사용 예시
if __name__ == "__main__":
    target_url = "https://example.com"
    tester = WebAppAPIKeyTest(target_url)
    
    try:
        findings = tester.run_full_test()
        
        # 결과를 JSON 파일로 저장
        with open(f'api_key_scan_{int(time.time())}.json', 'w') as f:
            json.dump(findings, f, indent=2)
        
        print(f"\n✅ Test completed. Results saved to file.")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
    
    finally:
        # 정리
        try:
            tester.driver.quit()
        except:
            pass
```

## 📊 영향 평가

### 비즈니스 영향

- **금전적 손실**: 무단 API 사용으로 인한 직접적인 비용 발생
- **데이터 유출**: API를 통한 민감한 정보 접근 및 유출
- **서비스 중단**: API 한도 초과로 인한 서비스 중단
- **신뢰도 손상**: 보안 사고로 인한 고객 및 파트너 신뢰 상실
- **규정 위반**: 개인정보보호법, GDPR 등 관련 규정 위반 가능성

### 기술적 영향

- **시스템 침해**: API 키를 통한 추가적인 시스템 접근
- **데이터 조작**: 쓰기 권한이 있는 API 키를 통한 데이터 변조
- **계정 탈취**: API 키를 이용한 사용자 계정 무단 접근
- **서비스 남용**: 봇넷을 통한 대량 API 호출

## 🔧 수정 가이드

### 즉시 적용할 수정사항

1. **모든 하드코딩된 API 키 제거**
2. **환경 변수로 API 키 이전**
3. **Git 히스토리에서 API 키 완전 제거**
4. **노출된 API 키 즉시 무효화 및 재발급**

### 장기적 개선사항

1. **클라우드 비밀 관리 서비스 도입**
2. **API 키 모니터링 및 알림 시스템 구축**
3. **정기적인 키 순환 정책 수립**
4. **개발팀 보안 교육 강화**

## 📚 참고 자료

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## 🎯 결론

API Key Leak은 현대 클라우드 환경에서 가장 위험하고 흔한 보안 취약점 중 하나입니다. 단순한 실수로 시작되어 심각한 금전적, 기술적 피해로 이어질 수 있으므로, 개발 초기 단계부터 체계적인 비밀 관리 체계를 구축하고 지속적인 모니터링을 통해 예방하는 것이 중요합니다.