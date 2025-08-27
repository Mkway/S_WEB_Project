# DOM Clobbering 취약점 분석

## 📋 취약점 개요

**DOM Clobbering**은 HTML 요소를 사용하여 JavaScript의 전역 변수나 객체 속성을 의도치 않게 덮어쓰는 공격 기법입니다. 브라우저의 DOM API 특성을 악용하여 `id`나 `name` 속성을 가진 HTML 요소가 전역 네임스페이스에 노출되는 점을 이용합니다.

### 🎯 공격 원리

1. **전역 네임스페이스 오염**: HTML 요소가 JavaScript 전역 객체에 노출
2. **속성 덮어쓰기**: 기존 변수나 함수를 HTML 요소로 대체
3. **타입 혼동**: 예상된 타입과 다른 객체 타입으로 인한 오동작
4. **보안 우회**: 보안 검증 로직의 우회 또는 무력화

### 🔍 주요 위험성

- **CVSS 점수**: 5.4 (Medium)
- **XSS 우회**: Content Security Policy 우회
- **인증 우회**: 보안 검증 로직 무력화
- **데이터 조작**: 중요한 애플리케이션 데이터 변조

## 🚨 공격 시나리오

### 시나리오 1: 기본 DOM Clobbering

```html
<!-- 취약한 HTML 구조 -->
<!DOCTYPE html>
<html>
<head>
    <script>
        // 전역 변수 선언
        var config = {
            apiUrl: 'https://api.example.com',
            debug: false
        };
        
        function makeApiCall() {
            if (config && config.apiUrl) {
                fetch(config.apiUrl + '/data');
            }
        }
    </script>
</head>
<body>
    <!-- 사용자 입력이 들어갈 수 있는 부분 -->
    <div id="content">
        <!-- 공격자가 삽입한 악성 HTML -->
        <a id="config" href="https://evil.com/api">Click me</a>
    </div>
    
    <script>
        console.log(config); // HTMLAnchorElement 객체가 됨
        console.log(config.apiUrl); // undefined (href 속성이 아니므로)
        
        // makeApiCall() 함수에서 config.apiUrl이 undefined가 되어
        // 의도치 않은 동작 발생
    </script>
</body>
</html>
```

### 시나리오 2: Form Elements Clobbering

```html
<!-- form 요소를 이용한 DOM Clobbering -->
<form>
    <input name="isAdmin" value="true">
    <input name="userId" value="1337">
</form>

<script>
// 기존 변수들이 form elements로 덮어씌워짐
console.log(typeof isAdmin); // "object" (HTMLInputElement)
console.log(isAdmin.value);   // "true"

// 보안 검증 우회 가능성
if (isAdmin && isAdmin.value === "true") {
    // 공격자가 의도한 관리자 권한 획득
    grantAdminAccess();
}
</script>
```

### 시나리오 3: 중첩된 객체 Clobbering

```html
<!-- 중첩된 객체 구조 공격 -->
<html>
<head>
    <script>
        var app = {
            config: {
                env: 'production',
                apiKey: 'secret123'
            }
        };
    </script>
</head>
<body>
    <!-- 공격자가 삽입한 HTML -->
    <div id="app">
        <div id="config">
            <span id="apiKey">hacked_key</span>
        </div>
    </div>
    
    <script>
        console.log(app.config); // HTMLDivElement
        console.log(app.config.apiKey); // HTMLSpanElement
        
        // 문자열 비교시 toString() 호출로 예상치 못한 결과
        if (app.config.apiKey == 'secret123') {
            // false가 되어 정상 로직 실행 안됨
        }
    </script>
</body>
</html>
```

### 시나리오 4: CSP 우회를 통한 XSS

```html
<!-- CSP가 적용된 환경에서의 DOM Clobbering -->
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">

<script>
// 안전하다고 가정한 코드
function loadScript(src) {
    if (typeof src === 'string' && src.startsWith('https://trusted.com/')) {
        var script = document.createElement('script');
        script.src = src;
        document.head.appendChild(script);
    }
}

// 설정에서 스크립트 소스 가져오기
if (window.config && window.config.scriptSrc) {
    loadScript(window.config.scriptSrc);
}
</script>

<!-- 공격자가 삽입한 DOM Clobbering 요소 -->
<iframe name="config" src="javascript:alert('XSS')"></iframe>

<!-- 또는 -->
<a id="config" href="javascript:alert('XSS')">
    <span id="scriptSrc">javascript:alert('XSS')</span>
</a>
```

## 🛡️ 방어 방법

### 1. 안전한 전역 변수 접근

```javascript
// 취약한 코드
function unsafeAccess() {
    if (config && config.apiUrl) {
        return config.apiUrl;
    }
}

// 안전한 코드
function safeAccess() {
    // hasOwnProperty로 실제 속성인지 확인
    if (window.hasOwnProperty('config') && 
        typeof window.config === 'object' &&
        window.config.hasOwnProperty('apiUrl') &&
        typeof window.config.apiUrl === 'string') {
        return window.config.apiUrl;
    }
}

// 더 안전한 접근 방법
const SafeConfigManager = (function() {
    let privateConfig = null;
    
    return {
        setConfig: function(config) {
            // 타입 검증
            if (typeof config !== 'object' || config === null) {
                throw new TypeError('Config must be an object');
            }
            privateConfig = Object.freeze({ ...config });
        },
        
        getConfig: function() {
            return privateConfig ? { ...privateConfig } : null;
        },
        
        getApiUrl: function() {
            return privateConfig && typeof privateConfig.apiUrl === 'string' 
                ? privateConfig.apiUrl 
                : null;
        }
    };
})();

// 사용 예제
SafeConfigManager.setConfig({
    apiUrl: 'https://api.example.com',
    debug: false
});

const apiUrl = SafeConfigManager.getApiUrl();
if (apiUrl) {
    fetch(apiUrl + '/data');
}
```

### 2. DOM Clobbering 방지 라이브러리

```javascript
class DOMClobberingDefense {
    constructor() {
        this.protectedNamespaces = new Set();
        this.originalObjects = new Map();
    }
    
    // 네임스페이스 보호
    protectNamespace(namespace, obj) {
        if (this.protectedNamespaces.has(namespace)) {
            return false;
        }
        
        // 원본 객체 백업
        this.originalObjects.set(namespace, obj);
        
        // 속성 정의로 덮어쓰기 방지
        Object.defineProperty(window, namespace, {
            value: obj,
            writable: false,
            configurable: false,
            enumerable: false
        });
        
        this.protectedNamespaces.add(namespace);
        return true;
    }
    
    // 안전한 속성 접근
    safeAccess(obj, path) {
        if (typeof obj !== 'object' || obj === null) {
            return null;
        }
        
        const keys = Array.isArray(path) ? path : path.split('.');
        let current = obj;
        
        for (const key of keys) {
            // DOM 요소인지 확인
            if (current instanceof Element) {
                return null;
            }
            
            // hasOwnProperty 확인
            if (!Object.prototype.hasOwnProperty.call(current, key)) {
                return null;
            }
            
            current = current[key];
            
            // 각 단계에서 타입 검증
            if (typeof current === 'undefined' || current === null) {
                return null;
            }
        }
        
        return current;
    }
    
    // 전역 변수 무결성 검사
    checkIntegrity() {
        const violations = [];
        
        for (const [namespace, originalObj] of this.originalObjects) {
            const currentObj = window[namespace];
            
            // 타입 변경 감지
            if (typeof currentObj !== typeof originalObj) {
                violations.push({
                    namespace,
                    issue: 'type_mismatch',
                    expected: typeof originalObj,
                    actual: typeof currentObj,
                    currentValue: currentObj
                });
            }
            
            // DOM 요소로 변경 감지
            if (currentObj instanceof Element) {
                violations.push({
                    namespace,
                    issue: 'dom_clobbering',
                    elementType: currentObj.tagName,
                    id: currentObj.id,
                    name: currentObj.name
                });
            }
        }
        
        return violations;
    }
    
    // HTML 정화
    sanitizeHTML(html) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // 위험한 id/name 속성 제거
        const dangerousIds = Array.from(this.protectedNamespaces);
        const elements = doc.querySelectorAll('*[id], *[name]');
        
        elements.forEach(element => {
            const id = element.getAttribute('id');
            const name = element.getAttribute('name');
            
            if (id && this.isDangerousIdentifier(id)) {
                element.removeAttribute('id');
                element.setAttribute('data-original-id', id);
            }
            
            if (name && this.isDangerousIdentifier(name)) {
                element.removeAttribute('name');
                element.setAttribute('data-original-name', name);
            }
        });
        
        return doc.body.innerHTML;
    }
    
    isDangerousIdentifier(identifier) {
        // 보호된 네임스페이스 확인
        if (this.protectedNamespaces.has(identifier)) {
            return true;
        }
        
        // 일반적인 위험한 식별자들
        const dangerousNames = [
            'config', 'app', 'user', 'admin', 'auth', 
            'window', 'document', 'console', 'location',
            'history', 'navigator', 'screen'
        ];
        
        return dangerousNames.includes(identifier.toLowerCase());
    }
    
    // 실시간 모니터링
    startMonitoring(interval = 5000) {
        setInterval(() => {
            const violations = this.checkIntegrity();
            
            if (violations.length > 0) {
                console.warn('DOM Clobbering detected:', violations);
                
                // 보안 이벤트 로깅
                this.logSecurityEvent('dom_clobbering_detected', violations);
                
                // 자동 복구 시도
                this.attemptRestore(violations);
            }
        }, interval);
    }
    
    attemptRestore(violations) {
        violations.forEach(violation => {
            if (this.originalObjects.has(violation.namespace)) {
                const originalObj = this.originalObjects.get(violation.namespace);
                
                try {
                    // 강제로 원본 객체 복구
                    delete window[violation.namespace];
                    window[violation.namespace] = originalObj;
                    
                    console.log(`Restored ${violation.namespace}`);
                } catch (e) {
                    console.error(`Failed to restore ${violation.namespace}:`, e);
                }
            }
        });
    }
    
    logSecurityEvent(event, data) {
        const eventData = {
            timestamp: new Date().toISOString(),
            event,
            data,
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        // 서버로 보안 이벤트 전송
        fetch('/api/security-events', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(eventData)
        }).catch(console.error);
    }
}

// 사용 예제
const defense = new DOMClobberingDefense();

// 중요한 전역 변수 보호
defense.protectNamespace('config', {
    apiUrl: 'https://api.example.com',
    debug: false
});

defense.protectNamespace('userSession', {
    isLoggedIn: true,
    userId: 12345,
    permissions: ['read', 'write']
});

// 안전한 접근 방법
function safeApiCall() {
    const apiUrl = defense.safeAccess(window, 'config.apiUrl');
    
    if (apiUrl && typeof apiUrl === 'string') {
        fetch(apiUrl + '/data');
    } else {
        console.error('Invalid API URL');
    }
}

// 실시간 모니터링 시작
defense.startMonitoring();
```

### 3. Content Security Policy (CSP) 강화

```html
<!-- CSP로 DOM Clobbering 완화 -->
<meta http-equiv="Content-Security-Policy" 
      content="script-src 'self' 'unsafe-eval'; 
               object-src 'none'; 
               base-uri 'none';">

<script>
// CSP와 함께 사용할 안전한 패턴
const SecureApp = (function() {
    'use strict';
    
    // private 스코프에 중요한 데이터 보관
    let config = null;
    let userSession = null;
    
    // 공개 API만 노출
    return {
        init: function(initialConfig) {
            if (typeof initialConfig === 'object' && initialConfig !== null) {
                config = Object.freeze({ ...initialConfig });
            }
        },
        
        setSession: function(session) {
            if (typeof session === 'object' && session !== null) {
                userSession = Object.freeze({ ...session });
            }
        },
        
        getApiUrl: function() {
            return config ? config.apiUrl : null;
        },
        
        isAuthenticated: function() {
            return userSession ? !!userSession.isLoggedIn : false;
        }
    };
})();

// 전역 네임스페이스 최소화
window.App = SecureApp;

// DOM이 변경될 때 검증
const observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
        if (mutation.type === 'childList') {
            mutation.addedNodes.forEach(function(node) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    validateNewElement(node);
                }
            });
        }
    });
});

function validateNewElement(element) {
    // 위험한 id/name 속성 확인
    const dangerousAttributes = ['id', 'name'];
    const protectedNames = ['config', 'app', 'user', 'admin'];
    
    dangerousAttributes.forEach(attr => {
        const value = element.getAttribute(attr);
        if (value && protectedNames.includes(value.toLowerCase())) {
            console.warn(`Potentially dangerous ${attr}="${value}" detected`);
            
            // 속성 제거 또는 수정
            element.removeAttribute(attr);
            element.setAttribute(`data-blocked-${attr}`, value);
        }
    });
    
    // 자식 요소들도 재귀적으로 검사
    element.querySelectorAll('*').forEach(validateNewElement);
}

// DOM 변경 감시 시작
observer.observe(document.body, {
    childList: true,
    subtree: true
});
</script>
```

### 4. 서버사이드 HTML 정화

```php
<?php
class DOMClobberingDefense {
    private $dangerousNames = [
        'config', 'app', 'user', 'admin', 'auth',
        'window', 'document', 'console', 'location',
        'history', 'navigator', 'screen', 'parent',
        'top', 'frames', 'self'
    ];
    
    public function sanitizeHTML($html) {
        $dom = new DOMDocument('1.0', 'UTF-8');
        $dom->loadHTML('<?xml encoding="utf-8" ?>' . $html, 
                      LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        
        $this->sanitizeNode($dom);
        
        return $dom->saveHTML();
    }
    
    private function sanitizeNode($node) {
        if ($node->nodeType === XML_ELEMENT_NODE) {
            // id 속성 확인
            if ($node->hasAttribute('id')) {
                $id = $node->getAttribute('id');
                if ($this->isDangerous($id)) {
                    $node->removeAttribute('id');
                    $node->setAttribute('data-blocked-id', $id);
                }
            }
            
            // name 속성 확인  
            if ($node->hasAttribute('name')) {
                $name = $node->getAttribute('name');
                if ($this->isDangerous($name)) {
                    $node->removeAttribute('name');
                    $node->setAttribute('data-blocked-name', $name);
                }
            }
            
            // 특정 태그 조합 확인
            $this->checkDangerousPatterns($node);
        }
        
        // 자식 노드 재귀 처리
        for ($i = 0; $i < $node->childNodes->length; $i++) {
            $this->sanitizeNode($node->childNodes->item($i));
        }
    }
    
    private function isDangerous($name) {
        // 보호된 이름 목록 확인
        if (in_array(strtolower($name), $this->dangerousNames)) {
            return true;
        }
        
        // 숫자로만 구성된 이름 (배열 인덱스 같은 경우)
        if (preg_match('/^\d+$/', $name)) {
            return true;
        }
        
        // JavaScript 키워드
        $jsKeywords = ['eval', 'function', 'var', 'let', 'const', 'class'];
        if (in_array(strtolower($name), $jsKeywords)) {
            return true;
        }
        
        return false;
    }
    
    private function checkDangerousPatterns($node) {
        $tagName = strtolower($node->tagName);
        
        // form 요소 내부의 input 확인
        if ($tagName === 'form') {
            $inputs = $node->getElementsByTagName('input');
            foreach ($inputs as $input) {
                if ($input->hasAttribute('name') && 
                    $this->isDangerous($input->getAttribute('name'))) {
                    $input->removeAttribute('name');
                }
            }
        }
        
        // iframe의 name 속성 특별 처리
        if ($tagName === 'iframe' && $node->hasAttribute('name')) {
            $node->removeAttribute('name');
        }
        
        // 중첩된 요소들의 id 패턴 확인
        if ($node->hasAttribute('id') && $node->hasChildNodes()) {
            $parentId = $node->getAttribute('id');
            if ($this->isDangerous($parentId)) {
                // 자식 요소들의 id도 함께 제거
                $this->removeChildIds($node);
            }
        }
    }
    
    private function removeChildIds($node) {
        if ($node->nodeType === XML_ELEMENT_NODE && $node->hasAttribute('id')) {
            $node->removeAttribute('id');
        }
        
        for ($i = 0; $i < $node->childNodes->length; $i++) {
            $this->removeChildIds($node->childNodes->item($i));
        }
    }
    
    public function validateUserInput($html) {
        $violations = [];
        
        $dom = new DOMDocument();
        $dom->loadHTML('<?xml encoding="utf-8" ?>' . $html, 
                      LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        
        $elements = $dom->getElementsByTagName('*');
        
        foreach ($elements as $element) {
            if ($element->hasAttribute('id')) {
                $id = $element->getAttribute('id');
                if ($this->isDangerous($id)) {
                    $violations[] = [
                        'type' => 'dangerous_id',
                        'value' => $id,
                        'element' => $element->tagName
                    ];
                }
            }
            
            if ($element->hasAttribute('name')) {
                $name = $element->getAttribute('name');
                if ($this->isDangerous($name)) {
                    $violations[] = [
                        'type' => 'dangerous_name',
                        'value' => $name,
                        'element' => $element->tagName
                    ];
                }
            }
        }
        
        return $violations;
    }
}

// 사용 예제
$defense = new DOMClobberingDefense();

// 사용자 입력 HTML 정화
$userHTML = $_POST['content'] ?? '';
$violations = $defense->validateUserInput($userHTML);

if (!empty($violations)) {
    error_log('DOM Clobbering attempt: ' . json_encode($violations));
}

$safeHTML = $defense->sanitizeHTML($userHTML);
echo $safeHTML;
?>
```

## 🧪 테스트 방법

### 1. DOM Clobbering 취약점 스캐너

```javascript
class DOMClobberingScanner {
    constructor() {
        this.testCases = [
            {
                name: 'basic_id_clobbering',
                payload: '<div id="config">test</div>',
                target: 'config'
            },
            {
                name: 'form_name_clobbering',
                payload: '<form><input name="isAdmin" value="true"></form>',
                target: 'isAdmin'
            },
            {
                name: 'nested_clobbering',
                payload: '<div id="app"><div id="config"><span id="apiKey">evil</span></div></div>',
                target: 'app'
            },
            {
                name: 'iframe_clobbering',
                payload: '<iframe name="config" src="about:blank"></iframe>',
                target: 'config'
            }
        ];
        
        this.results = [];
    }
    
    async scanPage(url) {
        console.log(`Scanning ${url} for DOM Clobbering vulnerabilities...`);
        
        for (const testCase of this.testCases) {
            await this.testDOMClobbering(url, testCase);
        }
        
        return this.generateReport();
    }
    
    async testDOMClobbering(url, testCase) {
        try {
            // 페이로드를 포함한 HTML 생성
            const testHTML = `
                <html>
                <head>
                    <script>
                        // 원본 전역 변수 설정
                        window.${testCase.target} = { original: true };
                    </script>
                </head>
                <body>
                    ${testCase.payload}
                    <script>
                        // DOM Clobbering 확인
                        const result = {
                            testName: '${testCase.name}',
                            target: '${testCase.target}',
                            originalType: typeof window.${testCase.target},
                            isElement: window.${testCase.target} instanceof Element,
                            hasOriginalProperty: window.${testCase.target} && window.${testCase.target}.original,
                            clobbered: false
                        };
                        
                        if (window.${testCase.target} instanceof Element) {
                            result.clobbered = true;
                            result.elementType = window.${testCase.target}.tagName;
                            result.elementId = window.${testCase.target}.id;
                            result.elementName = window.${testCase.target}.name;
                        }
                        
                        console.log('DOM_CLOBBERING_TEST:', JSON.stringify(result));
                    </script>
                </body>
                </html>
            `;
            
            // 결과 저장 (실제 구현에서는 브라우저 자동화 도구 사용)
            this.results.push({
                testCase: testCase.name,
                vulnerable: true, // 실제로는 브라우저에서 확인된 결과
                payload: testCase.payload,
                target: testCase.target
            });
            
        } catch (error) {
            console.error(`Test ${testCase.name} failed:`, error);
        }
    }
    
    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            totalTests: this.testCases.length,
            vulnerableTests: this.results.filter(r => r.vulnerable).length,
            results: this.results
        };
        
        console.log('DOM Clobbering Scan Report:');
        console.log('============================');
        console.log(`Total Tests: ${report.totalTests}`);
        console.log(`Vulnerable: ${report.vulnerableTests}`);
        
        report.results.forEach(result => {
            if (result.vulnerable) {
                console.log(`❌ ${result.testCase}: VULNERABLE`);
                console.log(`   Payload: ${result.payload}`);
                console.log(`   Target: ${result.target}`);
            } else {
                console.log(`✅ ${result.testCase}: SAFE`);
            }
        });
        
        return report;
    }
}

// 브라우저에서의 실시간 테스트
function testCurrentPage() {
    const tests = [
        () => {
            const div = document.createElement('div');
            div.id = 'config';
            document.body.appendChild(div);
            
            return {
                test: 'config_clobbering',
                vulnerable: window.config instanceof Element,
                element: window.config
            };
        },
        
        () => {
            const form = document.createElement('form');
            const input = document.createElement('input');
            input.name = 'isAdmin';
            input.value = 'true';
            form.appendChild(input);
            document.body.appendChild(form);
            
            return {
                test: 'form_clobbering',
                vulnerable: window.isAdmin instanceof Element,
                element: window.isAdmin
            };
        }
    ];
    
    const results = tests.map(test => {
        try {
            return test();
        } catch (e) {
            return { test: 'error', error: e.message };
        }
    });
    
    console.log('DOM Clobbering Test Results:', results);
    return results;
}

// 사용 예제
const scanner = new DOMClobberingScanner();
// scanner.scanPage('http://target.com');

// 현재 페이지에서 즉시 테스트
// testCurrentPage();
```

### 2. 자동화된 DOM Clobbering 방어 테스트

```python
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import json

class DOMClobberingTester:
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        
        self.driver = webdriver.Chrome(options=chrome_options)
        
        self.test_payloads = [
            '<div id="config">clobbered</div>',
            '<form><input name="user" value="admin"></form>',
            '<iframe name="location" src="about:blank"></iframe>',
            '<img name="document" src="x">',
            '<a id="app" href="#">test</a>',
            '<div id="window">evil</div>',
            '<form><input name="console" value="hacked"></form>'
        ]
    
    def test_dom_clobbering_protection(self, url, input_field_selector):
        results = []
        
        for payload in self.test_payloads:
            try:
                self.driver.get(url)
                
                # 입력 필드에 페이로드 입력
                input_field = self.driver.find_element("css selector", input_field_selector)
                input_field.clear()
                input_field.send_keys(payload)
                
                # 폼 제출
                submit_button = self.driver.find_element("css selector", "input[type='submit']")
                submit_button.click()
                
                # JavaScript 실행하여 DOM Clobbering 확인
                test_script = """
                var result = {
                    payload: arguments[0],
                    tests: {}
                };
                
                // 일반적인 전역 변수들 확인
                var targets = ['config', 'app', 'user', 'admin', 'window', 'document'];
                
                targets.forEach(function(target) {
                    if (window[target]) {
                        result.tests[target] = {
                            type: typeof window[target],
                            isElement: window[target] instanceof Element,
                            value: window[target].toString()
                        };
                    }
                });
                
                return result;
                """
                
                result = self.driver.execute_script(test_script, payload)
                
                # 취약점 확인
                vulnerable = any(
                    test_data['isElement'] 
                    for test_data in result['tests'].values()
                )
                
                results.append({
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'details': result['tests']
                })
                
            except Exception as e:
                results.append({
                    'payload': payload,
                    'error': str(e)
                })
        
        return results
    
    def test_csp_effectiveness(self, url):
        """CSP가 DOM Clobbering을 얼마나 막는지 테스트"""
        self.driver.get(url)
        
        # CSP 헤더 확인
        csp_script = """
        var meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        return meta ? meta.content : null;
        """
        
        csp_content = self.driver.execute_script(csp_script)
        
        # DOM Clobbering 시도
        clobbering_script = """
        try {
            var div = document.createElement('div');
            div.id = 'config';
            document.body.appendChild(div);
            
            return {
                success: true,
                configType: typeof window.config,
                isElement: window.config instanceof Element
            };
        } catch (e) {
            return {
                success: false,
                error: e.message
            };
        }
        """
        
        result = self.driver.execute_script(clobbering_script)
        
        return {
            'csp_header': csp_content,
            'clobbering_test': result
        }
    
    def generate_report(self, test_results):
        """테스트 결과 보고서 생성"""
        total_tests = len(test_results)
        vulnerable_tests = sum(1 for r in test_results if r.get('vulnerable', False))
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'vulnerable_tests': vulnerable_tests,
                'protection_rate': ((total_tests - vulnerable_tests) / total_tests * 100) if total_tests > 0 else 0
            },
            'details': test_results
        }
        
        print("DOM Clobbering Protection Test Report")
        print("====================================")
        print(f"Total Tests: {total_tests}")
        print(f"Vulnerable Tests: {vulnerable_tests}")
        print(f"Protection Rate: {report['summary']['protection_rate']:.1f}%")
        
        for result in test_results:
            if result.get('vulnerable'):
                print(f"\n❌ VULNERABLE: {result['payload']}")
                for target, details in result.get('details', {}).items():
                    if details['isElement']:
                        print(f"   {target} clobbered as {details['type']}")
        
        return report
    
    def cleanup(self):
        """리소스 정리"""
        self.driver.quit()

# 사용 예제
tester = DOMClobberingTester()

try:
    # 웹 애플리케이션 테스트
    results = tester.test_dom_clobbering_protection(
        'http://target.com/feedback', 
        'textarea[name="comment"]'
    )
    
    # CSP 효과성 테스트
    csp_result = tester.test_csp_effectiveness('http://target.com')
    print(f"CSP Test Result: {csp_result}")
    
    # 보고서 생성
    report = tester.generate_report(results)
    
finally:
    tester.cleanup()
```

## 📚 참고 자료

### 공식 문서
- [OWASP DOM Clobbering](https://owasp.org/www-community/attacks/DOM_Clobbering)
- [PortSwigger DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)

### 보안 가이드
- [MDN Web API Security](https://developer.mozilla.org/en-US/docs/Web/API)
- [Google Web Fundamentals Security](https://developers.google.com/web/fundamentals/security)

### 도구 및 리소스
- [DOM Invader (Burp Suite Extension)](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [OWASP ZAP DOM XSS Scanner](https://owasp.org/www-project-zap/)

---

## 🎯 핵심 요약

1. **네임스페이스 보호**: 중요한 전역 변수를 private 스코프에 보관
2. **타입 검증**: 모든 전역 객체 접근 시 타입 및 인스턴스 확인
3. **HTML 정화**: 사용자 입력의 위험한 id/name 속성 제거
4. **실시간 모니터링**: DOM 변경 감지 및 무결성 검사

**⚠️ 주의**: DOM Clobbering은 브라우저의 고유 동작을 악용하므로 JavaScript 레벨에서의 방어가 핵심입니다.