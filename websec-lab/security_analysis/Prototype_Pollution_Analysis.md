# Prototype Pollution 취약점 분석

## 📋 취약점 개요

**Prototype Pollution**은 JavaScript의 프로토타입 기반 상속 구조를 악용하여 Object.prototype이나 다른 생성자 함수의 prototype을 오염시키는 공격입니다. 공격자가 특별히 조작된 JSON 페이로드나 쿼리 파라미터를 통해 모든 객체에 영향을 미치는 속성을 추가하거나 수정할 수 있습니다.

### 🎯 공격 원리

1. **프로토타입 체인 조작**: `__proto__`나 `constructor.prototype` 경로 이용
2. **객체 병합 취약점**: 안전하지 않은 객체 병합 함수 악용
3. **전역 오염**: 모든 객체 인스턴스에 영향을 미치는 속성 추가
4. **애플리케이션 로직 우회**: 보안 검증이나 기능 무력화

### 🔍 주요 위험성

- **CVSS 점수**: 7.3 (High)
- **원격 코드 실행**: 서버사이드 JavaScript 환경에서 RCE 가능
- **권한 상승**: 애플리케이션 권한 검증 우회
- **서비스 거부**: 애플리케이션 로직 파괴로 인한 DoS

## 🚨 공격 시나리오

### 시나리오 1: 기본 Prototype Pollution

```javascript
// 취약한 객체 병합 함수
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 공격 페이로드
const maliciousPayload = JSON.parse('{"__proto__": {"isAdmin": true}}');

// 빈 객체에 병합
const config = {};
merge(config, maliciousPayload);

// 모든 객체가 영향받음
const user = {};
console.log(user.isAdmin); // true (오염됨!)

// 보안 검증 우회
function checkAdmin(userObj) {
    if (userObj.isAdmin) {
        return grantAdminAccess();
    }
    return denyAccess();
}

checkAdmin({}); // 관리자 권한 획득!
```

### 시나리오 2: 쿼리 파라미터를 통한 공격

```javascript
// Express.js 애플리케이션 예시
const express = require('express');
const app = express();

// 취약한 쿼리 파라미터 처리
app.get('/search', (req, res) => {
    const searchOptions = {};
    
    // 안전하지 않은 파라미터 병합
    Object.assign(searchOptions, req.query);
    
    // 검색 수행
    performSearch(searchOptions);
});

// 공격 URL:
// /search?__proto__[isAdmin]=true&__proto__[allowedCommands][]=rm&__proto__[allowedCommands][]=cp

// 결과: 모든 객체가 isAdmin과 allowedCommands 속성을 가지게 됨
```

### 시나리오 3: JSON 파싱을 통한 공격

```javascript
// 취약한 설정 파일 처리
function loadConfig(jsonString) {
    const config = JSON.parse(jsonString);
    const defaultConfig = {};
    
    // 재귀적 병합 (취약)
    function deepMerge(target, source) {
        for (const key in source) {
            if (source[key] && typeof source[key] === 'object') {
                target[key] = target[key] || {};
                deepMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
        return target;
    }
    
    return deepMerge(defaultConfig, config);
}

// 공격 페이로드
const attackPayload = `{
    "theme": "dark",
    "__proto__": {
        "toString": "alert('XSS')",
        "valueOf": "console.log('Polluted')",
        "isAdmin": true,
        "executeCommand": "rm -rf /"
    }
}`;

loadConfig(attackPayload);

// 이제 모든 객체가 오염됨
const normalUser = {};
console.log(normalUser.isAdmin); // true
```

### 시나리오 4: Node.js에서 RCE 공격

```javascript
// Node.js 환경에서의 위험한 Prototype Pollution
const childProcess = require('child_process');

// 취약한 템플릿 렌더링 함수
function renderTemplate(template, data) {
    // 안전하지 않은 데이터 병합
    const context = {};
    merge(context, data);  // 앞서 정의한 취약한 merge 함수
    
    // 템플릿에서 속성 참조
    if (context.shell && context.command) {
        // 위험: 동적 명령 실행
        return childProcess.execSync(context.command, { shell: context.shell });
    }
    
    return template.replace(/\{\{(\w+)\}\}/g, (match, prop) => {
        return context[prop] || '';
    });
}

// 공격 페이로드
const rcePayload = {
    "name": "John",
    "__proto__": {
        "shell": "/bin/bash",
        "command": "cat /etc/passwd"
    }
};

// RCE 실행
try {
    const result = renderTemplate("Hello {{name}}", rcePayload);
    console.log('Command executed:', result.toString());
} catch (e) {
    console.error('RCE attempt failed:', e.message);
}
```

### 시나리오 5: 클라이언트사이드 DOM 기반 공격

```html
<!DOCTYPE html>
<html>
<head>
    <title>Prototype Pollution XSS</title>
</head>
<body>
    <script>
        // 취약한 URL 파라미터 파싱
        function parseUrlParams() {
            const params = {};
            const urlParams = new URLSearchParams(window.location.search);
            
            for (const [key, value] of urlParams) {
                // 중첩된 객체 지원 (취약점)
                const keys = key.split('.');
                let current = params;
                
                for (let i = 0; i < keys.length - 1; i++) {
                    current[keys[i]] = current[keys[i]] || {};
                    current = current[keys[i]];
                }
                
                current[keys[keys.length - 1]] = value;
            }
            
            return params;
        }
        
        // DOM 업데이트 함수
        function updateDOM(config) {
            // 프로토타입 오염으로 인한 XSS
            if (config.innerHTML) {
                document.body.innerHTML = config.innerHTML;
            }
        }
        
        // URL: /?__proto__.innerHTML=<img src=x onerror=alert('XSS')>
        const config = parseUrlParams();
        
        // 모든 객체가 innerHTML 속성을 가지게 됨
        const emptyObj = {};
        updateDOM(emptyObj); // XSS 실행!
    </script>
</body>
</html>
```

## 🛡️ 방어 방법

### 1. 안전한 객체 병합

```javascript
// 안전한 객체 병합 함수
function safeMerge(target, source, options = {}) {
    const {
        allowedKeys = null,
        maxDepth = 10,
        preventPrototypePollution = true
    } = options;
    
    function isPrototypePolluting(key) {
        return [
            '__proto__',
            'constructor',
            'prototype'
        ].includes(key);
    }
    
    function deepMerge(target, source, depth = 0) {
        if (depth > maxDepth) {
            throw new Error('Maximum merge depth exceeded');
        }
        
        for (const key in source) {
            // Object.hasOwnProperty 대신 안전한 방법 사용
            if (!Object.prototype.hasOwnProperty.call(source, key)) {
                continue;
            }
            
            // 프로토타입 오염 방지
            if (preventPrototypePollution && isPrototypePolluting(key)) {
                console.warn(`Blocked potentially dangerous key: ${key}`);
                continue;
            }
            
            // 허용된 키 검증
            if (allowedKeys && !allowedKeys.includes(key)) {
                console.warn(`Blocked unauthorized key: ${key}`);
                continue;
            }
            
            const sourceValue = source[key];
            
            if (sourceValue && typeof sourceValue === 'object' && 
                !Array.isArray(sourceValue) && sourceValue.constructor === Object) {
                
                // 중첩 객체 처리
                if (!target[key] || typeof target[key] !== 'object') {
                    target[key] = {};
                }
                
                deepMerge(target[key], sourceValue, depth + 1);
            } else {
                // 원시값 또는 배열
                target[key] = sourceValue;
            }
        }
        
        return target;
    }
    
    return deepMerge(target, source);
}

// 사용 예제
const config = {};
const userInput = {
    name: 'John',
    settings: { theme: 'dark' },
    __proto__: { isAdmin: true }  // 차단됨
};

const result = safeMerge(config, userInput, {
    allowedKeys: ['name', 'settings', 'preferences'],
    maxDepth: 3
});

console.log(result); // { name: 'John', settings: { theme: 'dark' } }
console.log({}.isAdmin); // undefined (오염되지 않음)
```

### 2. JSON 안전 파싱

```javascript
// 안전한 JSON 파서
class SafeJSONParser {
    constructor(options = {}) {
        this.maxDepth = options.maxDepth || 10;
        this.maxKeys = options.maxKeys || 1000;
        this.allowedKeys = options.allowedKeys;
        this.blockedKeys = options.blockedKeys || [
            '__proto__', 'constructor', 'prototype'
        ];
    }
    
    parse(jsonString) {
        let parsed;
        
        try {
            parsed = JSON.parse(jsonString);
        } catch (e) {
            throw new Error('Invalid JSON format');
        }
        
        return this.sanitize(parsed);
    }
    
    sanitize(obj, depth = 0, keyCount = { count: 0 }) {
        if (depth > this.maxDepth) {
            throw new Error('Maximum object depth exceeded');
        }
        
        if (keyCount.count > this.maxKeys) {
            throw new Error('Maximum key count exceeded');
        }
        
        if (obj === null || typeof obj !== 'object') {
            return obj;
        }
        
        if (Array.isArray(obj)) {
            return obj.map(item => this.sanitize(item, depth + 1, keyCount));
        }
        
        const sanitized = Object.create(null); // 프로토타입 없는 객체 생성
        
        for (const key in obj) {
            if (!Object.prototype.hasOwnProperty.call(obj, key)) {
                continue;
            }
            
            keyCount.count++;
            
            // 차단된 키 확인
            if (this.blockedKeys.includes(key)) {
                console.warn(`Blocked dangerous key during parsing: ${key}`);
                continue;
            }
            
            // 허용된 키 확인
            if (this.allowedKeys && !this.allowedKeys.includes(key)) {
                console.warn(`Blocked unauthorized key during parsing: ${key}`);
                continue;
            }
            
            sanitized[key] = this.sanitize(obj[key], depth + 1, keyCount);
        }
        
        return sanitized;
    }
    
    stringify(obj, replacer = null, space = null) {
        return JSON.stringify(obj, (key, value) => {
            // 위험한 키 필터링
            if (this.blockedKeys.includes(key)) {
                return undefined;
            }
            
            if (replacer) {
                return replacer(key, value);
            }
            
            return value;
        }, space);
    }
}

// 사용 예제
const safeParser = new SafeJSONParser({
    maxDepth: 5,
    maxKeys: 100,
    allowedKeys: ['name', 'email', 'settings', 'preferences'],
    blockedKeys: ['__proto__', 'constructor', 'prototype', 'toString', 'valueOf']
});

const maliciousJSON = '{"name": "John", "__proto__": {"isAdmin": true}}';

try {
    const safe = safeParser.parse(maliciousJSON);
    console.log(safe); // { name: 'John' }
    console.log({}.isAdmin); // undefined
} catch (e) {
    console.error('Parsing failed:', e.message);
}
```

### 3. Express.js 미들웨어 보호

```javascript
const express = require('express');

// Prototype Pollution 방지 미들웨어
function prototypePollutionProtection(options = {}) {
    const {
        blockedKeys = ['__proto__', 'constructor', 'prototype'],
        logAttempts = true,
        throwOnViolation = false
    } = options;
    
    function sanitizeObject(obj, path = '') {
        if (obj === null || typeof obj !== 'object') {
            return obj;
        }
        
        if (Array.isArray(obj)) {
            return obj.map((item, index) => 
                sanitizeObject(item, `${path}[${index}]`)
            );
        }
        
        const sanitized = {};
        
        for (const key in obj) {
            if (!Object.prototype.hasOwnProperty.call(obj, key)) {
                continue;
            }
            
            const currentPath = path ? `${path}.${key}` : key;
            
            if (blockedKeys.includes(key)) {
                if (logAttempts) {
                    console.warn(`Prototype pollution attempt blocked at ${currentPath}`);
                }
                
                if (throwOnViolation) {
                    const error = new Error(`Dangerous key detected: ${key}`);
                    error.status = 400;
                    throw error;
                }
                
                continue;
            }
            
            sanitized[key] = sanitizeObject(obj[key], currentPath);
        }
        
        return sanitized;
    }
    
    return (req, res, next) => {
        try {
            // Query parameters 정화
            if (req.query && typeof req.query === 'object') {
                req.query = sanitizeObject(req.query, 'query');
            }
            
            // Request body 정화
            if (req.body && typeof req.body === 'object') {
                req.body = sanitizeObject(req.body, 'body');
            }
            
            // Parameters 정화
            if (req.params && typeof req.params === 'object') {
                req.params = sanitizeObject(req.params, 'params');
            }
            
            next();
        } catch (error) {
            next(error);
        }
    };
}

// Express 애플리케이션에 적용
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 프로토타입 오염 방지 미들웨어 적용
app.use(prototypePollutionProtection({
    logAttempts: true,
    throwOnViolation: true
}));

// 테스트 라우트
app.post('/api/config', (req, res) => {
    const config = {};
    Object.assign(config, req.body);
    
    res.json({
        success: true,
        config: config,
        globalCheck: ({}).isAdmin // undefined이어야 함
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

### 4. 프로토타입 고정(Freezing)

```javascript
// Object prototype 보호
function lockDownPrototypes() {
    // Object.prototype 동결
    if (Object.prototype) {
        Object.freeze(Object.prototype);
        Object.seal(Object.prototype);
    }
    
    // Array.prototype 동결
    if (Array.prototype) {
        Object.freeze(Array.prototype);
        Object.seal(Array.prototype);
    }
    
    // Function.prototype 동결
    if (Function.prototype) {
        Object.freeze(Function.prototype);
        Object.seal(Function.prototype);
    }
    
    // String.prototype 동결
    if (String.prototype) {
        Object.freeze(String.prototype);
        Object.seal(String.prototype);
    }
    
    console.log('All prototypes have been locked down');
}

// 애플리케이션 시작시 실행
lockDownPrototypes();

// 테스트: 프로토타입 수정 시도
try {
    Object.prototype.isAdmin = true;
    console.log({}.isAdmin); // undefined (수정 실패)
} catch (e) {
    console.log('Prototype modification blocked:', e.message);
}
```

### 5. 런타임 프로토타입 모니터링

```javascript
// 프로토타입 변조 감지 시스템
class PrototypeMonitor {
    constructor() {
        this.originalPrototypes = new Map();
        this.monitoredObjects = [Object, Array, Function, String, Number];
        this.alertCallbacks = [];
        
        this.takeSnapshot();
        this.startMonitoring();
    }
    
    takeSnapshot() {
        for (const Constructor of this.monitoredObjects) {
            const properties = Object.getOwnPropertyNames(Constructor.prototype);
            this.originalPrototypes.set(Constructor.name, new Set(properties));
        }
    }
    
    startMonitoring() {
        setInterval(() => {
            this.checkForChanges();
        }, 1000); // 1초마다 확인
    }
    
    checkForChanges() {
        for (const Constructor of this.monitoredObjects) {
            const currentProperties = Object.getOwnPropertyNames(Constructor.prototype);
            const originalProperties = this.originalPrototypes.get(Constructor.name);
            
            const newProperties = currentProperties.filter(
                prop => !originalProperties.has(prop)
            );
            
            if (newProperties.length > 0) {
                this.handlePrototypePollution(Constructor.name, newProperties);
            }
        }
    }
    
    handlePrototypePollution(constructorName, newProperties) {
        const alert = {
            timestamp: new Date().toISOString(),
            type: 'prototype_pollution_detected',
            constructor: constructorName,
            addedProperties: newProperties,
            severity: 'HIGH'
        };
        
        console.error('SECURITY ALERT:', alert);
        
        // 콜백 실행
        this.alertCallbacks.forEach(callback => {
            try {
                callback(alert);
            } catch (e) {
                console.error('Alert callback failed:', e);
            }
        });
        
        // 자동 정화 시도
        this.cleanupPrototype(constructorName, newProperties);
    }
    
    cleanupPrototype(constructorName, properties) {
        const Constructor = global[constructorName] || window[constructorName];
        
        if (Constructor && Constructor.prototype) {
            for (const prop of properties) {
                try {
                    delete Constructor.prototype[prop];
                    console.log(`Cleaned up property: ${constructorName}.prototype.${prop}`);
                } catch (e) {
                    console.warn(`Failed to cleanup property: ${prop}`, e.message);
                }
            }
        }
    }
    
    addAlertCallback(callback) {
        this.alertCallbacks.push(callback);
    }
    
    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            monitoredConstructors: this.monitoredObjects.map(c => c.name),
            originalPropertyCounts: {}
        };
        
        for (const [name, properties] of this.originalPrototypes) {
            report.originalPropertyCounts[name] = properties.size;
        }
        
        return report;
    }
}

// 모니터링 시작
const monitor = new PrototypeMonitor();

// 알림 콜백 추가
monitor.addAlertCallback((alert) => {
    // 슬랙이나 이메일로 알림 전송
    console.log('Sending security alert:', alert);
});

// 테스트
setTimeout(() => {
    Object.prototype.testProp = 'polluted';
}, 2000);
```

## 🧪 테스트 방법

### 1. 자동화된 Prototype Pollution 스캐너

```javascript
class PrototypePollutionScanner {
    constructor() {
        this.testPayloads = [
            // 기본 __proto__ 공격
            { "__proto__": { "isAdmin": true } },
            { "__proto__": { "polluted": "yes" } },
            
            // constructor 공격
            { "constructor": { "prototype": { "isAdmin": true } } },
            
            // 중첩된 경로
            { "user": { "__proto__": { "role": "admin" } } },
            
            // 배열을 통한 공격
            { "__proto__": ["polluted"] },
            
            // toString 오염
            { "__proto__": { "toString": "alert('XSS')" } },
            
            // valueOf 오염
            { "__proto__": { "valueOf": "console.log('Polluted')" } }
        ];
        
        this.vulnerabilities = [];
    }
    
    async scanEndpoint(url, method = 'POST') {
        console.log(`Scanning ${url} for Prototype Pollution...`);
        
        for (let i = 0; i < this.testPayloads.length; i++) {
            const payload = this.testPayloads[i];
            
            try {
                const result = await this.testPayload(url, method, payload, i);
                if (result.vulnerable) {
                    this.vulnerabilities.push(result);
                }
            } catch (e) {
                console.error(`Test ${i} failed:`, e.message);
            }
        }
        
        return this.generateReport();
    }
    
    async testPayload(url, method, payload, testId) {
        const testResult = {
            testId,
            payload,
            vulnerable: false,
            evidence: null,
            response: null
        };
        
        try {
            const response = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });
            
            const responseText = await response.text();
            testResult.response = {
                status: response.status,
                headers: Object.fromEntries(response.headers),
                body: responseText
            };
            
            // 응답에서 오염 증거 찾기
            const evidence = this.detectPollutionEvidence(responseText, payload);
            if (evidence) {
                testResult.vulnerable = true;
                testResult.evidence = evidence;
            }
            
        } catch (e) {
            testResult.error = e.message;
        }
        
        return testResult;
    }
    
    detectPollutionEvidence(responseText, payload) {
        const evidence = [];
        
        // JSON 응답에서 오염된 속성 찾기
        try {
            const jsonResponse = JSON.parse(responseText);
            
            // __proto__ 페이로드의 속성들이 빈 객체에 나타나는지 확인
            if (payload.__proto__) {
                for (const [key, value] of Object.entries(payload.__proto__)) {
                    if (this.checkForPollution(jsonResponse, key, value)) {
                        evidence.push({
                            type: 'prototype_pollution',
                            key,
                            expectedValue: value,
                            found: true
                        });
                    }
                }
            }
            
        } catch (e) {
            // JSON이 아닌 응답의 경우 문자열 검색
            if (responseText.includes('"polluted":"yes"') || 
                responseText.includes('"isAdmin":true')) {
                evidence.push({
                    type: 'string_evidence',
                    content: responseText.substring(0, 200)
                });
            }
        }
        
        return evidence.length > 0 ? evidence : null;
    }
    
    checkForPollution(obj, key, expectedValue) {
        // 빈 객체가 해당 속성을 가지는지 확인
        if (obj && typeof obj === 'object') {
            // 응답에서 빈 객체나 새로운 객체가 오염된 속성을 가지는지 확인
            const emptyObjCheck = obj.globalCheck || obj.emptyObject || {};
            return emptyObjCheck[key] === expectedValue;
        }
        
        return false;
    }
    
    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            totalTests: this.testPayloads.length,
            vulnerableTests: this.vulnerabilities.length,
            riskLevel: this.calculateRiskLevel(),
            vulnerabilities: this.vulnerabilities,
            recommendations: this.getRecommendations()
        };
        
        console.log('\n=== Prototype Pollution Scan Report ===');
        console.log(`Total tests: ${report.totalTests}`);
        console.log(`Vulnerable tests: ${report.vulnerableTests}`);
        console.log(`Risk level: ${report.riskLevel}`);
        
        if (report.vulnerableTests > 0) {
            console.log('\nVulnerabilities found:');
            this.vulnerabilities.forEach((vuln, i) => {
                console.log(`${i + 1}. Test ${vuln.testId}: ${JSON.stringify(vuln.payload)}`);
                if (vuln.evidence) {
                    console.log(`   Evidence: ${JSON.stringify(vuln.evidence)}`);
                }
            });
        }
        
        return report;
    }
    
    calculateRiskLevel() {
        const vulnCount = this.vulnerabilities.length;
        if (vulnCount === 0) return 'LOW';
        if (vulnCount <= 2) return 'MEDIUM';
        return 'HIGH';
    }
    
    getRecommendations() {
        const recommendations = [
            'Implement safe object merging functions',
            'Validate and sanitize all user input',
            'Use Object.create(null) for config objects',
            'Freeze Object.prototype at application startup'
        ];
        
        if (this.vulnerabilities.length > 0) {
            recommendations.push(
                'Implement prototype pollution detection middleware',
                'Add runtime prototype monitoring',
                'Review all object manipulation code'
            );
        }
        
        return recommendations;
    }
}

// 사용 예제
const scanner = new PrototypePollutionScanner();

// 엔드포인트 스캔
scanner.scanEndpoint('http://localhost:3000/api/config')
    .then(report => {
        console.log('Scan completed');
        
        if (report.riskLevel !== 'LOW') {
            console.log('\nRecommendations:');
            report.recommendations.forEach((rec, i) => {
                console.log(`${i + 1}. ${rec}`);
            });
        }
    })
    .catch(error => {
        console.error('Scan failed:', error);
    });
```

### 2. 브라우저 기반 테스트 도구

```html
<!DOCTYPE html>
<html>
<head>
    <title>Prototype Pollution Tester</title>
</head>
<body>
    <h1>Prototype Pollution Test Suite</h1>
    <div id="results"></div>
    
    <script>
        class BrowserPrototypePollutionTester {
            constructor() {
                this.results = [];
                this.testCases = [
                    {
                        name: 'Basic __proto__ pollution',
                        test: () => {
                            const obj = {};
                            this.merge(obj, JSON.parse('{"__proto__": {"polluted": true}}'));
                            return ({}).polluted === true;
                        }
                    },
                    {
                        name: 'constructor.prototype pollution',
                        test: () => {
                            const obj = {};
                            this.merge(obj, {"constructor": {"prototype": {"polluted2": true}}});
                            return ({}).polluted2 === true;
                        }
                    },
                    {
                        name: 'toString pollution',
                        test: () => {
                            const obj = {};
                            this.merge(obj, JSON.parse('{"__proto__": {"toString": "polluted"}}'));
                            return ({}).toString === "polluted";
                        }
                    },
                    {
                        name: 'Array prototype pollution',
                        test: () => {
                            const obj = {};
                            this.merge(obj, JSON.parse('{"__proto__": {"customProp": "array-polluted"}}'));
                            return [].customProp === "array-polluted";
                        }
                    }
                ];
            }
            
            // 취약한 merge 함수 (테스트용)
            merge(target, source) {
                for (let key in source) {
                    if (typeof source[key] === 'object' && source[key] !== null) {
                        if (!target[key]) target[key] = {};
                        this.merge(target[key], source[key]);
                    } else {
                        target[key] = source[key];
                    }
                }
                return target;
            }
            
            runAllTests() {
                console.log('Running Prototype Pollution tests...');
                
                this.testCases.forEach((testCase, index) => {
                    try {
                        const startTime = performance.now();
                        const result = testCase.test();
                        const endTime = performance.now();
                        
                        this.results.push({
                            name: testCase.name,
                            passed: result,
                            duration: endTime - startTime,
                            vulnerable: result // 이 경우 취약하면 테스트가 성공
                        });
                        
                        console.log(`${testCase.name}: ${result ? 'VULNERABLE' : 'SAFE'}`);
                        
                    } catch (error) {
                        this.results.push({
                            name: testCase.name,
                            passed: false,
                            error: error.message,
                            vulnerable: false
                        });
                        
                        console.error(`${testCase.name}: ERROR - ${error.message}`);
                    }
                });
                
                this.displayResults();
                return this.generateSummary();
            }
            
            displayResults() {
                const resultsDiv = document.getElementById('results');
                let html = '<h2>Test Results</h2>';
                
                this.results.forEach(result => {
                    const status = result.vulnerable ? 'VULNERABLE ⚠️' : 'SAFE ✅';
                    const color = result.vulnerable ? 'red' : 'green';
                    
                    html += `
                        <div style="margin: 10px 0; padding: 10px; border: 1px solid ${color};">
                            <strong>${result.name}</strong>: 
                            <span style="color: ${color}">${status}</span>
                            ${result.duration ? ` (${result.duration.toFixed(2)}ms)` : ''}
                            ${result.error ? `<br>Error: ${result.error}` : ''}
                        </div>
                    `;
                });
                
                resultsDiv.innerHTML = html;
            }
            
            generateSummary() {
                const vulnerable = this.results.filter(r => r.vulnerable).length;
                const total = this.results.length;
                
                const summary = {
                    totalTests: total,
                    vulnerableTests: vulnerable,
                    safeTests: total - vulnerable,
                    riskLevel: vulnerable === 0 ? 'LOW' : vulnerable <= 2 ? 'MEDIUM' : 'HIGH'
                };
                
                console.log('Test Summary:', summary);
                return summary;
            }
            
            // 프로토타입 정리 (테스트 후)
            cleanup() {
                delete Object.prototype.polluted;
                delete Object.prototype.polluted2;
                delete Object.prototype.toString;
                delete Array.prototype.customProp;
                console.log('Prototype cleanup completed');
            }
        }
        
        // 테스트 실행
        window.onload = function() {
            const tester = new BrowserPrototypePollutionTester();
            const summary = tester.runAllTests();
            
            // 정리
            setTimeout(() => {
                tester.cleanup();
            }, 5000);
        };
    </script>
</body>
</html>
```

## 📚 참고 자료

### 공식 문서
- [OWASP Prototype Pollution](https://owasp.org/www-community/vulnerabilities/Prototype_Pollution)
- [Snyk Research: Prototype Pollution](https://snyk.io/vuln/SNYK-JS-LODASH-450202)

### 보안 가이드
- [PortSwigger Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [Mozilla JavaScript Inheritance](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Inheritance_and_the_prototype_chain)

### 도구 및 리소스
- [Prototype Pollution Scanner](https://github.com/dwisiswant0/ppfuzz)
- [Burp Suite PP Scanner Extension](https://portswigger.net/bappstore)

---

## 🎯 핵심 요약

1. **안전한 객체 병합**: `__proto__`, `constructor`, `prototype` 키 차단
2. **입력 검증**: 모든 사용자 입력에서 위험한 키 필터링
3. **프로토타입 동결**: `Object.freeze()`로 프로토타입 보호
4. **런타임 모니터링**: 프로토타입 변조 실시간 감지

**⚠️ 주의**: Prototype Pollution은 JavaScript 언어의 특성을 악용하므로 언어 레벨에서의 방어가 핵심입니다.