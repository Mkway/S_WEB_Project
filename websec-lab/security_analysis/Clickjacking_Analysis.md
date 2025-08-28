# Clickjacking (클릭재킹) 취약점 분석

## 📋 취약점 개요

**Clickjacking**은 사용자가 의도하지 않은 행동을 하도록 유도하는 공격 기법입니다. 공격자는 투명하거나 숨겨진 레이어를 사용하여 사용자를 속이고, 사용자가 다른 웹사이트나 애플리케이션의 요소를 클릭하도록 만듭니다.

### 🎯 공격 원리

1. **레이어 오버레이**: 악의적인 페이지 위에 투명한 iframe을 배치
2. **시각적 속임수**: 사용자에게는 다른 버튼이나 링크로 보이도록 조작
3. **의도하지 않은 클릭**: 사용자가 실제로는 숨겨진 요소를 클릭하게 됨

### 🔍 주요 위험성

- **CVSS 점수**: 4.3 (Medium)
- **무단 작업 수행**: 사용자 모르게 중요한 작업 실행
- **계정 탈취**: 로그인 정보나 개인정보 노출
- **피싱 공격**: 사용자를 속여 악성 사이트로 유도

## 🚨 공격 시나리오

### 시나리오 1: 소셜 미디어 버튼 조작

```html
<!-- 악의적인 페이지 -->
<div style="position: relative;">
    <button style="z-index: 1;">무료 다운로드</button>
    
    <!-- 숨겨진 소셜 미디어 버튼 -->
    <iframe src="https://facebook.com/like-button" 
            style="position: absolute; top: 0; left: 0; 
                   opacity: 0; z-index: 2;"></iframe>
</div>
```

### 시나리오 2: 관리자 페이지 조작

```html
<!-- 투명한 관리자 패널 -->
<iframe src="https://admin.example.com/delete-user" 
        style="opacity: 0; position: absolute; 
               top: 100px; left: 200px; 
               width: 300px; height: 200px;"></iframe>

<div style="position: relative; top: 150px; left: 250px;">
    <button>상품 보기</button>
</div>
```

### 시나리오 3: 결제 페이지 조작

```html
<!-- 결제 확인 버튼을 숨김 -->
<div class="fake-content">
    <h1>축하합니다! 당첨되었습니다!</h1>
    <button class="prize-button">상금 받기</button>
</div>

<iframe src="https://payment.site.com/confirm-payment" 
        class="hidden-payment-frame"></iframe>
```

## 🛡️ 방어 방법

### 1. X-Frame-Options 헤더 설정

```php
<?php
// PHP에서 X-Frame-Options 설정
header('X-Frame-Options: DENY');
// 또는
header('X-Frame-Options: SAMEORIGIN');
?>
```

### 2. Content Security Policy (CSP) 사용

```html
<!-- HTML meta 태그로 설정 -->
<meta http-equiv="Content-Security-Policy" 
      content="frame-ancestors 'none';">

<!-- 또는 HTTP 헤더로 설정 -->
```

```php
<?php
header("Content-Security-Policy: frame-ancestors 'self' https://trusted-site.com");
?>
```

### 3. JavaScript를 통한 Frame Busting

```javascript
// 기본 Frame Busting 코드
if (top !== self) {
    top.location = self.location;
}

// 더 안전한 버전
(function() {
    if (window.top !== window.self) {
        try {
            if (window.top.location.hostname !== window.self.location.hostname) {
                throw new Error('Clickjacking detected');
            }
        } catch (e) {
            window.top.location = window.self.location;
        }
    }
})();
```

### 4. SameSite 쿠키 속성 활용

```php
<?php
// SameSite 속성으로 쿠키 보호
setcookie('session', $value, [
    'samesite' => 'Strict',
    'secure' => true,
    'httponly' => true
]);
?>
```

## 🔧 코드 구현 예제

### 보안이 강화된 페이지 예제

```php
<?php
// 안전한 페이지 헤더 설정
function setSecureHeaders() {
    header('X-Frame-Options: DENY');
    header('Content-Security-Policy: frame-ancestors \'none\'');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

setSecureHeaders();
?>
<!DOCTYPE html>
<html>
<head>
    <title>보안이 강화된 페이지</title>
    <script>
        // Frame Busting 스크립트
        if (window.top !== window.self) {
            window.top.location = window.self.location;
        }
    </script>
</head>
<body>
    <h1>안전한 컨텐츠</h1>
    <p>이 페이지는 Clickjacking 공격으로부터 보호됩니다.</p>
</body>
</html>
```

### Nginx 설정 예제

```nginx
# /etc/nginx/sites-available/default
server {
    listen 80;
    server_name example.com;
    
    # Clickjacking 방지 헤더
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "frame-ancestors 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

## 🧪 테스트 및 검증

### 1. 수동 테스트

```html
<!-- 테스트용 iframe 생성 -->
<iframe src="https://target-site.com" width="100%" height="600px"></iframe>
```

### 2. 브라우저 개발자 도구 확인

1. F12 키로 개발자 도구 열기
2. Console 탭에서 프레임 관련 오류 확인
3. Network 탭에서 X-Frame-Options 헤더 확인

### 3. 온라인 도구 사용

- **Security Headers**: https://securityheaders.com/
- **Mozilla Observatory**: https://observatory.mozilla.org/

## ⚠️ 우회 기법 및 대응

### 공격자의 우회 시도

1. **Double Frame**: 중첩된 프레임 사용
2. **204 No Content**: 특별한 응답 코드 활용
3. **Meta Refresh**: 자동 새로고침을 통한 우회

### 강화된 방어

```javascript
// 고급 Frame Busting
(function() {
    var style = document.createElement('style');
    style.innerHTML = 'body { display: none !important; }';
    document.head.appendChild(style);
    
    if (window.top === window.self) {
        style.innerHTML = 'body { display: block !important; }';
    } else {
        window.top.location = window.self.location;
    }
})();
```

## 📚 참고 자료

### 공식 문서
- [OWASP Clickjacking Defense](https://owasp.org/www-community/attacks/Clickjacking)
- [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)

### 보안 가이드
- [PortSwigger Clickjacking](https://portswigger.net/web-security/clickjacking)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### 도구 및 리소스
- [Burp Suite Clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit)
- [OWASP ZAP Proxy](https://owasp.org/www-project-zap/)

---

## 🎯 핵심 요약

1. **X-Frame-Options**와 **CSP frame-ancestors** 헤더 필수 설정
2. **JavaScript Frame Busting** 코드를 통한 이중 보안
3. 정기적인 **보안 헤더 검증** 및 **테스트** 수행
4. **사용자 교육**을 통한 의식 제고

**⚠️ 주의**: Clickjacking은 사용자의 행동을 악용하는 공격이므로, 기술적 방어와 함께 사용자 교육이 중요합니다.