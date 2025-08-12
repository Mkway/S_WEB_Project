# CSRF (Cross-Site Request Forgery) 분석 보고서

## 1. CSRF 란?

**사용자의 의지와 무관하게 공격자가 의도한 행동을 수행하다**

- **정의:** 사용자가 자신의 의지와는 무관하게, 공격자가 의도한 행위(수정, 삭제, 등록 등)를 특정 웹사이트에 요청하게 만드는 공격입니다.
- **원리:** 사용자가 취약한 웹사이트에 로그인되어 있는 상태에서, 공격자가 만든 악성 링크나 페이지에 접근할 때 발생합니다. 브라우저는 자동으로 로그인된 사용자의 인증 정보(쿠키)를 담아 요청을 보내게 됩니다.
- **영향:**
    - **계정 정보 변경:** 사용자의 비밀번호나 이메일 주소가 변경되어 계정을 탈취당할 수 있습니다.
    - **금전적 피해:** 사용자의 계좌에서 돈이 이체되거나, 온라인 쇼핑몰에서 상품이 주문될 수 있습니다.
    - **데이터 손실:** 게시글, 댓글 등 사용자의 데이터가 임의로 삭제되거나 수정될 수 있습니다.

---

## 2. 취약한 코드 분석 (예시)

**문제의 핵심: CSRF 토큰이 없는 폼(Form)**

```html
<!-- 사용자의 이메일 주소를 변경하는 폼 -->
<form action="/change_email" method="POST">
  <input type="email" name="email" value="new_email@example.com">
  <input type="submit" value="이메일 변경">
</form>
```

**핵심 문제점:** 이 폼 요청이 정말로 사용자가 직접 의도한 것인지 확인할 수 있는 수단(CSRF 토큰)이 없습니다. 따라서 다른 사이트에서 위조된 요청이 들어와도 서버는 정상적인 요청으로 판단하고 처리하게 됩니다.

---

## 3. 공격 시나리오: 사용자 계정 탈취

**공격 목표:** 희생자의 이메일 주소를 공격자의 이메일로 변경하여 계정 탈취하기

**공격자가 만든 악성 웹페이지 (`attacker.com`):**

```html
<body onload="document.forms[0].submit()">
  <h3>무료 경품에 당첨되셨습니다!</h3>
  <form action="http://victim.com/change_email" method="POST" style="display:none;">
    <input type="email" name="email" value="attacker@evil.com">
  </form>
</body>
```

**공격 과정:**
1.  희생자는 `victim.com`에 로그인된 상태입니다.
2.  희생자가 이메일이나 메신저를 통해 받은 악성 링크(`attacker.com`)를 클릭합니다.
3.  페이지가 로드되자마자, `onload` 이벤트에 의해 숨겨진 폼이 자동으로 `victim.com`으로 제출됩니다.
4.  브라우저는 이 요청에 `victim.com`의 인증 쿠키를 자동으로 포함하여 전송합니다.
5.  `victim.com` 서버는 인증된 사용자의 정상적인 요청으로 판단하고, 이메일 주소를 `attacker@evil.com`으로 변경합니다.
6.  공격자는 이제 '비밀번호 찾기' 기능으로 계정의 제어권을 완전히 탈취할 수 있습니다.

---

## 4. 해결책: 안티-CSRF 토큰 (Anti-CSRF Token)

**가장 안전한 방법: 예측 불가능한 고유 토큰 사용하기**

**1. 서버에서 토큰 생성 및 세션에 저장:**

```php
// 예측 불가능한 랜덤 토큰 생성
$csrf_token = bin2hex(random_bytes(32));
// 생성된 토큰을 사용자 세션에 저장
$_SESSION['csrf_token'] = $csrf_token;
```

**2. 폼에 토큰 포함시키기:**

```html
<form action="/change_email" method="POST">
  <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
  <input type="email" name="email" value="new_email@example.com">
  <input type="submit" value="이메일 변경">
</form>
```

**3. 서버에서 토큰 검증:**

```php
// 세션에 저장된 토큰과 폼으로 전송된 토큰이 일치하는지 확인
if (hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    // 토큰이 일치하면, 정상적인 요청으로 판단하고 처리
} else {
    // 토큰이 불일치하면, CSRF 공격으로 판단하고 요청을 차단
}
```

**작동 원리:** 공격자는 사용자의 세션에 저장된 CSRF 토큰 값을 알 수 없으므로, 위조된 요청에 올바른 토큰을 포함시킬 수 없습니다. 따라서 서버는 토큰 값의 일치 여부만으로도 요청의 유효성을 검증할 수 있습니다.

---

## 5. CSRF 방어 전략

1.  **안티-CSRF 토큰 사용 (필수):** 상태를 변경하는 모든 요청(POST, PUT, DELETE 등)에 예측 불가능한 토큰을 포함하고 서버에서 검증합니다.
2.  **SameSite 쿠키 속성 사용:** 세션 쿠키의 `SameSite` 속성을 `Strict` 또는 `Lax`로 설정하여, 외부 사이트에서 시작된 요청에는 쿠키가 전송되지 않도록 제한합니다.
3.  **Referer 헤더 검증:** 요청 헤더의 `Referer` 값을 확인하여, 허용된 도메인에서 온 요청인지 검증합니다. (보조적인 수단)
4.  **재인증:** 비밀번호 변경, 송금 등 매우 중요한 작업에 대해서는 사용자의 비밀번호를 다시 한번 입력받아 재인증 절차를 거칩니다.
