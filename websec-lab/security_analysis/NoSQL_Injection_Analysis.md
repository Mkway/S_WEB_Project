# NoSQL Injection 분석 보고서

## 1. NoSQL Injection 이란?

**관계형 데이터베이스를 넘어서**

- **NoSQL Injection이란?** MongoDB, Redis 등 NoSQL 데이터베이스를 사용하는 웹 애플리케이션을 대상으로 하는 공격입니다. 공격자는 NoSQL 쿼리 구문을 주입하여, 데이터베이스의 로직을 조작하고 정보를 탈취하거나 인증을 우회합니다.
- **원리:** NoSQL 데이터베이스는 종종 JSON, BSON과 같은 구조화된 데이터 형식을 쿼리에 사용합니다. 애플리케이션이 사용자 입력값을 제대로 검증하거나 정제하지 않고 쿼리의 일부로 사용할 경우, 공격자는 쿼리 연산자(`$ne`, `$gt` 등)나 특수 구문을 주입하여 쿼리의 의도를 변경할 수 있습니다.
- **영향:**
    - **인증 우회:** 로그인 로직을 우회하여 임의의 사용자나 관리자 계정으로 접근합니다.
    - **데이터 유출:** 데이터베이스에 저장된 모든 데이터를 열람하거나 탈취합니다.
    - **데이터 조작/삭제:** 데이터베이스의 내용을 임의로 수정하거나 삭제합니다.
    - **서비스 거부(DoS):** 과도한 부하를 유발하는 쿼리를 실행하여 데이터베이스를 마비시킵니다.

---

## 2. 취약한 코드 분석 (MongoDB 예시)

**문제의 핵심: 사용자 입력을 그대로 NoSQL 쿼리에 사용**

```php
// 로그인 폼에서 받은 사용자 입력
$username = $_POST['username'];
$password = $_POST['password'];

// 취약한 코드
// 애플리케이션은 사용자가 문자열을 입력할 것으로 예상하지만,
// 공격자는 JSON 객체를 전송할 수 있습니다.
$user = $collection->findOne([
    'username' => $username,
    'password' => $password
]);

if ($user) {
    // 로그인 성공
}
```

**핵심 문제점:** NoSQL 데이터베이스는 스키마가 유연하기 때문에, 사용자 입력이 예상된 데이터 타입(예: 문자열)인지, 아니면 쿼리 연산자를 포함한 객체인지 반드시 검증해야 합니다.

---

## 3. 공격 시나리오: 인증 우회

**공격 목표:** 아이디나 비밀번호 없이 첫 번째 사용자로 로그인하기

**공격용 악성 페이로드:**
- **Username:** `{"$ne": "nonexistentuser"}`
- **Password:** `{"$ne": "nonexistentuser"}`

**서버에서 실행되는 실제 MongoDB 쿼리:**
```javascript
db.users.findOne({
    "username": { "$ne": "nonexistentuser" },
    "password": { "$ne": "nonexistentuser" }
})
```

**공격 과정:**
1.  공격자는 `username`과 `password` 파라미터에 단순 문자열 대신, MongoDB의 연산자(`$ne`: not equal)를 포함한 JSON 객체를 전송합니다.
2.  이 쿼리는 데이터베이스에게 "username이 'nonexistentuser'가 아니고, password도 'nonexistentuser'가 아닌 첫 번째 사용자를 찾아라"고 요청합니다.
3.  데이터베이스는 이 조건에 맞는 첫 번째 사용자를 반환하며, 이 사용자는 보통 가장 먼저 생성된 관리자 계정일 확률이 높습니다.

---

## 4. 해결책: 입력값 검증 및 정제

**가장 안전한 방법: 사용자 입력의 구조와 타입을 신뢰하지 않기**

```php
// 로그인 폼에서 받은 사용자 입력
$username = $_POST['username'];
$password = $_POST['password'];

// 1. 입력값이 예상된 타입(문자열)인지 확인
if (!is_string($username) || !is_string($password)) {
    // 예상과 다른 타입의 입력은 거부
    die("잘못된 입력입니다.");
}

// 2. NoSQL 연산에 사용될 수 있는 특수 문자 제거 또는 이스케이프
// (사용하는 DB와 라이브러리에 따라 방법이 다름)
$sanitized_username = sanitize_nosql_input($username);
$sanitized_password = sanitize_nosql_input($password);

// 3. 안전하게 처리된 값을 쿼리에 사용
$user = $collection->findOne([
    'username' => $sanitized_username,
    'password' => $sanitized_password
]);
```

**작동 원리:** 사용자 입력이 쿼리 연산자를 포함한 객체가 아닌, 단순 문자열임을 강제하여 공격자가 쿼리 로직 자체를 변경할 가능성을 차단합니다.

---

## 5. NoSQL Injection 방어 전략

1.  **안전한 API 또는 ODM 사용:** 가능하면 데이터베이스 드라이버가 제공하는 매개변수화된 쿼리나, 안전한 쿼리 생성을 지원하는 ODM(Object-Document Mapper) 라이브러리를 사용합니다.
2.  **입력값 검증 및 정제 (필수):** 모든 사용자 입력에 대해 예상된 데이터 타입과 형식을 서버 측에서 엄격하게 검증합니다. NoSQL 쿼리에서 특별한 의미를 갖는 문자(`, $, {, }` 등)를 필터링하거나 이스케이프 처리합니다.
3.  **최소 권한 원칙:** 데이터베이스에 연결하는 애플리케이션 계정은 꼭 필요한 최소한의 권한(CRUD 등)만 갖도록 설정합니다.
4.  **서버 사이드 JavaScript 비활성화:** MongoDB의 `$where` 연산자처럼, 서버 측에서 JavaScript 실행을 허용하는 기능은 필요하지 않다면 비활성화합니다.
