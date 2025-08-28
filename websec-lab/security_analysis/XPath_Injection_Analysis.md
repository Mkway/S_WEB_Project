# XPath Injection 분석 보고서

## 1. XPath Injection 이란?

**XML 문서에 악의적인 질의를 보내다**

- **XPath Injection이란?** 웹 애플리케이션이 사용자 입력을 기반으로 XPath(XML Path Language) 쿼리를 동적으로 생성할 때, 공격자가 악의적인 입력을 통해 쿼리의 구조와 의도를 변경하는 공격 기법입니다.
- **원리:** SQL Injection과 유사하게, 공격자는 XPath 쿼리에서 특별한 의미를 갖는 메타문자(`'`, `"`, `or`, `and`, `not`, `|`, `*` 등)를 주입하여, 개발자가 의도한 쿼리를 무력화하고 원하는 결과를 얻어냅니다.
- **영향:**
    - **인증 우회:** 정상적인 아이디와 비밀번호 없이 시스템에 로그인합니다.
    - **정보 유출:** XML 문서에 저장된 사용자 계정, 설정 정보, 민감한 데이터 등을 탈취합니다.
    - **데이터 조작:** XML 문서의 내용을 임의로 수정하거나 삭제합니다. (경우에 따라)

---

## 2. 취약한 코드 분석 (예시)

**문제의 핵심: 사용자 입력을 그대로 XPath 쿼리에 결합**

```php
// 로그인 폼에서 받은 사용자 입력
$username = $_POST['username'];
$password = $_POST['password'];

// XML 문서 로드 (예: users.xml)
$xml = simplexml_load_file('users.xml');

// 취약한 XPath 쿼리 생성
// 사용자 입력을 아무런 처리 없이 그대로 문자열에 합칩니다.
$xpath_query = "/users/user[username='" . $username . "' and password='" . $password . "']";

// XPath 쿼리 실행
$result = $xml->xpath($xpath_query);

if ($result) {
    // 로그인 성공
}
```

**핵심 문제점:** 사용자 입력값을 검증이나 이스케이프 처리 없이 XPath 쿼리문의 일부로 사용하는 것이 모든 문제의 원인입니다.

---

## 3. 공격 시나리오: 인증 우회

**공격 목표:** `admin` 사용자의 비밀번호를 몰라도 로그인하기

**공격용 악성 페이로드:**
- **Username:** `admin' or '1'='1`
- **Password:** `admin' or '1'='1`

**서버에서 생성되는 실제 XPath 쿼리:**
`/users/user[username='admin' or '1'='1' and password='admin' or '1'='1']`

**공격 과정:**
1.  공격자는 `username`과 `password` 필드에 `or '1'='1'`과 같은 항상 참(True)이 되는 조건을 주입합니다.
2.  XPath 쿼리는 `username='admin' or '1'='1'` (항상 참) 그리고 `password='admin' or '1'='1'` (항상 참)이 되어, 결국 모든 `user` 노드를 선택하게 됩니다.
3.  애플리케이션은 쿼리 결과로 첫 번째 사용자 엔트리를 반환하며, 이는 종종 관리자 계정일 수 있어 공격자에게 접근 권한을 부여합니다.

---

## 4. 해결책: 모든 사용자 입력 이스케이프 처리

**가장 안전한 방법: 특수 문자를 일반 문자로 취급하도록 만들기**

```php
// 로그인 폼에서 받은 사용자 입력
$username = $_POST['username'];
$password = $_POST['password'];

// XML 문서 로드
$dom = new DOMDocument();
$dom->load('users.xml');
$xpath = new DOMXPath($dom);

// 안전한 방법
// 작은따옴표(')를 두 개의 작은따옴표('')로 이스케이프 처리합니다.
$escaped_username = str_replace("'", "''", $username);
$escaped_password = str_replace("'", "''", $password);

// 안전하게 처리된 값으로 XPath 쿼리 생성
$xpath_query = "/users/user[username='" . $escaped_username . "' and password='" . $escaped_password . "']";

// 이제 이 쿼리를 안전하게 사용할 수 있습니다.
$result = $xpath->query($xpath_query);

if ($result->length > 0) {
    // 로그인 성공
}
```

**작동 원리:** `str_replace("'", "''", $input)`와 같은 함수를 사용하여 사용자 입력 내의 작은따옴표를 두 개의 작은따옴표로 변환합니다. 이렇게 하면 XPath 파서는 이를 문자열의 일부로 인식하고, 공격자가 쿼리 구조를 변경하는 것을 막을 수 있습니다.

---

## 5. XPath Injection 방어 전략

1.  **사용자 입력 이스케이프 (필수):** XPath 쿼리에 사용자 입력을 사용하기 전에, 반드시 모든 입력을 이스케이프 처리합니다. 특히 작은따옴표(`'`)는 `''`로, 큰따옴표(`"`)는 `""`로 변환해야 합니다.
2.  **입력값 검증 (화이트리스트):** 입력값의 형식이 정해져 있다면, 허용된 문자 목록(화이트리스트)을 만들어 해당 형식에 맞는지 엄격하게 검증합니다.
3.  **동적 XPath 쿼리 사용 지양:** 가능하다면 사용자 입력을 직접 사용하여 XPath 쿼리를 동적으로 생성하는 것을 피합니다. 대신, 매개변수화된 쿼리(Parameterized Query)를 지원하는 라이브러리 기능을 활용합니다.
4.  **최소 권한 원칙:** 웹 애플리케이션이 XML 문서에 접근할 때 사용하는 계정은, 꼭 필요한 최소한의 읽기 권한만 갖도록 제한합니다.
