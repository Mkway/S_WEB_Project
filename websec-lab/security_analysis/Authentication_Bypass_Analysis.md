# Authentication Bypass 분석 보고서

## 1. Authentication Bypass 란?

**열쇠 없이 정문을 통과하다**

- **정의:** 공격자가 정상적인 인증 절차를 거치지 않고, 시스템이나 애플리케이션에 접근 권한을 얻어내는 모든 종류의 공격을 의미합니다.
- **원리:** 인증 로직의 허점을 파고들어 발생합니다. 가장 흔한 방법은 SQL Injection이지만, NoSQL Injection, LDAP Injection, 취약한 세션 관리 등 다양한 기법이 사용됩니다.
- **영향:**
    - **계정 완전 탈취:** 일반 사용자 또는 관리자의 계정을 완전히 탈취합니다.
    - **민감 정보 유출:** 시스템 내부의 모든 민감 데이터에 접근할 수 있게 됩니다.
    - **시스템 장악:** 서버의 제어권을 획득하여 돌이킬 수 없는 피해를 유발합니다.

---

## 2. 취약한 코드 분석 (예시)

**문제의 핵심: SQL Injection에 취약한 로그인 로직**

```php
// 로그인 폼에서 받은 사용자 입력
$username = $_POST['username'];
$password = $_POST['password'];

// 취약한 쿼리
// 사용자 입력값을 그대로 쿼리문에 결합합니다.
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $query);

if (mysqli_num_rows($result) > 0) {
    // 쿼리 결과가 한 줄이라도 있으면 로그인 성공으로 처리
    $_SESSION['loggedin'] = true;
    $_SESSION['username'] = $username;
}
```

**핵심 문제점:** 인증 로직은 공격의 첫 번째 목표 지점입니다. 사용자 입력값을 신뢰하고 그대로 쿼리에 사용하는 것은 시스템의 모든 권한을 넘겨주는 것과 같습니다.

---

## 3. 공격 시나리오: SQL Injection을 이용한 로그인 우회

**공격 목표:** `admin` 사용자의 비밀번호를 몰라도 로그인하기

**공격 페이로드:**
- **Username:** `admin'--`
- **Password:** (아무 값이나 입력)

**서버에서 실행되는 실제 쿼리:**

```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
```

- SQL에서 `--`는 주석을 의미합니다. 이로 인해 `AND password = '...'` 부분이 모두 주석 처리되어, 쿼리에서 무시됩니다.
- 결과적으로 데이터베이스는 `SELECT * FROM users WHERE username = 'admin'` 쿼리만 실행하게 됩니다.
- `admin` 사용자가 존재하면 해당 사용자 정보가 반환되고, 애플리케이션은 공격자를 `admin`으로 인식하여 로그인시킵니다.

---

## 4. 해결책: 준비된 문과 비밀번호 해싱

**가장 안전한 방법: 사용자 입력을 신뢰하지 않고, 비밀번호는 절대 평문으로 저장하지 않기**

```php
// 로그인 폼에서 받은 사용자 입력
$username = $_POST['username'];
$password = $_POST['password'];

// 1. SQL Injection을 방어하기 위해 준비된 문 사용
$query = "SELECT * FROM users WHERE username = ?";
$stmt = $pdo->prepare($query);
$stmt->execute([$username]);
$user = $stmt->fetch();

// 2. password_verify() 함수로 해시된 비밀번호를 안전하게 비교
if ($user && password_verify($password, $user['password_hash'])) {
    // 로그인 성공
    $_SESSION['loggedin'] = true;
    $_SESSION['user_id'] = $user['id'];
}
```

**작동 원리:**
1.  **준비된 문:** 공격자가 쿼리의 구조를 변경하는 것을 원천적으로 차단합니다.
2.  **`password_verify()`:** 데이터베이스에 저장된 해시값과 사용자가 입력한 비밀번호를 타이밍 공격에 안전한 방식으로 비교합니다. 이 함수를 사용하려면, 회원가입 시 `password_hash()`로 비밀번호를 암호화하여 저장해야 합니다.

---

## 5. 인증 우회 방어 전략

1.  **준비된 문 사용 (필수):** SQL Injection 기반의 인증 우회를 막는 가장 기본적인 방어책입니다.
2.  **강력한 비밀번호 해싱 사용:** `password_hash()`와 `password_verify()` (PHP 기준) 또는 각 언어에서 제공하는 검증된 라이브러리(Bcrypt, Scrypt, Argon2)를 사용합니다. 절대 비밀번호를 평문으로 저장하지 않습니다.
3.  **다중 인증 (MFA) 도입:** 로그인 시 아이디/비밀번호 외에 OTP, SMS, 생체 인증 등 추가 인증 수단을 도입하여 보안을 강화합니다.
4.  **강력한 비밀번호 정책 강제:** 사용자가 추측하기 어려운 복잡한 비밀번호를 사용하도록 강제합니다.
5.  **계정 잠금 및 로그인 시도 제한:** 무차별 대입 공격(Brute-force)을 막기 위해, 일정 횟수 이상 로그인 실패 시 계정을 잠그거나 특정 시간 동안 로그인을 제한합니다.
