# Type Juggling 취약점 상세 분석

## 📋 개요

**Type Juggling**은 PHP와 같은 동적 타입 언어에서 느슨한 타입 비교(`==`)를 사용할 때 발생하는 취약점입니다. 서로 다른 타입의 값이 예상치 못하게 같다고 평가되어 인증 우회, 로직 우회 등의 보안 문제가 발생할 수 있습니다.

## 🎯 취약점 정보

- **CVSS 3.1 점수**: 8.1 (High)
- **공격 복잡성**: Low
- **필요 권한**: None
- **사용자 상호작용**: None
- **영향 범위**: Confidentiality, Integrity, Availability

## 🔍 취약점 원리

### 핵심 개념

Type Juggling은 다음과 같은 PHP의 타입 변환 규칙을 악용합니다:

1. **느슨한 비교(`==`)**: 값만 비교하고 타입은 무시
2. **자동 타입 변환**: 비교 시 PHP가 자동으로 타입을 변환
3. **과학적 표기법 해석**: `0e` 문자열이 지수 표기법으로 해석됨

### 위험한 타입 변환 패턴

```php
// 모두 true로 평가됨
var_dump(0 == "0");           // true
var_dump(0 == "");            // true  
var_dump(0 == "0e123456");    // true (과학적 표기법)
var_dump(0 == "0e999999");    // true (모든 0e로 시작하는 문자열)
var_dump(false == "");        // true
var_dump(null == "");         // true
var_dump(array() == false);   // true
```

## 🚨 공격 시나리오

### 1. MD5 해시 우회 공격

**취약한 코드**:
```php
$user_input = $_GET['password'];
$stored_hash = "0e462097431906509019562988736854"; // MD5('240610708')

if ($user_input == $stored_hash) {
    // 로그인 성공 처리
    echo "Login successful!";
}
```

**공격 벡터**:
```php
// 다음 문자열들의 MD5 해시는 모두 0e로 시작함
$magic_strings = [
    '240610708',     // MD5: 0e462097431906509019562988736854
    'QNKCDZO',       // MD5: 0e830400451993494058024219903391
    'aabg7XSs',      // MD5: 0e087386482136013740957780965295
    '0e1137126905'   // 직접적인 0e 문자열
];

foreach ($magic_strings as $string) {
    if ($string == $stored_hash) {
        echo "Hash collision: $string bypasses authentication!";
    }
}
```

### 2. SHA1 해시 우회 공격

```php
// SHA1 해시도 동일한 문제 발생
$vulnerable_hashes = [
    'aaroZmOk' => '0e66507019969427134894567494305185566735',  // SHA1
    'aaK1STfY' => '0e76658526655756207688271159624026011393',  // SHA1
    'aaO8zKZF' => '0e89257456677279068558073954252716165668'   // SHA1
];
```

### 3. JSON 데이터 우회

```php
// API에서 JSON 데이터 처리 시
$json_data = json_decode($_POST['data'], true);

if ($json_data['user_id'] == 0) {
    // 관리자 계정 처리
    $is_admin = true;
}

// 공격 페이로드: {"user_id": "0e123456"}
// 결과: 일반 사용자가 관리자 권한 획득
```

### 4. 토큰 검증 우회

```php
$expected_token = "0e123456789012345678901234567890";
$user_token = $_POST['token'];

if ($user_token == $expected_token) {
    // CSRF 토큰 검증 통과
    performSensitiveAction();
}

// 공격: token=0e999999999999999999999999999999
// 결과: CSRF 보호 우회
```

## 🛡️ 방어 방법

### 1. 엄격한 타입 비교 사용

```php
// 취약한 코드
if ($user_input == $expected_value) {
    // 위험!
}

// 안전한 코드
if ($user_input === $expected_value) {
    // 안전 - 값과 타입 모두 비교
}
```

### 2. 명시적 타입 검증

```php
function secureCompare($input, $expected) {
    // 1. 타입 검증
    if (!is_string($input) || !is_string($expected)) {
        return false;
    }
    
    // 2. 길이 검증
    if (strlen($input) !== strlen($expected)) {
        return false;
    }
    
    // 3. 엄격한 비교
    return $input === $expected;
}

// 사용 예
if (secureCompare($user_token, $expected_token)) {
    // 안전한 검증
}
```

### 3. 해시 검증 강화

```php
class SecureHashValidator {
    public static function verifyPassword($input, $hash) {
        // password_verify 사용 (timing attack 방지)
        return password_verify($input, $hash);
    }
    
    public static function verifyToken($input, $expected) {
        // hash_equals 사용 (timing attack 방지)
        return hash_equals($expected, $input);
    }
    
    public static function generateSecureToken($length = 32) {
        // 암호학적으로 안전한 토큰 생성
        return bin2hex(random_bytes($length));
    }
}

// 사용 예
$password_hash = password_hash($password, PASSWORD_ARGON2ID);
if (SecureHashValidator::verifyPassword($input, $password_hash)) {
    // 안전한 비밀번호 검증
}
```

### 4. 입력 검증 및 정제

```php
class InputValidator {
    public static function validateNumeric($input) {
        // 숫자인지 엄격하게 검증
        if (!is_numeric($input)) {
            throw new InvalidArgumentException('Input must be numeric');
        }
        
        // 0e 패턴 차단
        if (is_string($input) && preg_match('/^0e\d+$/i', $input)) {
            throw new SecurityException('Scientific notation not allowed');
        }
        
        return (int)$input;
    }
    
    public static function validateHash($input) {
        // 해시 형식 검증
        if (!is_string($input)) {
            return false;
        }
        
        // 0e로 시작하는 해시 차단 (의심스러운 패턴)
        if (preg_match('/^0e[0-9a-f]*$/i', $input)) {
            error_log("Suspicious hash pattern detected: " . $input);
            return false;
        }
        
        return ctype_xdigit($input);
    }
}
```

### 5. 프레임워크 레벨 보호

```php
// Laravel에서의 안전한 구현
class SecureAuthController extends Controller {
    public function login(Request $request) {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:8'
        ]);
        
        // Laravel의 내장 인증 사용 (자동으로 안전한 비교)
        if (Auth::attempt($credentials)) {
            return redirect()->intended('/dashboard');
        }
        
        return back()->withErrors([
            'email' => 'The provided credentials do not match our records.',
        ]);
    }
    
    public function verifyToken(Request $request) {
        $token = $request->input('token');
        $expected = session('csrf_token');
        
        // hash_equals 사용하여 timing attack 방지
        if (!hash_equals($expected, $token)) {
            abort(419, 'Token mismatch');
        }
        
        return response()->json(['status' => 'verified']);
    }
}
```

## 🔍 취약점 탐지 방법

### 1. 정적 코드 분석

```bash
# PHP에서 위험한 느슨한 비교 패턴 검색
grep -r "==" . --include="*.php" | grep -v "===" | head -20

# 특히 위험한 패턴들
grep -r "\$.*==.*\$" . --include="*.php"
grep -r "if.*==.*MD5\|SHA1\|hash" . --include="*.php"
grep -r "password.*==" . --include="*.php"
```

### 2. 동적 테스트 도구

```python
import hashlib
import requests

class TypeJugglingTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.magic_strings = []
        self.generate_magic_strings()
    
    def generate_magic_strings(self):
        """0e로 시작하는 해시를 생성하는 문자열들"""
        known_md5 = [
            '240610708',    # MD5: 0e462097431906509019562988736854
            'QNKCDZO',      # MD5: 0e830400451993494058024219903391
            'aabg7XSs',     # MD5: 0e087386482136013740957780965295
            '0e1137126905', # 직접적인 0e 문자열
        ]
        
        known_sha1 = [
            'aaroZmOk',     # SHA1: 0e66507019969427134894567494305185566735
            'aaK1STfY',     # SHA1: 0e76658526655756207688271159624026011393
        ]
        
        self.magic_strings.extend(known_md5)
        self.magic_strings.extend(known_sha1)
    
    def test_authentication_bypass(self):
        """인증 우회 테스트"""
        for magic_string in self.magic_strings:
            data = {
                'username': 'admin',
                'password': magic_string
            }
            
            response = requests.post(f"{self.target_url}/login", data=data)
            
            if "success" in response.text.lower():
                print(f"Potential type juggling vulnerability: {magic_string}")
                return True
        
        return False
    
    def test_token_bypass(self):
        """토큰 검증 우회 테스트"""
        bypass_tokens = ['0e123456789', '0e999999999', '0']
        
        for token in bypass_tokens:
            headers = {'X-CSRF-Token': token}
            response = requests.post(f"{self.target_url}/api/sensitive", 
                                   headers=headers)
            
            if response.status_code == 200:
                print(f"Token bypass successful with: {token}")
                return True
        
        return False

# 사용 예
tester = TypeJugglingTester("https://target.com")
tester.test_authentication_bypass()
tester.test_token_bypass()
```

### 3. Burp Suite 확장

```javascript
// Burp Suite extension for Type Juggling detection
function processHttpMessage(toolFlag, messageIsRequest, messageInfo) {
    if (!messageIsRequest) {
        var response = messageInfo.getResponse();
        var responseString = helpers.bytesToString(response);
        
        // 0e 패턴을 포함한 응답 탐지
        if (responseString.match(/0e[0-9a-f]{30,}/gi)) {
            var issue = {
                url: messageInfo.getUrl(),
                name: "Potential Type Juggling Hash",
                detail: "Response contains hash starting with 0e",
                severity: "High"
            };
            
            callbacks.addScanIssue(issue);
        }
    }
}
```

## 🧪 테스트 시나리오

### 시나리오 1: 로그인 우회 테스트

```php
<?php
// 테스트 대상 코드
function vulnerable_login($username, $password) {
    $users = [
        'admin' => '0e462097431906509019562988736854' // MD5('240610708')
    ];
    
    if (isset($users[$username]) && $password == $users[$username]) {
        return true;
    }
    
    return false;
}

// 테스트 케이스
$test_cases = [
    ['admin', '240610708'],      // 정상 비밀번호
    ['admin', 'QNKCDZO'],        // Type juggling 공격
    ['admin', '0e123456789'],    // 직접적인 0e 문자열
    ['admin', '0'],              // 숫자 0
    ['admin', 'wrongpass']       // 잘못된 비밀번호
];

foreach ($test_cases as [$username, $password]) {
    $result = vulnerable_login($username, $password);
    echo "Username: $username, Password: $password, Result: " . ($result ? 'SUCCESS' : 'FAIL') . "\n";
}
?>
```

### 시나리오 2: API 토큰 우회 테스트

```javascript
// JavaScript로 API 테스트
async function testTypeJuggling() {
    const baseUrl = 'https://api.target.com';
    const magicValues = [
        '0e123456789012345678901234567890',
        '0e999999999999999999999999999999',
        '0',
        0,
        false,
        null,
        ''
    ];
    
    for (const value of magicValues) {
        try {
            const response = await fetch(`${baseUrl}/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${value}`
                },
                body: JSON.stringify({
                    token: value,
                    user_id: value
                })
            });
            
            if (response.ok) {
                console.log(`Type juggling bypass successful with: ${value}`);
            }
        } catch (error) {
            console.error(`Error testing ${value}:`, error);
        }
    }
}

testTypeJuggling();
```

## 📊 영향 평가

### 비즈니스 영향

- **인증 우회**: 무단 계정 접근으로 인한 데이터 유출
- **권한 상승**: 일반 사용자의 관리자 권한 획득
- **데이터 무결성**: 중요한 비즈니스 데이터의 무단 변경
- **규정 위반**: 접근 제어 실패로 인한 컴플라이언스 위반

### 기술적 영향

- **세션 하이재킹**: 토큰 검증 우회를 통한 세션 탈취
- **CSRF 보호 우회**: 보안 토큰 검증 실패
- **로직 우회**: 애플리케이션 보안 로직 전반의 무력화

## 🔧 수정 가이드

### 즉시 적용할 수정사항

1. **모든 `==` 비교를 `===`로 변경**
2. **`password_verify()` 및 `hash_equals()` 사용**
3. **입력 검증 강화**
4. **0e 패턴 탐지 및 차단**

### 장기적 개선사항

1. **정적 분석 도구 도입**
2. **코딩 표준 수립 (`===` 사용 의무화)**
3. **자동화된 보안 테스트**
4. **개발자 보안 교육**

## 📚 참고 자료

- [PHP Manual - Type Juggling](https://www.php.net/manual/en/language.types.type-juggling.php)
- [OWASP - Type Juggling](https://owasp.org/www-community/vulnerabilities/PHP_Type_Juggling)
- [Magic Hashes - PHP Type Juggling](https://github.com/spaze/hashes)
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## 🎯 결론

Type Juggling은 PHP의 동적 타입 시스템과 느슨한 비교의 부작용으로 발생하는 심각한 보안 취약점입니다. 엄격한 타입 비교(`===`)와 적절한 해시 검증 함수 사용을 통해 효과적으로 방어할 수 있으며, 모든 사용자 입력에 대한 타입 검증이 필수적입니다.