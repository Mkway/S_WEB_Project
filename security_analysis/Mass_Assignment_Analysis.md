# Mass Assignment 취약점 상세 분석

## 📋 개요

**Mass Assignment**는 웹 애플리케이션에서 사용자로부터 받은 데이터를 검증 없이 대량으로 객체나 모델에 할당할 때 발생하는 취약점입니다. 공격자가 의도하지 않은 속성을 조작하여 권한 상승이나 데이터 무결성을 위반할 수 있습니다.

## 🎯 취약점 정보

- **CVSS 3.1 점수**: 7.5 (High)
- **공격 복잡성**: Low
- **필요 권한**: None/Low
- **사용자 상호작용**: None
- **영향 범위**: Confidentiality, Integrity, Availability

## 🔍 취약점 원리

### 핵심 개념

Mass Assignment는 다음과 같은 상황에서 발생합니다:

1. **자동 바인딩**: 프레임워크가 HTTP 요청 데이터를 자동으로 객체에 바인딩
2. **검증 부족**: 할당 가능한 필드에 대한 제한이 없음
3. **권한 분리 실패**: 사용자가 수정할 수 있는 필드와 시스템 전용 필드의 구분 부족

### 공격 메커니즘

```php
// 취약한 코드 예시
class User {
    public $username;
    public $email;
    public $is_admin;
    public $balance;
}

// 위험한 할당 방식
$user = new User();
foreach ($_POST as $key => $value) {
    if (property_exists($user, $key)) {
        $user->$key = $value;  // 모든 속성에 대한 무차별 할당
    }
}
```

## 🚨 공격 시나리오

### 1. 권한 상승 공격

**공격 벡터**:
```html
<!-- 정상적인 폼 -->
<form method="POST">
    <input name="username" value="john">
    <input name="email" value="john@example.com">
    <!-- 공격자가 개발자 도구로 추가하는 필드 -->
    <input name="is_admin" value="true">
    <input name="role" value="administrator">
</form>
```

**결과**: 일반 사용자가 관리자 권한 획득

### 2. 잔액 조작 공격

**공격 벡터**:
```html
<form method="POST" action="/profile/update">
    <input name="name" value="attacker">
    <!-- 숨겨진 필드로 잔액 조작 -->
    <input name="balance" value="1000000">
    <input name="credit_limit" value="999999">
</form>
```

**결과**: 계정 잔액 및 신용 한도 무단 변경

### 3. 비즈니스 로직 우회

**공격 벡터**:
```javascript
// AJAX 요청을 통한 공격
fetch('/api/user/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        username: 'newuser',
        email: 'new@example.com',
        account_verified: true,    // 이메일 인증 우회
        subscription_tier: 'premium',  // 프리미엄 구독 획득
        created_at: '2020-01-01'   // 계정 생성일 조작
    })
});
```

## 🛡️ 방어 방법

### 1. 화이트리스트 기반 속성 보호

```php
class SecureUser {
    private $fillable = ['username', 'email', 'bio'];  // 허용된 필드만 명시
    private $guarded = ['id', 'is_admin', 'balance', 'created_at'];
    
    public function fill(array $data) {
        foreach ($data as $key => $value) {
            if (in_array($key, $this->fillable) && !in_array($key, $this->guarded)) {
                $this->$key = $value;
            }
        }
    }
}
```

### 2. 명시적 할당 (권장)

```php
// 안전한 명시적 할당
function updateProfile($data) {
    $allowedFields = ['username', 'email', 'bio'];
    $user = new User();
    
    foreach ($allowedFields as $field) {
        if (isset($data[$field])) {
            $user->$field = sanitize($data[$field]);
        }
    }
    
    return $user->save();
}
```

### 3. DTO (Data Transfer Object) 패턴

```php
class UserUpdateDTO {
    public string $username;
    public string $email;
    public string $bio;
    
    public function __construct(array $data) {
        $this->username = $data['username'] ?? '';
        $this->email = $data['email'] ?? '';
        $this->bio = $data['bio'] ?? '';
        // 민감한 필드는 의도적으로 제외
    }
    
    public function validate(): bool {
        return !empty($this->username) && 
               filter_var($this->email, FILTER_VALIDATE_EMAIL);
    }
}
```

### 4. 프레임워크별 보호 방법

#### Laravel
```php
class User extends Model {
    protected $fillable = ['username', 'email', 'bio'];
    protected $guarded = ['id', 'is_admin', 'balance'];
    
    // 또는 $hidden 사용
    protected $hidden = ['password', 'is_admin', 'api_token'];
}
```

#### Symfony
```php
class UserType extends AbstractType {
    public function buildForm(FormBuilderInterface $builder, array $options) {
        $builder
            ->add('username', TextType::class)
            ->add('email', EmailType::class)
            ->add('bio', TextareaType::class);
            // is_admin 필드는 의도적으로 제외
    }
}
```

### 5. 입력 검증 및 승인 체계

```php
class SecureUserController {
    public function updateProfile(Request $request) {
        $user = auth()->user();
        
        // 1. 허용된 필드만 추출
        $allowedData = $request->only(['username', 'email', 'bio']);
        
        // 2. 입력 검증
        $validator = Validator::make($allowedData, [
            'username' => 'required|string|max:50',
            'email' => 'required|email|unique:users,email,' . $user->id,
            'bio' => 'nullable|string|max:500'
        ]);
        
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 400);
        }
        
        // 3. 안전한 업데이트
        $user->update($allowedData);
        
        return response()->json(['message' => 'Profile updated successfully']);
    }
    
    // 관리자 권한 업데이트는 별도 엔드포인트
    public function updateAdminStatus(Request $request, $userId) {
        if (!auth()->user()->hasRole('super_admin')) {
            return response()->json(['error' => 'Unauthorized'], 403);
        }
        
        $user = User::findOrFail($userId);
        $user->is_admin = $request->boolean('is_admin');
        $user->save();
        
        return response()->json(['message' => 'Admin status updated']);
    }
}
```

## 🔍 취약점 탐지 방법

### 1. 정적 코드 분석

```bash
# PHP에서 위험한 패턴 검색
grep -r "foreach.*\$_POST" .
grep -r "extract(\$_POST" .
grep -r "array_merge.*\$_REQUEST" .

# Laravel 모델 검사
grep -r "protected \$fillable" . | grep -v ".php" || echo "Fillable 설정이 누락된 모델이 있을 수 있습니다"
```

### 2. 동적 테스트

```javascript
// Burp Suite나 OWASP ZAP 스크립트
function testMassAssignment(baseRequest) {
    const sensitiveFields = [
        'is_admin', 'role', 'balance', 'credit_limit',
        'verified', 'status', 'permissions', 'group_id'
    ];
    
    sensitiveFields.forEach(field => {
        const testRequest = baseRequest.clone();
        testRequest.addParameter(field, 'true');
        
        const response = sendRequest(testRequest);
        if (response.contains(field) || response.statusCode === 200) {
            reportVulnerability(`Possible mass assignment: ${field}`);
        }
    });
}
```

### 3. 수동 테스트 절차

1. **폼 분석**: 개발자 도구로 숨겨진 필드 추가
2. **JSON 페이로드**: API 엔드포인트에 추가 속성 포함
3. **응답 분석**: 예상치 못한 필드 업데이트 확인
4. **권한 테스트**: 권한 상승 시도 후 접근 권한 검증

## 🧪 테스트 시나리오

### 시나리오 1: 웹 폼 기반 테스트

```html
<!-- 기본 폼 -->
<form id="profileForm" method="POST" action="/profile/update">
    <input name="username" value="testuser">
    <input name="email" value="test@example.com">
    <button type="submit">Update</button>
</form>

<script>
// 테스트용 숨겨진 필드 동적 추가
document.getElementById('profileForm').addEventListener('submit', function(e) {
    // 권한 상승 테스트
    const adminField = document.createElement('input');
    adminField.type = 'hidden';
    adminField.name = 'is_admin';
    adminField.value = 'true';
    this.appendChild(adminField);
    
    // 잔액 조작 테스트
    const balanceField = document.createElement('input');
    balanceField.type = 'hidden';
    balanceField.name = 'balance';
    balanceField.value = '1000000';
    this.appendChild(balanceField);
});
</script>
```

### 시나리오 2: API 기반 테스트

```python
import requests
import json

def test_mass_assignment_api():
    url = "https://target.com/api/user/update"
    
    # 정상 업데이트 데이터
    legitimate_data = {
        "username": "testuser",
        "email": "test@example.com",
        "bio": "Updated bio"
    }
    
    # 공격 페이로드 추가
    attack_payloads = [
        {"is_admin": True},
        {"role": "administrator"},
        {"balance": 1000000},
        {"verified": True},
        {"permissions": ["read", "write", "admin"]},
        {"created_at": "2020-01-01"},
        {"user_type": "premium"}
    ]
    
    for payload in attack_payloads:
        test_data = {**legitimate_data, **payload}
        
        response = requests.post(url, 
                               json=test_data,
                               headers={"Authorization": "Bearer TOKEN"})
        
        print(f"Testing {list(payload.keys())[0]}: {response.status_code}")
        
        if response.status_code == 200:
            print(f"Potential vulnerability with field: {list(payload.keys())[0]}")
```

## 📊 영향 평가

### 비즈니스 영향

- **데이터 무결성 손상**: 중요한 비즈니스 데이터의 무단 변경
- **권한 상승**: 일반 사용자의 관리자 권한 획득
- **금융 손실**: 잔액, 결제 정보 등의 조작으로 인한 직접적 손실
- **규정 위반**: GDPR, PCI DSS 등 데이터 보호 규정 위반

### 기술적 영향

- **인증/인가 우회**: 시스템 보안 체계 전반의 무력화
- **비즈니스 로직 우회**: 애플리케이션 흐름 제어 실패
- **데이터 일관성 파괴**: 데이터베이스 무결성 제약 조건 우회

## 🔧 수정 가이드

### 즉시 적용할 수정사항

1. **모든 모델에 $fillable 또는 $guarded 설정**
2. **명시적 필드 할당으로 코드 리팩토링**
3. **민감한 필드에 대한 별도 업데이트 로직 구현**
4. **입력 검증 강화**

### 장기적 개선사항

1. **DTO 패턴 도입**
2. **RBAC (Role-Based Access Control) 구현**
3. **API 버전 관리 및 스키마 검증**
4. **자동화된 보안 테스트 도구 구축**

## 📚 참고 자료

- [OWASP Mass Assignment](https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [Laravel Mass Assignment](https://laravel.com/docs/eloquent#mass-assignment)
- [Ruby on Rails Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)

## 🎯 결론

Mass Assignment 취약점은 개발 편의성을 위해 도입된 자동 바인딩 기능의 부작용으로 발생합니다. 화이트리스트 기반의 필드 제어와 명시적 할당을 통해 효과적으로 방어할 수 있으며, 모든 사용자 입력에 대한 엄격한 검증이 필수적입니다.