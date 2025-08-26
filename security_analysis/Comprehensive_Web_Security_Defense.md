# 웹 보안 공격 방어 종합 가이드

## 📋 개요
웹 애플리케이션에서 발생할 수 있는 주요 보안 공격과 그에 대한 방어 방법을 종합적으로 정리한 문서입니다.

## 🛡️ 주요 웹 공격 유형별 방어 방법

### 1. XSS (Cross-Site Scripting) 방어

#### 방어 방법
1. **출력 인코딩 (Output Encoding)**
   ```php
   // HTML 컨텍스트
   echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
   
   // JavaScript 컨텍스트
   echo json_encode($user_input, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
   
   // CSS 컨텍스트
   echo preg_replace('/[^a-zA-Z0-9\s\-_]/', '', $user_input);
   ```

2. **입력 검증 및 필터링**
   ```php
   // HTML 태그 제거
   $clean_input = strip_tags($_POST['content']);
   
   // 허용된 태그만 유지
   $clean_input = strip_tags($_POST['content'], '<b><i><u><p>');
   
   // 커스텀 필터링 함수 (utils.php에서 사용)
   function safe_output($string) {
       return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
   }
   ```

3. **Content Security Policy (CSP) 헤더**
   ```php
   header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
   ```

#### 추가 방어 기법
- DOMPurify 라이브러리 사용
- X-XSS-Protection 헤더 설정
- HttpOnly 쿠키 플래그 사용

### 2. SQL Injection 방어

#### 1차 방어: Prepared Statements
```php
// PDO 사용 예시
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

// mysqli 사용 예시
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

#### 2차 방어: 입력 검증
```php
// 숫자 검증
$user_id = filter_var($_POST['user_id'], FILTER_VALIDATE_INT);
if ($user_id === false) {
    die("Invalid user ID");
}

// 문자열 길이 제한
if (strlen($username) > 50) {
    die("Username too long");
}

// 특수문자 이스케이프 (최후 수단)
$username = mysqli_real_escape_string($connection, $username);
```

#### 3차 방어: 데이터베이스 권한 최소화
- 애플리케이션 전용 DB 사용자 생성
- 필요한 최소 권한만 부여
- DDL 권한 제거

### 3. CSRF (Cross-Site Request Forgery) 방어

#### 토큰 기반 방어
```php
// 토큰 생성 (utils.php에서 사용)
function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// 토큰 검증
function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// HTML 폼에서 사용
echo '<input type="hidden" name="csrf_token" value="' . generate_csrf_token() . '">';
```

#### 추가 방어 방법
- SameSite 쿠키 속성 사용
- Referer 헤더 검증
- Double Submit Cookie 패턴

### 4. 인증 및 세션 보안

#### 안전한 패스워드 해싱
```php
// 패스워드 해싱
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// 패스워드 검증
if (password_verify($password, $hashed_password)) {
    // 로그인 성공
}

// 강력한 패스워드 정책 (utils.php에서 사용)
function validate_password($password) {
    $result = ['is_valid' => true, 'message' => ''];
    
    if (strlen($password) < 8) {
        $result['is_valid'] = false;
        $result['message'] = '비밀번호는 최소 8자 이상이어야 합니다.';
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $result['is_valid'] = false;
        $result['message'] = '대문자가 포함되어야 합니다.';
    }
    
    return $result;
}
```

#### 세션 보안 강화
```php
// 안전한 세션 시작 (utils.php에서 사용)
function secure_session_start() {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_secure', 1); // HTTPS 환경
        
        session_start();
        
        // 세션 고정 공격 방지
        if (!isset($_SESSION['initiated'])) {
            session_regenerate_id(true);
            $_SESSION['initiated'] = true;
        }
        
        // 세션 타임아웃 체크
        if (isset($_SESSION['last_activity']) && 
            (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
            session_destroy();
        }
        
        $_SESSION['last_activity'] = time();
    }
}
```

### 5. 파일 업로드 보안

#### 파일 검증 및 필터링
```php
// 파일 확장자 검증 (utils.php에서 사용)
function is_allowed_file_extension($filename, $allowed_extensions) {
    $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($file_extension, $allowed_extensions);
}

// 안전한 파일명 검사
function isSafeFilename($filename) {
    // 디렉터리 순회 공격 방지
    if (strpos($filename, '..') !== false) return false;
    if (strpos($filename, '/') !== false) return false;
    if (strpos($filename, '\\') !== false) return false;
    
    // 위험한 확장자 차단
    $dangerous_exts = ['php', 'exe', 'sh', 'bat', 'com', 'scr', 'vbs', 'js'];
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (in_array($ext, $dangerous_exts)) return false;
    
    // 시스템 파일 차단
    if (strpos($filename, '.ht') === 0) return false;
    if ($filename === 'web.config') return false;
    
    return true;
}

// MIME 타입 검증
function validateMimeType($file_path, $allowed_types) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file_path);
    finfo_close($finfo);
    
    return in_array($mime_type, $allowed_types);
}
```

### 6. 명령어 주입 (Command Injection) 방어

#### 안전한 시스템 명령 실행
```php
// 입력값 검증
function sanitizeCommandInput($input) {
    // 허용된 문자만 유지
    return preg_replace('/[^a-zA-Z0-9\-_\.]/', '', $input);
}

// 안전한 명령 실행
function executeSafeCommand($command, $args = []) {
    // escapeshellcmd와 escapeshellarg 사용
    $safe_command = escapeshellcmd($command);
    foreach ($args as $arg) {
        $safe_command .= ' ' . escapeshellarg($arg);
    }
    
    return shell_exec($safe_command);
}

// 더 안전한 방법: 화이트리스트 기반
$allowed_commands = ['ls', 'pwd', 'date'];
if (in_array($user_command, $allowed_commands)) {
    // 명령 실행
}
```

### 7. 디렉터리 순회 (Directory Traversal) 방어

#### 경로 검증
```php
function sanitizePath($path) {
    // 상대 경로 제거
    $path = str_replace(['../', '..\\'], '', $path);
    
    // 절대 경로를 상대 경로로 변환
    $path = ltrim($path, '/\\');
    
    // 허용된 디렉터리 내부인지 확인
    $base_dir = realpath('/var/www/uploads/');
    $full_path = realpath($base_dir . '/' . $path);
    
    if (strpos($full_path, $base_dir) !== 0) {
        throw new Exception("Invalid path");
    }
    
    return $full_path;
}
```

### 8. LDAP/NoSQL Injection 방어

#### LDAP 보안
```php
function escapeLdapInput($input) {
    $search = ['\\', '*', '(', ')', "\x00", '/'];
    $replace = ['\\\\', '\\*', '\\(', '\\)', '\\00', '\\/'];
    return str_replace($search, $replace, $input);
}
```

#### NoSQL (MongoDB) 보안
```javascript
// JavaScript (Node.js) 예시
const MongoClient = require('mongodb').MongoClient;

// 파라미터화된 쿼리 사용
db.collection('users').findOne({
    username: username, // 직접 문자열 연결 금지
    password: password
});

// 입력 타입 검증
if (typeof username !== 'string' || typeof password !== 'string') {
    throw new Error('Invalid input type');
}
```

## 🔧 프로젝트에서 사용하는 보안 함수 목록

### utils.php에서 제공하는 보안 함수들

1. **XSS 방어**
   - `safe_output($string)` - HTML 엔티티 인코딩
   - `clean_input($input)` - 입력값 정리

2. **CSRF 방어**
   - `generate_csrf_token()` - CSRF 토큰 생성
   - `verify_csrf_token($token)` - CSRF 토큰 검증

3. **세션 보안**
   - `secure_session_start()` - 안전한 세션 시작
   - `is_logged_in()` - 로그인 상태 확인
   - `is_admin()` - 관리자 권한 확인

4. **파일 보안**
   - `is_allowed_file_extension($filename, $allowed_extensions)` - 파일 확장자 검증
   - `isSafeFilename($filename)` - 안전한 파일명 검사 (SecurityTest.php에서 사용)

5. **입력 검증**
   - `is_valid_email($email)` - 이메일 형식 검증
   - `validate_password($password)` - 패스워드 강도 검증

6. **권한 관리**
   - `require_admin()` - 관리자 권한 필요
   - `require_login()` - 로그인 필요
   - `redirect_to_login($message)` - 로그인 페이지 리다이렉트

7. **보안 리다이렉트**
   - `safe_redirect($url, $default_url)` - 오픈 리다이렉트 방지

8. **예외 처리**
   - `handle_exception($e, $user_message)` - 안전한 예외 처리

### 다른 코드에서 사용하는 PHP 내장 보안 함수들

1. **데이터베이스 보안**
   ```php
   // PDO prepare/execute - 전체 프로젝트에서 사용
   $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
   $stmt->execute([$user_id]);
   
   // 패스워드 해싱 - install.php, register.php 등에서 사용
   $hashed = password_hash($password, PASSWORD_DEFAULT);
   if (password_verify($input_password, $stored_hash)) { /* ... */ }
   ```

2. **출력 보안**
   ```php
   // htmlspecialchars - 전체 프로젝트에서 광범위하게 사용
   echo htmlspecialchars($user_data, ENT_QUOTES, 'UTF-8');
   ```

3. **입력 검증**
   ```php
   // filter_var - utils.php에서 이메일 검증에 사용
   filter_var($email, FILTER_VALIDATE_EMAIL);
   
   // strip_tags - 일부 입력 처리에서 사용
   $clean_content = strip_tags($user_input, '<b><i><u>');
   ```

4. **암호화 및 해싱**
   ```php
   // hash_equals - CSRF 토큰 비교에 사용 (타이밍 공격 방지)
   hash_equals($_SESSION['csrf_token'], $submitted_token);
   
   // bin2hex, random_bytes - 토큰 생성에 사용
   $token = bin2hex(random_bytes(32));
   ```

5. **파일 보안**
   ```php
   // pathinfo - 파일 확장자 추출
   $extension = pathinfo($filename, PATHINFO_EXTENSION);
   
   // realpath - 경로 정규화
   $safe_path = realpath($base_dir . '/' . $user_path);
   ```

## 📊 보안 테스트 현황

현재 SecurityTest.php에서 구현된 테스트:
- CSRF 토큰 검증 테스트
- SQL Injection 방어 테스트 (기본 + 고급 페이로드)
- XSS 방어 테스트 (다양한 XSS 벡터)
- 세션 보안 테스트
- 파일 업로드 보안 테스트
- 패스워드 강도 검증 테스트
- 입력 길이 제한 테스트
- 사용자 권한 확인 테스트

## ⚠️ 추가 고려사항

1. **로깅 및 모니터링**
   - 보안 이벤트 로깅 (utils.php에 일부 구현됨)
   - 실패한 로그인 시도 추적
   - 의심스러운 활동 모니터링

2. **네트워크 보안**
   - HTTPS 강제 사용
   - HSTS 헤더 설정
   - 적절한 CORS 정책

3. **정기 보안 검토**
   - 의존성 업데이트
   - 보안 패치 적용
   - 코드 감사

이 문서는 프로젝트의 보안 강화를 위한 종합적인 가이드라인을 제공하며, 실제 구현된 보안 함수들과 함께 실무에서 바로 활용할 수 있는 방어 기법들을 포함하고 있습니다.