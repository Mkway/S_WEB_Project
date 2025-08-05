<?php
/**
 * Directory Traversal 테스트 페이지
 * PayloadsAllTheThings의 Directory Traversal 페이로드를 기반으로 구성
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
$path = $_POST['path'] ?? '';
$action = $_POST['action'] ?? 'read';

// Directory Traversal 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'basic' => [
        '../',
        '../../',
        '../../../',
        '../../../../',
        '../../../../../',
        '../../../../../../',
        '../../../../../../../',
        '../../../../../../../../'
    ],
    'encoded' => [
        '%2e%2e/',
        '%2e%2e%2f',
        '..%2f',
        '..%252f',
        '..%c0%af',
        '..%ef%bc%8f',
        '..%c1%9c'
    ],
    'double_encoded' => [
        '%252e%252e%252f',
        '%252e%252e/',
        '..%255c',
        '..%255c%255c'
    ],
    'unicode' => [
        '..%u2215',
        '..%u2216',
        '..%uEFC8',
        '..%uF025'
    ],
    'bypass' => [
        '....///',
        '....\\\\\\',
        '....//',
        '....\\//',
        '..///',
        '..\\\\',
        '../\\',
        '..\\/'
    ],
    'common_files' => [
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../etc/shadow',
        '../etc/hosts',
        '../proc/version',
        '../proc/self/environ',
        '../var/log/apache2/access.log',
        '../var/log/nginx/access.log'
    ],
    'windows' => [
        '..\\windows\\system32\\config\\sam',
        '..\\..\\windows\\system32\\config\\sam',
        '..\\windows\\system32\\drivers\\etc\\hosts',
        '..\\boot.ini',
        '..\\windows\\win.ini',
        '..\\windows\\system.ini',
        '..\\inetpub\\logs\\logfiles\\w3svc1\\',
        'C:\\windows\\system32\\config\\sam',
        'C:\\boot.ini'
    ]
];

// 안전한 디렉토리 구조 (시뮬레이션용)
$safe_structure = [
    'public' => [
        'index.html' => 'Welcome to our website!',
        'about.html' => 'About us page content',
        'contact.html' => 'Contact information'
    ],
    'uploads' => [
        'image1.jpg' => '[JPEG Image Data]',
        'document.pdf' => '[PDF Document Data]'
    ],
    'logs' => [
        'access.log' => '127.0.0.1 - - [01/Jan/2024:00:00:01] "GET / HTTP/1.1" 200',
        'error.log' => '[error] [client 127.0.0.1] File does not exist'
    ]
];

// 테스트 실행
if ($_POST && isset($_POST['path'])) {
    // 위험한 패턴 감지
    $dangerous_patterns = [
        '/\.\.\//',           // Basic traversal
        '/\.\.\\\\/',         // Windows traversal
        '/%2e%2e/',           // URL encoded
        '/%252e/',            // Double encoded
        '/etc\/passwd/',      // System files
        '/etc\/shadow/',      // Shadow file
        '/proc\//',           // Process files
        '/var\/log/',         // Log files
        '/windows\//',        // Windows system
        '/boot\.ini/',        // Windows boot
        '/system32\//',       // Windows system32
    ];
    
    $is_dangerous = false;
    $detected_patterns = [];
    
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, strtolower($path))) {
            $is_dangerous = true;
            $detected_patterns[] = str_replace('/', '', $pattern);
        }
    }
    
    if ($is_dangerous) {
        $result = "⚠️ 위험한 Directory Traversal 공격이 감지되었습니다!\n\n";
        $result .= "입력된 경로: " . htmlspecialchars($path) . "\n";
        $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
        
        // 실제 공격이었다면 어떤 일이 일어났을지 시뮬레이션
        $result .= "🎯 공격 시뮬레이션:\n";
        
        if (preg_match('/etc\/passwd/', strtolower($path))) {
            $result .= "만약 취약했다면 시스템 사용자 정보가 노출되었을 것입니다:\n";
            $result .= "root:x:0:0:root:/root:/bin/bash\n";
            $result .= "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
            $result .= "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
        } elseif (preg_match('/etc\/shadow/', strtolower($path))) {
            $result .= "만약 취약했다면 암호 해시가 노출되었을 것입니다:\n";
            $result .= "root:$6$randomsalt$hashedpassword::0:99999:7:::\n";
            $result .= "daemon:*:18474:0:99999:7:::\n";
        } elseif (preg_match('/boot\.ini/', strtolower($path))) {
            $result .= "만약 취약했다면 Windows 부팅 정보가 노출되었을 것입니다:\n";
            $result .= "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\n";
        } else {
            $result .= "시스템의 중요한 파일에 무단 접근을 시도했습니다.\n";
            $result .= "이는 심각한 보안 위험을 초래할 수 있습니다.";
        }
        
        $result .= "\n\n🛡️ 다행히 이 시스템은 적절한 보안 조치로 보호되고 있습니다.";
        
    } else {
        // 안전한 경로 처리
        $clean_path = trim($path, '/\\');
        $path_parts = explode('/', $clean_path);
        
        if (count($path_parts) == 1 && isset($safe_structure[$path_parts[0]])) {
            // 디렉토리 목록 표시
            $result = "✅ 디렉토리 내용:\n\n";
            $result .= "디렉토리: /" . htmlspecialchars($path_parts[0]) . "/\n\n";
            foreach ($safe_structure[$path_parts[0]] as $file => $content) {
                $result .= "📄 " . htmlspecialchars($file) . "\n";
            }
        } elseif (count($path_parts) == 2 && isset($safe_structure[$path_parts[0]][$path_parts[1]])) {
            // 파일 내용 표시
            $result = "✅ 파일 내용:\n\n";
            $result .= "파일: /" . htmlspecialchars(implode('/', $path_parts)) . "\n\n";
            $result .= htmlspecialchars($safe_structure[$path_parts[0]][$path_parts[1]]);
        } else {
            $result = "❌ 요청한 경로를 찾을 수 없습니다.\n\n";
            $result .= "사용 가능한 디렉토리:\n" . implode(', ', array_keys($safe_structure));
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Directory Traversal 테스트 - 보안 테스트</title>
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
            font-family: monospace;
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
        
        .safe-structure {
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
        
        .examples {
            background: #fff3cd;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: monospace;
        }
        
        .severity-high {
            color: #dc3545;
            font-weight: bold;
        }
        
        .severity-critical {
            color: #721c24;
            font-weight: bold;
            background: #f8d7da;
            padding: 2px 4px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>Directory Traversal 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Directory Traversal</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>📂 Directory Traversal 테스트</h3>
            <p><strong>Directory Traversal</strong> (Path Traversal)은 웹 애플리케이션이 파일 경로를 부적절하게 처리할 때 발생하는 취약점입니다.</p>
            <p>공격자가 <code>../</code> 같은 시퀀스를 사용하여 웹 루트 디렉토리 밖의 파일에 접근할 수 있습니다.</p>
            <p><strong>참고:</strong> 이 페이지에서는 실제 시스템 파일에 접근하지 않고 안전하게 시뮬레이션합니다.</p>
        </div>

        <!-- 경고 -->
        <div class="danger-box">
            <h3>⚠️ <span class="severity-critical">CRITICAL</span> 보안 위험</h3>
            <p>Directory Traversal 취약점은 다음과 같은 심각한 결과를 초래할 수 있습니다:</p>
            <ul>
                <li><span class="severity-high">민감한 시스템 파일 노출</span> (/etc/passwd, /etc/shadow, boot.ini 등)</li>
                <li><span class="severity-high">애플리케이션 소스 코드 노출</span></li>
                <li><span class="severity-high">데이터베이스 설정 파일 노출</span></li>
                <li><span class="severity-high">로그 파일을 통한 정보 수집</span></li>
                <li><span class="severity-critical">전체 시스템 권한 탈취 가능</span></li>
            </ul>
        </div>

        <!-- Basic Traversal -->
        <div class="payload-section">
            <h3>🔧 Basic Directory Traversal</h3>
            <p>기본적인 <code>../</code> 시퀀스를 사용한 디렉토리 순회입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['basic'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>etc/passwd')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- URL Encoded -->
        <div class="payload-section">
            <h3>🔤 URL Encoded Traversal</h3>
            <p>URL 인코딩을 사용하여 필터를 우회하는 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['encoded'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>etc/passwd')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Double Encoded -->
        <div class="payload-section">
            <h3>🔄 Double URL Encoded</h3>
            <p>이중 URL 인코딩을 통한 고급 우회 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['double_encoded'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>etc/passwd')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Unicode -->
        <div class="payload-section">
            <h3>🌐 Unicode Encoding</h3>
            <p>유니코드 인코딩을 사용한 필터 우회 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['unicode'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>etc/passwd')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Filter Bypass -->
        <div class="payload-section">
            <h3>🚫 Filter Bypass Techniques</h3>
            <p>다양한 필터링 메커니즘을 우회하는 기법들입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['bypass'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>etc/passwd')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Common Target Files -->
        <div class="payload-section">
            <h3>🎯 Common Target Files</h3>
            <p>공격자들이 주로 노리는 시스템 파일들입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['common_files'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(basename($p)); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Windows Targets -->
        <div class="payload-section">
            <h3>🪟 Windows System Files</h3>
            <p>Windows 환경에서 노리는 중요한 시스템 파일들입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['windows'] as $p): ?>
                    <button class="payload-btn dangerous" onclick="setPayload('<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, -20)); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 안전한 디렉토리 구조 -->
        <div class="safe-structure">
            <h3>✅ 테스트 가능한 안전한 구조</h3>
            <p>이 페이지에서는 실제 시스템 파일 대신 다음 구조를 사용합니다:</p>
            <div class="payload-buttons">
                <button class="payload-btn" onclick="setPayload('public')" style="background: #28a745;">public/</button>
                <button class="payload-btn" onclick="setPayload('uploads')" style="background: #28a745;">uploads/</button>
                <button class="payload-btn" onclick="setPayload('logs')" style="background: #28a745;">logs/</button>
                <button class="payload-btn" onclick="setPayload('public/index.html')" style="background: #17a2b8;">public/index.html</button>
                <button class="payload-btn" onclick="setPayload('uploads/image1.jpg')" style="background: #17a2b8;">uploads/image1.jpg</button>
            </div>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 Directory Traversal 테스트</h3>
            <label for="path">파일/디렉토리 경로:</label>
            <input type="text" name="path" id="path" placeholder="예: ../../../etc/passwd 또는 public/" value="<?php echo htmlspecialchars($path); ?>">
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">경로 접근 테스트</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- 예제 공격 시나리오 -->
        <div class="examples">
            <h3>💡 공격 시나리오 예제</h3>
            <p><strong>시나리오 1:</strong> 웹 애플리케이션이 <code>?file=page.html</code> 형태로 파일을 읽어올 때</p>
            <code>?file=../../../etc/passwd</code> → 시스템 사용자 정보 노출
            <br><br>
            <p><strong>시나리오 2:</strong> 파일 다운로드 기능에서</p>
            <code>download.php?filename=../../../etc/shadow</code> → 암호 해시 노출
            <br><br>
            <p><strong>시나리오 3:</strong> 이미지 표시 기능에서</p>
            <code>image.php?img=../../../../var/log/apache2/access.log</code> → 로그 파일 노출
        </div>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ Directory Traversal 방어 방법</h3>
            <ul>
                <li><strong>입력 검증:</strong> 사용자 입력에서 <code>../</code>, <code>..\</code> 등 위험한 패턴 필터링</li>
                <li><strong>화이트리스트 방식:</strong> 허용된 파일/디렉토리 목록만 사용</li>
                <li><strong>경로 정규화:</strong> <code>realpath()</code>, <code>Path.GetFullPath()</code> 등으로 경로 정규화</li>
                <li><strong>Chroot Jail:</strong> 프로세스를 특정 디렉토리로 제한</li>
                <li><strong>파일명만 사용:</strong> <code>basename()</code>으로 디렉토리 경로 제거</li>
                <li><strong>접근 권한 제한:</strong> 웹 서버 프로세스 권한 최소화</li>
                <li><strong>WAF 사용:</strong> 웹 애플리케이션 방화벽으로 패턴 차단</li>
            </ul>
        </div>

        <!-- 위험한 패턴들 -->
        <div style="background: #f8d7da; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>⚠️ 위험한 패턴 및 문자들</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h4>기본 패턴:</h4>
                    <code>../</code>, <code>..\</code>, <code>./</code>, <code>.\</code>
                    <h4>인코딩된 패턴:</h4>
                    <code>%2e%2e%2f</code>, <code>%2e%2e%5c</code>, <code>%252e</code>
                </div>
                <div>
                    <h4>우회 기법:</h4>
                    <code>....//</code>, <code>..../</code>, <code>..\\</code>
                    <h4>절대 경로:</h4>
                    <code>/etc/</code>, <code>C:\</code>, <code>/proc/</code>
                </div>
            </div>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal" target="_blank">PayloadsAllTheThings - Directory Traversal</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Path_Traversal" target="_blank">OWASP - Path Traversal</a></li>
                <li><a href="https://portswigger.net/web-security/file-path-traversal" target="_blank">PortSwigger - Directory Traversal</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/22.html" target="_blank">CWE-22: Path Traversal</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setPayload(payload) {
            document.getElementById('path').value = payload;
        }

        // 실시간 위험 패턴 감지
        document.getElementById('path').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const dangerousPatterns = [
                /\.\.\//,          // Basic traversal
                /\.\.%2f/,         // URL encoded
                /\.\.%5c/,         // Backslash encoded
                /%2e%2e/,          // Dot encoded
                /%252e/,           // Double encoded
                /etc\/passwd/,     // System files
                /etc\/shadow/,     // Shadow file
                /boot\.ini/,       // Windows boot
                /system32/,        // Windows system
                /proc\//,          // Process files
                /var\/log/         // Log files
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
            const path = document.getElementById('path').value.toLowerCase();
            const dangerousPatterns = [
                /\.\.\//,
                /\.\.%2f/,
                /%2e%2e/,
                /%252e/,
                /etc\/passwd/,
                /etc\/shadow/,
                /boot\.ini/,
                /system32/,
                /proc\//,
                /var\/log/
            ];
            
            let isDangerous = false;
            for (let pattern of dangerousPatterns) {
                if (pattern.test(path)) {
                    isDangerous = true;
                    break;
                }
            }
            
            if (isDangerous) {
                const confirmed = confirm(
                    '입력된 경로에 위험한 Directory Traversal 패턴이 포함되어 있습니다.\n' +
                    '이는 시스템 파일에 무단 접근을 시도하는 공격일 수 있습니다.\n\n' +
                    '교육 목적으로 계속 진행하시겠습니까?'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            } else {
                const confirmed = confirm(
                    'Directory Traversal 테스트를 실행하시겠습니까?\n' +
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