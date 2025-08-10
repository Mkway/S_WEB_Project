<?php
/**
 * SSRF (Server-Side Request Forgery) 취약점 테스트 페이지
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

// This page demonstrates a basic Server-Side Request Forgery vulnerability.
// An SSRF vulnerability allows an attacker to induce the server-side application
// to make HTTP requests to an arbitrary domain specified by the attacker.
// This can be used to target internal systems behind firewalls, access local files,
// or interact with other services that the server has access to.

// --- How it works ---
// The application takes a URL as input from the user and then fetches the content
// from that URL using a server-side function (e.g., file_get_contents(), curl).
// If the input is not properly validated, an attacker can supply internal IP addresses,
// localhost, or file paths, causing the server to make requests to these locations.

// --- Exploitation Examples ---
// 1. Accessing internal network resources: http://localhost/admin
// 2. Accessing cloud metadata services (AWS EC2): http://169.254.169.254/latest/meta-data/
// 3. Reading local files (if file:// protocol is allowed): file:///etc/passwd

// --- Mitigation ---
// - Validate and sanitize user-supplied URLs: Use a whitelist of allowed domains/protocols.
// - Disable unused URL schemas (e.g., file://, gopher://, ftp://).
// - Implement network segmentation and firewall rules to restrict outbound connections.
// - Use a URL parsing library to ensure the URL points to an expected host.

$result = '';
$url = '';

if (isset($_GET['url'])) {
    $url = $_GET['url'];
    
    // 취약점 시뮬레이션을 위한 안전한 구현
    // 실제 환경에서는 절대 이렇게 구현하지 마세요!
    if (empty($url)) {
        $result = "URL을 입력해주세요.";
    } else {
        // 교육 목적으로만 제한된 SSRF 시뮬레이션
        if (strpos($url, 'file://') === 0) {
            $result = "[시뮬레이션] file:// 프로토콜 감지됨\n";
            $result .= "실제 환경에서는 로컬 파일 접근이 가능할 수 있습니다.\n";
            $result .= "예: /etc/passwd, C:\\Windows\\system32\\drivers\\etc\\hosts 등";
        } elseif (strpos($url, '127.0.0.1') !== false || strpos($url, 'localhost') !== false) {
            $result = "[시뮬레이션] 내부 네트워크 접근 시도 감지\n";
            $result .= "실제 환경에서는 내부 서비스에 접근할 수 있습니다.\n";
            $result .= "예: 관리자 패널, 내부 API, 데이터베이스 등";
        } elseif (strpos($url, '169.254.169.254') !== false) {
            $result = "[시뮬레이션] AWS EC2 메타데이터 서비스 접근 시도\n";
            $result .= "실제 환경에서는 AWS 인스턴스 정보 및 크리덴셜 노출 가능\n";
            $result .= "예: IAM 역할, 보안 그룹, 인스턴스 정보 등";
        } else {
            // 외부 URL만 실제로 요청 (안전한 테스트)
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5,
                    'user_agent' => 'SSRF-Test-Agent'
                ]
            ]);
            $result = @file_get_contents($url, false, $context);
            
            if ($result === false) {
                $result = "외부 URL 접근 실패: 네트워크 오류 또는 접근 제한";
            } else {
                $result = "외부 URL 접근 성공:\n" . htmlspecialchars(substr($result, 0, 500)) . "...";
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
    <title>SSRF 취약점 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        h1, h2 {
            color: #333;
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
        form {
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            margin-right: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        input[type="submit"] {
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
        pre {
            background-color: #eee;
            padding: 15px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .error {
            color: red;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>SSRF 취약점 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🌐 SSRF (Server-Side Request Forgery) 취약점</h2>
            <p><strong>설명:</strong> 서버가 공격자가 제어하는 URL로 요청을 보내도록 유도하는 공격입니다. 
            내부 네트워크 스캔, 메타데이터 서비스 접근, 로컬 파일 읽기 등이 가능합니다.</p>
            
            <h3>📋 테스트 페이로드:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testPayload('http://127.0.0.1')" class="payload-btn">내부 네트워크</button>
                <button onclick="testPayload('http://localhost/admin')" class="payload-btn">관리자 페이지</button>
                <button onclick="testPayload('file:///etc/passwd')" class="payload-btn">시스템 파일</button>
                <button onclick="testPayload('http://169.254.169.254/latest/meta-data/')" class="payload-btn">AWS 메타데이터</button>
                <button onclick="testPayload('https://httpbin.org/ip')" class="payload-btn">외부 API</button>
            </div>
        </div>

        <form action="" method="GET">
            <label for="url">🎯 테스트할 URL 입력:</label><br>
            <input type="text" id="url" name="url" value="<?php echo htmlspecialchars($url); ?>" placeholder="예: http://127.0.0.1 또는 file:///etc/passwd" style="width: 80%;">
            <input type="submit" value="요청 전송" class="btn">
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
                <li><strong>URL 검증:</strong> 허용된 도메인/프로토콜 화이트리스트 사용</li>
                <li><strong>프로토콜 제한:</strong> HTTP/HTTPS만 허용, file://, gopher:// 등 차단</li>
                <li><strong>네트워크 분리:</strong> 내부 네트워크와 외부 연결 분리</li>
                <li><strong>IP 필터링:</strong> 내부 IP 대역 (127.0.0.1, 10.x.x.x, 192.168.x.x) 차단</li>
                <li><strong>타임아웃 설정:</strong> 요청 시간 제한으로 DoS 방지</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        function testPayload(payload) {
            if (confirm('⚠️ 교육 목적의 SSRF 테스트를 실행하시겠습니까?\n\n페이로드: ' + payload)) {
                document.getElementById('url').value = payload;
                document.querySelector('form').submit();
            }
        }

        // 위험 패턴 경고
        document.getElementById('url').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['127.0.0.1', 'localhost', 'file://', '169.254.169.254'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // 페이로드 버튼 스타일 추가
        const style = document.createElement('style');
        style.textContent = `
            .payload-btn {
                background: #17a2b8;
                color: white;
                border: none;
                padding: 8px 12px;
                margin: 5px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                transition: background 0.3s;
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
            .nav-links .btn:hover {
                background: #0056b3;
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>