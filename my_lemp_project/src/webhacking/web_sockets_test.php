<?php
/**
 * Web Sockets Vulnerabilities 테스트 페이지
 * 웹 소켓 통신에서 발생할 수 있는 취약점(예: 인증/권한 부족, 메시지 주입)을 시뮬레이션합니다.
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
$message_to_send = $_POST['message_to_send'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_websocket_attack') {
        // 웹 소켓 취약점 시뮬레이션
        // 실제 환경에서는 웹 소켓 서버와 클라이언트 간의 통신이 필요합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "Web Socket 취약점 시뮬레이션이 시작되었습니다.<br>";
        $result .= "전송 시도 메시지: <code>" . htmlspecialchars($message_to_send) . "</code><br>";
        $result .= "<br>만약 웹 소켓 서버가 메시지에 대한 적절한 인증/권한 검증 없이 처리한다면, 공격자는 임의의 메시지를 주입하여 다른 사용자에게 영향을 주거나, 서버의 기능을 오용할 수 있습니다.";
        $result .= "<br>또한, 웹 소켓 통신이 암호화되지 않거나(ws://), 메시지 내용에 대한 검증이 부족하면 정보 유출이나 XSS 등의 공격으로 이어질 수 있습니다.";
        $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 웹 소켓 통신을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
    } else {
        $error = "알 수 없는 요청입니다.";
    }
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Sockets Vulnerabilities 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .payload-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
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
        }
        .error-box {
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
        code {
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: monospace;
        }
        textarea {
            width: 100%;
            min-height: 80px;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>Web Sockets Vulnerabilities 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Web Sockets Vulnerabilities</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🔌 Web Sockets Vulnerabilities 테스트</h3>
            <p><strong>Web Sockets Vulnerabilities</strong>는 웹 소켓 통신(<code>ws://</code> 또는 <code>wss://</code>)에서 발생할 수 있는 취약점입니다. 웹 소켓은 클라이언트와 서버 간의 양방향 통신을 가능하게 하지만, 부적절하게 구현될 경우 다양한 보안 문제를 야기할 수 있습니다.</p>
            <p>이는 인증/권한 부여 부족, 메시지 주입, XSS, CSRF, 정보 유출 등으로 이어질 수 있습니다.</p>
            <p>이 페이지에서는 웹 소켓 통신을 이용한 공격의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 웹 소켓 공격 시뮬레이션</h3>
            <p>아래 입력 필드에 웹 소켓을 통해 전송할 가상의 메시지를 입력하여 시뮬레이션을 시작하세요.</p>
            <label for="message_to_send">전송할 메시지:</label>
            <textarea id="message_to_send" name="message_to_send" placeholder="예: {'action': 'admin_command', 'cmd': 'rm -rf /'}" required><?php echo htmlspecialchars($message_to_send); ?></textarea>
            <br><br>
            <button type="submit" name="action" value="simulate_websocket_attack" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
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
            <h3>🛡️ Web Sockets Vulnerabilities 방어 방법</h3>
            <ul>
                <li><strong>인증 및 권한 부여:</strong> 웹 소켓 연결 및 메시지에 대해 강력한 인증 및 권한 부여를 적용합니다.</li>
                <li><strong>입력 값 검증:</strong> 웹 소켓을 통해 수신되는 모든 메시지에 대해 서버 측에서 철저한 입력 값 검증을 수행합니다.</li>
                <li><strong>Origin 헤더 검증:</strong> 웹 소켓 연결 시 <code>Origin</code> 헤더를 검증하여 신뢰할 수 있는 도메인에서만 연결을 허용합니다.</li>
                <li><strong>메시지 암호화:</strong> 민감한 정보는 <code>wss://</code> (WebSocket Secure)를 사용하여 암호화된 통신을 보장합니다.</li>
                <li><strong>세션 관리:</strong> 웹 소켓 세션도 HTTP 세션과 동일하게 안전하게 관리합니다.</li>
                <li><strong>로깅 및 모니터링:</strong> 웹 소켓 통신을 로깅하고 비정상적인 활동을 모니터링합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/WebSockets_Security" target="_blank">OWASP - WebSockets Security</a></li>
                <li><a href="https://portswigger.net/web-security/websockets" target="_blank">PortSwigger - WebSockets</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
