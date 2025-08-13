<?php
/**
 * DNS Rebinding 테스트 페이지
 * DNS Rebinding 공격은 동일 출처 정책(Same-Origin Policy)을 우회하여
 * 공격자가 제어하는 도메인이 내부 IP 주소로 재바인딩되도록 하여 내부 네트워크에 접근하는 공격입니다.
 * 이 페이지는 공격의 개념을 시뮬레이션하며, 실제 공격은 DNS 서버 제어가 필요합니다.
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
$target_url = $_POST['target_url'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_dns_rebinding') {
        // DNS Rebinding 공격 시뮬레이션
        // 실제 공격은 클라이언트 측(브라우저)에서 발생하며, DNS 서버 조작이 필요합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "DNS Rebinding 공격 시뮬레이션이 시작되었습니다.";
        $result .= "<br>공격자는 <code>{$target_url}</code>과 같은 도메인을 사용하여 DNS 응답을 조작합니다.";
        $result .= "<br>첫 번째 DNS 쿼리에서는 공격자 서버의 IP를 반환하고, TTL이 짧게 설정됩니다.";
        $result .= "<br>두 번째 DNS 쿼리에서는 내부 네트워크의 IP 주소(예: 192.168.1.1)를 반환하여 동일 출처 정책을 우회합니다.";
        $result .= "<br>이후 브라우저는 내부 IP 주소에 대한 요청을 동일 출처로 간주하여 내부 자원에 접근할 수 있게 됩니다.";
        $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 DNS Rebinding 공격을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
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
    <title>DNS Rebinding 테스트 - 보안 테스트</title>
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
        input[type="text"] {
            width: calc(100% - 22px);
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ced4da;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>DNS Rebinding 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>DNS Rebinding</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🌐 DNS Rebinding 테스트</h3>
            <p><strong>DNS Rebinding</strong>은 공격자가 제어하는 도메인의 DNS 레코드를 조작하여, 동일 출처 정책(Same-Origin Policy)을 우회하고 내부 네트워크 자원에 접근하는 공격 기법입니다.</p>
            <p>브라우저가 처음에는 공격자 서버의 IP를 받았다가, 짧은 TTL(Time-To-Live) 이후 내부 IP 주소로 재바인딩되도록 하여 내부망 공격을 가능하게 합니다.</p>
            <p>이 페이지에서는 DNS Rebinding 공격의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 DNS Rebinding 시뮬레이션</h3>
            <p>아래 입력 필드에 공격자가 사용할 가상의 도메인을 입력하여 시뮬레이션을 시작하세요.</p>
            <label for="target_url">공격자 제어 도메인 (가상):</label>
            <input type="text" id="target_url" name="target_url" value="<?php echo htmlspecialchars($target_url); ?>" placeholder="예: attacker.com" required>
            <br><br>
            <button type="submit" name="action" value="simulate_dns_rebinding" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
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
            <h3>🛡️ DNS Rebinding 방어 방법</h3>
            <ul>
                <li><strong>내부 IP 주소로의 요청 차단:</strong> 웹 서버나 애플리케이션에서 HTTP Host 헤더를 검증하여 내부 IP 주소로의 요청을 차단합니다.</li>
                <li><strong>DNS 응답 검증:</strong> 애플리케이션이 DNS 쿼리를 수행할 때, 응답으로 받은 IP 주소가 내부 IP 대역에 속하는지 확인하고 차단합니다.</li>
                <li><strong>방화벽 규칙 강화:</strong> 내부 네트워크에서 외부로의 불필요한 연결을 제한하고, 외부에서 내부로의 접근을 엄격하게 통제합니다.</li>
                <li><strong>동일 출처 정책 강화:</strong> 웹 애플리케이션에서 CORS(Cross-Origin Resource Sharing) 정책을 엄격하게 설정하여 신뢰할 수 있는 도메인만 리소스에 접근하도록 합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://portswigger.net/web-security/dns-rebinding" target="_blank">PortSwigger - DNS rebinding</a></li>
                <li><a href="https://owasp.org/www-community/attacks/DNS_Rebinding" target="_blank">OWASP - DNS Rebinding</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
