<?php
/**
 * Reverse Proxy Misconfigurations 테스트 페이지
 * 잘못 구성된 리버스 프록시가 내부 서비스 노출, 보안 제어 우회, 정보 유출 등으로 이어지는 시나리오를 시뮬레이션합니다.
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
$internal_path = $_POST['internal_path'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_misconfig') {
        // 리버스 프록시 설정 오류 시뮬레이션
        // 실제 환경에서는 리버스 프록시 설정(Nginx, Apache 등)에 따라 동작이 달라집니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "리버스 프록시 설정 오류 시뮬레이션이 시작되었습니다.";
        $result .= "<br>공격자는 <code>{$internal_path}</code>와 같은 내부 경로를 직접 요청하여 리버스 프록시의 잘못된 설정을 악용할 수 있습니다.";
        $result .= "<br>예: <code>/admin</code>, <code>/internal-api</code>, <code>/.git</code> 등
";
        $result .= "<br>만약 리버스 프록시가 이러한 내부 경로를 적절히 차단하지 못하면, 공격자는 민감한 정보에 접근하거나 내부 시스템을 조작할 수 있습니다.";
        $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 리버스 프록시를 조작하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
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
    <title>Reverse Proxy Misconfigurations 테스트 - 보안 테스트</title>
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
            <h1>Reverse Proxy Misconfigurations 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Reverse Proxy Misconfigurations</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🔄 Reverse Proxy Misconfigurations 테스트</h3>
            <p><strong>Reverse Proxy Misconfigurations</strong>는 리버스 프록시(예: Nginx, Apache)가 잘못 설정되어 내부 서비스나 민감한 정보가 외부에 노출되거나, 보안 제어가 우회되는 취약점입니다.</p>
            <p>이는 잘못된 경로 설정, 불필요한 헤더 노출, 내부 IP 주소 노출 등으로 발생할 수 있습니다.</p>
            <p>이 페이지에서는 리버스 프록시 설정 오류의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 리버스 프록시 설정 오류 시뮬레이션</h3>
            <p>아래 입력 필드에 공격자가 직접 접근을 시도할 가상의 내부 경로를 입력하여 시뮬레이션을 시작하세요.</p>
            <label for="internal_path">가상의 내부 경로:</label>
            <input type="text" id="internal_path" name="internal_path" value="<?php echo htmlspecialchars($internal_path); ?>" placeholder="예: /admin, /internal-api, /.git" required>
            <br><br>
            <button type="submit" name="action" value="simulate_misconfig" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
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
            <h3>🛡️ Reverse Proxy Misconfigurations 방어 방법</h3>
            <ul>
                <li><strong>경로 및 접근 제어 강화:</strong> 리버스 프록시 설정에서 내부 서비스나 민감한 경로에 대한 외부 접근을 엄격히 제한하고, 필요한 경우 인증 및 권한 부여를 적용합니다.</li>
                <li><strong>불필요한 헤더 제거:</strong> <code>Server</code>, <code>X-Powered-By</code> 등 서버 정보를 노출하는 헤더를 제거하거나 일반적인 값으로 변경합니다.</li>
                <li><strong>내부 IP 주소 노출 방지:</strong> 에러 페이지나 리다이렉션 시 내부 IP 주소가 노출되지 않도록 설정합니다.</li>
                <li><strong>정기적인 설정 감사:</strong> 리버스 프록시 설정을 정기적으로 검토하고, 보안 모범 사례에 따라 업데이트합니다.</li>
                <li><strong>웹 애플리케이션 방화벽 (WAF) 사용:</strong> WAF를 통해 비정상적인 요청을 탐지하고 차단합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/Reverse_Proxy_Bypass" target="_blank">OWASP - Reverse Proxy Bypass</a></li>
                <li><a href="https://portswigger.net/web-security/host-header" target="_blank">PortSwigger - Host header attacks (관련)</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
