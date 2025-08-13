<?php
/**
 * API Key Leaks 테스트 페이지
 * 실제 환경에서는 API 키가 코드에 하드코딩되거나, 클라이언트 측에 노출되는 경우 발생합니다.
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
$exposed_key = '';

// 시연을 위한 가상의 API 키 (실제 환경에서는 절대 이렇게 노출하면 안 됩니다!)
$simulated_api_key = 'sk_test_thisisafakeapikey1234567890abcdef'; 

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'reveal_key') {
        $exposed_key = $simulated_api_key;
        $result = "가상의 API 키가 노출되었습니다. 실제 환경에서는 이 키를 사용하여 민감한 작업이 수행될 수 있습니다.";
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
    <title>API Key Leaks 테스트 - 보안 테스트</title>
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
        .exposed-key-box {
            background: #ffeeba;
            border: 1px solid #ffdf7e;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
            font-weight: bold;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>API Key Leaks 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>API Key Leaks</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🔑 API Key Leaks 테스트</h3>
            <p><strong>API Key Leaks</strong>는 API 키가 코드에 하드코딩되거나, 버전 관리 시스템에 포함되거나, 클라이언트 측 코드에 노출되어 공격자에게 유출되는 취약점입니다.</p>
            <p>유출된 API 키는 서비스 오용, 데이터 접근, 비용 발생 등 심각한 보안 문제로 이어질 수 있습니다.</p>
            <p>이 페이지에서는 API 키가 노출되는 상황을 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 API 키 노출 시뮬레이션</h3>
            <p>아래 버튼을 클릭하면, 개발자 도구(소스 보기)를 통해 코드에 하드코딩된 가상의 API 키가 노출되는 것을 확인할 수 있습니다.</p>
            <button type="submit" name="action" value="reveal_key" class="btn" style="background: #dc3545;">API 키 노출 시도</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <?php if ($exposed_key): ?>
            <div class="exposed-key-box">
                <h3>🚨 노출된 가상의 API 키:</h3>
                <code><?php echo htmlspecialchars($exposed_key); ?></code>
                <p><strong>경고:</strong> 이 키는 시연용이며, 실제 API 키는 절대 이렇게 노출되어서는 안 됩니다!</p>
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
            <h3>🛡️ API Key Leaks 방어 방법</h3>
            <ul>
                <li><strong>환경 변수 사용:</strong> API 키를 코드에 직접 하드코딩하지 않고 환경 변수나 외부 설정 파일을 통해 관리합니다.</li>
                <li><strong>버전 관리 시스템 제외:</strong> <code>.gitignore</code> 등을 사용하여 API 키 파일이 버전 관리 시스템에 커밋되지 않도록 합니다.</li>
                <li><strong>클라이언트 측 노출 방지:</strong> 클라이언트 측(프론트엔드) 코드에 민감한 API 키를 직접 포함하지 않습니다. 필요한 경우 백엔드 프록시를 통해 요청을 처리합니다.</li>
                <li><strong>클라우드 서비스의 비밀 관리 도구 사용:</strong> AWS Secrets Manager, Azure Key Vault, Google Secret Manager 등 클라우드 제공자의 비밀 관리 서비스를 활용합니다.</li>
                <li><strong>API 키 제한:</strong> API 키에 필요한 최소한의 권한만 부여하고, IP 주소 제한, HTTP 리퍼러 제한 등을 설정하여 오용을 방지합니다.</li>
                <li><strong>정기적인 키 교체:</strong> API 키를 주기적으로 교체하여 유출 위험을 줄입니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-project-api-security/api-security-top-10/#api10-insufficient-logging--monitoring" target="_blank">OWASP API Security Top 10 - API10: Insufficient Logging & Monitoring (관련)</a></li>
                <li><a href="https://portswigger.net/web-security/api-security/api-keys" target="_blank">PortSwigger - API keys</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
