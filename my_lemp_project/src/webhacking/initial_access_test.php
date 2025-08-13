<?php
/**
 * Initial Access (초기 접근) 테스트 페이지
 * 공격자가 시스템에 처음으로 접근하는 시나리오를 시뮬레이션합니다.
 * 이는 약한 자격 증명, 공개된 관리 인터페이스, 또는 알려진 취약점 악용을 통해 발생할 수 있습니다.
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
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// 시뮬레이션: 약한 기본 자격 증명
$default_admin_user = 'admin';
$default_admin_pass = 'password'; // 매우 약한 기본 비밀번호

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'attempt_login') {
        if ($username === $default_admin_user && $password === $default_admin_pass) {
            $result = "<span style=\"color: red; font-weight: bold;\">초기 접근 성공!</span><br>";
            $result .= "약한 기본 자격 증명(<code>{$default_admin_user}</code>/<code>{$default_admin_pass}</code>)을 통해 관리자 계정에 접근했습니다.";
            $result .= "<br>실제 환경에서는 즉시 기본 자격 증명을 변경해야 합니다.";
        } else {
            $error = "로그인 실패: 잘못된 사용자 이름 또는 비밀번호입니다.";
        }
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
    <title>Initial Access 테스트 - 보안 테스트</title>
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
        input[type="text"], input[type="password"] {
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
            <h1>Initial Access 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Initial Access</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🚪 Initial Access (초기 접근) 테스트</h3>
            <p><strong>Initial Access</strong>는 공격자가 시스템이나 네트워크에 처음으로 발판을 마련하는 단계입니다. 이는 약한 자격 증명, 공개된 관리 인터페이스, 알려진 취약점 악용, 피싱 등 다양한 방법으로 발생할 수 있습니다.</p>
            <p>이 페이지에서는 약한 기본 자격 증명을 통한 초기 접근 시나리오를 시뮬레이션합니다.</p>
            <p><strong>시뮬레이션 계정:</strong> <code>admin</code> / <code>password</code></p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 초기 접근 시뮬레이션 (약한 자격 증명)</h3>
            <p>아래 입력 필드에 약한 기본 자격 증명을 입력하여 관리자 계정에 접근해보세요.</p>
            <label for="username">사용자 이름:</label>
            <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>" required>
            
            <label for="password">비밀번호:</label>
            <input type="password" id="password" name="password" value="<?php echo htmlspecialchars($password); ?>" required>
            
            <br><br>
            <button type="submit" name="action" value="attempt_login" class="btn" style="background: #dc3545;">로그인 시도</button>
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
            <h3>🛡️ Initial Access 방어 방법</h3>
            <ul>
                <li><strong>강력한 자격 증명 정책:</strong> 기본 자격 증명을 사용하지 않고, 복잡하고 유추하기 어려운 비밀번호를 강제합니다.</li>
                <li><strong>다단계 인증 (MFA):</strong> 모든 계정에 MFA를 적용하여 자격 증명 탈취 시에도 계정 접근을 어렵게 합니다.</li>
                <li><strong>공개된 관리 인터페이스 제한:</strong> 관리자 페이지나 민감한 서비스는 외부에서 직접 접근할 수 없도록 IP 화이트리스트, VPN, 방화벽 등으로 접근을 제한합니다.</li>
                <li><strong>취약점 관리:</strong> 소프트웨어 및 시스템의 알려진 취약점을 정기적으로 스캔하고 패치합니다.</li>
                <li><strong>로그인 시도 모니터링:</strong> 비정상적인 로그인 시도나 무차별 대입 공격을 탐지하고 차단하는 시스템을 구축합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://attack.mitre.org/tactics/TA0001/" target="_blank">MITRE ATT&CK - Initial Access</a></li>
                <li><a href="https://owasp.org/www-project-10/2021/A07_2021-Identification_and_Authentication_Failures" target="_blank">OWASP Top 10 2021 - A07: Identification and Authentication Failures (관련)</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
