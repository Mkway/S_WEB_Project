<?php
/**
 * External Variable Modification 테스트 페이지
 * 공격자가 HTTP 헤더, 쿠키, 환경 변수 등 외부 변수를 조작하여 애플리케이션의 동작을 변경하는 취약점을 시뮬레이션합니다.
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
$user_role = 'guest'; // 기본 역할

// 시뮬레이션: HTTP 헤더를 통해 사용자 역할을 설정 (취약한 방식)
// 실제 환경에서는 세션이나 DB에서 가져와야 합니다.
if (isset($_SERVER['HTTP_X_USER_ROLE'])) {
    $user_role = $_SERVER['HTTP_X_USER_ROLE'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'check_role') {
        $result = "현재 사용자 역할: <strong>" . htmlspecialchars($user_role) . "</strong><br>";
        $result .= "HTTP 헤더 <code>X-User-Role</code>을 조작하여 역할을 변경해보세요. (예: <code>X-User-Role: admin</code>)";
        
        if ($user_role === 'admin') {
            $result .= "<br><span style=\"color: red; font-weight: bold;\">관리자 권한 획득 시뮬레이션 성공!</span>";
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
    <title>External Variable Modification 테스트 - 보안 테스트</title>
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
            <h1>External Variable Modification 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>External Variable Modification</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>⚙️ External Variable Modification 테스트</h3>
            <p><strong>External Variable Modification</strong>은 공격자가 HTTP 헤더, 쿠키, 환경 변수 등 애플리케이션 외부에서 주입되는 변수들을 조작하여 애플리케이션의 동작을 변경하거나 권한을 상승시키는 취약점입니다.</p>
            <p>이 페이지에서는 HTTP 헤더 <code>X-User-Role</code>을 통해 사용자 역할을 설정하는 취약한 시나리오를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 외부 변수 조작 시뮬레이션</h3>
            <p>현재 페이지는 HTTP 요청 헤더 <code>X-User-Role</code>의 값에 따라 사용자 역할을 결정합니다.</p>
            <p>프록시 도구(예: Burp Suite)를 사용하여 요청 헤더에 <code>X-User-Role: admin</code>을 추가한 후 아래 버튼을 클릭해보세요.</p>
            <br>
            <button type="submit" name="action" value="check_role" class="btn" style="background: #dc3545;">역할 확인</button>
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
            <h3>🛡️ External Variable Modification 방어 방법</h3>
            <ul>
                <li><strong>신뢰할 수 없는 소스 검증:</strong> HTTP 헤더, 쿠키 등 클라이언트 측에서 전송되는 모든 외부 변수는 신뢰할 수 없으므로, 서버 측에서 철저히 검증하고 필터링해야 합니다.</li>
                <li><strong>서버 측에서 중요한 값 관리:</strong> 사용자 역할, 권한 등 보안에 중요한 정보는 서버 측 세션이나 데이터베이스에서 관리하고, 클라이언트 측에서 전송된 값을 직접 사용하지 않습니다.</li>
                <li><strong>화이트리스트 방식 사용:</strong> 허용된 값만 허용하고, 그 외의 모든 입력은 거부합니다.</li>
                <li><strong>최소 권한 원칙:</strong> 애플리케이션이 외부 변수를 통해 접근할 수 있는 권한을 최소화합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution" target="_blank">OWASP - HTTP Parameter Pollution (관련)</a></li>
                <li><a href="https://portswigger.net/web-security/access-control" target="_blank">PortSwigger - Access control vulnerabilities (관련)</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
