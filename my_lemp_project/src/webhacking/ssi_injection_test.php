<?php
/**
 * Server Side Include (SSI) Injection 테스트 페이지
 * 공격자가 SSI (Server Side Include) 지시어를 웹 페이지에 주입하여 웹 서버에서 명령을 실행하거나 파일에 접근하는 취약점을 시뮬레이션합니다.
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
$user_input = $_POST['user_input'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_ssi_injection') {
        // SSI Injection 공격 시뮬레이션
        // 실제 환경에서는 웹 서버(Apache, Nginx)가 SSI를 처리하도록 설정되어 있어야 합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "SSI Injection 시뮬레이션이 실행되었습니다.<br>";
        $result .= "사용자 입력: <code>" . htmlspecialchars($user_input) . "</code><br>";
        $result .= "<br>만약 웹 서버가 사용자 입력에 포함된 SSI 지시어를 필터링 없이 처리한다면, 공격자는 다음과 같은 명령을 실행할 수 있습니다:";
        $result .= "<ul>";
        $result .= "<li><code>&lt;!--#exec cmd=\"ls -la\" --&gt;</code>: 서버에서 임의의 명령 실행</li>";
        $result .= "<li><code>&lt;!--#include virtual=\"/etc/passwd\" --&gt;</code>: 로컬 파일 읽기</li>";
        $result .= "<li><code>&lt;!--#echo var=\"DATE_LOCAL\" --&gt;</code>: 서버 변수 출력</li>";
        $result .= "</ul>";
        $result .= "<br><strong>참고:</strong> 이 시뮬레이션은 실제 SSI 명령을 실행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
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
    <title>SSI Injection 테스트 - 보안 테스트</title>
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
            <h1>SSI Injection 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>SSI Injection</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🖥️ Server Side Include (SSI) Injection 테스트</h3>
            <p><strong>SSI (Server Side Include) Injection</strong>은 웹 서버가 HTML 페이지를 클라이언트에 전송하기 전에 서버 측에서 동적으로 콘텐츠를 포함시키는 SSI 지시어를 처리하는 과정에서 발생하는 취약점입니다.</p>
            <p>공격자는 사용자 입력에 SSI 지시어를 주입하여 웹 서버에서 임의의 명령을 실행하거나, 로컬 파일을 읽거나, 서버 변수를 출력하는 등의 공격을 수행할 수 있습니다.</p>
            <p>이 페이지에서는 SSI Injection 공격의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 SSI Injection 시뮬레이션</h3>
            <p>아래 입력 필드에 SSI 지시어를 포함한 문자열을 입력하여 시뮬레이션을 시작하세요.</p>
            <label for="user_input">사용자 입력:</label>
            <textarea id="user_input" name="user_input" placeholder="예: &lt;!--#exec cmd=\"id\" --&gt; 또는 &lt;!--#include virtual=\"/etc/passwd\" --&gt;" required><?php echo htmlspecialchars($user_input); ?></textarea>
            <br><br>
            <button type="submit" name="action" value="simulate_ssi_injection" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
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
            <h3>🛡️ SSI Injection 방어 방법</h3>
            <ul>
                <li><strong>사용자 입력 필터링:</strong> 사용자 입력에서 SSI 지시어(예: <code>&lt;!--#</code>) 및 관련 특수 문자를 제거하거나 인코딩합니다.</li>
                <li><strong>SSI 비활성화:</strong> 웹 서버 설정에서 불필요한 경우 SSI 기능을 완전히 비활성화합니다.</li>
                <li><strong>최소 권한 원칙:</strong> SSI를 사용하는 경우, <code>exec</code>와 같은 위험한 지시어의 사용을 제한하거나, SSI가 실행되는 프로세스의 권한을 최소화합니다.</li>
                <li><strong>웹 애플리케이션 방화벽 (WAF):</strong> SSI Injection 패턴을 탐지하고 차단하는 WAF를 사용합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection" target="_blank">OWASP - Server-Side Includes (SSI) Injection</a></li>
                <li><a href="https://portswigger.net/web-security/ssi" target="_blank">PortSwigger - SSI injection</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
