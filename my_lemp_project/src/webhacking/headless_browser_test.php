<?php
/**
 * Headless Browser Vulnerabilities 테스트 페이지
 * 웹 스크래핑, PDF 생성 등 서버 측에서 헤드리스 브라우저를 사용할 때 발생할 수 있는 취약점을 시뮬레이션합니다.
 * 공격자는 헤드리스 브라우저를 통해 내부 네트워크에 접근하거나, 로컬 파일을 읽거나, 악성 코드를 실행할 수 있습니다.
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

    if ($action === 'simulate_headless_exploit') {
        // 헤드리스 브라우저 익스플로잇 시뮬레이션
        // 실제 환경에서는 서버에서 Puppeteer, Selenium 등으로 URL을 로드합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "헤드리스 브라우저 익스플로잇 시뮬레이션이 시작되었습니다.";
        $result .= "<br>서버가 <code>{$target_url}</code>을(를) 헤드리스 브라우저로 로드한다고 가정합니다.";
        $result .= "<br>공격자는 <code>file:///etc/passwd</code> 또는 <code>http://localhost/internal_admin</code>과 같은 URL을 주입하여 내부 파일에 접근하거나 내부 서비스에 요청을 보낼 수 있습니다.";
        $result .= "<br>또한, 로드된 페이지의 JavaScript를 통해 추가적인 공격(예: XSS, SSRF)을 수행할 수도 있습니다.";
        $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 헤드리스 브라우저를 실행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
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
    <title>Headless Browser Vulnerabilities 테스트 - 보안 테스트</title>
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
            <h1>Headless Browser Vulnerabilities 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Headless Browser Vulnerabilities</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>👻 Headless Browser Vulnerabilities 테스트</h3>
            <p><strong>Headless Browser Vulnerabilities</strong>는 서버 측에서 웹 페이지 렌더링, 스크린샷 생성, PDF 변환 등을 위해 헤드리스 브라우저(예: Puppeteer, Selenium)를 사용할 때 발생할 수 있는 취약점입니다.</p>
            <p>공격자는 헤드리스 브라우저가 로드하는 URL을 조작하여 내부 네트워크에 접근하거나, 로컬 파일을 읽거나, 악성 JavaScript를 실행시킬 수 있습니다.</p>
            <p>이 페이지에서는 헤드리스 브라우저를 이용한 공격의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 헤드리스 브라우저 익스플로잇 시뮬레이션</h3>
            <p>아래 입력 필드에 헤드리스 브라우저가 로드할 가상의 URL을 입력하여 시뮬레이션을 시작하세요.</p>
            <label for="target_url">헤드리스 브라우저 로드 URL (가상):</label>
            <input type="text" id="target_url" name="target_url" value="<?php echo htmlspecialchars($target_url); ?>" placeholder="예: http://localhost/admin 또는 file:///etc/passwd" required>
            <br><br>
            <button type="submit" name="action" value="simulate_headless_exploit" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
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
            <h3>🛡️ Headless Browser Vulnerabilities 방어 방법</h3>
            <ul>
                <li><strong>입력 값 검증:</strong> 헤드리스 브라우저가 로드할 URL에 대해 엄격한 화이트리스트 기반의 검증을 수행합니다. 내부 IP 주소, <code>file://</code>, <code>data://</code> 등 위험한 스키마를 차단합니다.</li>
                <li><strong>샌드박스 환경:</strong> 헤드리스 브라우저를 격리된 샌드박스 환경에서 실행하여 시스템 자원에 대한 접근을 제한합니다.</li>
                <li><strong>최소 권한 원칙:</strong> 헤드리스 브라우저 프로세스에 필요한 최소한의 권한만 부여합니다.</li>
                <li><strong>보안 헤더 설정:</strong> 로드되는 페이지에 <code>Content-Security-Policy (CSP)</code>, <code>X-Frame-Options</code> 등 보안 헤더를 적용하여 공격을 완화합니다.</li>
                <li><strong>정기적인 업데이트:</strong> 헤드리스 브라우저 및 관련 라이브러리를 항상 최신 버전으로 유지하여 알려진 취약점을 패치합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" target="_blank">OWASP - Server Side Request Forgery (SSRF) (관련)</a></li>
                <li><a href="https://portswigger.net/web-security/ssrf" target="_blank">PortSwigger - Server-side request forgery (SSRF) (관련)</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
