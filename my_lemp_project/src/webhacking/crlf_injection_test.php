<?php
/**
 * CRLF Injection 테스트 페이지
 * HTTP 응답 분할 (HTTP Response Splitting) 또는 로그 주입 (Log Injection)을 시뮬레이션합니다.
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
$input_header = $_POST['input_header'] ?? '';
$log_entry = $_POST['log_entry'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'http_response_splitting') {
        // HTTP 응답 분할 시뮬레이션
        // 실제 환경에서는 Location 헤더 등에 사용자 입력이 그대로 들어갈 때 발생
        header("X-User-Input: " . $input_header);
        $result = "HTTP 응답 헤더에 사용자 입력이 반영되었습니다. 개발자 도구에서 'X-User-Input' 헤더를 확인하세요.";
        $result .= "<br>CRLF(%0d%0a)를 사용하여 추가 헤더나 응답 본문을 주입할 수 있습니다.";
    } elseif ($action === 'log_injection') {
        // 로그 주입 시뮬레이션
        // 실제 환경에서는 로그 파일에 사용자 입력이 그대로 기록될 때 발생
        $log_file = './logs/crlf_test.log';
        $timestamp = date('Y-m-d H:i:s');
        $log_message = "[{$timestamp}] User input: {$log_entry}\n";
        
        // 취약한 로깅: CRLF 필터링 없이 그대로 파일에 씀
        file_put_contents($log_file, $log_message, FILE_APPEND);
        
        $result = "로그 파일에 사용자 입력이 기록되었습니다. 'logs/crlf_test.log' 파일을 확인하세요.";
        $result .= "<br>CRLF(%0d%0a)를 사용하여 새로운 로그 라인을 주입하거나 로그를 변조할 수 있습니다.";
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
    <title>CRLF Injection 테스트 - 보안 테스트</title>
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
            <h1>CRLF Injection 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>CRLF Injection</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>↩️ CRLF Injection 테스트</h3>
            <p><strong>CRLF Injection</strong>은 캐리지 리턴(CR, <code>%0d</code>)과 라인 피드(LF, <code>%0a</code>) 문자를 주입하여 HTTP 응답 헤더나 로그 파일 등을 조작하는 공격입니다.</p>
            <p>이를 통해 HTTP 응답 분할(HTTP Response Splitting), 캐시 오염, 로그 변조 등의 공격이 가능해집니다.</p>
            <p>이 페이지에서는 HTTP 응답 헤더 주입과 로그 주입 시나리오를 시뮬레이션합니다.</p>
        </div>

        <!-- HTTP Response Splitting 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 HTTP Response Splitting 시뮬레이션</h3>
            <p>아래 입력 필드에 <code>%0d%0a</code> (CRLF)를 포함한 문자열을 입력하여 HTTP 응답 헤더를 조작해보세요.</p>
            <label for="input_header">주입할 헤더 값:</label>
            <textarea id="input_header" name="input_header" placeholder="예: Value%0d%0aSet-Cookie: injected_cookie=malicious"><?php echo htmlspecialchars($input_header); ?></textarea>
            <br><br>
            <button type="submit" name="action" value="http_response_splitting" class="btn" style="background: #dc3545;">HTTP 응답 분할 시도</button>
        </form>

        <!-- Log Injection 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 Log Injection 시뮬레이션</h3>
            <p>아래 입력 필드에 <code>%0d%0a</code> (CRLF)를 포함한 문자열을 입력하여 로그 파일을 조작해보세요.</p>
            <label for="log_entry">로그에 기록할 내용:</label>
            <textarea id="log_entry" name="log_entry" placeholder="예: 정상적인 로그%0d%0aATTACKER_LOG: Malicious activity detected"><?php echo htmlspecialchars($log_entry); ?></textarea>
            <br><br>
            <button type="submit" name="action" value="log_injection" class="btn" style="background: #dc3545;">로그 주입 시도</button>
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
            <h3>🛡️ CRLF Injection 방어 방법</h3>
            <ul>
                <li><strong>CRLF 문자 필터링:</strong> 사용자 입력에서 <code>%0d</code> (CR)와 <code>%0a</code> (LF) 문자를 제거하거나 인코딩합니다.</li>
                <li><strong>안전한 API 사용:</strong> HTTP 헤더 설정 시, CRLF 문자를 자동으로 처리하거나 금지하는 내장 함수나 라이브러리를 사용합니다.</li>
                <li><strong>로그 라이브러리 사용:</strong> 안전한 로깅을 위해 검증된 로그 라이브러리를 사용하고, 사용자 입력이 로그에 기록되기 전에 적절히 이스케이프 처리합니다.</li>
                <li><strong>입력 값 검증:</strong> 모든 사용자 입력을 화이트리스트 방식으로 검증하여 예상된 문자만 허용합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection" target="_blank">PayloadsAllTheThings - CRLF Injection</a></li>
                <li><a href="https://owasp.org/www-community/attacks/HTTP_Response_Splitting" target="_blank">OWASP - HTTP Response Splitting</a></li>
                <li><a href="https://portswigger.net/web-security/crlf-injection" target="_blank">PortSwigger - CRLF injection</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
