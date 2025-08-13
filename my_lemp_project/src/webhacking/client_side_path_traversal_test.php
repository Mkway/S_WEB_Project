<?php
/**
 * Client Side Path Traversal 테스트 페이지
 * 클라이언트 측 JavaScript에서 사용자 입력에 따라 파일 경로를 구성할 때 발생할 수 있는 취약점을 시뮬레이션합니다.
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
$file_name = $_POST['file_name'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'load_file') {
        // 이 부분은 클라이언트 측 JavaScript에서 일어나는 일을 시뮬레이션합니다.
        // 실제로는 서버 측에서 파일 시스템에 접근하지 않습니다.
        $result = "클라이언트 측에서 요청된 파일 경로: <code>" . htmlspecialchars($file_name) . "</code>";
        $result .= "<br>이 경로는 클라이언트 측 스크립트에서 동적으로 생성되어 사용될 수 있습니다.";
        $result .= "<br>예: <code>document.getElementById('image').src = '/images/" + encodeURIComponent(userInput) + ".jpg';</code>";
        $result .= "<br><code>../</code>와 같은 경로 조작을 통해 의도치 않은 파일에 접근할 수 있습니다.";
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
    <title>Client Side Path Traversal 테스트 - 보안 테스트</title>
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
            <h1>Client Side Path Traversal 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Client Side Path Traversal</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>📁 Client Side Path Traversal 테스트</h3>
            <p><strong>클라이언트 측 경로 탐색</strong>은 웹 애플리케이션의 클라이언트 측 스크립트(주로 JavaScript)가 사용자 입력에 기반하여 파일 경로를 동적으로 구성할 때 발생할 수 있는 취약점입니다.</p>
            <p>공격자는 <code>../</code>와 같은 경로 조작 문자를 사용하여 웹 서버의 의도치 않은 파일이나 디렉토리에 접근하거나, 클라이언트 측에서 로드되는 리소스의 경로를 변경할 수 있습니다.</p>
            <p>이 페이지에서는 클라이언트 측에서 경로가 조작되는 상황을 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 파일 경로 로드 시뮬레이션</h3>
            <p>아래 입력 필드에 파일 이름을 입력하여 클라이언트 측에서 경로가 어떻게 구성되는지 확인하세요.</p>
            <label for="file_name">파일 이름:</label>
            <input type="text" id="file_name" name="file_name" value="<?php echo htmlspecialchars($file_name); ?>" placeholder="예: image.jpg 또는 ../../../etc/passwd" required>
            <br><br>
            <button type="submit" name="action" value="load_file" class="btn" style="background: #dc3545;">파일 로드 시뮬레이션</button>
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
            <h3>🛡️ Client Side Path Traversal 방어 방법</h3>
            <ul>
                <li><strong>클라이언트 측 입력 검증:</strong> JavaScript에서 사용자 입력에 <code>../</code>, <code>./</code>, <code>\</code> 등 경로 조작 문자가 포함되어 있는지 확인하고 제거합니다.</li>
                <li><strong>서버 측 입력 검증:</strong> 클라이언트 측 검증은 우회될 수 있으므로, 서버 측에서도 파일 경로를 구성하는 모든 입력에 대해 철저한 검증을 수행합니다.</li>
                <li><strong>화이트리스트 방식 사용:</strong> 허용된 파일 이름 또는 경로 패턴만 허용하고, 그 외의 모든 입력은 거부합니다.</li>
                <li><strong>경로 정규화:</strong> 파일 시스템에 접근하기 전에 경로를 정규화하여 <code>../</code>와 같은 문자를 제거합니다.</li>
                <li><strong>최소 권한 원칙:</strong> 웹 서버 프로세스가 파일 시스템에 접근할 수 있는 권한을 최소화합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/Path_Traversal" target="_blank">OWASP - Path Traversal</a></li>
                <li><a href="https://portswigger.net/web-security/file-path-traversal" target="_blank">PortSwigger - File path traversal</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
