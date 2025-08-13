<?php
/**
 * DoS (Denial of Service) 테스트 페이지
 * 리소스 고갈 (Resource Exhaustion) 공격을 시뮬레이션합니다.
 * 이 페이지는 서버가 과도한 연산을 수행하거나 메모리를 할당하도록 유도하여 서비스 거부를 일으킵니다.
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
$iterations = $_POST['iterations'] ?? 1000000;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_dos') {
        $start_time = microtime(true);
        $output_array = [];

        // 과도한 연산 시뮬레이션 (CPU 소모)
        for ($i = 0; $i < $iterations; $i++) {
            $hash = password_hash(uniqid(), PASSWORD_DEFAULT); // CPU 소모가 큰 연산
            // $output_array[] = $hash; // 메모리 소모를 추가하려면 주석 해제
        }

        $end_time = microtime(true);
        $execution_time = round($end_time - $start_time, 4);

        $result = "DoS 공격 시뮬레이션이 실행되었습니다.<br>";
        $result .= "반복 횟수: " . number_format($iterations) . "회<br>";
        $result .= "실행 시간: " . $execution_time . "초<br>";
        $result .= "<br><strong>참고:</strong> 반복 횟수를 늘리면 서버의 CPU 사용량이 급증하여 서비스 응답이 느려지거나 중단될 수 있습니다.";
        
        // 메모리 소모 시뮬레이션 (메모리 소모)
        // $large_array = array_fill(0, 1000000, str_repeat('A', 1024)); // 1GB 메모리 소모
        // $result .= "<br>할당된 메모리: " . round(memory_get_usage(true) / (1024 * 1024), 2) . " MB";

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
    <title>DoS 테스트 - 보안 테스트</title>
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
        input[type="number"] {
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
            <h1>DoS (Denial of Service) 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>DoS</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🚫 DoS (Denial of Service) 테스트</h3>
            <p><strong>DoS (Denial of Service)</strong> 공격은 서버의 자원(CPU, 메모리, 네트워크 대역폭 등)을 고갈시켜 정상적인 서비스 제공을 방해하는 공격입니다.</p>
            <p>이 페이지에서는 서버에 과도한 연산을 유도하여 CPU 자원을 소모시키는 DoS 공격을 시뮬레이션합니다.</p>
            <p><strong>주의:</strong> 반복 횟수를 너무 높게 설정하면 실제 서비스에 영향을 줄 수 있으니 주의하세요.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 DoS 시뮬레이션 (CPU 소모)</h3>
            <p>아래 반복 횟수를 설정하여 서버의 CPU 자원을 소모시키는 연산을 실행합니다.</p>
            <label for="iterations">반복 횟수:</label>
            <input type="number" id="iterations" name="iterations" value="<?php echo htmlspecialchars($iterations); ?>" min="1000" step="1000" required>
            <br><br>
            <button type="submit" name="action" value="simulate_dos" class="btn" style="background: #dc3545;">DoS 시뮬레이션 실행</button>
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
            <h3>🛡️ DoS 방어 방법</h3>
            <ul>
                <li><strong>입력 값 검증 및 제한:</strong> 사용자 입력의 크기, 복잡성, 반복 횟수 등을 제한하여 과도한 리소스 소모를 방지합니다.</li>
                <li><strong>속도 제한 (Rate Limiting):</strong> 특정 IP 주소나 사용자로부터의 요청 빈도를 제한하여 비정상적인 트래픽을 차단합니다.</li>
                <li><strong>웹 애플리케이션 방화벽 (WAF):</strong> DoS 공격 패턴을 탐지하고 차단하는 WAF를 사용합니다.</li>
                <li><strong>로드 밸런싱 및 오토 스케일링:</strong> 트래픽을 분산하고 필요에 따라 서버 자원을 자동으로 확장하여 공격에 대비합니다.</li>
                <li><strong>CDN (Content Delivery Network) 사용:</strong> 정적 콘텐츠를 캐싱하고 분산하여 원본 서버의 부하를 줄입니다.</li>
                <li><strong>블랙리스트/화이트리스트:</strong> 악성 IP 주소를 차단하거나, 신뢰할 수 있는 IP 주소만 허용합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/Denial_of_Service" target="_blank">OWASP - Denial of Service</a></li>
                <li><a href="https://portswigger.net/web-security/dos" target="_blank">PortSwigger - Denial of service</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
