<?php
/**
 * SSRF (Server-Side Request Forgery) 테스트 페이지
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
$url = $_POST['url'] ?? '';

// 페이로드 모음
$payloads = [
    'http://example.com', // 외부 정상 요청
    'http://localhost/admin.php', // 내부 서버의 관리자 페이지 접근 시도
    'file:///etc/passwd', // 로컬 파일 읽기 시도
    'http://169.254.169.254/latest/meta-data/', // 클라우드 메타데이터 접근 시도 (AWS)
];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($url)) {
    // SSRF 방어 로직 (주석 처리하여 취약점 활성화)
    /*
    $parsed_url = parse_url($url);
    if ($parsed_url === false || !isset($parsed_url['host'])) {
        $error = '유효하지 않은 URL입니다.';
    } else {
        $ip = gethostbyname($parsed_url['host']);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            // 안전한 경우에만 요청
            $result = @file_get_contents($url);
        } else {
            $error = '허용되지 않은 IP 주소입니다. (내부 IP 접근 불가)';
        }
    }
    */

    // 취약한 코드: 사용자 입력을 검증 없이 그대로 사용
    $result = @file_get_contents($url);
    if ($result === false) {
        $error = '요청한 URL의 내용을 가져올 수 없습니다.';
    }
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        /* 기존 xss_test.php와 유사한 스타일 */
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>SSRF (Server-Side Request Forgery) 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 Server-Side Request Forgery (SSRF) 테스트</h3>
            <p><strong>SSRF</strong>는 공격자가 서버로 하여금 임의의 다른 서버로 요청을 보내도록 조작하는 공격입니다.</p>
            <p>이를 통해 내부 네트워크 정보 유출, 로컬 파일 접근, 다른 서비스와의 상호작용 등이 가능해질 수 있습니다.</p>
        </div>

        <div class="payload-section">
            <h3>🎯 SSRF 페이로드 예시</h3>
            <div class="payload-buttons">
                <?php foreach ($payloads as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo htmlspecialchars($p, ENT_QUOTES); ?>')">
                        <?php echo htmlspecialchars($p); ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <form method="post" class="test-form">
            <h3>🧪 URL 내용 가져오기</h3>
            <label for="url">테스트할 URL:</label>
            <textarea name="url" id="url" placeholder="여기에 테스트할 URL을 입력하거나 위의 버튼을 클릭하세요"><?php echo htmlspecialchars($url); ?></textarea>
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">요청 보내기</button>
        </form>

        <?php if ($error): ?>
            <div class="vulnerable-demo">
                <h3>⚠️ 오류</h3>
                <p><?php echo htmlspecialchars($error); ?></p>
            </div>
        <?php endif; ?>

        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 요청 결과</h3>
                <pre><code><?php echo htmlspecialchars($result); ?></code></pre>
            </div>
        <?php endif; ?>

        <div class="info-box">
            <h3>🛡️ SSRF 방어 방법</h3>
            <ul>
                <li><strong>Whitelist 기반 검증:</strong> 허용된 도메인, IP, 포트 목록을 만들어 해당 목록에 있는 경우에만 요청을 허용합니다.</li>
                <li><strong>IP 주소 검증:</strong> 요청하려는 최종 IP 주소가 내부망(Private) IP 대역인지 확인하고 차단합니다.</li>
                <li>**리다이렉션 비활성화:** cURL 사용 시 `CURLOPT_FOLLOWLOCATION` 옵션을 비활성화하여 리다이렉트를 통한 우회를 막습니다.</li>
                <li><strong>프로토콜 제한:</strong> `http`, `https` 등 허용된 프로토콜만 사용하도록 제한합니다. (`file://`, `gopher://` 등 위험한 프로토콜 차단)</li>
            </ul>
        </div>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery" target="_blank">PayloadsAllTheThings - SSRF</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" target="_blank">OWASP - Server Side Request Forgery</a></li>
                <li><a href="https://portswigger.net/web-security/ssrf" target="_blank">PortSwigger - Server-side request forgery (SSRF)</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setPayload(payload) {
            document.getElementById('url').value = payload;
        }
    </script>
</body>
</html>
