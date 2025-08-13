<?php
/**
 * OAuth 2.0 Misconfiguration 테스트 페이지
 */
session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

// 간소화된 OAuth 2.0 시뮬레이션
$auth_server = 'http://localhost/webhacking/oauth_server_sim.php';
$client_id = 'my-client-id';
$client_secret = 'my-client-secret';
$redirect_uri = 'http://localhost/webhacking/oauth_test.php';

$info = '';

// 授权码回调处理
if (isset($_GET['code'])) {
    $code = $_GET['code'];
    $info = "인증 코드를 받았습니다: " . htmlspecialchars($code) . "\n";
    $info .= "이제 이 코드를 사용하여 액세스 토큰을 요청합니다.";
    // 실제로는 이 코드를 사용하여 토큰 엔드포인트에 액세스 토큰을 요청해야 합니다.
    // 여기서는 시뮬레이션이므로 토큰 요청 단계를 생략합니다.
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth 2.0 설정 오류 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        /* 기존 테스트 페이지와 유사한 스타일 */
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>OAuth 2.0 Misconfiguration 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 OAuth 2.0 설정 오류 테스트</h3>
            <p>OAuth 2.0은 안전한 인증/인가 프로토콜이지만, 잘못 설정하면 심각한 취약점이 발생할 수 있습니다.</p>
            <p>주요 취약점은 <strong>부적절한 `redirect_uri` 검증</strong>으로, 공격자가 인증 코드를 탈취하여 사용자 계정을 장악할 수 있습니다.</p>
        </div>

        <div class="test-form">
            <h3>🧪 OAuth 2.0 인증 시작</h3>
            <p>아래 버튼을 클릭하여 OAuth 2.0 인증 프로세스를 시작합니다. 이 과정은 타사 서비스(여기서는 시뮬레이션된 서버)에 대한 접근을 허용하는 것처럼 작동합니다.</p>
            <a href="<?php echo $auth_server . '?response_type=code&client_id=' . $client_id . '&redirect_uri=' . urlencode($redirect_uri); ?>" class="btn" style="background: #007bff;">인증 시작하기</a>
        </div>

        <?php if ($info): ?>
            <div class="result-box">
                <h3>📊 진행 상황</h3>
                <pre><code><?php echo htmlspecialchars($info); ?></code></pre>
            </div>
        <?php endif; ?>

        <div class="payload-section">
            <h3>🎯 공격 시나리오: Redirect URI 조작</h3>
            <p>만약 인증 서버가 `redirect_uri`를 제대로 검증하지 않는다면, 공격자는 `redirect_uri`를 자신의 서버 주소로 변경하여 인증 코드를 탈취할 수 있습니다.</p>
            <p><strong>공격 예시 URL:</strong></p>
            <code>
                <?php 
                $malicious_redirect = 'http://attacker.com/callback';
                $attack_url = $auth_server . '?response_type=code&client_id=' . $client_id . '&redirect_uri=' . urlencode($malicious_redirect);
                echo htmlspecialchars($attack_url);
                ?>
            </code>
            <p><small>사용자가 위 링크를 클릭하면, 인증 후 `attacker.com`으로 리디렉션되어 인증 코드가 유출됩니다.</small></p>
        </div>

        <div class="info-box">
            <h3>🛡️ OAuth 2.0 설정 오류 방어 방법</h3>
            <ul>
                <li><strong>`redirect_uri` 완전 일치 검증:</strong> 인증 서버는 사전에 등록된 `redirect_uri`와 요청 시의 `redirect_uri`가 정확히 일치하는지 반드시 확인해야 합니다.</li>
                <li><strong>State 파라미터 사용:</strong> CSRF 공격을 방지하기 위해 예측 불가능한 `state` 값을 생성하여 요청과 콜백에서 일치하는지 확인합니다.</li>
                <li><strong>PKCE (Proof Key for Code Exchange) 사용:</strong> 모바일 앱 등 public 클라이언트에서 인증 코드 탈취 공격을 방어하기 위해 사용합니다.</li>
            </ul>
        </div>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://www.oauth.com/oauth2-servers/redirect-uris/" target="_blank">OAuth.com - Redirect URIs</a></li>
                <li><a href="https://portswigger.net/web-security/oauth" target="_blank">PortSwigger - OAuth 2.0 authentication vulnerabilities</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
