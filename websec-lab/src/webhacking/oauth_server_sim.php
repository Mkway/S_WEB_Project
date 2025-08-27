<?php
/**
 * OAuth 2.0 인증 서버 시뮬레이터
 * 교육 목적으로 간소화됨
 */
session_start();

$registered_redirect_uri = 'http://localhost/webhacking/oauth_test.php';

// 파라미터 확인
if (!isset($_GET['response_type']) || $_GET['response_type'] !== 'code') {
    die('Invalid response_type');
}
if (!isset($_GET['client_id'])) {
    die('Invalid client_id');
}
if (!isset($_GET['redirect_uri'])) {
    die('redirect_uri is required');
}

$client_redirect_uri = $_GET['redirect_uri'];

// --- 취약점 발생 지점 --- //
// 방어 로직: 등록된 redirect_uri와 정확히 일치하는지 확인해야 함
/*
if ($client_redirect_uri !== $registered_redirect_uri) {
    die('Error: redirect_uri does not match.');
}
*/

// 취약한 로직: 단순히 URL의 시작 부분만 확인하여, 하위 디렉터리나 다른 도메인으로의 리디렉션을 허용할 수 있음
if (strpos($client_redirect_uri, 'http://localhost/webhacking/') !== 0) {
     // die('Error: redirect_uri is not allowed.'); // 실제로는 여기서 차단해야 함
}

// 사용자 동의 페이지 (시뮬레이션)
if (!isset($_POST['confirm'])) {
?>
    <div style="font-family: sans-serif; padding: 20px; border: 1px solid #ccc; margin: 50px auto; max-width: 500px;">
        <h2>앱 접근 동의</h2>
        <p><strong>My App</strong>이 당신의 프로필 정보에 접근하려고 합니다. 동의하십니까?</p>
        <p><small>리디렉션될 주소: <?php echo htmlspecialchars($client_redirect_uri); ?></small></p>
        <form method="post">
            <button type="submit" name="confirm" value="yes" style="padding: 10px 20px; background: #28a745; color: white; border: none;">동의</button>
            <button type="submit" name="confirm" value="no" style="padding: 10px 20px;">거부</button>
        </form>
    </div>
<?php
    exit();
}

// 동의 거부 시
if ($_POST['confirm'] === 'no') {
    header('Location: ' . $client_redirect_uri . '?error=access_denied');
    exit();
}

// 동의 시, 인증 코드 생성 및 리디렉션
$auth_code = 'auth_code_' . bin2hex(random_bytes(16));
$redirect_url = $client_redirect_uri . '?code=' . $auth_code;

header('Location: ' . $redirect_url);
exit();
