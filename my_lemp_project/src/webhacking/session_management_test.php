<?php
/**
 * Session Management 취약점 테스트 페이지
 */
session_start();

// --- 세션 고정 취약점 시뮬레이션 --- //
// 공격자가 미리 알고 있는 세션 ID를 URL을 통해 강제
if (isset($_GET['PHPSESSID'])) {
    if (session_id() !== $_GET['PHPSESSID']) {
        session_destroy();
        session_id($_GET['PHPSESSID']);
        session_start();
    }
}

require_once '../db.php';
require_once '../utils.php';

$login_message = '';

// 로그인 처리 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    // 취약한 로직: 로그인 성공 후 세션 ID를 재발급하지 않음
    // session_regenerate_id(true);
    
    $_SESSION['test_user'] = $_POST['username'];
    $login_message = htmlspecialchars($_POST['username']) . '님으로 로그인되었습니다. (취약한 방식)';
}

// 로그아웃 처리
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    unset($_SESSION['test_user']);
    $login_message = '로그아웃되었습니다.';
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Management 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        /* 기존 테스트 페이지와 유사한 스타일 */
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>Session Management 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 세션 관리 취약점 테스트</h3>
            <p>안전하지 않은 세션 관리는 인증 우회, 권한 상승 등 심각한 보안 문제로 이어질 수 있습니다.</p>
            <p>이 페이지에서는 대표적인 세션 공격인 <strong>세션 고정</strong>과 <strong>세션 하이재킹</strong>을 시뮬레이션합니다.</p>
        </div>

        <!-- 세션 고정 테스트 -->
        <div class="test-form">
            <h3>🧪 시나리오 1: 세션 고정 (Session Fixation)</h3>
            <p>공격자가 미리 알고 있는 세션 ID를 사용자에게 전달하고, 사용자가 그 세션 ID로 로그인하게 하여 해당 세션을 탈취하는 공격입니다.</p>
            <p><strong>현재 세션 ID:</strong> <code><?php echo session_id(); ?></code></p>
            
            <p><strong>공격 시뮬레이션:</strong></p>
            <ol>
                <li>아래 '공격용 링크 생성' 버튼을 클릭하여 공격자가 만든 링크를 확인합니다.</li>
                <li>생성된 링크를 새 탭에서 열면, 세션 ID가 공격자의 ID로 고정됩니다.</li>
                <li>그 상태에서 아래 폼으로 로그인을 시도합니다.</li>
                <li>로그인 후에도 세션 ID가 바뀌지 않으므로, 공격자는 원래의 세션 ID로 로그인된 세션을 탈취할 수 있습니다.</li>
            </ol>
            <button class="btn" onclick="generateAttackLink()">공격용 링크 생성</button>
            <p id="attack-link-p" style="display:none;"><strong>생성된 링크:</strong> <a id="attack-link" href=""></a></p>

            <form method="post" style="margin-top: 20px;">
                <h4>로그인 시뮬레이션</h4>
                <input type="text" name="username" placeholder="사용자 이름 (e.g., testuser)" required>
                <button type="submit" class="btn">로그인 (취약한 방식)</button>
            </form>
            <?php if (isset($_SESSION['test_user'])): ?>
                <p style="color:green; margin-top:10px;"><strong>로그인 상태:</strong> <?php echo htmlspecialchars($_SESSION['test_user']); ?>님, 환영합니다!</p>
                <a href="?action=logout" class="btn">로그아웃</a>
            <?php endif; ?>
            <?php if ($login_message): ?>
                <p style="color:blue; margin-top:10px;"><?php echo $login_message; ?></p>
            <?php endif; ?>
        </div>

        <!-- 세션 하이재킹 설명 -->
        <div class="info-box">
            <h3>🧪 시나리오 2: 세션 하이재킹 (Session Hijacking)</h3>
            <p>XSS 취약점이나 네트워크 스니핑 등을 통해 사용자의 세션 ID를 탈취하여 해당 사용자로 위장하는 공격입니다.</p>
            <p>예를 들어, XSS 공격으로 <code>alert(document.cookie)</code> 스크립트를 실행시키면 현재 사용자의 쿠키(세션 ID 포함)가 노출될 수 있습니다.</p>
            <p><strong>현재 세션 쿠키 값 (시뮬레이션):</strong> <code>PHPSESSID=<?php echo session_id(); ?>; ...</code></p>
        </div>

        <div class="info-box">
            <h3>🛡️ 안전한 세션 관리 방안</h3>
            <ul>
                <li><strong>로그인 성공 시 `session_regenerate_id(true)` 호출:</strong> 세션 고정 공격을 방어하기 위해 로그인 시 항상 새로운 세션 ID를 발급합니다.</li>
                <li><strong>HttpOnly 플래그 사용:</strong> 쿠키에 HttpOnly 플래그를 설정하여 JavaScript가 쿠키에 접근하는 것을 막습니다. (XSS를 통한 하이재킹 방어)</li>
                <li><strong>Secure 플래그 사용 및 HTTPS 적용:</strong> 쿠키에 Secure 플래그를 설정하고 모든 통신을 HTTPS로 암호화하여 네트워크 스니핑을 통한 하이재킹을 방어합니다.</li>
                <li><strong>세션 타임아웃 설정:</strong> 일정 시간 활동이 없으면 세션을 자동으로 만료시켜 탈취된 세션의 유효 시간을 최소화합니다.</li>
            </ul>
        </div>
    </div>

    <script>
        function generateAttackLink() {
            const attackSessionId = 'attack_session_id_' + Math.random().toString(36).substr(2, 9);
            const url = window.location.pathname + '?PHPSESSID=' + attackSessionId;
            const linkElement = document.getElementById('attack-link');
            linkElement.href = url;
            linkElement.textContent = window.location.origin + url;
            document.getElementById('attack-link-p').style.display = 'block';
        }
    </script>
</body>
</html>
