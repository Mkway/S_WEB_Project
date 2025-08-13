<?php
/**
 * Account Takeover (계정 탈취) 테스트 페이지
 * 약한 비밀번호 재설정 메커니즘, 세션 예측, 또는 기타 인증 우회 시나리오를 시뮬레이션합니다.
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
$username = $_POST['username'] ?? '';
$reset_code = $_POST['reset_code'] ?? '';
$new_password = $_POST['new_password'] ?? '';

// 시연을 위한 가상의 사용자 데이터 (실제 환경에서는 DB에서 가져와야 합니다)
$users = [
    'testuser' => [
        'password' => password_hash('password123', PASSWORD_DEFAULT),
        'reset_code' => '123456' // 매우 취약한 고정 재설정 코드
    ],
    'admin' => [
        'password' => password_hash('adminpass', PASSWORD_DEFAULT),
        'reset_code' => '654321'
    ]
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'request_reset') {
        // 비밀번호 재설정 요청 시뮬레이션
        if (isset($users[$username])) {
            // 실제로는 사용자에게 이메일/SMS로 코드를 보냅니다.
            $result = "{$username}님에게 재설정 코드가 발송되었습니다 (시뮬레이션).";
        } else {
            $error = "사용자 {$username}을(를) 찾을 수 없습니다.";
        }
    } elseif ($action === 'perform_takeover') {
        // 계정 탈취 시도 시뮬레이션
        if (isset($users[$username])) {
            if ($users[$username]['reset_code'] === $reset_code) {
                // 실제로는 여기서 비밀번호를 업데이트합니다.
                $result = "사용자 {$username}의 비밀번호가 성공적으로 재설정되었습니다 (시뮬레이션). 계정 탈취 성공!";
            } else {
                $error = "잘못된 재설정 코드입니다.";
            }
        } else {
            $error = "사용자 {$username}을(를) 찾을 수 없습니다.";
        }
    }
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Takeover 테스트 - 보안 테스트</title>
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
        input[type="text"], input[type="password"] {
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
            <h1>Account Takeover 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Account Takeover</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>👤 Account Takeover (계정 탈취) 테스트</h3>
            <p><strong>계정 탈취</strong>는 공격자가 합법적인 사용자 계정에 무단으로 접근하는 것을 의미합니다. 이는 약한 비밀번호 재설정 메커니즘, 세션 관리 취약점, 크리덴셜 스터핑 등 다양한 방법으로 발생할 수 있습니다.</p>
            <p>이 페이지에서는 약한 비밀번호 재설정 코드를 이용한 계정 탈취 시나리오를 시뮬레이션합니다.</p>
            <p><strong>시뮬레이션 계정:</strong> <code>testuser</code> (재설정 코드: <code>123456</code>), <code>admin</code> (재설정 코드: <code>654321</code>)</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 계정 탈취 시뮬레이션</h3>
            <label for="username">사용자 이름:</label>
            <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>" required>
            
            <label for="reset_code">재설정 코드 (취약한 코드):</label>
            <input type="text" id="reset_code" name="reset_code" value="<?php echo htmlspecialchars($reset_code); ?>" placeholder="예: 123456" required>
            
            <label for="new_password">새 비밀번호 (실제로는 사용되지 않음):</label>
            <input type="password" id="new_password" name="new_password" value="<?php echo htmlspecialchars($new_password); ?>" placeholder="새 비밀번호" required>
            
            <br><br>
            <button type="submit" name="action" value="perform_takeover" class="btn" style="background: #dc3545;">계정 탈취 시도</button>
            <button type="submit" name="action" value="request_reset" class="btn" style="background: #6c757d;">재설정 코드 요청 (시뮬레이션)</button>
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
            <h3>🛡️ Account Takeover 방어 방법</h3>
            <ul>
                <li><strong>강력한 비밀번호 정책:</strong> 복잡성, 길이, 주기적 변경을 강제합니다.</li>
                <li><strong>다단계 인증 (MFA):</strong> 비밀번호 외 추가 인증 수단을 요구합니다.</li>
                <li><strong>비밀번호 재설정 보안 강화:</strong> 예측 불가능한 일회성 토큰 사용, 재설정 시 기존 세션 무효화, 재설정 후 사용자에게 알림.</li>
                <li><strong>세션 관리 강화:</strong> 예측 불가능한 세션 ID 사용, 짧은 세션 만료 시간, 비활동 시 세션 무효화.</li>
                <li><strong>크리덴셜 스터핑 방어:</strong> 봇 탐지, CAPTCHA, IP 기반 속도 제한.</li>
                <li><strong>로그인 시도 모니터링 및 알림:</strong> 비정상적인 로그인 시도 감지 시 사용자에게 알림.</li>
                <li><strong>계정 잠금 정책:</strong> 일정 횟수 이상 로그인 실패 시 계정 잠금.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-project-top-10/2021/A07_2021-Identification_and_Authentication_Failures" target="_blank">OWASP Top 10 2021 - A07: Identification and Authentication Failures</a></li>
                <li><a href="https://portswigger.net/web-security/account-takeover" target="_blank">PortSwigger - Account takeover</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
