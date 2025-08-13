<?php
/**
 * Tabnabbing 취약점 테스트 페이지
 */
session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$message = '';

// 시뮬레이션된 피싱 사이트 URL
$phishing_site_url = 'https://example.com/phishing_login'; // 실제 피싱 사이트가 아님

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tabnabbing 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .info-box {
            background-color: #f9f9f9;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .test-area {
            background: #e0f7fa;
            border: 1px solid #b2ebf2;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .test-area a {
            font-size: 1.2em;
            color: #007bff;
            text-decoration: underline;
        }
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>Tabnabbing 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 Tabnabbing 취약점</h3>
            <p><strong>설명:</strong> 사용자가 현재 보고 있는 탭이 아닌, 백그라운드 탭의 내용을 피싱 사이트로 변경하여 사용자를 속이는 공격입니다.</p>
            <p>사용자가 백그라운드 탭으로 전환했을 때, 원래 보고 있던 사이트가 피싱 사이트로 바뀌어 있어 사용자가 속아 로그인 정보를 입력하게 유도합니다.</p>
        </div>

        <div class="test-area">
            <h3>🧪 테스트 시나리오</h3>
            <p>아래 링크를 <strong>새 탭에서 열어보세요.</strong></p>
            <p>새 탭에서 열린 페이지는 잠시 후 백그라운드 탭(이 페이지)의 내용을 피싱 사이트로 변경하려고 시도합니다.</p>
            <a href="tabnabbing_target.php" target="_blank" rel="noopener">새 탭에서 열기 (Tabnabbing 공격 시뮬레이션)</a>
            <p style="margin-top: 20px;"><strong>주의:</strong> 실제 피싱 사이트로 리다이렉션되지 않으며, 시뮬레이션된 메시지만 표시됩니다.</p>
        </div>

        <div class="warning-box">
            <h3>⚠️ 공격 원리</h3>
            <p>공격자는 `target="_blank"` 속성을 가진 링크에 `rel="noopener"` 또는 `rel="noreferrer"` 속성을 추가하지 않은 경우, 새 탭에서 열린 페이지가 `window.opener` 객체를 통해 원래 페이지의 `location`을 조작할 수 있다는 점을 악용합니다.</p>
            <p><strong>공격 코드 예시 (새 탭에서 열린 페이지의 JavaScript):</strong></p>
            <pre><code>if (window.opener) {
    window.opener.location.replace('<?php echo $phishing_site_url; ?>');
}</code></pre>
        </div>

        <div class="info-box">
            <h3>🛡️ Tabnabbing 방어 방법</h3>
            <ul>
                <li>모든 `target="_blank"` 링크에 `rel="noopener noreferrer"` 속성을 추가합니다.</li>
                <li>`noopener`: `window.opener` 객체에 대한 접근을 차단합니다.</li>
                <li>`noreferrer`: `Referer` 헤더 전송을 막습니다.</li>
            </ul>
        </div>
    </div>

    <script>
        // 이 페이지가 새 탭에서 열렸을 때, 원래 페이지(opener)의 URL을 변경하는 시뮬레이션
        // 실제 공격은 새 탭에서 열린 페이지의 스크립트에서 실행됩니다.
        // 이 페이지는 '원래 페이지' 역할을 합니다.
        
        // 시뮬레이션된 피싱 사이트 URL (실제 리다이렉션은 없음)
        const phishingUrl = '<?php echo $phishing_site_url; ?>';

        // 5초 후 백그라운드 탭의 내용을 변경하는 시뮬레이션
        setTimeout(() => {
            if (window.opener) {
                // 실제 공격에서는 window.opener.location.replace(phishingUrl)이 실행됩니다.
                // 여기서는 시뮬레이션 메시지를 표시합니다.
                document.body.innerHTML = '<div style="text-align: center; margin-top: 100px;">' +
                                        '<h1>⚠️ Tabnabbing 공격 시뮬레이션 성공!</h1>' +
                                        '<p>이 페이지는 백그라운드에서 피싱 사이트로 변경되었습니다.</p>' +
                                        '<p>원래 페이지의 URL: ' + window.location.href + '</p>' +
                                        '<p>변경 시도된 URL: ' + phishingUrl + '</p>' +
                                        '<p>실제 환경에서는 사용자가 속아 로그인 정보를 입력할 수 있습니다.</p>' +
                                        '<button onclick="window.location.reload()">원래 페이지로 돌아가기</button>' +
                                        '</div>';
                document.title = '로그인 세션 만료 - 다시 로그인해주세요';
            }
        }, 5000);
    </script>
</body>
</html>
