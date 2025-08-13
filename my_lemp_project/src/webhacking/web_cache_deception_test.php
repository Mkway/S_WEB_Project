<?php
/**
 * Web Cache Deception 테스트 페이지
 * 공격자가 캐싱 프록시를 속여 민감한 사용자 정보를 공개적으로 접근 가능한 캐시에 저장하도록 하는 취약점을 시뮬레이션합니다.
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
$user_profile_data = '사용자 ID: user123, 이메일: user@example.com, 민감한 정보: XXXXX';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_cache_deception') {
        // Web Cache Deception 공격 시뮬레이션
        // 실제 공격은 캐싱 프록시(CDN, 리버스 프록시 등)가 특정 URL을 캐싱하도록 유도할 때 발생합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "Web Cache Deception 시뮬레이션이 실행되었습니다.<br>";
        $result .= "공격자는 <code>/profile/user.php/nonexistent.css</code>와 같은 URL을 생성하여 사용자에게 클릭을 유도합니다.<br>";
        $result .= "웹 서버는 <code>/profile/user.php</code>의 내용을 반환하지만, 캐싱 프록시는 <code>.css</code> 확장자 때문에 이를 정적 파일로 오인하여 캐싱합니다.<br>";
        $result .= "이후 공격자는 <code>/profile/user.php/nonexistent.css</code>에 접근하여 캐시된 민감한 사용자 정보를 탈취할 수 있습니다.<br>";
        $result .= "<br><strong>시뮬레이션된 민감한 사용자 정보:</strong> <code>" . htmlspecialchars($user_profile_data) . "</code><br>";
        $result .= "<br><strong>참고:</strong> 이 시뮬레이션은 실제 캐싱을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
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
    <title>Web Cache Deception 테스트 - 보안 테스트</title>
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
            <h1>Web Cache Deception 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Web Cache Deception</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🕸️ Web Cache Deception 테스트</h3>
            <p><strong>Web Cache Deception</strong>은 공격자가 웹 캐시(CDN, 리버스 프록시 등)를 속여 민감한 사용자 정보가 포함된 페이지를 공개적으로 접근 가능한 캐시에 저장하도록 유도하는 취약점입니다.</p>
            <p>이는 주로 URL 경로 조작을 통해 발생하며, 캐싱 서버가 동적 콘텐츠를 정적 파일로 오인하여 캐싱할 때 발생합니다.</p>
            <p>이 페이지에서는 Web Cache Deception 공격의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 Web Cache Deception 시뮬레이션</h3>
            <p>아래 버튼을 클릭하여 Web Cache Deception 공격을 시뮬레이션합니다.</p>
            <p><strong>공격 시나리오:</strong> 공격자는 로그인한 사용자에게 <code>https://example.com/profile/user.php/nonexistent.css</code>와 같은 URL을 클릭하도록 유도합니다. 서버는 <code>/profile/user.php</code>의 내용을 반환하지만, 캐싱 프록시는 <code>.css</code> 확장자 때문에 이를 캐싱하여 공격자가 나중에 해당 URL로 접근하여 캐시된 사용자 정보를 탈취할 수 있게 됩니다.</p>
            <br>
            <button type="submit" name="action" value="simulate_cache_deception" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
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
            <h3>🛡️ Web Cache Deception 방어 방법</h3>
            <ul>
                <li><strong>캐싱 정책 강화:</strong> 민감한 정보가 포함된 페이지는 캐싱하지 않도록 <code>Cache-Control: no-store, no-cache</code> 헤더를 설정합니다.</li>
                <li><strong>URL 정규화:</strong> 캐싱 프록시가 URL을 정규화하도록 설정하여 <code>/profile/user.php/nonexistent.css</code>와 같은 비정상적인 경로를 동일한 리소스로 인식하도록 합니다.</li>
                <li><strong>파일 확장자 기반 캐싱 지양:</strong> 파일 확장자만으로 캐싱 여부를 결정하지 않고, 콘텐츠 타입(<code>Content-Type</code>) 헤더를 기반으로 캐싱을 결정합니다.</li>
                <li><strong>인증된 요청만 캐싱:</strong> 인증된 사용자로부터의 요청은 캐싱하지 않거나, 사용자별로 분리된 캐시를 사용합니다.</li>
                <li><strong>웹 애플리케이션 방화벽 (WAF):</strong> Web Cache Deception 공격 패턴을 탐지하고 차단하는 WAF를 사용합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://portswigger.net/web-security/web-cache-poisoning/web-cache-deception" target="_blank">PortSwigger - Web cache deception</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Web_Cache_Deception" target="_blank">OWASP - Web Cache Deception</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
