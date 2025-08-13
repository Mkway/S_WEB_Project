<?php
/**
 * Clickjacking 취약점 테스트 페이지
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

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clickjacking 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        body {
            font-family: sans-serif;
            background-color: #f0f2f5;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 900px;
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
            position: relative; /* iframe을 겹치기 위해 필요 */
            overflow: hidden; /* iframe이 넘치지 않도록 */
        }
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
        .click-target {
            background: #dc3545;
            color: white;
            padding: 15px 30px;
            font-size: 1.5em;
            border-radius: 8px;
            cursor: pointer;
            display: inline-block;
            margin-top: 20px;
            position: relative; /* iframe 아래에 위치 */
            z-index: 1; /* iframe보다 아래에 */
        }
        .overlay-iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001; /* 거의 투명하게 */
            z-index: 10; /* 클릭을 가로채기 위해 최상위 */
            border: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>Clickjacking 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 Clickjacking 취약점</h3>
            <p><strong>설명:</strong> 사용자가 웹 페이지의 특정 요소를 클릭했다고 생각하지만, 실제로는 투명한 <code>iframe</code> 위에 겹쳐진 다른 페이지의 요소를 클릭하게 만드는 공격입니다.</p>
            <p>이를 통해 사용자의 의도와 다르게 좋아요 누르기, 설정 변경, 계정 탈취 등 다양한 악성 행위를 유발할 수 있습니다.</p>
        </div>

        <div class="test-area">
            <h3>🧪 테스트 시나리오</h3>
            <p>아래 '클릭하세요!' 버튼을 클릭하면, 실제로는 투명한 <code>iframe</code> 위에 겹쳐진 외부 페이지의 버튼을 클릭하게 됩니다.</p>
            <p><strong>공격 목표:</strong> 외부 페이지의 '구독하기' 버튼</p>
            
            <div class="click-target">
                클릭하세요!
            </div>
            
            <!-- 투명한 iframe을 겹쳐서 클릭을 가로챕니다 -->
            <iframe class="overlay-iframe" src="https://www.youtube.com/embed/dQw4w9WgXcQ?autoplay=1" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
            
            <p style="margin-top: 20px;"><strong>주의:</strong> 위 iframe은 예시이며, 실제 공격에서는 사용자가 클릭할 만한 중요한 버튼(예: '결제', '확인', '삭제') 위에 겹쳐집니다.</p>
        </div>

        <div class="warning-box">
            <h3>⚠️ 공격 원리</h3>
            <p>공격자는 투명한 <code>iframe</code>을 사용하여 피해자가 방문하는 웹 페이지 위에 악성 페이지를 겹쳐 놓습니다. 
            피해자는 원래 페이지의 버튼을 클릭한다고 생각하지만, 실제로는 투명한 <code>iframe</code> 아래에 있는 악성 페이지의 버튼을 클릭하게 됩니다.</p>
            <p><code>opacity: 0.0001;</code>와 같은 CSS 속성을 사용하여 <code>iframe</code>을 거의 투명하게 만듭니다.</p>
        </div>

        <div class="info-box">
            <h3>🛡️ Clickjacking 방어 방법</h3>
            <ul>
                <li><strong>X-Frame-Options 헤더 사용:</strong> 웹 서버에서 <code>X-Frame-Options: DENY</code> 또는 <code>SAMEORIGIN</code> 헤더를 설정하여 페이지가 <code>iframe</code> 내에서 로드되는 것을 방지합니다.</li>
                <li><strong>Content Security Policy (CSP) `frame-ancestors` 지시어:</strong> <code>frame-ancestors 'self'</code>와 같이 설정하여 페이지를 포함할 수 있는 출처를 제한합니다.</li>
                <li><strong>프레임 버스팅(Frame Busting) 스크립트:</strong> JavaScript를 사용하여 페이지가 <code>iframe</code> 내에서 로드되었을 경우 최상위 프레임으로 이동시킵니다. (하지만 우회될 수 있음)</li>
            </ul>
        </div>
    </div>
</body>
</html>