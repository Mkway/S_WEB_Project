<?php
/**
 * Prototype Pollution 취약점 테스트 페이지
 * Node.js 애플리케이션을 대상으로 합니다.
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
$payload_input = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $payload_input = $_POST['payload'] ?? '';
    
    if (empty($payload_input)) {
        $result = "페이로드를 입력해주세요.";
    } else {
        // Node.js 앱으로 요청 전송 (클라이언트 측에서 JavaScript로 처리)
        // 여기서는 PHP가 직접 요청을 보내지 않고, 클라이언트 측 JavaScript가 Node.js 앱과 통신합니다.
        $result = "클라이언트 측 JavaScript를 통해 Node.js 앱으로 페이로드를 전송합니다.\n";
        $result .= "브라우저 개발자 도구의 콘솔 탭을 확인하세요.";
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prototype Pollution 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .vulnerability-description, .mitigation-guide {
            background-color: #f9f9f9;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .mitigation-guide {
            border-color: #28a745;
        }
        textarea {
            width: 100%;
            height: 150px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .payload-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .payload-btn:hover {
            background: #138496;
        }
        .nav {
            background: #343a40;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav h1 {
            margin: 0;
            color: white;
        }
        .nav-links .btn {
            margin-left: 10px;
            background: #007bff;
            color: white;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 4px;
        }
        .result-box {
            background: #f1f3f4;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #dc3545;
            white-space: pre-wrap;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>Prototype Pollution 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🧪 Prototype Pollution 취약점</h2>
            <p><strong>설명:</strong> JavaScript 객체의 프로토타입(<code>Object.prototype</code>)을 조작하여 
            모든 객체에 영향을 미치는 속성을 추가하거나 변경하는 취약점입니다. 
            주로 안전하지 않은 객체 병합(merge) 함수에서 발생합니다.</p>
            
            <h3>📋 테스트 페이로드:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testPayload('basic')" class="payload-btn">기본 오염</button>
                <button onclick="testPayload('rce_mock')" class="payload-btn">RCE 시뮬레이션</button>
                <button onclick="testPayload('safe')" class="payload-btn">안전한 페이로드</button>
            </div>
        </div>

        <form method="POST">
            <label for="payload">🎯 JSON 페이로드 입력:</label><br>
            <textarea id="payload" name="payload" placeholder="JSON 페이로드를 입력하세요..."><?php echo htmlspecialchars($payload_input); ?></textarea><br><br>
            <input type="submit" value="Node.js 앱으로 전송" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div class="result-box">
                <h2>📊 테스트 결과:</h2>
                <pre><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>객체 병합 시 키 검증:</strong> <code>__proto__</code>, <code>constructor</code>, <code>prototype</code>와 같은 
                예약된 키는 병합 대상에서 제외하거나 엄격하게 검증합니다.</li>
                <li><strong>JSON 스키마 유효성 검사:</strong> 입력받는 JSON 데이터의 구조를 엄격하게 정의하고 유효성을 검사합니다.</li>
                <li><strong>안전한 라이브러리 사용:</strong> 객체 병합 기능을 제공하는 라이브러리(예: Lodash의 <code>_.merge</code>)의 
                보안 패치 버전을 사용하거나, 직접 구현 시 안전하게 작성합니다.</li>
                <li><strong>Object.freeze() 또는 Object.seal():</strong> 민감한 객체의 프로토타입 체인을 
                동결(freeze)하거나 봉인(seal)하여 변경을 방지합니다.</li>
                <li><strong>입력 값 검증 및 정제:</strong> 모든 사용자 입력에 대해 엄격한 유효성 검사를 수행합니다.</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        const NODE_APP_URL = 'http://localhost:3000/prototype_pollution';

        const payloads = {
            basic: '{"__proto__": {"pollutedProperty": "polluted"}}',
            rce_mock: '{"__proto__": {"exec": "console.log(\"RCE simulated!\")"}}', // RCE 시뮬레이션 (실제 실행 아님)
            safe: '{"user": {"name": "test", "email": "test@example.com"}}'
        };

        async function testPayload(type) {
            const payload = payloads[type];
            document.getElementById('payload').value = payload;

            if (confirm('⚠️ 교육 목적의 Prototype Pollution 테스트를 실행하시겠습니까?\n\n유형: ' + type + '\n페이로드: ' + payload + '\n\nNode.js 앱으로 요청을 보냅니다. 브라우저 콘솔을 확인하세요.')) {
                try {
                    const response = await fetch(NODE_APP_URL, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: payload
                    });
                    const data = await response.json();
                    document.querySelector('.result-box pre').textContent = JSON.stringify(data, null, 2);
                    console.log('Node.js 앱 응답:', data);
                    
                    if (data.status === 'vulnerable') {
                        alert('✅ Prototype Pollution 성공! 브라우저 콘솔을 확인하세요.');
                    } else {
                        alert('ℹ️ Prototype Pollution 시도됨. Node.js 앱 응답을 확인하세요.');
                    }

                } catch (error) {
                    document.querySelector('.result-box pre').textContent = '오류 발생: ' + error.message + '\n\nNode.js 앱이 실행 중인지 확인하세요 (docker-compose up -d).';
                    console.error('Prototype Pollution 테스트 중 오류:', error);
                    alert('❌ Node.js 앱과 통신 중 오류가 발생했습니다. 콘솔을 확인하세요.');
                }
            }
        }
    </script>
</body>
</html>
