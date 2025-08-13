<?php
/**
 * DOM Clobbering 취약점 테스트 페이지
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
$user_input_id = $_GET['id'] ?? '';

// 취약한 JavaScript 코드 시뮬레이션
// var config = {};
// document.getElementById('user_data').innerHTML = config.admin ? '관리자 모드' : '일반 사용자 모드';

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOM Clobbering 테스트 - 보안 테스트</title>
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
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
        .code-block {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>DOM Clobbering 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 DOM Clobbering 취약점</h3>
            <p>HTML 요소의 <code>id</code>나 <code>name</code> 속성을 사용하여 JavaScript의 전역 변수를 덮어쓰거나 조작하는 공격입니다.</p>
            <p>특히, 전역 변수 이름과 동일한 <code>id</code>나 <code>name</code>을 가진 HTML 요소가 있을 때 발생할 수 있습니다.</p>
        </div>

        <div class="test-area">
            <h3>🧪 테스트 시나리오</h3>
            <p>아래 링크를 클릭하여 <code>id</code> 속성을 가진 HTML 요소가 JavaScript 전역 변수를 어떻게 오염시키는지 확인해 보세요.</p>
            <p><strong>취약한 JavaScript 코드 (시뮬레이션):</strong></p>
            <div class="code-block">
                <code>
var config = {}; // 전역 변수

// 이 부분은 실제 페이지에 존재한다고 가정
document.getElementById('user_status').innerHTML = config.admin ? '관리자 모드' : '일반 사용자 모드';
                </code>
            </div>
            <p style="margin-top: 15px;">아래 링크를 클릭하면, <code>id="config"</code>를 가진 HTML 요소가 <code>config</code> 전역 변수를 덮어씁니다.</p>
            <a href="?id=clobber" class="btn" style="background: #007bff;">DOM Clobbering 공격 시뮬레이션 링크</a>
            
            <div id="user_status" style="margin-top: 20px; font-size: 1.2em; font-weight: bold;">
                <!-- 여기에 결과가 표시됩니다 -->
            </div>
        </div>

        <div class="warning-box">
            <h3>⚠️ 공격 원리</h3>
            <p>브라우저는 HTML 요소의 <code>id</code>나 <code>name</code> 속성을 가진 요소를 전역 <code>window</code> 객체의 속성으로 노출시킵니다. 
            만약 JavaScript 코드에서 사용하는 전역 변수 이름과 동일한 <code>id</code>를 가진 HTML 요소가 있다면, 
            해당 전역 변수는 HTML 요소 객체로 덮어쓰여질 수 있습니다.</p>
            <p><strong>공격용 HTML 예시:</strong></p>
            <pre><code>&lt;img id="config" src="error"&gt;
&lt;img id="config" name="admin"&gt;
</code></pre>
            <p>위 HTML이 페이지에 삽입되면, JavaScript의 <code>config</code> 변수는 더 이상 빈 객체가 아니라 <code>&lt;img&gt;</code> 요소 객체가 됩니다. 
            이후 <code>config.admin</code>과 같은 접근은 <code>&lt;img&gt;</code> 요소의 <code>name="admin"</code> 속성을 참조하게 되어, 
            개발자가 의도하지 않은 동작을 유발할 수 있습니다.</p>
        </div>

        <div class="info-box">
            <h3>🛡️ DOM Clobbering 방어 방법</h3>
            <ul>
                <li>HTML 요소의 <code>id</code>나 <code>name</code> 속성으로 전역 변수를 덮어쓰지 않도록 주의합니다.</li>
                <li>전역 변수 사용을 최소화하고, 스코프를 제한하여 변수 충돌을 방지합니다.</li>
                <li>사용자 입력이 <code>id</code>나 <code>name</code> 속성으로 직접 사용되지 않도록 엄격하게 검증하고 필터링합니다.</li>
                <li><code>Object.create(null)</code>을 사용하여 프로토타입 체인이 없는 객체를 생성하여 프로토타입 오염을 방지합니다.</li>
            </ul>
        </div>
    </div>

    <script>
        // 이 스크립트는 DOM Clobbering 공격을 시뮬레이션합니다.
        // 실제 공격은 HTML에 삽입된 악성 요소에 의해 발생합니다.

        // 전역 변수 (공격 대상)
        var config = {}; 

        // URL 파라미터에서 id 값을 가져와서 시뮬레이션
        const urlParams = new URLSearchParams(window.location.search);
        const clobberId = urlParams.get('id');

        if (clobberId === 'clobber') {
            // 공격용 HTML 요소 삽입 시뮬레이션
            const attackDiv = document.createElement('div');
            attackDiv.innerHTML = '<img id="config" name="admin" style="display:none;">';
            document.body.appendChild(attackDiv);

            // 500ms 후 결과 표시 (DOM이 업데이트된 후)
            setTimeout(() => {
                const userStatusElement = document.getElementById('user_status');
                if (userStatusElement) {
                    // 취약한 코드 시뮬레이션: config.admin이 HTML 요소의 name 속성을 참조
                    userStatusElement.innerHTML = config.admin ? '<span style="color: red;">관리자 모드 (오염됨!)</span>' : '일반 사용자 모드';
                }
            }, 500);
        } else {
            // 초기 상태 표시
            setTimeout(() => {
                const userStatusElement = document.getElementById('user_status');
                if (userStatusElement) {
                    userStatusElement.innerHTML = config.admin ? '관리자 모드' : '일반 사용자 모드 (초기 상태)';
                }
            }, 100);
        }
    </script>
</body>
</html>
