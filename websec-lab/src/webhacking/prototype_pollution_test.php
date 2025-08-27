<?php
// 출력 버퍼링 시작 (헤더 전송 문제 방지)
ob_start();

// 세션 시작 (TestPage 전에)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . "/../db.php";
require_once __DIR__ . "/../utils.php";

// 로그인 확인
if (!is_logged_in()) {
    header("Location: ../login.php");
    exit();
}

require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Prototype Pollution';
$description = '<p><strong>Prototype Pollution</strong>은 JavaScript 객체의 프로토타입(`Object.prototype`)을 조작하여 
모든 객체에 영향을 미치는 속성을 추가하거나 변경하는 취약점입니다.</p>
<p>주로 안전하지 않은 객체 병합(merge) 함수에서 발생하며, Node.js 애플리케이션에서 심각한 영향을 미칠 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'basic' => [
        'title' => '기본 오염 페이로드',
        'description' => '모든 JavaScript 객체에 새로운 속성을 추가합니다.',
        'payloads' => [
            '{"__proto__": {"pollutedProperty": "polluted"}}',
            '{"constructor": {"prototype": {"pollutedProperty": "polluted"}}}'
        ]
    ],
    'rce_mock' => [
        'title' => 'RCE 시뮬레이션 페이로드',
        'description' => '임의 코드 실행(RCE)을 시뮬레이션하는 페이로드입니다. (실제 실행 아님)',
        'payloads' => [
            '{"__proto__": {"exec": "console.log(\"RCE simulated!\")"}}'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>객체 병합 시 키 검증:</strong> `__proto__`, `constructor`, `prototype`와 같은 예약된 키는 병합 대상에서 제외하거나 엄격하게 검증합니다.",
    "<strong>JSON 스키마 유효성 검사:</strong> 입력받는 JSON 데이터의 구조를 엄격하게 정의하고 유효성을 검사합니다.",
    "<strong>안전한 라이브러리 사용:</strong> 객체 병합 기능을 제공하는 라이브러리(예: Lodash의 `_.merge`)의 보안 패치 버전을 사용하거나, 직접 구현 시 안전하게 작성합니다.",
    "<strong>`Object.freeze()` 또는 `Object.seal()`:</strong> 민감한 객체의 프로토타입 체인을 동결(freeze)하거나 봉인(seal)하여 변경을 방지합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Prototype Pollution" => "https://owasp.org/www-community/attacks/Prototype_Pollution",
    "PortSwigger - Prototype pollution" => "https://portswigger.net/web-security/prototype-pollution"
];

// 5. 테스트 폼 UI 정의
$payload_input = htmlspecialchars($_POST['payload'] ?? '');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7; color: #856404;">
    <h3>⚠️ Node.js 앱 필요</h3>
    <p>이 테스트는 별도의 Node.js 애플리케이션(<code>node_app/server.js</code>)이 실행 중이어야 합니다.</p>
    <p><code>docker-compose up -d</code> 명령어로 Node.js 앱을 실행했는지 확인하세요.</p>
</div>

<form method="post" class="test-form">
    <h3>🧪 Prototype Pollution 테스트</h3>
    <label for="payload">🎯 JSON 페이로드 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="JSON 페이로드를 입력하세요...">{$payload_input}</textarea><br><br>
    <button type="button" onclick="testPrototypePollution()" class="btn">Node.js 앱으로 전송</button>
</form>

<div class="result-box" style="display: none;">
    <h2>📊 테스트 결과:</h2>
    <pre><code></code></pre>
</div>

<script>
    const NODE_APP_URL = 'http://localhost:3000/prototype_pollution';

    async function testPrototypePollution() {
        const payload = document.getElementById('payload').value;
        const resultBox = document.querySelector('.result-box');
        const resultPre = resultBox.querySelector('pre code');
        resultBox.style.display = 'block';
        resultPre.textContent = '요청 중...';

        try {
            const response = await fetch(NODE_APP_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: payload
            });
            const data = await response.json();
            resultPre.textContent = JSON.stringify(data, null, 2);
            console.log('Node.js 앱 응답:', data);
            
            if (data.status === 'vulnerable') {
                alert('✅ Prototype Pollution 성공! 브라우저 콘솔을 확인하세요.');
            } else {
                alert('ℹ️ Prototype Pollution 시도됨. Node.js 앱 응답을 확인하세요.');
            }

        } catch (error) {
            resultPre.textContent = '오류 발생: ' + error.message + '\n\nNode.js 앱이 실행 중인지 확인하세요 (docker-compose up -d).';
            console.error('Prototype Pollution 테스트 중 오류:', error);
            alert('❌ Node.js 앱과 통신 중 오류가 발생했습니다. 콘솔을 확인하세요.');
        }
    }
</script>
HTML;

// 6. 테스트 로직 콜백 정의 (클라이언트 측 시연이므로 서버 측 로직은 최소화)
$test_logic_callback = function($form_data) {
    // 이 페이지는 주로 클라이언트 측 JavaScript로 시연되므로, 서버 측 로직은 최소화합니다.
    // 실제 공격은 Node.js 앱과의 통신을 통해 발생합니다.
    return ['result' => '', 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>