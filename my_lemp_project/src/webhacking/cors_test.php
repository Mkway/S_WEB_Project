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
$page_title = 'CORS Misconfiguration';
$description = '<p><strong>CORS (Cross-Origin Resource Sharing)</strong>는 웹 브라우저가 다른 출처(origin)의 리소스에 접근할 수 있도록 허용하는 메커니즘입니다.</p>
<p>잘못된 CORS 설정은 공격자가 악의적인 웹사이트에서 사용자의 데이터를 탈취하거나, 인증된 세션을 이용하여 민감한 작업을 수행하게 할 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 CORS 설정 테스트',
        'description' => '아래 버튼을 클릭하여 다른 출처에서 이 서버의 API에 접근을 시도합니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>허용된 출처 명시:</strong> `Access-Control-Allow-Origin` 헤더에 `*` 대신 특정 도메인을 명시합니다.",
    "<strong>`Vary: Origin` 헤더 사용:</strong> 캐싱 프록시가 출처별로 다른 응답을 캐시하도록 합니다.",
    "<strong>`Access-Control-Allow-Credentials` 주의:</strong> 이 헤더를 `true`로 설정할 경우, `Access-Control-Allow-Origin`에 `*`를 사용할 수 없습니다.",
    "<strong>Preflight 요청 처리:</strong> `OPTIONS` 메서드 요청을 올바르게 처리하고, 허용된 메서드와 헤더를 명시합니다.",
    "<strong>최소한의 메서드 허용:</strong> `Access-Control-Allow-Methods`에 필요한 HTTP 메서드만 포함합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - CORS" => "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    "PortSwigger - Cross-origin resource sharing (CORS)" => "https://portswigger.net/web-security/cors"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<div class="info-box" style="background: #e3f2fd; border-color: #2196f3;">
    <h3>🎯 테스트 목표</h3>
    <p>이 테스트는 서버의 <code>/api/user_info.php</code> 엔드포인트에 다른 출처(이 페이지)에서 AJAX 요청을 보내, 서버의 CORS 정책을 확인합니다.</p>
    <p>개발자 도구의 '네트워크' 탭에서 실제 HTTP 요청과 응답 헤더를 확인할 수 있습니다.</p>
</div>

<form id="cors-test-form" class="test-form">
    <h3>🧪 CORS 테스트 실행</h3>
    <p>아래 버튼을 클릭하여 다른 출처에서 이 서버의 API에 접근을 시도합니다.</p>
    <button type="button" id="cors-test-btn" class="btn" style="background: #dc3545;">API 요청 보내기</button>
</form>

<script>
document.getElementById('cors-test-btn').addEventListener('click', function() {
    const resultBox = document.querySelector('.result-box pre');
    resultBox.innerHTML = 'API 요청 중...';

    fetch('/api/user_info.php', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('네트워크 응답이 올바르지 않습니다.');
        }
        return response.json();
    })
    .then(data => {
        resultBox.innerHTML = '<strong>✅ 요청 성공!</strong><br><br>';
        resultBox.innerHTML += '서버 응답:<br>';
        resultBox.innerHTML += JSON.stringify(data, null, 2);
        resultBox.innerHTML += '<br><br><strong>분석:</strong> 서버가 이 출처를 허용하도록 설정되어 있습니다. `Access-Control-Allow-Origin` 헤더를 확인하세요.';
    })
    .catch(error => {
        resultBox.innerHTML = '<strong>❌ 요청 실패!</strong><br><br>';
        resultBox.innerHTML += '오류: ' + error.message + '<br><br>';
        resultBox.innerHTML += '<strong>분석:</strong> CORS 정책에 의해 요청이 차단되었을 가능성이 높습니다. 개발자 도구의 콘솔에서 자세한 오류를 확인하세요.';
    });
});
</script>
HTML;

// 6. 테스트 로직 콜백 정의 (클라이언트 측 시연이므로 서버 측 로직은 최소화)
$test_logic_callback = function($form_data) {
    return ['result' => '', 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();