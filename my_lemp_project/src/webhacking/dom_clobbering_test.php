<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'DOM Clobbering';
$description = '<p><strong>DOM Clobbering</strong>은 HTML 요소의 <code>id</code>나 <code>name</code> 속성을 사용하여 JavaScript의 전역 변수를 덮어쓰거나 조작하는 공격입니다.</p>
<p>특히, 전역 변수 이름과 동일한 <code>id</code>나 <code>name</code>을 가진 HTML 요소가 있을 때 발생할 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 테스트 시나리오',
        'description' => '아래 링크를 클릭하여 <code>id</code> 속성을 가진 HTML 요소가 JavaScript 전역 변수를 어떻게 오염시키는지 확인해 보세요.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "HTML 요소의 <code>id</code>나 <code>name</code> 속성으로 전역 변수를 덮어쓰지 않도록 주의합니다.",
    "전역 변수 사용을 최소화하고, 스코프를 제한하여 변수 충돌을 방지합니다.",
    "사용자 입력이 <code>id</code>나 <code>name</code> 속성으로 직접 사용되지 않도록 엄격하게 검증하고 필터링합니다.",
    "<code>Object.create(null)</code>을 사용하여 프로토타입 체인이 없는 객체를 생성하여 프로토타입 오염을 방지합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - DOM Clobbering" => "https://owasp.org/www-community/attacks/DOM_Clobbering",
    "PortSwigger - DOM Clobbering" => "https://portswigger.net/web-security/dom-clobbering"
];

// 5. 테스트 폼 UI 정의 (클라이언트 측 시연이므로 간단한 폼)
$test_form_ui = <<<HTML
<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7; color: #856404;">
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

<div class="test-form">
    <h3>🧪 DOM Clobbering 시뮬레이션</h3>
    <p>아래 링크를 클릭하면, <code>id="config"</code>를 가진 HTML 요소가 <code>config</code> 전역 변수를 덮어씁니다.</p>
    <a href="?id=clobber" class="btn" style="background: #007bff;">DOM Clobbering 공격 시뮬레이션 링크</a>
    
    <div id="user_status" style="margin-top: 20px; font-size: 1.2em; font-weight: bold;">
        <!-- 여기에 결과가 표시됩니다 -->
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
HTML;

// 6. 테스트 로직 콜백 정의 (클라이언트 측 시연이므로 서버 측 로직은 최소화)
$test_logic_callback = function($form_data) {
    // 이 페이지는 주로 클라이언트 측 JavaScript로 시연되므로, 서버 측 로직은 최소화합니다.
    // 실제 공격은 HTML에 삽입된 악성 요소에 의해 발생합니다.
    return ['result' => '', 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();