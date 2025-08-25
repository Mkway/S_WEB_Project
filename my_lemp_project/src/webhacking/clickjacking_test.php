
<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Clickjacking';
$description = '<p><strong>Clickjacking</strong>은 사용자가 웹 페이지의 특정 요소를 클릭했다고 생각하지만, 실제로는 투명한 `iframe` 위에 겹쳐진 다른 페이지의 요소를 클릭하게 만드는 공격입니다.</p>
<p>이를 통해 사용자의 의도와 다르게 좋아요 누르기, 설정 변경, 계정 탈취 등 다양한 악성 행위를 유발할 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 테스트 시나리오',
        'description' => '아래 '클릭하세요!' 버튼을 클릭하면, 실제로는 투명한 `iframe` 위에 겹쳐진 외부 페이지의 버튼을 클릭하게 됩니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>X-Frame-Options 헤더 사용:</strong> 웹 서버에서 `X-Frame-Options: DENY` 또는 `SAMEORIGIN` 헤더를 설정하여 페이지가 `iframe` 내에서 로드되는 것을 방지합니다.",
    "<strong>Content Security Policy (CSP) `frame-ancestors` 지시어:</strong> `frame-ancestors 'self'`와 같이 설정하여 페이지를 포함할 수 있는 출처를 제한합니다.",
    "<strong>프레임 버스팅(Frame Busting) 스크립트:</strong> JavaScript를 사용하여 페이지가 `iframe` 내에서 로드되었을 경우 최상위 프레임으로 이동시킵니다. (하지만 우회될 수 있음)"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Clickjacking" => "https://owasp.org/www-community/attacks/Clickjacking",
    "PortSwigger - Clickjacking" => "https://portswigger.net/web-security/clickjacking"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7; color: #856404;">
    <h3>⚠️ 공격 원리</h3>
    <p>공격자는 투명한 `iframe`을 사용하여 피해자가 방문하는 웹 페이지 위에 악성 페이지를 겹쳐 놓습니다. 
    피해자는 원래 페이지의 버튼을 클릭한다고 생각하지만, 실제로는 투명한 `iframe` 아래에 있는 악성 페이지의 버튼을 클릭하게 됩니다.</p>
    <p><code>opacity: 0.0001;</code>와 같은 CSS 속성을 사용하여 `iframe`을 거의 투명하게 만듭니다.</p>
</div>

<div class="test-form" style="position: relative; overflow: hidden;">
    <h3>🧪 Clickjacking 시뮬레이션</h3>
    <p><strong>공격 목표:</strong> 외부 페이지의 '구독하기' 버튼</p>
    
    <div class="click-target" style="background: #dc3545; color: white; padding: 15px 30px; font-size: 1.5em; border-radius: 8px; cursor: pointer; display: inline-block; margin-top: 20px; position: relative; z-index: 1;">
        클릭하세요!
    </div>
    
    <!-- 투명한 iframe을 겹쳐서 클릭을 가로챕니다 -->
    <iframe class="overlay-iframe" src="https://www.youtube.com/embed/dQw4w9WgXcQ?autoplay=1" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.0001; z-index: 10; border: none;"></iframe>
    
    <p style="margin-top: 20px;"><strong>주의:</strong> 위 iframe은 예시이며, 실제 공격에서는 사용자가 클릭할 만한 중요한 버튼(예: '결제', '확인', '삭제') 위에 겹쳐집니다.</p>
</div>
HTML;

// 6. 테스트 로직 콜백 정의 (클라이언트 측 시연이므로 서버 측 로직은 최소화)
$test_logic_callback = function($form_data) {
    // 이 페이지는 주로 클라이언트 측 HTML/CSS/JavaScript로 시연되므로, 서버 측 로직은 최소화합니다.
    return ['result' => '', 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
