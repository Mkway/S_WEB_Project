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
$page_title = 'Tabnabbing';
$description = '<p><strong>Tabnabbing</strong>은 사용자가 현재 보고 있는 탭이 아닌, 백그라운드 탭의 내용을 피싱 사이트로 변경하여 사용자를 속이는 공격입니다.</p>
<p>사용자가 백그라운드 탭으로 전환했을 때, 원래 보고 있던 사이트가 피싱 사이트로 바뀌어 있어 사용자가 속아 로그인 정보를 입력하게 유도합니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 테스트 시나리오',
        'description' => '아래 링크를 <strong>새 탭에서 열어보세요.</strong> 새 탭에서 열린 페이지는 잠시 후 백그라운드 탭(이 페이지)의 내용을 피싱 사이트로 변경하려고 시도합니다.',
        'payloads' => [] // 페이로드 버튼은 없음
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "모든 `target=\"_blank\"` 링크에 `rel=\"noopener noreferrer\"` 속성을 추가합니다.",
    "`noopener`: `window.opener` 객체에 대한 접근을 차단합니다.",
    "`noreferrer`: `Referer` 헤더 전송을 막습니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Tabnabbing" => "https://owasp.org/www-community/attacks/Tabnabbing",
    "PortSwigger - Tabnabbing" => "https://portswigger.net/web-security/tabnabbing"
];

// 5. 테스트 폼 UI 정의
$phishing_site_url = 'https://example.com/phishing_login'; // 시뮬레이션된 피싱 사이트 URL

$test_form_ui = <<<HTML
<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7; color: #856404;">
    <h3>⚠️ 공격 원리</h3>
    <p>공격자는 `target="_blank"` 속성을 가진 링크에 `rel="noopener"` 또는 `rel="noreferrer"` 속성을 추가하지 않은 경우, 새 탭에서 열린 페이지가 `window.opener` 객체를 통해 원래 페이지의 `location`을 조작할 수 있다는 점을 악용합니다.</p>
    <p><strong>공격 코드 예시 (새 탭에서 열린 페이지의 JavaScript):</strong></p>
    <pre><code>if (window.opener) {
    window.opener.location.replace('{$phishing_site_url}');
}</code></pre>
</div>

<div class="test-form">
    <h3>🧪 Tabnabbing 시뮬레이션</h3>
    <a href="tabnabbing_target.php" target="_blank" rel="noopener">새 탭에서 열기 (Tabnabbing 공격 시뮬레이션)</a>
    <p style="margin-top: 20px;"><strong>주의:</strong> 실제 피싱 사이트로 리다이렉션되지 않으며, 시뮬레이션된 메시지만 표시됩니다.</p>
</div>

<script>
    // 이 페이지가 새 탭에서 열렸을 때, 원래 페이지(opener)의 URL을 변경하는 시뮬레이션
    // 실제 공격은 새 탭에서 열린 페이지의 스크립트에서 실행됩니다.
    // 이 페이지는 '원래 페이지' 역할을 합니다.
    
    // 시뮬레이션된 피싱 사이트 URL (실제 리다이렉션은 없음)
    const phishingUrl = '{$phishing_site_url}';

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
HTML;

// 6. 테스트 로직 콜백 정의 (클라이언트 측 시연이므로 서버 측 로직은 최소화)
$test_logic_callback = function($form_data) {
    // 이 페이지는 주로 클라이언트 측 JavaScript로 시연되므로, 서버 측 로직은 최소화합니다.
    return ['result' => '', 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>