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
$page_title = 'Client Side Path Traversal';
$description = '<p><strong>클라이언트 측 경로 탐색</strong>은 웹 애플리케이션의 클라이언트 측 스크립트(주로 JavaScript)가 사용자 입력에 기반하여 파일 경로를 동적으로 구성할 때 발생할 수 있는 취약점입니다.</p>
<p>공격자는 `../`와 같은 경로 조작 문자를 사용하여 웹 서버의 의도치 않은 파일이나 디렉토리에 접근하거나, 클라이언트 측에서 로드되는 리소스의 경로를 변경할 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'scenario' => [
        'title' => '🧪 파일 경로 로드 시뮬레이션',
        'description' => '아래 입력 필드에 파일 이름을 입력하여 클라이언트 측에서 경로가 어떻게 구성되는지 확인하세요.',
        'payloads' => [
            'image.jpg',
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>클라이언트 측 입력 검증:</strong> JavaScript에서 사용자 입력에 `../`, `./`, `\` 등 경로 조작 문자가 포함되어 있는지 확인하고 제거합니다.",
    "<strong>서버 측 입력 검증:</strong> 클라이언트 측 검증은 우회될 수 있으므로, 서버 측에서도 파일 경로를 구성하는 모든 입력에 대해 철저한 검증을 수행합니다.",
    "<strong>화이트리스트 방식 사용:</strong> 허용된 파일 이름 또는 경로 패턴만 허용하고, 그 외의 모든 입력은 거부합니다.",
    "<strong>경로 정규화:</strong> 파일 시스템에 접근하기 전에 경로를 정규화하여 `../`와 같은 문자를 제거합니다.",
    "<strong>최소 권한 원칙:</strong> 웹 서버 프로세스가 파일 시스템에 접근할 수 있는 권한을 최소화합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Path Traversal" => "https://owasp.org/www-community/attacks/Path_Traversal",
    "PortSwigger - File path traversal" => "https://portswigger.net/web-security/file-path-traversal"
];

// 5. 테스트 폼 UI 정의
$file_name_input = htmlspecialchars($_POST['payload'] ?? '');
$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 파일 경로 로드 시뮬레이션</h3>
    <p>아래 입력 필드에 파일 이름을 입력하여 클라이언트 측에서 경로가 어떻게 구성되는지 확인하세요.</p>
    <label for="payload">파일 이름:</label>
    <input type="text" id="payload" name="payload" value="{$file_name_input}" placeholder="예: image.jpg 또는 ../../../etc/passwd" required>
    <br><br>
    <button type="submit" name="action" value="load_file" class="btn" style="background: #dc3545;">파일 로드 시뮬레이션</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $file_name = $form_data['payload'] ?? '';
    $result = '';
    $error = '';

    if (empty($file_name)) {
        $error = "파일 이름을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $result = "클라이언트 측에서 요청된 파일 경로: <code>" . htmlspecialchars($file_name) . "</code>";
    $result .= "<br>이 경로는 클라이언트 측 스크립트에서 동적으로 생성되어 사용될 수 있습니다.";
    $result .= "<br>예: <code>document.getElementById('image').src = '/images/" + encodeURIComponent(userInput) + ".jpg';</code>";
    $result .= "<br><code>../</code>와 같은 경로 조작을 통해 의도치 않은 파일에 접근할 수 있습니다.";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>