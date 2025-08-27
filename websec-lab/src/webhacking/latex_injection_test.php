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
$page_title = 'LaTeX Injection';
$description = '<p><strong>LaTeX Injection</strong>은 LaTeX 문서 처리 시스템에서 악의적인 LaTeX 명령어를 주입하여 시스템에 피해를 주는 공격입니다.</p>
<p>이는 민감한 시스템 파일 읽기, 시스템 명령어 실행, 악성 파일 생성 등으로 이어질 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'file_read' => [
        'title' => '파일 읽기 공격',
        'description' => '\input 명령어를 사용하여 시스템 파일을 읽어 민감한 정보를 노출시킵니다.',
        'payloads' => [
            '\\input{/etc/passwd}',
            '\\input{config.php}'
        ]
    ],
    'command_execution' => [
        'title' => '명령어 실행 공격',
        'description' => '\write18 또는 \immediate\write를 사용하여 시스템 명령어를 실행합니다.',
        'payloads' => [
            '\\write18{id}',
            '\\immediate\\write18{ls -la}'
        ]
    ],
    'macro_redefinition' => [
        'title' => '매크로 재정의',
        'description' => '기존 매크로를 재정의하여 악의적인 동작을 숨기거나 유도합니다.',
        'payloads' => [
            '\\def\\normaltext{\\input{/etc/passwd}}'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>위험한 LaTeX 명령어 필터링:</strong> `\\input`, `\\include`, `\\write18`, `\\immediate\\write` 등 위험한 명령어를 화이트리스트/블랙리스트 방식으로 필터링합니다.",
    "<strong>샌드박스 환경에서 LaTeX 실행:</strong> LaTeX 컴파일을 격리된 샌드박스 환경에서 수행하여 시스템 자원에 대한 접근을 제한합니다.",
    "<strong>파일 시스템 접근 제한:</strong> LaTeX 프로세스가 필요한 최소한의 파일 시스템 권한만 가지도록 설정합니다.",
    "<strong>입력 검증 및 이스케이핑:</strong> 모든 사용자 입력을 철저히 검증하고, 특수 문자를 적절히 이스케이프 처리합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - LaTeX Injection" => "https://owasp.org/www-community/attacks/LaTeX_Injection",
    "PortSwigger - LaTeX injection" => "https://portswigger.net/web-security/latex-injection"
];

// 5. 테스트 폼 UI 정의
$latex_input_val = htmlspecialchars($_POST['payload'] ?? '');
$document_title_val = htmlspecialchars($_POST['document_title'] ?? 'Test Document');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 LaTeX 문서 처리 시뮬레이터</h3>
    <div class="form-group">
        <label for="document_title">문서 제목:</label>
        <input type="text" name="document_title" id="document_title" value="{$document_title_val}" placeholder="문서 제목을 입력하세요">
    </div>
    
    <div class="form-group">
        <label for="payload">LaTeX 내용:</label>
        <textarea name="payload" id="payload" class="latex-input" placeholder="LaTeX 코드를 입력하세요...\n예: \textbf{Hello World}\n또는 공격 페이로드를 테스트해보세요.">{$latex_input_val}</textarea>
    </div>
    
    <button type="submit" class="btn">LaTeX 문서 처리</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $latex_input = $form_data['payload'] ?? '';
    $document_title = $form_data['document_title'] ?? 'Test Document';
    $result = '';
    $error = '';

    if (empty($latex_input)) {
        $error = "LaTeX 내용을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] LaTeX 문서 처리 결과\n";
    $response_sim .= "입력된 LaTeX: " . htmlspecialchars($latex_input) . "\n";
    $response_sim .= "문서 제목: " . htmlspecialchars($document_title) . "\n\n";

    // 위험한 패턴 감지
    $dangerous_patterns = [
        '/\\input{/', '/\\include{/', '/\\usepackage{/', '/\\def\\/',
        '/\\write18/', '/\\immediate\\write/', '/\\jobname/'
    ];
    
    $payload_detected = false;
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $latex_input)) {
            $payload_detected = true;
            break;
        }
    }

    if ($payload_detected) {
        $response_sim .= "🚨 위험한 LaTeX 명령어 감지됨!\n";
        $response_sim .= "실제 환경에서는 다음과 같은 공격이 가능합니다:\n";
        $response_sim .= "- 시스템 파일 읽기 (예: /etc/passwd)\n";
        $response_sim .= "- 시스템 명령어 실행 (예: `id`)\n";
        $response_sim .= "- 악성 파일 생성\n";
        $response_sim .= "<br><strong>참고:</strong> 이 시뮬레이션은 실제 LaTeX 명령을 실행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
    } else {
        $response_sim .= "✅ 안전한 LaTeX 내용입니다.\n";
        $response_sim .= "위험한 패턴이 감지되지 않았습니다.\n";
        $response_sim .= "LaTeX 문서가 정상적으로 처리될 것으로 예상됩니다.";
    }

    return ['result' => "<pre>{$response_sim}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

