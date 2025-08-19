<?php
require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'SSTI (Server-Side Template Injection)';
$description = "<p><strong>SSTI (Server-Side Template Injection)</strong>는 템플릿 엔진에서 사용자 입력을 안전하게 처리하지 않을 때 발생하는 취약점입니다.</p>\n<p>서버 사이드 코드 실행, 파일 읽기, 시스템 명령 실행이 가능합니다.</p>";

// 2. 페이로드 정의
$payloads = [
    'twig' => [
        'title' => '📋 Twig (PHP) 테스트 페이로드',
        'description' => 'Twig 템플릿 엔진에 대한 SSTI 페이로드입니다.',
        'payloads' => [
            '{{ "Hello " ~ name }}', // 기본 템플릿
            '{{ dump(app) }}', // 정보 노출
            '{{_self.env.registerUndefinedFilterCallback("exec")}}', // 코드 실행
            '{{ "/etc/passwd"|file_get_contents }}' // 파일 접근
        ]
    ],
    'jinja2' => [
        'title' => '📋 Jinja2 (Python) 테스트 페이로드',
        'description' => 'Jinja2 템플릿 엔진에 대한 SSTI 페이로드입니다.',
        'payloads' => [
            '{{ "Hello " + name }}', // 기본 템플릿
            '{{ config.items() }}', // 정보 노출
            '{{\'\'.__class__.__mro__[2].__subclasses__()}}', // 코드 실행
            '{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}' // 파일 접근
        ]
    ],
    'smarty' => [
        'title' => '📋 Smarty (PHP) 테스트 페이로드',
        'description' => 'Smarty 템플릿 엔진에 대한 SSTI 페이로드입니다.',
        'payloads' => [
            '{$name}', // 기본 템플릿
            '{$smarty.version}', // 정보 노출
            '{php}echo `id`;{/php}', // 코드 실행
            '{php}echo file_get_contents("/etc/passwd");{/php}' // 파일 접근
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>입력 검증:</strong> 사용자 입력에서 템플릿 구문 문자 필터링",
    "<strong>샌드박스 모드:</strong> 템플릿 엔진의 샌드박스 기능 활성화",
    "<strong>화이트리스트:</strong> 허용된 함수/메소드만 사용 가능하도록 제한",
    "<strong>정적 템플릿:</strong> 동적 템플릿 생성 최소화",
    "<strong>권한 분리:</strong> 템플릿 렌더링을 낮은 권한으로 실행"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Server-Side Template Injection" => "https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
    "PortSwigger - SSTI injection" => "https://portswigger.net/web-security/ssi"
];

// 5. 테스트 폼 UI 정의
$template_input = htmlspecialchars($_POST['payload'] ?? '');
$engine_type = htmlspecialchars($_POST['engine'] ?? 'twig');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 SSTI 테스트</h3>
    <label for="engine">🔧 템플릿 엔진 선택:</label><br>
    <select id="engine" name="engine">
        <option value="twig" " . ($engine_type === 'twig' ? 'selected' : '') . ">Twig (PHP)</option>
        <option value="jinja2" " . ($engine_type === 'jinja2' ? 'selected' : '') . ">Jinja2 (Python)</option>
        <option value="smarty" " . ($engine_type === 'smarty' ? 'selected' : '') . ">Smarty (PHP)</option>
        <option value="freemarker" " . ($engine_type === 'freemarker' ? 'selected' : '') . ">FreeMarker (Java)</option>
        <option value="velocity" " . ($engine_type === 'velocity' ? 'selected' : '') . ">Velocity (Java)</option>
    </select><br><br>
    
    <label for="payload">🎯 템플릿 데이터 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="템플릿 데이터를 입력하세요...">{$template_input}</textarea><br><br>
    <button type="submit" class="btn">템플릿 렌더링</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $template_input = $form_data['payload'] ?? '';
    $engine_type = $form_data['engine'] ?? 'twig';
    $result = '';
    $error = '';

    if (empty($template_input)) {
        $error = "템플릿 데이터를 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] SSTI 공격 분석\n";
    $response_sim .= "템플릿 엔진: " . strtoupper($engine_type) . "\n";
    $response_sim .= "입력 템플릿: " . htmlspecialchars($template_input) . "\n\n";

    // 위험한 패턴 검사
    $dangerous_patterns = [
        'twig' => ['{{', '}}', '_self', 'dump', 'exec'],
        'jinja2' => ['{{', '}}', '__class__', '__mro__', '__subclasses__'],
        'smarty' => ['{', '}', 'php', 'eval', 'system'],
        'freemarker' => ['${', '}', 'new', 'execute'],
        'velocity' => ['$', '{', '}', 'class', 'runtime']
    ];

    $payload_detected = false;
    $detected_patterns = [];
    if (isset($dangerous_patterns[$engine_type])) {
        foreach ($dangerous_patterns[$engine_type] as $pattern) {
            if (stripos($template_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
            }
        }
    }

    if ($payload_detected) {
        $response_sim .= "🚨 공격 감지됨!\n";
        $response_sim .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n";
        $response_sim .= "예상 공격 유형: " . strtoupper($engine_type) . " SSTI\n\n";
        $response_sim .= "이러한 패턴들은 서버 사이드 코드 실행, 파일 읽기, 시스템 명령 실행 등에 사용될 수 있습니다.\n";
        $response_sim .= "실제 환경에서는 심각한 보안 문제를 야기할 수 있습니다.";
    } else {
        $response_sim .= "✅ 안전한 템플릿입니다.\n";
        $response_sim .= "위험한 패턴이 감지되지 않았습니다.\n";
        $response_sim .= "템플릿이 정상적으로 처리될 것으로 예상됩니다.\n\n";
        $response_sim .= "예상 렌더링 결과: " . htmlspecialchars($template_input);
    }

    return ['result' => "<pre>{$response_sim}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>
