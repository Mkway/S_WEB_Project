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

    $result .= "<div class='vulnerable-output'>";
    $result .= "<h4>🚨 취약한 SSTI 실행 결과</h4>";
    $result .= "<p><strong>템플릿 엔진:</strong> " . strtoupper($engine_type) . "</p>";
    $result .= "<p><strong>입력 템플릿:</strong> " . htmlspecialchars($template_input) . "</p>";
    
    // 실제 SSTI 공격 실행 시뮬레이션 (교육 목적)
    try {
        $rendered_output = "";
        $execution_result = "";
        
        // 간단한 템플릿 처리 엔진 시뮬레이션
        if ($engine_type === 'twig' || $engine_type === 'jinja2') {
            // {{ expression }} 패턴 처리
            if (preg_match('/\{\{(.+?)\}\}/', $template_input, $matches)) {
                $expression = trim($matches[1]);
                $result .= "<p class='warning'>⚠️ <strong>위험한 템플릿 표현식 감지:</strong> <code>" . htmlspecialchars($expression) . "</code></p>";
                
                // 위험한 패턴 체크 및 실행 시뮬레이션
                if (strpos($expression, 'file_get_contents') !== false) {
                    $result .= "<p class='danger'>🔥 <strong>파일 읽기 시도 감지!</strong></p>";
                    if (strpos($expression, '/etc/passwd') !== false) {
                        $execution_result = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n...";
                        $result .= "<p class='danger'>🔥 실제 환경에서는 /etc/passwd 파일 내용이 노출될 수 있습니다.</p>";
                    }
                } elseif (strpos($expression, 'exec') !== false || strpos($expression, 'system') !== false) {
                    $result .= "<p class='danger'>🔥 <strong>시스템 명령 실행 시도 감지!</strong></p>";
                    $execution_result = "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
                    $result .= "<p class='danger'>🔥 실제 환경에서는 서버 명령이 실행될 수 있습니다.</p>";
                } elseif (strpos($expression, '__class__') !== false || strpos($expression, '__mro__') !== false) {
                    $result .= "<p class='danger'>🔥 <strong>Python 객체 접근 시도 감지!</strong></p>";
                    $execution_result = "&lt;class 'str'&gt;, &lt;class 'object'&gt;, &lt;class 'subprocess.Popen'&gt;";
                    $result .= "<p class='danger'>🔥 실제 환경에서는 시스템 클래스에 접근할 수 있습니다.</p>";
                } else {
                    // 기본 변수 치환
                    $name = "TestUser";
                    $rendered_output = str_replace('name', '"' . $name . '"', $expression);
                    $result .= "<p class='success'>✅ 기본 템플릿 변수 처리</p>";
                }
            }
        } elseif ($engine_type === 'smarty') {
            // {php} 태그 처리
            if (strpos($template_input, '{php}') !== false && strpos($template_input, '{/php}') !== false) {
                $result .= "<p class='danger'>🔥 <strong>Smarty PHP 태그 실행 시도!</strong></p>";
                
                if (strpos($template_input, 'file_get_contents') !== false) {
                    $execution_result = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
                    $result .= "<p class='danger'>🔥 실제 환경에서는 파일 내용이 노출될 수 있습니다.</p>";
                } elseif (strpos($template_input, 'id') !== false || strpos($template_input, 'whoami') !== false) {
                    $execution_result = "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
                    $result .= "<p class='danger'>🔥 실제 환경에서는 시스템 명령이 실행될 수 있습니다.</p>";
                }
            } elseif (preg_match('/\{\$(.+?)\}/', $template_input, $matches)) {
                $variable = trim($matches[1]);
                $result .= "<p class='success'>✅ Smarty 변수 처리: <code>\${$variable}</code></p>";
                $rendered_output = "TestValue";
            }
        }
        
        // 실행 결과 표시
        if ($execution_result) {
            $result .= "<p><strong>실행 결과:</strong></p>";
            $result .= "<pre class='attack-result'>" . htmlspecialchars($execution_result) . "</pre>";
        } elseif ($rendered_output) {
            $result .= "<p><strong>렌더링 결과:</strong></p>";
            $result .= "<pre class='attack-result'>" . htmlspecialchars($rendered_output) . "</pre>";
        }
        
    } catch (Exception $e) {
        $result .= "<p class='error'>❌ SSTI 실행 중 오류: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    $result .= "</div>";
    
    // 안전한 구현 비교
    $result .= "<div class='safe-comparison'>";
    $result .= "<h4>✅ 안전한 템플릿 처리 구현</h4>";
    
    // 입력 검증 및 필터링
    $dangerous_patterns = ['{{', '}}', '{php}', '{/php}', '__class__', '__mro__', 'file_get_contents', 'exec', 'system', 'eval'];
    $contains_dangerous = false;
    
    foreach ($dangerous_patterns as $pattern) {
        if (stripos($template_input, $pattern) !== false) {
            $contains_dangerous = true;
            break;
        }
    }
    
    if ($contains_dangerous) {
        $result .= "<p class='success'>🛡️ <strong>차단됨:</strong> 위험한 템플릿 구문이 감지되어 처리를 거부했습니다.</p>";
        $result .= "<p><strong>안전한 처리 결과:</strong> 입력이 일반 텍스트로 처리됨</p>";
        $result .= "<pre class='safe-result'>" . htmlspecialchars($template_input) . "</pre>";
    } else {
        $result .= "<p class='success'>✅ <strong>안전한 템플릿:</strong> 위험한 구문이 없어 정상 처리됩니다.</p>";
        // 안전한 변수 치환 예시
        $safe_output = str_replace(['name', 'user'], ['SafeUser', 'SafeValue'], $template_input);
        $result .= "<pre class='safe-result'>" . htmlspecialchars($safe_output) . "</pre>";
    }
    
    $result .= "</div>";
    
    // 보안 권장사항
    $result .= "<div class='security-recommendations'>";
    $result .= "<h4>🔒 SSTI 방어 권장사항</h4>";
    $result .= "<ul>";
    $result .= "<li><strong>입력 검증:</strong> 템플릿 구문 문자 (<code>{{</code>, <code>{}</code>, <code>\$</code>) 필터링</li>";
    $result .= "<li><strong>샌드박스 모드:</strong> 템플릿 엔진의 안전 모드 활성화</li>";
    $result .= "<li><strong>화이트리스트:</strong> 허용된 함수/메서드만 사용 가능하도록 제한</li>";
    $result .= "<li><strong>정적 템플릿:</strong> 사용자 입력으로 템플릿 생성 금지</li>";
    $result .= "<li><strong>권한 분리:</strong> 템플릿 렌더링을 최소 권한으로 실행</li>";
    $result .= "<li><strong>CSP 적용:</strong> Content Security Policy로 스크립트 실행 제한</li>";
    $result .= "</ul>";
    $result .= "</div>";

    return ['result' => $result, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "SSTI_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>
