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
$page_title = 'Insecure Deserialization';
$description = '<p><strong>Insecure Deserialization</strong>은 신뢰할 수 없는 소스에서 받은 직렬화된 데이터를 역직렬화할 때 발생하는 취약점입니다.</p>
<p>임의 코드 실행, 권한 상승, DoS 공격 등이 가능하며 OWASP Top 10에 포함된 심각한 취약점입니다.</p>
<p><strong>⚠️ 주의사항:</strong> 이 테스트는 시뮬레이션으로만 동작합니다. 실제 환경에서 악의적인 직렬화된 데이터를 역직렬화하면 시스템이 완전히 손상될 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'php' => [
        'title' => '📋 PHP Deserialization 페이로드',
        'description' => 'PHP의 `unserialize()` 함수와 관련된 페이로드입니다.',
        'payloads' => [
            'O:15:"VulnerableClass":1:{s:7:"command";s:2:"id";}', // Object Injection
            'a:1:{s:4:"test";s:16:"<?php phpinfo(); ?>";}' // Magic Method
        ]
    ],
    'java' => [
        'title' => '📋 Java Deserialization 페이로드',
        'description' => 'Java의 `ObjectInputStream.readObject()`와 관련된 페이로드입니다.',
        'payloads' => [
            'aced0005737200116a6176612e7574696c...' // Gadget Chain
        ]
    ],
    'python' => [
        'title' => '📋 Python Pickle 페이로드',
        'description' => 'Python의 `pickle.loads()`와 관련된 페이로드입니다.',
        'payloads' => [
            'c__builtin__\neval\np0\n(Vos.system("id")\np1\ntp2\nRp3\n.' // RCE
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>직렬화 사용 최소화:</strong> 가능한 한 JSON 등 텍스트 기반 형식 사용",
    "<strong>데이터 서명:</strong> HMAC 등을 사용한 데이터 무결성 검증",
    "<strong>화이트리스트:</strong> 역직렬화 가능한 클래스 제한",
    "<strong>샌드박스:</strong> 역직렬화를 격리된 환경에서 수행",
    "<strong>타입 체크:</strong> 역직렬화 전 데이터 타입 검증"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Insecure Deserialization" => "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization.html"
];

// 5. 테스트 폼 UI 정의
$serialized_input = htmlspecialchars($_POST['payload'] ?? '');
$format_type = htmlspecialchars($_POST['format'] ?? 'php');

// 선택된 옵션 처리를 위한 변수들
$php_selected = ($format_type === 'php') ? 'selected' : '';
$java_selected = ($format_type === 'java') ? 'selected' : '';
$python_selected = ($format_type === 'python') ? 'selected' : '';
$dotnet_selected = ($format_type === 'dotnet') ? 'selected' : '';
$nodejs_selected = ($format_type === 'nodejs') ? 'selected' : '';

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 Deserialization 시뮬레이션</h3>
    <label for="format">🔧 직렬화 형식 선택:</label><br>
    <select id="format" name="format">
        <option value="php" $php_selected>PHP Serialization</option>
        <option value="java" $java_selected>Java Serialization</option>
        <option value="python" $python_selected>Python Pickle</option>
        <option value="dotnet" $dotnet_selected>.NET BinaryFormatter</option>
        <option value="nodejs" $nodejs_selected>Node.js JSON</option>
    </select><br><br>
    
    <label for="payload">🎯 직렬화된 데이터 입력:</label><br>
    <textarea id="payload" name="payload" placeholder="직렬화된 데이터를 입력하세요...">{$serialized_input}</textarea><br><br>
    <button type="submit" class="btn">역직렬화 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $serialized_input = $form_data['payload'] ?? '';
    $format_type = $form_data['format'] ?? 'php';
    $result = '';
    $error = '';

    if (empty($serialized_input)) {
        $error = "직렬화된 데이터를 입력해주세요.";
        return ['result' => $result, 'error' => $error];
    }

    // 시뮬레이션 로직
    $dangerous_patterns = [
        'php' => ['O:', '__wakeup', '__destruct', 'system'],
        'java' => ['aced0005', 'readObject', 'Runtime'],
        'python' => ['pickle', '__reduce__', 'os.system']
    ];

    $payload_detected = false;
    $detected_patterns = [];
    if (isset($dangerous_patterns[$format_type])) {
        foreach ($dangerous_patterns[$format_type] as $pattern) {
            if (stripos($serialized_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
            }
        }
    }

    if ($payload_detected) {
        $result = "<strong>[시뮬레이션] Insecure Deserialization 공격 감지됨</strong>\n";
        $result .= "형식: " . strtoupper($format_type) . "\n";
        $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
        $result .= "PHP의 경우, `VulnerableClass` 같은 클래스의 매직 메소드(`__wakeup`, `__destruct`)가 호출되어 임의 코드 실행으로 이어질 수 있습니다.";
    } else {
        $result = "안전한 직렬화 데이터로 판단됩니다. (시뮬레이션)";
    }

    return ['result' => "<pre>{$result}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Insecure_Deserialization_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>