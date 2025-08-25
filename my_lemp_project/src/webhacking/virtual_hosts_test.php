<?php
require_once 'TestPage.php';

// 모의 가상 호스트 설정
$virtual_hosts_config = [
    'production' => [
        'domain' => 'example.com',
        'document_root' => '/var/www/production',
        'access_level' => 'public',
        'debug_mode' => false,
        'exposed_info' => []
    ],
    'staging' => [
        'domain' => 'staging.example.com',
        'document_root' => '/var/www/staging',
        'access_level' => 'restricted',
        'debug_mode' => true,
        'exposed_info' => ['database_name', 'cache_status']
    ],
    'development' => [
        'domain' => 'dev.example.com',
        'document_root' => '/var/www/development',
        'access_level' => 'internal',
        'debug_mode' => true,
        'exposed_info' => ['database_credentials', 'api_keys', 'internal_urls']
    ],
    'admin' => [
        'domain' => 'admin.example.com',
        'document_root' => '/var/www/admin',
        'access_level' => 'admin_only',
        'debug_mode' => false,
        'exposed_info' => ['admin_functions', 'system_config_paths']
    ]
];

// 1. 페이지 설정
$page_title = 'Virtual Hosts';
$description = '<p><strong>Virtual Hosts 취약점</strong>은 웹 서버의 가상 호스트 설정 오류로 인해 의도하지 않은 애플리케이션이나 관리 인터페이스에 접근할 수 있는 취약점입니다.</p>
<p>이는 Host 헤더 조작, 기본 가상 호스트 폴백, 내부 호스트명 접근 등으로 발생할 수 있습니다.</p>';

// 2. 페이로드 정의
$payloads = [
    'host_header_manipulation' => [
        'title' => 'Host 헤더 조작 페이로드',
        'description' => 'HTTP Host 헤더를 조작하여 다른 가상 호스트에 접근을 시도합니다.',
        'payloads' => [
            'staging.example.com',
            'dev.example.com',
            'admin.example.com',
            'localhost',
            '127.0.0.1',
            'internal.local',
            'test.example.com', // 와일드카드 서브도메인
            'malicious.com' // 유효하지 않은 호스트
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>엄격한 Host 헤더 검증:</strong> 웹 서버 설정에서 허용된 Host 헤더만 명시적으로 허용하고, 그 외의 모든 요청은 차단합니다.",
    "<strong>화이트리스트 기반 도메인 허용:</strong> 애플리케이션 수준에서 `Host` 헤더를 검증하여 신뢰할 수 있는 도메인만 처리합니다.",
    "<strong>내부 호스트명/IP 접근 차단:</strong> `localhost`, 내부 IP 주소, 내부 호스트명으로의 직접 접근을 차단합니다.",
    "<strong>기본 가상 호스트 비활성화 또는 제한:</strong> 매칭되지 않는 `Host` 헤더 요청이 기본 가상 호스트로 폴백되지 않도록 하거나, 기본 가상 호스트는 에러 페이지만 제공하도록 설정합니다.",
    "<strong>개발/스테이징 환경 외부 노출 금지:</strong> 민감한 개발/스테이징 환경은 외부에서 접근할 수 없도록 방화벽, VPN 등으로 보호합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Host Header Injection" => "https://owasp.org/www-community/attacks/Host_Header_Injection",
    "PortSwigger - Host header attacks" => "https://portswigger.net/web-security/host-header"
];

// 5. 테스트 폼 UI 정의
$host_header_input = htmlspecialchars($_POST["payload"] ?? 'example.com');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #e3f2fd; border-color: #2196f3;">
    <h4>🏗️ 가상 호스트 설정 현황 (시뮬레이션)</h4>
    <div class="config-grid">
        <?php foreach ($virtual_hosts_config as $name => $config): ?>
        <div class="info-box" style="background: white; border-color: #ddd;">
            <div class="config-name">{$name}</div>
            <div class="config-detail"><span class="label">도메인:</span> <span class="value">{$config['domain']}</span></div>
            <div class="config-detail"><span class="label">접근 수준:</span> <span class="value">{$config['access_level']}</span></div>
            <div class="config-detail"><span class="label">디버그 모드:</span> <span class="value">{$config['debug_mode'] ? 'Yes' : 'No'}</span></div>
            <div class="config-detail"><span class="label">노출 정보:</span> <span class="value">{$config['exposed_info'] ? implode(', ', $config['exposed_info']) : 'None'}</span></div>
        </div>
        <?php endforeach; ?>
    </div>
</div>

<form method="post" class="test-form">
    <h3>🧪 Host 헤더 조작 테스트</h3>
    <p>아래 입력 필드에 Host 헤더 값을 입력하여 시뮬레이션을 시작하세요.</p>
    <label for="payload">Host 헤더 값:</label>
    <input type="text" name="payload" id="payload" value="{$host_header_input}" placeholder="예: staging.example.com" required>
    <br><br>
    <button type="submit" class="btn">Host 헤더 테스트 실행</button>
</form>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($virtual_hosts_config) {
    $host_header = $form_data['payload'] ?? '';
    $result_html = '';
    $error = '';

    if (empty($host_header)) {
        $error = "Host 헤더 값을 입력해주세요.";
        return ['result' => '', 'error' => $error];
    }

    $response_sim = "[시뮬레이션] 가상 호스트 처리 분석\n";
    $response_sim .= "요청 Host 헤더: " . htmlspecialchars($host_header) . "\n\n";

    $matched_config = null;
    $matched_name = 'default_fallback'; // 매칭되지 않을 경우 기본 폴백

    // Host 헤더 매칭 시뮬레이션
    foreach ($virtual_hosts_config as $name => $config) {
        if ($config['domain'] === $host_header) {
            $matched_config = $config;
            $matched_name = $name;
            break;
        }
    }

    if ($matched_config) {
        $response_sim .= "✅ 매칭된 가상 호스트: " . htmlspecialchars($matched_name) . " (도메인: " . htmlspecialchars($matched_config['domain']) . ")\n";
        $response_sim .= "접근 수준: " . htmlspecialchars($matched_config['access_level']) . "\n";
        $response_sim .= "디버그 모드: " . ($matched_config['debug_mode'] ? '활성화' : '비활성화') . "\n";

        if (!empty($matched_config['exposed_info'])) {
            $response_sim .= "🚨 노출된 정보: " . implode(', ', $matched_config['exposed_info']) . "\n";
            $response_sim .= "이는 민감한 데이터 유출로 이어질 수 있습니다.\n";
        }
    } else {
        $response_sim .= "⚠️ 매칭되는 가상 호스트 없음. 기본 폴백 처리됨.\n";
        $response_sim .= "이는 의도하지 않은 애플리케이션 접근으로 이어질 수 있습니다.\n";
    }

    return ['result' => "<pre>{"$response_sim"}</pre>", 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>
