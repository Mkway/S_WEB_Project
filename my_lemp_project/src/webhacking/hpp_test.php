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
$page_title = 'HPP (HTTP Parameter Pollution)';
$description = '<p><strong>HPP (HTTP Parameter Pollution)</strong>는 동일한 이름의 HTTP 매개변수를 여러 번 전송할 때, 서버나 애플리케이션이 이를 모호하게 처리하여 발생하는 취약점입니다.</p>
<p>인증 우회, 필터 우회, 캐시 독으로 등의 공격이 가능합니다.</p>';

// 2. 페이로드 정의 (공격 시나리오 설명)
$payloads = [
    'scenarios' => [
        'title' => '📋 테스트 시나리오',
        'description' => '다양한 HPP 공격 시나리오를 시뮬레이션합니다.',
        'payloads' => [
            '인증 우회: ?user=guest&user=admin',
            '권한 상승: ?role=user&action=view&role=admin',
            '필터 우회: ?filter=safe&filter=<script>alert(1)</script>',
            '캐시 독으로: ?lang=en&lang=../../../etc/passwd'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>매개변수 정규화:</strong> 중복된 매개변수 처리 방식 명확화 (예: 첫 번째 값만 사용, 마지막 값만 사용, 배열로 처리 등)",
    "<strong>입력 검증:</strong> 모든 매개변수 값에 대한 엄격한 유효성 검증 수행",
    "<strong>배열 처리:</strong> 중복 매개변수를 배열로 명시적으로 처리하고, 필요한 경우에만 배열의 특정 인덱스에 접근",
    "<strong>웹 서버 설정:</strong> 웹 서버 수준에서 중복 매개변수를 거부하도록 설정",
    "<strong>로깅:</strong> 의심스러운 매개변수 패턴을 모니터링하고 로깅"
];

// 4. 참고 자료 정의
$references = [
    "OWASP - HTTP Parameter Pollution" => "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
    "PortSwigger - HTTP Parameter Pollution" => "https://portswigger.net/web-security/http-parameter-pollution"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<div class="info-box" style="background: #fff3cd; border-color: #ffeaa7; color: #856404;">
    <h3>💡 HPP 공격 예제</h3>
    <p><strong>인증 우회:</strong> <code>?user=guest&user=admin</code></p>
    <p><strong>권한 상승:</strong> <code>?role=user&action=view&role=admin</code></p>
    <p><strong>필터 우회:</strong> <code>?search=&lt;script&gt;&search=alert(1)</code></p>
    <p><strong>캐시 독으로:</strong> <code>?lang=en&lang=../../../etc/passwd</code></p>
</div>

<div class="test-form">
    <h3>🎯 실시간 매개변수 분석</h3>
    <p>현재 요청에서 감지된 HTTP 매개변수들을 실시간으로 분석합니다.</p>
    <label>URL 매개변수 (GET):</label>
    <input type="text" id="get_params" placeholder="예: param1=value1&param1=value2&param2=test">
    
    <label>POST 데이터:</label>
    <textarea id="post_data" rows="3" placeholder="예: param1=admin&param2=user"></textarea>
    
    <button onclick="analyzeParameters()" class="btn">매개변수 분석</button>
</div>

<script>
    function analyzeParameters() {
        const getParams = document.getElementById('get_params').value;
        const postData = document.getElementById('post_data').value;
        
        if (!getParams && !postData) {
            alert('매개변수를 입력해주세요.');
            return;
        }
        
        let url = window.location.pathname;
        if (getParams) {
            url += '?' + getParams;
        }
        
        if (postData) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = url;
            
            const postParams = new URLSearchParams(postData);
            for (const [key, value] of postParams) {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = key;
                input.value = value;
                form.appendChild(input);
            }
            
            document.body.appendChild(form);
            form.submit();
        } else {
            window.location.href = url;
        }
    }

    // 실시간 매개변수 검증
    document.getElementById('get_params').addEventListener('input', function() {
        const value = this.value;
        const duplicates = [];
        const params = new URLSearchParams(value);
        const seen = {};
        
        for (const [key] of params) {
            if (seen[key]) {
                duplicates.push(key);
            } else {
                seen[key] = true;
            }
        }
        
        if (duplicates.length > 0) {
            this.style.borderColor = '#dc3545';
            this.style.backgroundColor = '#fff5f5';
            this.title = '중복된 매개변수 감지: ' + duplicates.join(', ');
        } else {
            this.style.borderColor = '#ddd';
            this.style.backgroundColor = 'white';
            this.title = '';
        }
    });
</script>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $all_params = array_merge($_GET, $_POST);
    $result_html = '';

    if (!empty($all_params)) {
        $duplicated_params = [];
        $param_analysis = [];

        foreach ($_GET as $key => $value) {
            if (is_array($value)) {
                $duplicated_params[] = $key;
                $param_analysis[$key] = ['type' => 'GET', 'values' => $value, 'count' => count($value)];
            } else {
                $param_analysis[$key] = ['type' => 'GET', 'values' => [$value], 'count' => 1];
            }
        }

        foreach ($_POST as $key => $value) {
            if (is_array($value)) {
                $duplicated_params[] = $key;
                $param_analysis[$key] = ['type' => 'POST', 'values' => $value, 'count' => count($value)];
            } else {
                if (isset($param_analysis[$key])) {
                    $duplicated_params[] = $key;
                    $param_analysis[$key]['type'] = 'GET+POST';
                    $param_analysis[$key]['values'] = array_merge((array)$param_analysis[$key]['values'], [$value]);
                    $param_analysis[$key]['count'] = count($param_analysis[$key]['values']);
                } else {
                    $param_analysis[$key] = ['type' => 'POST', 'values' => [$value], 'count' => 1];
                }
            }
        }

        if (!empty($duplicated_params)) {
            $result_html .= "<pre>[경고] HTTP Parameter Pollution 감지됨!\n\n";
            $result_html .= "중복된 매개변수 발견: " . htmlspecialchars(implode(', ', array_unique($duplicated_params))) . "\n\n";
            
            foreach ($param_analysis as $param => $info) {
                if ($info['count'] > 1) {
                    $result_html .= "매개변수: " . htmlspecialchars($param) . "\n";
                    $result_html .= "- 전송 방식: " . htmlspecialchars($info['type']) . "\n";
                    $result_html .= "- 값 개수: " . htmlspecialchars($info['count']) . "개\n";
                    $result_html .= "- 값 목록: " . htmlspecialchars(implode(' | ', $info['values'])) . "\n";
                    $result_html .= "- 처리 결과: ";
                    
                    if (isset($all_params[$param])) {
                        if (is_array($all_params[$param])) {
                            $result_html .= "배열로 처리됨 [" . htmlspecialchars(implode(', ', $all_params[$param])) . "]\n";
                        } else {
                            $result_html .= "마지막 값으로 처리됨: '" . htmlspecialchars($all_params[$param]) . "'\n";
                        }
                    }
                    $result_html .= "\n";
                }
            }
            $result_html .= "</pre>";
        } else {
            $result_html .= "<pre>일반적인 HTTP 요청:\n\n";
            foreach ($param_analysis as $param => $info) {
                $result_html .= "매개변수: " . htmlspecialchars($param) . " = '" . htmlspecialchars($info['values'][0]) . "' (" . htmlspecialchars($info['type']) . ")\n";
            }
            $result_html .= "\n중복된 매개변수가 감지되지 않았습니다.</pre>";
        }
    } else {
        $result_html = "<pre>매개변수가 감지되지 않았습니다. GET 또는 POST 요청을 보내보세요.</pre>";
    }

    return ['result' => $result_html, 'error' => ''];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

