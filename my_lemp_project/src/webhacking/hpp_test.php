<?php
/**
 * HPP (HTTP Parameter Pollution) 취약점 테스트 페이지
 * 교육 목적으로만 사용하시기 바랍니다.
 */

session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$result = '';
$test_result = '';

// HPP 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'POST') {
    $all_params = array_merge($_GET, $_POST);
    
    if (!empty($all_params)) {
        // 매개변수 중복 검사
        $duplicated_params = [];
        $param_analysis = [];
        
        // GET 매개변수 분석
        if (!empty($_GET)) {
            foreach ($_GET as $key => $value) {
                if (is_array($value)) {
                    $duplicated_params[] = $key;
                    $param_analysis[$key] = [
                        'type' => 'GET',
                        'values' => $value,
                        'count' => count($value)
                    ];
                } else {
                    $param_analysis[$key] = [
                        'type' => 'GET',
                        'values' => [$value],
                        'count' => 1
                    ];
                }
            }
        }
        
        // POST 매개변수 분석
        if (!empty($_POST)) {
            foreach ($_POST as $key => $value) {
                if (is_array($value)) {
                    $duplicated_params[] = $key;
                    $param_analysis[$key] = [
                        'type' => 'POST',
                        'values' => $value,
                        'count' => count($value)
                    ];
                } else {
                    if (isset($param_analysis[$key])) {
                        // GET과 POST에 동일한 매개변수가 있는 경우
                        $duplicated_params[] = $key;
                        $param_analysis[$key]['type'] = 'GET+POST';
                        $param_analysis[$key]['values'] = array_merge(
                            (array)$param_analysis[$key]['values'], 
                            [$value]
                        );
                        $param_analysis[$key]['count'] = count($param_analysis[$key]['values']);
                    } else {
                        $param_analysis[$key] = [
                            'type' => 'POST',
                            'values' => [$value],
                            'count' => 1
                        ];
                    }
                }
            }
        }
        
        // 결과 분석
        if (!empty($duplicated_params)) {
            $result = "[경고] HTTP Parameter Pollution 감지됨!\n\n";
            $result .= "중복된 매개변수 발견: " . implode(', ', array_unique($duplicated_params)) . "\n\n";
            
            foreach ($param_analysis as $param => $info) {
                if ($info['count'] > 1) {
                    $result .= "매개변수: {$param}\n";
                    $result .= "- 전송 방식: {$info['type']}\n";
                    $result .= "- 값 개수: {$info['count']}개\n";
                    $result .= "- 값 목록: " . implode(' | ', $info['values']) . "\n";
                    $result .= "- 처리 결과: ";
                    
                    // PHP의 매개변수 처리 방식 설명
                    if (isset($all_params[$param])) {
                        if (is_array($all_params[$param])) {
                            $result .= "배열로 처리됨 [" . implode(', ', $all_params[$param]) . "]\n";
                        } else {
                            $result .= "마지막 값으로 처리됨: '{$all_params[$param]}'\n";
                        }
                    }
                    $result .= "\n";
                }
            }
            
            $result .= "HPP 공격 시나리오:\n";
            $result .= "- 인증 우회: user=admin&user=guest (마지막 값 사용)\n";
            $result .= "- 권한 상승: role=user&role=admin\n";
            $result .= "- 필터 우회: blocked=true&blocked=false\n";
            $result .= "- 캐시 독으로: param=safe&param=malicious\n";
            
        } else {
            $result = "일반적인 HTTP 요청:\n\n";
            foreach ($param_analysis as $param => $info) {
                $result .= "매개변수: {$param} = '{$info['values'][0]}' ({$info['type']})\n";
            }
            $result .= "\n중복된 매개변수가 감지되지 않았습니다.";
        }
    }
}

// 테스트 시나리오별 결과 처리
if (isset($_GET['test_scenario'])) {
    $scenario = $_GET['test_scenario'];
    
    switch ($scenario) {
        case 'auth_bypass':
            $test_result = "인증 우회 테스트 결과:\n";
            $test_result .= "- 첫 번째 user 값: " . ($_GET['user'][0] ?? 'N/A') . "\n";
            $test_result .= "- 마지막 user 값: " . (end($_GET['user']) ?? 'N/A') . "\n";
            $test_result .= "PHP는 마지막 값을 우선적으로 처리합니다.";
            break;
            
        case 'privilege_escalation':
            $test_result = "권한 상승 테스트 결과:\n";
            $test_result .= "- 역할 값들: " . implode(', ', $_GET['role'] ?? []) . "\n";
            $test_result .= "시스템에 따라 다른 값이 우선적으로 처리될 수 있습니다.";
            break;
            
        case 'filter_bypass':
            $test_result = "필터 우회 테스트 결과:\n";
            $test_result .= "- 필터 상태 값들: " . implode(', ', $_GET['filter'] ?? []) . "\n";
            $test_result .= "모호한 매개변수 처리로 인한 필터 우회 가능";
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HPP 취약점 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .vulnerability-description, .mitigation-guide {
            background-color: #f9f9f9;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .mitigation-guide {
            border-color: #28a745;
        }
        .test-form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border: 1px solid #dee2e6;
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin: 5px 0;
        }
        .payload-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .payload-btn:hover {
            background: #138496;
        }
        .nav {
            background: #343a40;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav h1 {
            margin: 0;
            color: white;
        }
        .nav-links .btn {
            margin-left: 10px;
            background: #007bff;
            color: white;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 4px;
        }
        .scenario-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .scenario-card h4 {
            color: #dc3545;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>HPP 취약점 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🔄 HPP (HTTP Parameter Pollution) 취약점</h2>
            <p><strong>설명:</strong> 동일한 이름의 HTTP 매개변수를 여러 번 전송할 때, 서버나 애플리케이션이 
            이를 모호하게 처리하여 발생하는 취약점입니다. 인증 우회, 필터 우회, 캐시 독으로 등의 공격이 가능합니다.</p>
            
            <h3>📋 테스트 시나리오:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testScenario('auth_bypass')" class="payload-btn">인증 우회</button>
                <button onclick="testScenario('privilege_escalation')" class="payload-btn">권한 상승</button>
                <button onclick="testScenario('filter_bypass')" class="payload-btn">필터 우회</button>
                <button onclick="testScenario('cache_poisoning')" class="payload-btn">캐시 독으로</button>
                <button onclick="testScenario('custom')" class="payload-btn">직접 테스트</button>
            </div>
        </div>

        <div class="scenario-card">
            <h4>🎯 실시간 매개변수 분석</h4>
            <p>현재 요청에서 감지된 HTTP 매개변수들을 실시간으로 분석합니다.</p>
            
            <div class="test-form">
                <label>URL 매개변수 (GET):</label>
                <input type="text" id="get_params" placeholder="예: param1=value1&param1=value2&param2=test">
                
                <label>POST 데이터:</label>
                <textarea id="post_data" rows="3" placeholder="예: param1=admin&param2=user"></textarea>
                
                <button onclick="analyzeParameters()" class="btn">매개변수 분석</button>
            </div>
        </div>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 매개변수 분석 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <?php if (!empty($test_result)): ?>
            <div style="margin-top: 20px;">
                <h2>🧪 테스트 시나리오 결과:</h2>
                <pre style="background: #e3f2fd; padding: 15px; border-radius: 5px; border-left: 4px solid #2196f3;"><?php echo htmlspecialchars($test_result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="scenario-card">
            <h4>💡 HPP 공격 예제</h4>
            <p><strong>인증 우회:</strong> <code>?user=guest&user=admin</code></p>
            <p><strong>권한 상승:</strong> <code>?role=user&action=view&role=admin</code></p>
            <p><strong>필터 우회:</strong> <code>?search=<script>&search=alert(1)</code></p>
            <p><strong>캐시 독으로:</strong> <code>?lang=en&lang=../../../etc/passwd</code></p>
        </div>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>매개변수 정규화:</strong> 중복된 매개변수 처리 방식 명확화</li>
                <li><strong>입력 검증:</strong> 모든 매개변수 값에 대한 검증 수행</li>
                <li><strong>배열 처리:</strong> 중복 매개변수를 배열로 명시적 처리</li>
                <li><strong>웹 서버 설정:</strong> 중복 매개변수 거부 설정</li>
                <li><strong>로깅:</strong> 의심스러운 매개변수 패턴 모니터링</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        function testScenario(scenario) {
            let url = '';
            let message = '';
            
            switch(scenario) {
                case 'auth_bypass':
                    url = '?test_scenario=auth_bypass&user=guest&user=admin';
                    message = '인증 우회 시나리오: 사용자 권한 우회 시도';
                    break;
                    
                case 'privilege_escalation':
                    url = '?test_scenario=privilege_escalation&role=user&action=view&role=admin';
                    message = '권한 상승 시나리오: 관리자 권한 획득 시도';
                    break;
                    
                case 'filter_bypass':
                    url = '?test_scenario=filter_bypass&filter=safe&filter=<script>alert(1)</script>';
                    message = '필터 우회 시나리오: XSS 필터 우회 시도';
                    break;
                    
                case 'cache_poisoning':
                    url = '?lang=en&page=home&lang=../../../etc/passwd';
                    message = '캐시 독으로 시나리오: 캐시 오염 시도';
                    break;
                    
                case 'custom':
                    const getParams = prompt('GET 매개변수를 입력하세요 (예: param=value1&param=value2):');
                    if (getParams) {
                        url = '?' + getParams;
                        message = '사용자 정의 HPP 테스트';
                    } else {
                        return;
                    }
                    break;
            }
            
            if (confirm('⚠️ 교육 목적의 HPP 테스트를 실행하시겠습니까?\n\n' + message)) {
                window.location.href = url;
            }
        }

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
                // POST 데이터가 있는 경우 폼으로 전송
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
</body>
</html>