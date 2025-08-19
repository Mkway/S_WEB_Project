<?php
require_once '../config.php';
require_once '../db.php';

$vulnerability_enabled = isVulnerabilityEnabled('redos', $_GET);

function timeRegexExecution($pattern, $input) {
    $start_time = microtime(true);
    $result = @preg_match($pattern, $input);
    $end_time = microtime(true);
    
    return [
        'result' => $result,
        'execution_time' => ($end_time - $start_time) * 1000, // 밀리초로 변환
        'matched' => $result === 1
    ];
}

function validateEmail($email, $vulnerable = false) {
    if ($vulnerable) {
        // 취약한 정규식: 재귀적 백트래킹 발생
        $pattern = '/^([a-zA-Z0-9])+([a-zA-Z0-9._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9._-]+)+\.[a-zA-Z]{2,6}$/';
    } else {
        // 안전한 정규식: 백트래킹 최소화
        $pattern = '/^[a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9_-]+\.[a-zA-Z]{2,6}$/';
    }
    
    return timeRegexExecution($pattern, $email);
}

function validatePassword($password, $vulnerable = false) {
    if ($vulnerable) {
        // 취약한 정규식: 중첩된 양화사로 인한 catastrophic backtracking
        $pattern = '/^(?=.*[a-z])+(?=.*[A-Z])+(?=.*\d)+(?=.*[@$!%*?&])+[A-Za-z\d@$!%*?&]{8,}$/';
    } else {
        // 안전한 정규식: 원자 그룹 사용
        $pattern = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/';
    }
    
    return timeRegexExecution($pattern, $password);
}

function validateURL($url, $vulnerable = false) {
    if ($vulnerable) {
        // 취약한 정규식: 여러 중첩된 선택사항으로 인한 exponential blowup
        $pattern = '/^(https?|ftp):\/\/(([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})+([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*@)*(([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.)*[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.?|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(:[0-9]+)?(\/([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*(\/([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*)*(\?([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*)?(#([a-zA-Z0-9$_.+!*(),;:@&=-]|%[0-9a-fA-F]{2})*)?)?$/';
    } else {
        // 안전한 정규식: filter_var 사용 권장
        return [
            'result' => filter_var($url, FILTER_VALIDATE_URL) !== false ? 1 : 0,
            'execution_time' => 0,
            'matched' => filter_var($url, FILTER_VALIDATE_URL) !== false
        ];
    }
    
    return timeRegexExecution($pattern, $url);
}

$test_results = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    $test_input = $_POST['test_input'] ?? '';
    
    switch ($test_type) {
        case 'email':
            $result = validateEmail($test_input, $vulnerability_enabled);
            break;
        case 'password':
            $result = validatePassword($test_input, $vulnerability_enabled);
            break;
        case 'url':
            $result = validateURL($test_input, $vulnerability_enabled);
            break;
        case 'custom':
            $custom_pattern = $_POST['custom_pattern'] ?? '';
            if (!empty($custom_pattern)) {
                $result = timeRegexExecution($custom_pattern, $test_input);
            }
            break;
        default:
            $result = ['result' => false, 'execution_time' => 0, 'matched' => false];
    }
    
    $test_results[] = [
        'type' => $test_type,
        'input' => $test_input,
        'pattern' => $_POST['custom_pattern'] ?? '',
        'vulnerable' => $vulnerability_enabled,
        'result' => $result
    ];
}

$redos_payloads = [
    [
        'name' => 'Email ReDoS',
        'type' => 'email',
        'payload' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
        'description' => '이메일 검증 정규식에서 백트래킹을 유발하는 입력'
    ],
    [
        'name' => 'Password ReDoS',
        'type' => 'password',
        'payload' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
        'description' => '복잡한 패스워드 정규식에서 catastrophic backtracking 유발'
    ],
    [
        'name' => 'URL ReDoS',
        'type' => 'url',
        'payload' => 'http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'description' => 'URL 검증 정규식에서 exponential blowup 유발'
    ],
    [
        'name' => 'Nested Quantifiers',
        'type' => 'custom',
        'pattern' => '/^(a+)+$/',
        'payload' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
        'description' => '중첩된 양화사로 인한 exponential time complexity'
    ],
    [
        'name' => 'Alternation Attack',
        'type' => 'custom',
        'pattern' => '/^(a|a)*$/',
        'payload' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab',
        'description' => '선택사항이 겹치는 패턴으로 인한 백트래킹'
    ],
    [
        'name' => 'Grouping Attack',
        'type' => 'custom',
        'pattern' => '/^(a|b)*c$/',
        'payload' => 'ababababababababababababababab',
        'description' => '그룹화된 선택사항에서 매칭 실패 시 백트래킹'
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReDoS (Regular Expression Denial of Service) 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .regex-tester {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .test-result {
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
        
        .result-success {
            background: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }
        
        .result-warning {
            background: #fff3cd;
            border-color: #ffeaa7;
            color: #856404;
        }
        
        .result-danger {
            background: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        
        .execution-time {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .execution-time.fast {
            color: #28a745;
        }
        
        .execution-time.medium {
            color: #ffc107;
        }
        
        .execution-time.slow {
            color: #dc3545;
        }
        
        .payload-examples {
            background: #fff3e0;
            border: 1px solid #ffb74d;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }
        
        .payload-item {
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .payload-item:hover {
            background: #f5f5f5;
        }
        
        .payload-name {
            font-weight: bold;
            color: #d32f2f;
        }
        
        .payload-pattern {
            font-family: monospace;
            background: #f5f5f5;
            padding: 5px;
            margin: 5px 0;
            border-radius: 3px;
            font-size: 0.9em;
        }
        
        .vulnerability-status {
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-weight: bold;
        }
        
        .vulnerability-enabled {
            background: #ffcdd2;
            color: #c62828;
            border: 1px solid #f44336;
        }
        
        .vulnerability-disabled {
            background: #c8e6c9;
            color: #2e7d32;
            border: 1px solid #4caf50;
        }
        
        .form-group {
            margin: 15px 0;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .form-group select,
        .form-group input,
        .form-group textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ ReDoS (Regular Expression Denial of Service) 테스트</h1>
        
        <div class="vulnerability-status <?php echo $vulnerability_enabled ? 'vulnerability-enabled' : 'vulnerability-disabled'; ?>">
            상태: <?php echo $vulnerability_enabled ? '취약한 정규식 사용 (ReDoS 가능)' : '안전한 정규식 사용 (ReDoS 방어)'; ?>
        </div>
        
        <div class="description">
            <h2>📋 ReDoS (Regular Expression Denial of Service)란?</h2>
            <p><strong>ReDoS</strong>는 정규식의 백트래킹 특성을 악용하여 과도한 CPU 사용을 유발하는 공격입니다.</p>
            
            <h3>발생 원인</h3>
            <ul>
                <li><strong>Catastrophic Backtracking</strong>: 중첩된 양화사 (+, *, {n,m})</li>
                <li><strong>Exponential Blowup</strong>: 여러 선택사항이 겹치는 패턴</li>
                <li><strong>Nested Quantifiers</strong>: (a+)+ 같은 중첩된 구조</li>
                <li><strong>Alternation Issues</strong>: (a|a)* 같은 모호한 선택</li>
            </ul>
            
            <h3>방어 방법</h3>
            <ul>
                <li>원자 그룹 (?>...) 사용</li>
                <li>소유 양화사 (possessive quantifier) 사용</li>
                <li>입력 길이 제한</li>
                <li>정규식 실행 시간 제한</li>
                <li>미리 컴파일된 안전한 패턴 사용</li>
            </ul>
        </div>

        <div class="regex-tester">
            <h2>🧪 정규식 성능 테스터</h2>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="test_type">테스트 유형:</label>
                    <select name="test_type" id="test_type" onchange="toggleCustomPattern()">
                        <option value="email">이메일 검증</option>
                        <option value="password">비밀번호 검증</option>
                        <option value="url">URL 검증</option>
                        <option value="custom">사용자 정의 정규식</option>
                    </select>
                </div>
                
                <div class="form-group" id="custom_pattern_group" style="display: none;">
                    <label for="custom_pattern">사용자 정의 정규식 패턴:</label>
                    <input type="text" name="custom_pattern" id="custom_pattern" placeholder="/^(a+)+$/" value="<?php echo htmlspecialchars($_POST['custom_pattern'] ?? ''); ?>">
                </div>
                
                <div class="form-group">
                    <label for="test_input">테스트 입력:</label>
                    <textarea name="test_input" id="test_input" rows="3" placeholder="테스트할 문자열을 입력하세요..."><?php echo htmlspecialchars($_POST['test_input'] ?? ''); ?></textarea>
                </div>
                
                <button type="submit" class="btn">정규식 성능 테스트 실행</button>
            </form>
            
            <?php if (!empty($test_results)): ?>
                <?php foreach ($test_results as $result): ?>
                <div class="test-result <?php 
                    if ($result['result']['execution_time'] > 100) {
                        echo 'result-danger';
                    } elseif ($result['result']['execution_time'] > 10) {
                        echo 'result-warning';
                    } else {
                        echo 'result-success';
                    }
                ?>">
                    <h4>테스트 결과</h4>
                    <p><strong>유형:</strong> <?php echo htmlspecialchars($result['type']); ?></p>
                    <p><strong>입력:</strong> <code><?php echo htmlspecialchars($result['input']); ?></code></p>
                    <?php if (!empty($result['pattern'])): ?>
                    <p><strong>패턴:</strong> <code><?php echo htmlspecialchars($result['pattern']); ?></code></p>
                    <?php endif; ?>
                    <p><strong>매칭 결과:</strong> <?php echo $result['result']['matched'] ? '✅ 매칭됨' : '❌ 매칭되지 않음'; ?></p>
                    <p class="execution-time <?php 
                        if ($result['result']['execution_time'] > 100) echo 'slow';
                        elseif ($result['result']['execution_time'] > 10) echo 'medium';
                        else echo 'fast';
                    ?>">
                        <strong>실행 시간:</strong> <?php echo number_format($result['result']['execution_time'], 2); ?>ms
                    </p>
                    
                    <?php if ($result['result']['execution_time'] > 100): ?>
                    <p class="alert alert-danger">⚠️ <strong>ReDoS 위험!</strong> 실행 시간이 100ms를 초과했습니다.</p>
                    <?php elseif ($result['result']['execution_time'] > 10): ?>
                    <p class="alert alert-warning">⚠️ <strong>성능 주의!</strong> 실행 시간이 비교적 깁니다.</p>
                    <?php else: ?>
                    <p class="alert alert-success">✅ <strong>정상!</strong> 빠른 실행 시간입니다.</p>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="payload-examples">
            <h3>🎯 ReDoS 공격 페이로드 예제</h3>
            <p>아래 예제들을 클릭하면 자동으로 테스트할 수 있습니다:</p>
            
            <?php foreach ($redos_payloads as $payload): ?>
            <div class="payload-item" onclick="setPayload('<?php echo $payload['type']; ?>', '<?php echo addslashes($payload['payload']); ?>', '<?php echo addslashes($payload['pattern'] ?? ''); ?>')">
                <div class="payload-name"><?php echo htmlspecialchars($payload['name']); ?></div>
                <?php if (isset($payload['pattern'])): ?>
                <div class="payload-pattern">패턴: <?php echo htmlspecialchars($payload['pattern']); ?></div>
                <?php endif; ?>
                <div class="payload-pattern">입력: <?php echo htmlspecialchars($payload['payload']); ?></div>
                <div class="payload-description"><?php echo htmlspecialchars($payload['description']); ?></div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="mitigation">
            <h2>🛡️ 완화 방안</h2>
            <div class="code-block">
                <h3>안전한 정규식 작성법</h3>
                <pre><code>// 1. 위험한 패턴 (ReDoS 취약)
$bad_email = '/^([a-zA-Z0-9])+([a-zA-Z0-9._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9._-]+)+\.[a-zA-Z]{2,6}$/';

// 2. 안전한 패턴 (ReDoS 방어)
$safe_email = '/^[a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9_-]+\.[a-zA-Z]{2,6}$/';

// 3. 실행 시간 제한
function safeRegexMatch($pattern, $input, $timeout = 100) {
    $start = microtime(true);
    
    // PCRE_JIT을 비활성화하여 시간 제한 적용
    ini_set('pcre.jit', 0);
    
    $result = @preg_match($pattern, $input);
    
    $time = (microtime(true) - $start) * 1000;
    
    if ($time > $timeout) {
        throw new Exception("Regex execution timeout");
    }
    
    return $result;
}

// 4. 입력 길이 제한
function validateWithLimit($input, $max_length = 100) {
    if (strlen($input) > $max_length) {
        return false;
    }
    
    return safeRegexMatch('/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/', $input);
}</code></pre>
            </div>
        </div>

        <div class="navigation">
            <a href="index.php" class="btn">🏠 메인으로</a>
            <a href="?vuln=<?php echo $vulnerability_enabled ? 'disabled' : 'enabled'; ?>" class="btn">
                🔄 <?php echo $vulnerability_enabled ? '보안 모드' : '취약 모드'; ?>로 전환
            </a>
        </div>
    </div>

    <script>
        function toggleCustomPattern() {
            const testType = document.getElementById('test_type').value;
            const customGroup = document.getElementById('custom_pattern_group');
            
            if (testType === 'custom') {
                customGroup.style.display = 'block';
            } else {
                customGroup.style.display = 'none';
            }
        }
        
        function setPayload(type, payload, pattern) {
            document.getElementById('test_type').value = type;
            document.getElementById('test_input').value = payload;
            
            if (pattern) {
                document.getElementById('custom_pattern').value = pattern;
            }
            
            toggleCustomPattern();
        }
        
        // 페이지 로드 시 초기 상태 설정
        document.addEventListener('DOMContentLoaded', function() {
            toggleCustomPattern();
        });
    </script>
</body>
</html>