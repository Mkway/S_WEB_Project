<?php
require_once '../config.php';
require_once '../db.php';

$vulnerability_enabled = isVulnerabilityEnabled('insecure_randomness', $_GET);

function generateInsecurePassword($length = 8) {
    // 취약한 방법: 예측 가능한 시드와 rand() 사용
    srand(time()); // 현재 시간을 시드로 사용 (예측 가능)
    
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $password = '';
    
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[rand(0, strlen($chars) - 1)];
    }
    
    return $password;
}

function generateSecurePassword($length = 8) {
    // 안전한 방법: 암호학적으로 안전한 난수 생성
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    $password = '';
    
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    
    return $password;
}

function generateInsecureToken($length = 16) {
    // 취약한 방법: mt_rand()와 시간 기반 시드
    mt_srand(microtime(true) * 1000); // 마이크로초 기반 시드 (여전히 예측 가능)
    
    $token = '';
    for ($i = 0; $i < $length; $i++) {
        $token .= dechex(mt_rand(0, 15));
    }
    
    return $token;
}

function generateSecureToken($length = 32) {
    // 안전한 방법: random_bytes() 사용
    return bin2hex(random_bytes($length / 2));
}

function generateInsecureSessionId() {
    // 취약한 방법: 사용자 정보와 시간 조합
    $user_id = $_SESSION['user_id'] ?? 1;
    $time = time();
    
    return md5($user_id . $time); // 예측 가능한 해시
}

function generateSecureSessionId() {
    // 안전한 방법: 완전한 랜덤 데이터
    return bin2hex(random_bytes(32));
}

function analyzeRandomness($data_array) {
    $analysis = [
        'count' => count($data_array),
        'unique_count' => count(array_unique($data_array)),
        'uniqueness_ratio' => 0,
        'patterns' => [],
        'entropy' => 0
    ];
    
    if ($analysis['count'] > 0) {
        $analysis['uniqueness_ratio'] = $analysis['unique_count'] / $analysis['count'];
        
        // 간단한 패턴 분석
        for ($i = 0; $i < count($data_array) - 1; $i++) {
            $current = $data_array[$i];
            $next = $data_array[$i + 1];
            
            // 연속된 값 체크
            if (is_numeric($current) && is_numeric($next)) {
                if (abs($next - $current) <= 1) {
                    $analysis['patterns'][] = "Sequential values detected: $current -> $next";
                }
            }
            
            // 반복 패턴 체크
            if ($current === $next) {
                $analysis['patterns'][] = "Duplicate values: $current";
            }
        }
        
        // 간단한 엔트로피 계산
        $value_counts = array_count_values($data_array);
        $total = count($data_array);
        
        foreach ($value_counts as $count) {
            $probability = $count / $total;
            $analysis['entropy'] -= $probability * log($probability, 2);
        }
    }
    
    return $analysis;
}

$test_results = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    $sample_count = min((int)($_POST['sample_count'] ?? 10), 100); // 최대 100개로 제한
    
    $generated_data = [];
    
    switch ($test_type) {
        case 'password':
            for ($i = 0; $i < $sample_count; $i++) {
                if ($vulnerability_enabled) {
                    $generated_data[] = generateInsecurePassword();
                } else {
                    $generated_data[] = generateSecurePassword();
                }
            }
            break;
            
        case 'token':
            for ($i = 0; $i < $sample_count; $i++) {
                if ($vulnerability_enabled) {
                    $generated_data[] = generateInsecureToken();
                } else {
                    $generated_data[] = generateSecureToken();
                }
            }
            break;
            
        case 'session_id':
            for ($i = 0; $i < $sample_count; $i++) {
                if ($vulnerability_enabled) {
                    $generated_data[] = generateInsecureSessionId();
                } else {
                    $generated_data[] = generateSecureSessionId();
                }
            }
            break;
            
        case 'random_numbers':
            for ($i = 0; $i < $sample_count; $i++) {
                if ($vulnerability_enabled) {
                    $generated_data[] = rand(1, 100);
                } else {
                    $generated_data[] = random_int(1, 100);
                }
            }
            break;
    }
    
    $analysis = analyzeRandomness($generated_data);
    
    $test_results[] = [
        'type' => $test_type,
        'vulnerable' => $vulnerability_enabled,
        'data' => $generated_data,
        'analysis' => $analysis
    ];
}

$randomness_tests = [
    [
        'name' => '패스워드 생성',
        'type' => 'password',
        'description' => '임시 패스워드나 초기 패스워드 생성 시 랜덤성 테스트'
    ],
    [
        'name' => '토큰 생성',
        'type' => 'token',
        'description' => 'API 토큰, 인증 토큰 등의 랜덤성 테스트'
    ],
    [
        'name' => '세션 ID 생성',
        'type' => 'session_id',
        'description' => '세션 식별자의 예측 가능성 테스트'
    ],
    [
        'name' => '난수 생성',
        'type' => 'random_numbers',
        'description' => '일반적인 난수 생성 함수의 품질 테스트'
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insecure Randomness 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .randomness-tester {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .generated-data {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .data-item {
            font-family: monospace;
            background: white;
            padding: 5px 8px;
            margin: 3px 0;
            border-radius: 3px;
            border: 1px solid #e0e0e0;
            font-size: 0.9em;
        }
        
        .analysis-result {
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .analysis-metric {
            display: flex;
            justify-content: space-between;
            margin: 8px 0;
            padding: 5px 0;
            border-bottom: 1px solid #ddd;
        }
        
        .metric-label {
            font-weight: bold;
        }
        
        .metric-value {
            font-family: monospace;
        }
        
        .metric-good {
            color: #2e7d32;
        }
        
        .metric-warning {
            color: #f57c00;
        }
        
        .metric-bad {
            color: #d32f2f;
        }
        
        .patterns-list {
            background: #ffebee;
            border: 1px solid #f44336;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .pattern-item {
            color: #d32f2f;
            margin: 5px 0;
            font-family: monospace;
            font-size: 0.9em;
        }
        
        .test-types {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .test-type-card {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .test-type-card:hover {
            background: #f5f5f5;
            border-color: #2196f3;
        }
        
        .test-type-card.selected {
            background: #e3f2fd;
            border-color: #2196f3;
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
        
        .form-group input,
        .form-group select {
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
        <h1>🎲 Insecure Randomness 취약점 테스트</h1>
        
        <div class="vulnerability-status <?php echo $vulnerability_enabled ? 'vulnerability-enabled' : 'vulnerability-disabled'; ?>">
            상태: <?php echo $vulnerability_enabled ? '취약한 난수 생성 (예측 가능)' : '안전한 난수 생성 (암호학적 보안)'; ?>
        </div>
        
        <div class="description">
            <h2>📋 Insecure Randomness란?</h2>
            <p><strong>Insecure Randomness</strong>는 예측 가능한 의사난수 생성기를 사용하여 보안에 중요한 값들을 생성할 때 발생하는 취약점입니다.</p>
            
            <h3>위험한 함수들</h3>
            <ul>
                <li><strong>rand() / srand()</strong>: 선형 합동 생성기, 예측 가능</li>
                <li><strong>mt_rand() / mt_srand()</strong>: 메르센 트위스터, 시드 예측 시 위험</li>
                <li><strong>time() 기반 시드</strong>: 시간으로 시드 설정 시 예측 가능</li>
                <li><strong>uniqid()</strong>: 시간 기반, 고유성은 보장하지만 예측 가능</li>
            </ul>
            
            <h3>안전한 함수들</h3>
            <ul>
                <li><strong>random_bytes()</strong>: 암호학적으로 안전한 난수</li>
                <li><strong>random_int()</strong>: 안전한 정수 난수</li>
                <li><strong>openssl_random_pseudo_bytes()</strong>: OpenSSL 기반 난수</li>
                <li><strong>mcrypt_create_iv()</strong>: (PHP < 7.2) 암호화 초기화 벡터</li>
            </ul>
        </div>

        <div class="randomness-tester">
            <h2>🧪 난수 품질 분석기</h2>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="test_type">테스트 유형:</label>
                    <select name="test_type" id="test_type">
                        <?php foreach ($randomness_tests as $test): ?>
                        <option value="<?php echo $test['type']; ?>" <?php echo ($_POST['test_type'] ?? '') === $test['type'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($test['name']); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="sample_count">샘플 개수 (최대 100개):</label>
                    <input type="number" name="sample_count" id="sample_count" min="5" max="100" value="<?php echo $_POST['sample_count'] ?? '20'; ?>">
                </div>
                
                <button type="submit" class="btn">난수 생성 및 분석</button>
            </form>
            
            <?php if (!empty($test_results)): ?>
                <?php foreach ($test_results as $result): ?>
                <div class="analysis-result">
                    <h3>분석 결과 - <?php echo htmlspecialchars($result['type']); ?></h3>
                    
                    <div class="analysis-metric">
                        <span class="metric-label">생성된 샘플 수:</span>
                        <span class="metric-value"><?php echo $result['analysis']['count']; ?>개</span>
                    </div>
                    
                    <div class="analysis-metric">
                        <span class="metric-label">고유값 개수:</span>
                        <span class="metric-value"><?php echo $result['analysis']['unique_count']; ?>개</span>
                    </div>
                    
                    <div class="analysis-metric">
                        <span class="metric-label">고유성 비율:</span>
                        <span class="metric-value <?php 
                            $ratio = $result['analysis']['uniqueness_ratio'];
                            if ($ratio >= 0.95) echo 'metric-good';
                            elseif ($ratio >= 0.8) echo 'metric-warning';
                            else echo 'metric-bad';
                        ?>">
                            <?php echo number_format($result['analysis']['uniqueness_ratio'] * 100, 1); ?>%
                        </span>
                    </div>
                    
                    <div class="analysis-metric">
                        <span class="metric-label">엔트로피:</span>
                        <span class="metric-value <?php 
                            $entropy = $result['analysis']['entropy'];
                            if ($entropy >= 3.5) echo 'metric-good';
                            elseif ($entropy >= 2.0) echo 'metric-warning';
                            else echo 'metric-bad';
                        ?>">
                            <?php echo number_format($result['analysis']['entropy'], 2); ?> bits
                        </span>
                    </div>
                    
                    <?php if (!empty($result['analysis']['patterns'])): ?>
                    <div class="patterns-list">
                        <strong>⚠️ 발견된 패턴:</strong>
                        <?php foreach ($result['analysis']['patterns'] as $pattern): ?>
                        <div class="pattern-item"><?php echo htmlspecialchars($pattern); ?></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    
                    <details>
                        <summary><strong>생성된 데이터 보기</strong></summary>
                        <div class="generated-data">
                            <?php foreach ($result['data'] as $index => $item): ?>
                            <div class="data-item"><?php echo ($index + 1) . ': ' . htmlspecialchars($item); ?></div>
                            <?php endforeach; ?>
                        </div>
                    </details>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="test-types">
            <h3>🎯 테스트 유형별 설명</h3>
            <?php foreach ($randomness_tests as $test): ?>
            <div class="test-type-card">
                <h4><?php echo htmlspecialchars($test['name']); ?></h4>
                <p><?php echo htmlspecialchars($test['description']); ?></p>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="mitigation">
            <h2>🛡️ 완화 방안</h2>
            <div class="code-block">
                <h3>안전한 난수 생성</h3>
                <pre><code>// ❌ 위험한 방법들
function badRandomPassword() {
    srand(time()); // 시간 기반 시드
    return substr(md5(rand()), 0, 8);
}

function badToken() {
    return md5(uniqid()); // 시간 기반, 예측 가능
}

function badSessionId() {
    return md5($_SERVER['REMOTE_ADDR'] . time());
}

// ✅ 안전한 방법들
function secureRandomPassword($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    $password = '';
    
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    
    return $password;
}

function secureToken($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

function secureSessionId() {
    return bin2hex(random_bytes(32));
}

// 암호화 키 생성
function generateEncryptionKey($keySize = 32) {
    return random_bytes($keySize);
}

// CSRF 토큰 생성
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
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
</body>
</html>