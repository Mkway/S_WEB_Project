<?php
require_once '../config.php';
require_once '../db.php';

$vulnerability_enabled = isVulnerabilityEnabled('encoding_transformations', $_GET);

function applyEncodingTransformations($input, $encoding_types = [], $vulnerable = false) {
    $result = [
        'original_input' => $input,
        'transformations' => [],
        'bypassed_filters' => [],
        'security_issues' => []
    ];
    
    foreach ($encoding_types as $encoding) {
        $transformed = $input;
        
        switch ($encoding) {
            case 'url_encode':
                $transformed = urlencode($input);
                $result['transformations']['URL Encoding'] = $transformed;
                break;
                
            case 'double_url_encode':
                $transformed = urlencode(urlencode($input));
                $result['transformations']['Double URL Encoding'] = $transformed;
                break;
                
            case 'html_entity':
                $transformed = htmlentities($input, ENT_QUOTES, 'UTF-8');
                $result['transformations']['HTML Entity Encoding'] = $transformed;
                break;
                
            case 'html_numeric':
                $transformed = '';
                for ($i = 0; $i < strlen($input); $i++) {
                    $transformed .= '&#' . ord($input[$i]) . ';';
                }
                $result['transformations']['HTML Numeric Entities'] = $transformed;
                break;
                
            case 'hex_encode':
                $transformed = bin2hex($input);
                $result['transformations']['Hexadecimal Encoding'] = $transformed;
                break;
                
            case 'base64':
                $transformed = base64_encode($input);
                $result['transformations']['Base64 Encoding'] = $transformed;
                break;
                
            case 'unicode_escape':
                $transformed = json_encode($input, JSON_UNESCAPED_SLASHES);
                $result['transformations']['Unicode Escape'] = $transformed;
                break;
                
            case 'mixed_case':
                $transformed = '';
                for ($i = 0; $i < strlen($input); $i++) {
                    $transformed .= ($i % 2 === 0) ? strtoupper($input[$i]) : strtolower($input[$i]);
                }
                $result['transformations']['Mixed Case'] = $transformed;
                break;
                
            case 'null_byte':
                $transformed = str_replace(' ', "\x00", $input);
                $result['transformations']['Null Byte Injection'] = addcslashes($transformed, "\0");
                break;
                
            case 'utf8_overlong':
                // UTF-8 Overlong 인코딩 시뮬레이션
                if (strpos($input, '<') !== false) {
                    $transformed = str_replace('<', "\xC0\xBC", $input); // Overlong encoding of '<'
                    $result['transformations']['UTF-8 Overlong'] = addcslashes($transformed, "\x00..\x1f\x7f..\xff");
                }
                break;
                
            case 'charset_confusion':
                // 문자셋 혼동 공격 시뮬레이션
                if (strpos($input, 'script') !== false) {
                    $transformed = iconv('UTF-8', 'ISO-8859-1//IGNORE', $input);
                    $result['transformations']['Charset Confusion'] = $transformed;
                }
                break;
        }
    }
    
    return $result;
}

function simulateInputValidation($input, $vulnerable = false) {
    $result = [
        'input' => $input,
        'validation_result' => '',
        'bypassed' => false,
        'detected_attacks' => [],
        'blocked' => false
    ];
    
    // 기본적인 XSS 패턴
    $xss_patterns = [
        '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
        '/on\w+\s*=\s*["\']?[^"\'>\s]+["\']?/i',
        '/javascript:/i',
        '/<iframe\b/i',
        '/<object\b/i',
        '/<embed\b/i'
    ];
    
    // SQL 인젝션 패턴
    $sqli_patterns = [
        '/union\s+select/i',
        '/or\s+1\s*=\s*1/i',
        '/drop\s+table/i',
        '/insert\s+into/i',
        '/update\s+.*set/i',
        '/delete\s+from/i'
    ];
    
    $all_patterns = array_merge($xss_patterns, $sqli_patterns);
    
    if ($vulnerable) {
        // 취약한 검증: 기본적인 패턴만 확인, 인코딩 우회 가능
        foreach ($all_patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                $result['detected_attacks'][] = "Pattern matched: " . $pattern;
                $result['blocked'] = true;
                break;
            }
        }
        
        // 인코딩된 입력은 검증하지 않음
        if (strpos($input, '%') !== false || strpos($input, '&#') !== false || 
            strpos($input, '\\u') !== false || preg_match('/[A-Fa-f0-9]{6,}/', $input)) {
            $result['validation_result'] = "Input appears encoded, bypassing validation";
            $result['bypassed'] = true;
        } else {
            $result['validation_result'] = $result['blocked'] ? "Blocked" : "Allowed";
        }
        
    } else {
        // 안전한 검증: 디코딩 후 검증
        $decoded_input = $input;
        
        // 다중 디코딩 시도
        for ($i = 0; $i < 3; $i++) {
            $previous = $decoded_input;
            $decoded_input = urldecode($decoded_input);
            $decoded_input = html_entity_decode($decoded_input, ENT_QUOTES, 'UTF-8');
            
            if ($previous === $decoded_input) {
                break; // 더 이상 디코딩되지 않음
            }
        }
        
        // 디코딩된 입력에 대해 검증
        foreach ($all_patterns as $pattern) {
            if (preg_match($pattern, $decoded_input)) {
                $result['detected_attacks'][] = "Pattern matched after decoding: " . $pattern;
                $result['blocked'] = true;
            }
        }
        
        $result['validation_result'] = $result['blocked'] ? "Blocked after decoding" : "Allowed";
        
        if ($decoded_input !== $input && $result['blocked']) {
            $result['bypassed'] = false; // 디코딩 후 탐지됨
        }
    }
    
    return $result;
}

function generateEncodingPayloads() {
    return [
        [
            'name' => 'Basic XSS',
            'payload' => '<script>alert("XSS")</script>',
            'description' => '기본 XSS 페이로드'
        ],
        [
            'name' => 'URL Encoded XSS',
            'payload' => '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
            'description' => 'URL 인코딩된 XSS'
        ],
        [
            'name' => 'Double URL Encoded',
            'payload' => '%253Cscript%253Ealert%2528%2522XSS%2522%2529%253C%252Fscript%253E',
            'description' => '이중 URL 인코딩'
        ],
        [
            'name' => 'HTML Entity XSS',
            'payload' => '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
            'description' => 'HTML 엔티티 인코딩'
        ],
        [
            'name' => 'Numeric Entities',
            'payload' => '&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;',
            'description' => 'HTML 숫자 엔티티'
        ],
        [
            'name' => 'Mixed Case Bypass',
            'payload' => '<ScRiPt>AlErT("XSS")</ScRiPt>',
            'description' => '대소문자 혼용'
        ],
        [
            'name' => 'SQL Injection',
            'payload' => "' OR 1=1 --",
            'description' => '기본 SQL 인젝션'
        ],
        [
            'name' => 'URL Encoded SQLi',
            'payload' => '%27%20OR%201%3D1%20--',
            'description' => 'URL 인코딩된 SQL 인젝션'
        ],
        [
            'name' => 'Unicode Escape',
            'payload' => '\\u003cscript\\u003ealert(\\u0022XSS\\u0022)\\u003c/script\\u003e',
            'description' => 'Unicode 이스케이프 시퀀스'
        ],
        [
            'name' => 'Base64 Encoded',
            'payload' => base64_encode('<script>alert("XSS")</script>'),
            'description' => 'Base64 인코딩된 페이로드'
        ]
    ];
}

$test_results = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    
    if ($test_type === 'encoding_test') {
        $input = $_POST['input'] ?? '';
        $encodings = $_POST['encodings'] ?? [];
        
        if (!empty($input)) {
            $encoding_result = applyEncodingTransformations($input, $encodings, $vulnerability_enabled);
            $validation_result = simulateInputValidation($input, $vulnerability_enabled);
            
            $test_results[] = [
                'type' => 'encoding_transformation',
                'encoding_result' => $encoding_result,
                'validation_result' => $validation_result
            ];
        }
        
    } elseif ($test_type === 'validation_test') {
        $payload = $_POST['payload'] ?? '';
        
        if (!empty($payload)) {
            $validation_result = simulateInputValidation($payload, $vulnerability_enabled);
            
            $test_results[] = [
                'type' => 'validation_test',
                'validation_result' => $validation_result
            ];
        }
        
    } elseif ($test_type === 'batch_test') {
        $payloads = generateEncodingPayloads();
        
        foreach ($payloads as $payload_info) {
            $validation_result = simulateInputValidation($payload_info['payload'], $vulnerability_enabled);
            $validation_result['payload_info'] = $payload_info;
            
            $test_results[] = [
                'type' => 'batch_validation',
                'validation_result' => $validation_result
            ];
        }
    }
}

$encoding_techniques = [
    [
        'name' => 'URL Encoding',
        'description' => '%20, %3C, %3E 등으로 특수문자를 인코딩하여 필터 우회',
        'example' => '<script> → %3Cscript%3E'
    ],
    [
        'name' => 'Double Encoding',
        'description' => '이중 인코딩으로 디코딩 과정에서 필터 우회',
        'example' => '< → %3C → %253C'
    ],
    [
        'name' => 'HTML Entity Encoding',
        'description' => 'HTML 엔티티로 변환하여 브라우저에서 실행',
        'example' => '<script> → &lt;script&gt;'
    ],
    [
        'name' => 'Unicode Normalization',
        'description' => 'Unicode 정규화 과정에서 악성 코드 생성',
        'example' => 'Fullwidth characters → Normal ASCII'
    ],
    [
        'name' => 'Charset Confusion',
        'description' => '문자셋 변환 과정에서 바이트 시퀀스 조작',
        'example' => 'UTF-8 → ISO-8859-1 변환'
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Encoding Transformations 취약점 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .encoding-simulator {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .encoding-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        
        .encoding-checkbox {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        
        .encoding-checkbox input[type="checkbox"] {
            width: auto;
        }
        
        .encoding-checkbox label {
            margin: 0;
            cursor: pointer;
            flex: 1;
        }
        
        .transformation-display {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            font-family: monospace;
        }
        
        .transformation-item {
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        
        .transformation-name {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }
        
        .transformation-value {
            word-break: break-all;
            background: #f5f5f5;
            padding: 5px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        
        .validation-result {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .validation-allowed {
            border-color: #28a745;
            background: #d4edda;
            color: #155724;
        }
        
        .validation-blocked {
            border-color: #dc3545;
            background: #f8d7da;
            color: #721c24;
        }
        
        .validation-bypassed {
            border-color: #ffc107;
            background: #fff3cd;
            color: #856404;
        }
        
        .payload-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        
        .payload-card {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .payload-card:hover {
            background: #f8f9fa;
            border-color: #007bff;
        }
        
        .payload-name {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 8px;
        }
        
        .payload-value {
            font-family: monospace;
            background: #f5f5f5;
            padding: 8px;
            border-radius: 3px;
            margin: 8px 0;
            word-break: break-all;
            font-size: 0.8em;
        }
        
        .payload-description {
            font-size: 0.9em;
            color: #666;
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
        
        .form-group textarea,
        .form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .form-group textarea {
            font-family: monospace;
            min-height: 80px;
            resize: vertical;
        }
        
        .btn-group {
            display: flex;
            gap: 10px;
            margin: 15px 0;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
        }
        
        .technique-examples {
            background: #fff3e0;
            border: 1px solid #ffb74d;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }
        
        .technique-item {
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .technique-name {
            font-weight: bold;
            color: #d32f2f;
            margin-bottom: 5px;
        }
        
        .technique-description {
            font-size: 0.9em;
            color: #666;
            margin: 5px 0;
        }
        
        .technique-example {
            font-family: monospace;
            background: #f5f5f5;
            padding: 5px;
            border-radius: 3px;
            margin-top: 5px;
            font-size: 0.8em;
        }
        
        .tab-container {
            margin: 20px 0;
        }
        
        .tab-buttons {
            display: flex;
            background: #e9ecef;
            border-radius: 8px 8px 0 0;
        }
        
        .tab-button {
            flex: 1;
            padding: 12px;
            background: transparent;
            border: none;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .tab-button:first-child {
            border-radius: 8px 0 0 0;
        }
        
        .tab-button:last-child {
            border-radius: 0 8px 0 0;
        }
        
        .tab-button.active {
            background: white;
            border-bottom: 2px solid #007bff;
        }
        
        .tab-content {
            background: white;
            border: 1px solid #dee2e6;
            border-top: none;
            border-radius: 0 0 8px 8px;
            padding: 20px;
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔄 Encoding Transformations 취약점 테스트</h1>
        
        <div class="vulnerability-status <?php echo $vulnerability_enabled ? 'vulnerability-enabled' : 'vulnerability-disabled'; ?>">
            상태: <?php echo $vulnerability_enabled ? '취약한 입력 검증 (인코딩 우회 가능)' : '안전한 입력 검증 (디코딩 후 검증)'; ?>
        </div>
        
        <div class="description">
            <h2>📋 Encoding Transformations 취약점이란?</h2>
            <p><strong>Encoding Transformations 취약점</strong>은 문자 인코딩 변환 과정에서 입력 검증 필터를 우회하여 악성 코드를 실행하는 취약점입니다.</p>
            
            <h3>주요 공격 기법</h3>
            <ul>
                <li><strong>Double Encoding</strong>: 이중 인코딩으로 필터 우회</li>
                <li><strong>Mixed Encoding</strong>: 여러 인코딩 방식 조합</li>
                <li><strong>Unicode Normalization</strong>: Unicode 정규화 과정 악용</li>
                <li><strong>Charset Confusion</strong>: 문자셋 변환 과정 조작</li>
                <li><strong>Overlong UTF-8</strong>: 비표준 UTF-8 인코딩 사용</li>
            </ul>
            
            <h3>우회 가능한 필터</h3>
            <ul>
                <li>XSS 방어 필터 (스크립트 태그 탐지)</li>
                <li>SQL 인젝션 필터 (키워드 기반 차단)</li>
                <li>경로 순회 필터 (../  패턴 차단)</li>
                <li>명령어 인젝션 필터 (특수문자 차단)</li>
            </ul>
            
            <h3>방어 방법</h3>
            <ul>
                <li>정규화 후 검증 (Decode-then-Validate)</li>
                <li>화이트리스트 기반 입력 검증</li>
                <li>출력 시점 이스케이핑</li>
                <li>Content-Type 헤더 명시</li>
                <li>입력 길이 및 형식 제한</li>
            </ul>
        </div>

        <div class="encoding-simulator">
            <h2>🧪 인코딩 변환 시뮬레이터</h2>
            
            <div class="tab-container">
                <div class="tab-buttons">
                    <button class="tab-button active" onclick="switchTab('manual')">수동 테스트</button>
                    <button class="tab-button" onclick="switchTab('payloads')">페이로드 테스트</button>
                    <button class="tab-button" onclick="switchTab('batch')">일괄 테스트</button>
                </div>
                
                <!-- 수동 테스트 -->
                <div id="manual-tab" class="tab-content active">
                    <h3>수동 인코딩 테스트</h3>
                    <form method="POST" action="">
                        <input type="hidden" name="test_type" value="encoding_test">
                        
                        <div class="form-group">
                            <label for="input">입력 텍스트:</label>
                            <textarea name="input" id="input" placeholder="인코딩할 텍스트를 입력하세요"><?php echo htmlspecialchars($_POST['input'] ?? '<script>alert("XSS")</script>'); ?></textarea>
                        </div>
                        
                        <div class="form-group">
                            <label>적용할 인코딩 방식:</label>
                            <div class="encoding-options">
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="url_encode" id="url_encode" checked>
                                    <label for="url_encode">URL Encoding</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="double_url_encode" id="double_url_encode">
                                    <label for="double_url_encode">Double URL Encoding</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="html_entity" id="html_entity">
                                    <label for="html_entity">HTML Entity</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="html_numeric" id="html_numeric">
                                    <label for="html_numeric">HTML Numeric</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="hex_encode" id="hex_encode">
                                    <label for="hex_encode">Hexadecimal</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="base64" id="base64">
                                    <label for="base64">Base64</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="unicode_escape" id="unicode_escape">
                                    <label for="unicode_escape">Unicode Escape</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="mixed_case" id="mixed_case">
                                    <label for="mixed_case">Mixed Case</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="null_byte" id="null_byte">
                                    <label for="null_byte">Null Byte</label>
                                </div>
                                <div class="encoding-checkbox">
                                    <input type="checkbox" name="encodings[]" value="utf8_overlong" id="utf8_overlong">
                                    <label for="utf8_overlong">UTF-8 Overlong</label>
                                </div>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn">인코딩 변환 및 검증</button>
                    </form>
                </div>
                
                <!-- 페이로드 테스트 -->
                <div id="payloads-tab" class="tab-content">
                    <h3>사전 정의된 페이로드 테스트</h3>
                    
                    <div class="payload-grid">
                        <?php foreach (generateEncodingPayloads() as $payload): ?>
                        <div class="payload-card" onclick="testPayload('<?php echo addslashes($payload['payload']); ?>')">
                            <div class="payload-name"><?php echo htmlspecialchars($payload['name']); ?></div>
                            <div class="payload-value"><?php echo htmlspecialchars($payload['payload']); ?></div>
                            <div class="payload-description"><?php echo htmlspecialchars($payload['description']); ?></div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <!-- 일괄 테스트 -->
                <div id="batch-tab" class="tab-content">
                    <h3>전체 페이로드 일괄 테스트</h3>
                    <p>모든 사전 정의된 페이로드에 대해 입력 검증을 수행합니다.</p>
                    
                    <form method="POST" action="">
                        <input type="hidden" name="test_type" value="batch_test">
                        <button type="submit" class="btn">전체 페이로드 테스트</button>
                    </form>
                </div>
            </div>
            
            <?php if (!empty($test_results)): ?>
                <h3>테스트 결과</h3>
                <?php foreach ($test_results as $result): ?>
                
                    <?php if ($result['type'] === 'encoding_transformation'): ?>
                    <div class="transformation-display">
                        <h4>인코딩 변환 결과</h4>
                        <p><strong>원본 입력:</strong> <code><?php echo htmlspecialchars($result['encoding_result']['original_input']); ?></code></p>
                        
                        <?php foreach ($result['encoding_result']['transformations'] as $name => $value): ?>
                        <div class="transformation-item">
                            <div class="transformation-name"><?php echo htmlspecialchars($name); ?></div>
                            <div class="transformation-value"><?php echo htmlspecialchars($value); ?></div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <div class="validation-result <?php 
                        if ($result['validation_result']['bypassed']) echo 'validation-bypassed';
                        elseif ($result['validation_result']['blocked']) echo 'validation-blocked';
                        else echo 'validation-allowed';
                    ?>">
                        <h4>입력 검증 결과</h4>
                        <p><strong>결과:</strong> <?php echo htmlspecialchars($result['validation_result']['validation_result']); ?></p>
                        <p><strong>우회 여부:</strong> <?php echo $result['validation_result']['bypassed'] ? 'Yes' : 'No'; ?></p>
                        
                        <?php if (!empty($result['validation_result']['detected_attacks'])): ?>
                        <p><strong>탐지된 공격:</strong></p>
                        <ul>
                            <?php foreach ($result['validation_result']['detected_attacks'] as $attack): ?>
                            <li><?php echo htmlspecialchars($attack); ?></li>
                            <?php endforeach; ?>
                        </ul>
                        <?php endif; ?>
                    </div>
                    
                    <?php elseif ($result['type'] === 'validation_test' || $result['type'] === 'batch_validation'): ?>
                    <div class="validation-result <?php 
                        if ($result['validation_result']['bypassed']) echo 'validation-bypassed';
                        elseif ($result['validation_result']['blocked']) echo 'validation-blocked';
                        else echo 'validation-allowed';
                    ?>">
                        <?php if (isset($result['validation_result']['payload_info'])): ?>
                        <h4><?php echo htmlspecialchars($result['validation_result']['payload_info']['name']); ?></h4>
                        <p><strong>페이로드:</strong> <code><?php echo htmlspecialchars($result['validation_result']['payload_info']['payload']); ?></code></p>
                        <p><strong>설명:</strong> <?php echo htmlspecialchars($result['validation_result']['payload_info']['description']); ?></p>
                        <?php else: ?>
                        <h4>검증 결과</h4>
                        <p><strong>입력:</strong> <code><?php echo htmlspecialchars($result['validation_result']['input']); ?></code></p>
                        <?php endif; ?>
                        
                        <p><strong>결과:</strong> <?php echo htmlspecialchars($result['validation_result']['validation_result']); ?></p>
                        <p><strong>우회 여부:</strong> <?php echo $result['validation_result']['bypassed'] ? 'Yes' : 'No'; ?></p>
                        
                        <?php if (!empty($result['validation_result']['detected_attacks'])): ?>
                        <p><strong>탐지된 공격:</strong></p>
                        <ul>
                            <?php foreach ($result['validation_result']['detected_attacks'] as $attack): ?>
                            <li><?php echo htmlspecialchars($attack); ?></li>
                            <?php endforeach; ?>
                        </ul>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>
                    
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="technique-examples">
            <h3>🎯 인코딩 우회 기법</h3>
            <?php foreach ($encoding_techniques as $technique): ?>
            <div class="technique-item">
                <div class="technique-name"><?php echo htmlspecialchars($technique['name']); ?></div>
                <div class="technique-description"><?php echo htmlspecialchars($technique['description']); ?></div>
                <div class="technique-example"><strong>예시:</strong> <?php echo htmlspecialchars($technique['example']); ?></div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="mitigation">
            <h2>🛡️ 완화 방안</h2>
            <div class="code-block">
                <h3>안전한 입력 검증 및 출력 처리</h3>
                <pre><code>// ❌ 위험한 방법: 인코딩된 입력을 그대로 검증
function vulnerableInputValidation($input) {
    // 기본적인 패턴만 확인
    if (strpos($input, '<script>') !== false) {
        return false; // 차단
    }
    return true; // 허용
}

// URL 인코딩된 <script> 태그는 우회됨
// %3Cscript%3E는 탐지되지 않음

// ✅ 안전한 방법: 다중 디코딩 후 검증
function secureInputValidation($input) {
    $decoded = $input;
    
    // 최대 3번까지 디코딩 시도
    for ($i = 0; $i < 3; $i++) {
        $previous = $decoded;
        
        // URL 디코딩
        $decoded = urldecode($decoded);
        
        // HTML 엔티티 디코딩
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // 변화가 없으면 중단
        if ($previous === $decoded) {
            break;
        }
    }
    
    // 디코딩된 입력에 대해 검증
    $dangerous_patterns = [
        '/<script\b/i',
        '/on\w+\s*=/i',
        '/javascript:/i',
        '/union\s+select/i',
        '/or\s+1\s*=\s*1/i'
    ];
    
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $decoded)) {
            return false;
        }
    }
    
    return true;
}

// 화이트리스트 기반 검증
function whitelistValidation($input, $allowedChars) {
    $decoded = multiDecode($input);
    
    // 허용된 문자만 포함하는지 확인
    if (preg_match('/^[' . preg_quote($allowedChars, '/') . ']+$/', $decoded)) {
        return true;
    }
    
    return false;
}

// 출력 시점 이스케이핑
function safeOutput($data, $context = 'html') {
    switch ($context) {
        case 'html':
            return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            
        case 'js':
            return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
            
        case 'css':
            return preg_replace('/[^a-zA-Z0-9\s\-_]/', '', $data);
            
        case 'url':
            return urlencode($data);
            
        default:
            return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}

// Content-Type 헤더 명시
function setSecureHeaders() {
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Content-Security-Policy: default-src \'self\'');
}

// 입력 정규화 함수
function normalizeInput($input) {
    // Unicode 정규화
    if (class_exists('Normalizer')) {
        $input = Normalizer::normalize($input, Normalizer::FORM_C);
    }
    
    // 다중 디코딩
    $input = multiDecode($input);
    
    // 제어 문자 제거
    $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);
    
    return $input;
}

function multiDecode($input) {
    $decoded = $input;
    
    for ($i = 0; $i < 5; $i++) {
        $previous = $decoded;
        
        // 여러 디코딩 방식 적용
        $decoded = urldecode($decoded);
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $decoded = rawurldecode($decoded);
        
        if ($previous === $decoded) {
            break;
        }
    }
    
    return $decoded;
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
        function switchTab(tabName) {
            // 모든 탭 버튼과 콘텐츠 비활성화
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // 선택된 탭 활성화
            document.querySelector(`button[onclick="switchTab('${tabName}')"]`).classList.add('active');
            document.getElementById(`${tabName}-tab`).classList.add('active');
        }
        
        function testPayload(payload) {
            // 폼을 동적으로 생성하여 페이로드 테스트
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '';
            
            const testTypeInput = document.createElement('input');
            testTypeInput.type = 'hidden';
            testTypeInput.name = 'test_type';
            testTypeInput.value = 'validation_test';
            
            const payloadInput = document.createElement('input');
            payloadInput.type = 'hidden';
            payloadInput.name = 'payload';
            payloadInput.value = payload;
            
            form.appendChild(testTypeInput);
            form.appendChild(payloadInput);
            document.body.appendChild(form);
            form.submit();
        }
    </script>
</body>
</html>