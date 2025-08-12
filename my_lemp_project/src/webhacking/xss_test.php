<?php
/**
 * XSS (Cross-Site Scripting) 테스트 페이지
 * PayloadsAllTheThings의 XSS 페이로드를 기반으로 구성
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
$error = '';
$test_type = $_POST['test_type'] ?? 'reflected';
$payload = $_POST['payload'] ?? '';
$output = '';

// XSS 페이로드 모음 (PayloadsAllTheThings 기반)
$payloads = [
    'reflected' => [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(1)">',
        '<svg onload="alert(1)">',
        '"><script>alert(1)</script>',
        '\'-alert(1)-\'',
        'javascript:alert(1)',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload="alert(1)">',
        '<input onfocus="alert(1)" autofocus>',
        '<select onfocus="alert(1)" autofocus>'
    ],
    'stored' => [
        '<script>alert("Stored XSS")</script>',
        '<img src="x" onerror="alert(\'Stored\')">',
        '<svg/onload=alert(/Stored/)>',
        '"><script>alert("Stored")</script>',
        '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
        '<object data="data:text/html,<script>alert(1)</script>"></object>'
    ],
    'dom' => [
        'javascript:alert(1)',
        '#<img src=x onerror=alert(1)>',
        'data:text/html,<script>alert(1)</script>',
        '<script>document.write("<img src=x onerror=alert(1)>")</script>',
        '<script>document.location="javascript:alert(1)"</script>'
    ],
    'polyglot' => [
        'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>',
        '"><img src=x onerror=alert(1)//',
        '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
    ],
    'bypass' => [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>al\\u0065rt(1)</script>',
        '<script>eval("\\u0061lert(1)")</script>',
        '<script>window["\\u0061lert"](1)</script>',
        '<script>top["\\u0061lert"](1)</script>',
        '<script>Function("alert(1)")()</script>',
        '<svg><script>alert(1)</script></svg>',
        '<math><script>alert(1)</script></math>',
        '<div onclick="alert(1)">click</div>',
        '<details ontoggle="alert(1)" open>test</details>'
    ]
];

// 테스트 실행
if ($_POST && isset($_POST['payload'])) {
    $safe_payload = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');
    
    switch ($test_type) {
        case 'reflected':
            // Reflected XSS 시뮬레이션 (안전하게 처리됨)
            $output = "입력값: " . $safe_payload;
            $result = "Reflected XSS 테스트가 실행되었습니다. htmlspecialchars()로 인해 스크립트가 무력화되었습니다.";
            break;
            
        case 'stored':
            // Stored XSS 시뮬레이션 (데이터베이스에 저장하지 않고 시뮬레이션만)
            $output = "저장될 데이터: " . $safe_payload;
            $result = "Stored XSS 테스트가 실행되었습니다. 실제로는 데이터베이스에 저장되지 않으며, 저장 시에도 적절한 인코딩이 적용됩니다.";
            break;
            
        case 'dom':
            // DOM-based XSS 시뮬레이션
            $output = "DOM 조작 시뮬레이션: " . $safe_payload;
            $result = "DOM-based XSS 테스트가 실행되었습니다. 서버 측에서 안전하게 처리되었습니다.";
            break;
            
        default:
            $result = "알 수 없는 테스트 유형입니다.";
    }
    
    // 취약한 출력이 어떻게 보일지 시연 (실제로는 실행되지 않음)
    $vulnerable_output = "만약 취약했다면: " . $payload;
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .xss-demo {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .payload-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .payload-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 10px 0;
        }
        
        .payload-btn {
            background: #6c757d;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .payload-btn:hover {
            background: #5a6268;
        }
        
        .test-form {
            background: white;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .result-box {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #155724;
        }
        
        .vulnerable-demo {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #721c24;
        }
        
        .info-box {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #0c5460;
        }
        
        textarea {
            width: 100%;
            min-height: 100px;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
        }
        
        .test-type-selector {
            margin: 15px 0;
        }
        
        .test-type-selector label {
            margin-right: 15px;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>XSS (Cross-Site Scripting) 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>XSS 테스트</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🚨 Cross-Site Scripting (XSS) 테스트</h3>
            <p><strong>XSS</strong>는 웹 애플리케이션에 악성 스크립트를 주입하여 다른 사용자의 브라우저에서 실행시키는 공격입니다.</p>
            <p>이 페이지에서는 Reflected, Stored, DOM-based XSS를 안전한 환경에서 테스트할 수 있습니다.</p>
            <p><strong>참고:</strong> 모든 출력은 안전하게 인코딩되어 실제 스크립트는 실행되지 않습니다.</p>
        </div>

        <!-- Reflected XSS -->
        <div class="payload-section">
            <h3>🔄 Reflected XSS Payloads</h3>
            <p>사용자 입력이 즉시 응답에 반영되는 XSS 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['reflected'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes(htmlspecialchars($p)); ?>', 'reflected')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 25)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Stored XSS -->
        <div class="payload-section">
            <h3>💾 Stored XSS Payloads</h3>
            <p>악성 스크립트가 서버에 저장되어 다른 사용자에게 영향을 주는 XSS 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['stored'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes(htmlspecialchars($p)); ?>', 'stored')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 25)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- DOM-based XSS -->
        <div class="payload-section">
            <h3>🌐 DOM-based XSS Payloads</h3>
            <p>클라이언트 측 JavaScript에서 DOM 조작을 통해 발생하는 XSS 공격입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['dom'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes(htmlspecialchars($p)); ?>', 'dom')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 25)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Polyglot XSS -->
        <div class="payload-section">
            <h3>🔀 Polyglot XSS Payloads</h3>
            <p>다양한 컨텍스트에서 작동하는 범용 XSS 페이로드입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['polyglot'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes(htmlspecialchars($p)); ?>', 'reflected')" title="<?php echo htmlspecialchars($p); ?>">
                        Polyglot <?php echo array_search($p, $payloads['polyglot']) + 1; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Filter Bypass -->
        <div class="payload-section">
            <h3>🚫 Filter Bypass Payloads</h3>
            <p>XSS 필터를 우회하기 위한 다양한 인코딩 및 난독화 기법입니다.</p>
            <div class="payload-buttons">
                <?php foreach ($payloads['bypass'] as $p): ?>
                    <button class="payload-btn" onclick="setPayload('<?php echo addslashes(htmlspecialchars($p)); ?>', 'reflected')" title="<?php echo htmlspecialchars($p); ?>">
                        <?php echo htmlspecialchars(substr($p, 0, 25)) . '...'; ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 XSS 페이로드 테스트</h3>
            
            <div class="test-type-selector">
                <label><input type="radio" name="test_type" value="reflected" <?php echo $test_type === 'reflected' ? 'checked' : ''; ?>> Reflected XSS</label>
                <label><input type="radio" name="test_type" value="stored" <?php echo $test_type === 'stored' ? 'checked' : ''; ?>> Stored XSS</label>
                <label><input type="radio" name="test_type" value="dom" <?php echo $test_type === 'dom' ? 'checked' : ''; ?>> DOM-based XSS</label>
            </div>
            
            <label for="payload">XSS 페이로드:</label>
            <textarea name="payload" id="payload" placeholder="여기에 테스트할 XSS 페이로드를 입력하거나 위의 버튼을 클릭하세요"><?php echo htmlspecialchars($payload); ?></textarea>
            <br><br>
            <button type="submit" class="btn" style="background: #dc3545;">테스트 실행</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <p><?php echo $result; ?></p>
                <?php if ($output): ?>
                    <p><strong>안전한 출력:</strong> <code><?php echo $output; ?></code></p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if (isset($vulnerable_output) && $vulnerable_output): ?>
            <div class="vulnerable-demo">
                <h3>⚠️ 취약한 출력 시뮬레이션</h3>
                <p><strong>주의:</strong> 아래는 취약한 애플리케이션에서 어떻게 보일지를 보여주는 시뮬레이션입니다. 실제로는 실행되지 않습니다.</p>
                <code><?php echo htmlspecialchars($vulnerable_output); ?></code>
            </div>
        <?php endif; ?>

        <!-- XSS 시연 영역 -->
        <div class="xss-demo">
            <h3>🎭 XSS 시연 영역</h3>
            <p>이 영역은 XSS가 어떻게 작동하는지 보여주기 위한 것입니다.</p>
            <div id="demo-area" style="border: 1px dashed #ccc; padding: 10px; min-height: 50px;">
                <em>여기에 안전하게 처리된 출력이 표시됩니다.</em>
            </div>
            <button onclick="demoXSS()" class="btn" style="margin-top: 10px;">안전한 XSS 시연</button>
        </div>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ XSS 방어 방법</h3>
            <ul>
                <li><strong>출력 인코딩:</strong> HTML, JavaScript, CSS, URL 컨텍스트에 적절한 인코딩 사용</li>
                <li><strong>입력 검증:</strong> 사용자 입력을 서버 측에서 검증 및 필터링</li>
                <li><strong>Content Security Policy (CSP):</strong> 스크립트 실행을 제한하는 헤더 설정</li>
                <li><strong>HttpOnly 쿠키:</strong> JavaScript에서 쿠키 접근 차단</li>
                <li><strong>X-XSS-Protection 헤더:</strong> 브라우저의 XSS 필터 활성화</li>
                <li><strong>템플릿 엔진 사용:</strong> 자동 이스케이프 기능이 있는 템플릿 엔진 활용</li>
                <li><strong>정규식 기반 필터링:</strong> 위험한 태그 및 속성 제거</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection" target="_blank">PayloadsAllTheThings - XSS Injection</a></li>
                <li><a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP - Cross-site Scripting (XSS)</a></li>
                <li><a href="https://portswigger.net/web-security/cross-site-scripting" target="_blank">PortSwigger - Cross-site scripting</a></li>
                <li><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP" target="_blank">MDN - Content Security Policy</a></li>
            </ul>
        </div>
    </div>

    <script>
        function setPayload(payload, testType) {
            document.getElementById('payload').value = payload;
            document.querySelector(`input[value="${testType}"]`).checked = true;
        }

        function demoXSS() {
            const demoArea = document.getElementById('demo-area');
            demoArea.innerHTML = '<div style="background: #d4edda; padding: 10px; border-radius: 4px;">' +
                                '<strong>안전한 시연:</strong> 이것은 XSS가 실행되었다면 보였을 내용입니다. ' +
                                '하지만 적절한 보안 조치로 인해 안전하게 처리되었습니다!' +
                                '</div>';
        }

        // 폼 제출 시 확인
        document.querySelector('form').addEventListener('submit', function(e) {
            const confirmed = confirm(
                'XSS 테스트를 실행하시겠습니까?\n' +
                '이 테스트는 교육 목적으로만 사용하세요.'
            );
            
            if (!confirmed) {
                e.preventDefault();
            }
        });

        // 페이로드 길이가 긴 경우 툴팁 표시
        document.querySelectorAll('.payload-btn').forEach(btn => {
            btn.addEventListener('mouseenter', function() {
                if (this.title) {
                    // 툴팁 스타일링은 브라우저 기본값 사용
                }
            });
        });
    </script>
</body>
</html>