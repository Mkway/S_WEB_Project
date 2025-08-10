<?php
/**
 * Open Redirect 취약점 테스트 페이지
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
$redirect_url = '';
$attack_type = 'basic';

// Open Redirect 공격 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['test_redirect'])) {
    $redirect_url = $_POST['redirect_url'] ?? '';
    $attack_type = $_POST['attack_type'] ?? 'basic';
    
    if (empty($redirect_url)) {
        $result = "리다이렉트 URL을 입력해주세요.";
    } else {
        $result = simulateOpenRedirect($redirect_url, $attack_type);
    }
}

function simulateOpenRedirect($url, $type) {
    $response = "[시뮬레이션] Open Redirect 공격 분석\n";
    $response .= "공격 유형: " . strtoupper($type) . "\n";
    $response .= "리다이렉트 URL: " . $url . "\n\n";
    
    // URL 분석
    $parsed_url = parse_url($url);
    $is_external = false;
    $is_dangerous = false;
    $attack_vector = [];
    
    // 외부 도메인 검사
    if (isset($parsed_url['host'])) {
        $host = strtolower($parsed_url['host']);
        $safe_domains = ['example.com', 'test.local', 'localhost', '127.0.0.1'];
        
        if (!in_array($host, $safe_domains)) {
            $is_external = true;
        }
        
        // 악의적 도메인 패턴 검사
        $malicious_patterns = [
            'evil', 'malicious', 'phishing', 'fake', 'scam', 
            'attacker', 'hacker', 'steal', 'credential'
        ];
        
        foreach ($malicious_patterns as $pattern) {
            if (strpos($host, $pattern) !== false) {
                $is_dangerous = true;
                $attack_vector[] = "악의적 도메인명 포함: {$pattern}";
                break;
            }
        }
    }
    
    // 프로토콜 검사
    if (isset($parsed_url['scheme'])) {
        $scheme = strtolower($parsed_url['scheme']);
        if (in_array($scheme, ['javascript', 'data', 'vbscript', 'file'])) {
            $is_dangerous = true;
            $attack_vector[] = "위험한 프로토콜: {$scheme}";
        }
    }
    
    // URL 인코딩 우회 기법 검사
    $encoded_patterns = [
        '%2F%2F' => '//',     // 이중 슬래시
        '%2E%2E' => '..',     // 디렉토리 순회
        '%40' => '@',         // 사용자 정보
        '%3A' => ':',         // 콜론
        '%23' => '#',         // 프래그먼트
    ];
    
    foreach ($encoded_patterns as $encoded => $decoded) {
        if (strpos($url, $encoded) !== false) {
            $attack_vector[] = "URL 인코딩 우회: {$encoded} → {$decoded}";
        }
    }
    
    // IP 주소 변형 검사 (8진수, 16진수, 정수형)
    if (preg_match('/(?:0x[0-9a-f]+|0[0-7]+|\d{8,10})/', $url)) {
        $attack_vector[] = "IP 주소 변형 (8진수/16진수/정수) 사용";
        $is_dangerous = true;
    }
    
    // 결과 분석
    if ($is_dangerous || $is_external) {
        $response .= "🚨 취약점 발견: Open Redirect 공격 가능\n\n";
        
        if ($is_external) {
            $response .= "위험 요소: 외부 도메인으로 리다이렉트\n";
            $response .= "대상 도메인: " . ($parsed_url['host'] ?? 'N/A') . "\n";
        }
        
        if (!empty($attack_vector)) {
            $response .= "감지된 공격 기법:\n";
            foreach ($attack_vector as $vector) {
                $response .= "- " . $vector . "\n";
            }
        }
        
        $response .= "\n공격 시나리오:\n";
        
        switch ($type) {
            case 'phishing':
                $response .= "1. 피싱 공격 시나리오:\n";
                $response .= "   - 신뢰할 수 있는 도메인에서 시작\n";
                $response .= "   - 사용자를 가짜 로그인 페이지로 리다이렉트\n";
                $response .= "   - 사용자 자격 증명 탈취\n";
                $response .= "   예: https://bank.com/redirect?url=https://fake-bank.com/login\n";
                break;
                
            case 'malware':
                $response .= "1. 멀웨어 배포 시나리오:\n";
                $response .= "   - 합법적 사이트를 통한 신뢰성 확보\n";
                $response .= "   - 멀웨어 다운로드 사이트로 리다이렉트\n";
                $response .= "   - 자동 다운로드 트리거\n";
                $response .= "   예: https://trusted.com/go?url=https://malware-site.com/download\n";
                break;
                
            case 'oauth':
                $response .= "1. OAuth 리다이렉트 하이재킹:\n";
                $response .= "   - OAuth 인증 과정 중 리다이렉트 조작\n";
                $response .= "   - Authorization Code 탈취\n";
                $response .= "   - 사용자 계정 접근 권한 획득\n";
                $response .= "   예: /oauth/callback?redirect_uri=https://attacker.com/steal\n";
                break;
                
            case 'bypass':
                $response .= "1. 필터 우회 시나리오:\n";
                $response .= "   - URL 인코딩으로 필터 우회\n";
                $response .= "   - IP 주소 변형으로 도메인 검증 우회\n";
                $response .= "   - 경로 순회로 검증 로직 우회\n";
                if (strpos($url, '//') !== false) {
                    $response .= "   - 이중 슬래시(//): 프로토콜 상대 URL 악용\n";
                }
                break;
                
            default:
                $response .= "1. 기본 Open Redirect 공격:\n";
                $response .= "   - 신뢰할 수 있는 도메인 남용\n";
                $response .= "   - 사용자를 악의적 사이트로 유도\n";
                $response .= "   - 피싱, 멀웨어 배포 등 2차 공격\n";
        }
        
        $response .= "\n실제 리다이렉트 결과:\n";
        if ($is_dangerous) {
            $response .= "❌ 위험: 악의적 사이트로 리다이렉트됨\n";
            $response .= "사용자가 피해를 입을 수 있습니다!";
        } else {
            $response .= "⚠️ 경고: 외부 사이트로 리다이렉트됨\n";
            $response .= "사용자 확인 없이 외부로 이동합니다.";
        }
        
    } else {
        // 안전한 리다이렉트
        $response .= "✅ 안전한 리다이렉트 URL\n";
        $response .= "내부 도메인으로의 리다이렉트입니다.\n";
        $response .= "위험한 패턴이 감지되지 않았습니다.\n\n";
        
        if (isset($parsed_url['path'])) {
            $response .= "리다이렉트 경로: " . $parsed_url['path'] . "\n";
        }
        
        $response .= "예상 동작: 안전한 내부 페이지로 이동";
    }
    
    return $response;
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Open Redirect 테스트 - <?php echo SITE_NAME; ?></title>
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
        input[type="url"], input[type="text"], select {
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
        .redirect-demo {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .attack-examples {
            background: #ffebee;
            border: 1px solid #ef5350;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .url-preview {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>Open Redirect 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="index.php" class="btn">웹해킹 메뉴</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <div class="vulnerability-description">
            <h2>🔀 Open Redirect 취약점</h2>
            <p><strong>설명:</strong> 사용자 입력을 통해 리다이렉트 URL을 조작할 수 있는 취약점입니다. 
            신뢰할 수 있는 도메인을 악용하여 사용자를 악의적인 사이트로 유도하는 피싱 공격에 주로 사용됩니다.</p>
            
            <div class="redirect-demo">
                <h4>🎯 Open Redirect 작동 원리</h4>
                <p><strong>1. 정상적인 리다이렉트:</strong> <code>https://site.com/redirect?url=https://site.com/dashboard</code></p>
                <p><strong>2. 악의적 리다이렉트:</strong> <code>https://site.com/redirect?url=https://evil-site.com</code></p>
                <p><strong>3. 사용자 관점:</strong> 신뢰할 수 있는 site.com에서 시작하여 악의적 사이트로 이동</p>
                <p><strong>4. 피해:</strong> 피싱, 멀웨어 다운로드, OAuth 토큰 탈취 등</p>
            </div>
            
            <h3>📋 공격 시나리오별 테스트:</h3>
            <div style="margin: 10px 0;">
                <button onclick="testRedirect('basic', 'https://evil-site.com')" class="payload-btn">기본 공격</button>
                <button onclick="testRedirect('phishing', 'https://fake-bank.com/login')" class="payload-btn">피싱 공격</button>
                <button onclick="testRedirect('malware', 'https://malware-download.com')" class="payload-btn">멀웨어 배포</button>
                <button onclick="testRedirect('oauth', 'https://attacker.com/oauth')" class="payload-btn">OAuth 하이재킹</button>
                <button onclick="testRedirect('bypass', '//evil.com')" class="payload-btn">필터 우회</button>
                <button onclick="testRedirect('safe', 'https://example.com/safe')" class="payload-btn">안전한 URL</button>
            </div>
        </div>

        <form method="POST">
            <label for="attack_type">🎯 공격 유형 선택:</label>
            <select id="attack_type" name="attack_type">
                <option value="basic" <?php echo ($attack_type == 'basic') ? 'selected' : ''; ?>>Basic Redirect</option>
                <option value="phishing" <?php echo ($attack_type == 'phishing') ? 'selected' : ''; ?>>Phishing Attack</option>
                <option value="malware" <?php echo ($attack_type == 'malware') ? 'selected' : ''; ?>>Malware Distribution</option>
                <option value="oauth" <?php echo ($attack_type == 'oauth') ? 'selected' : ''; ?>>OAuth Hijacking</option>
                <option value="bypass" <?php echo ($attack_type == 'bypass') ? 'selected' : ''; ?>>Filter Bypass</option>
            </select><br><br>
            
            <label for="redirect_url">🌐 리다이렉트 URL 입력:</label>
            <input type="text" id="redirect_url" name="redirect_url" value="<?php echo htmlspecialchars($redirect_url); ?>" 
                   placeholder="예: https://evil-site.com 또는 //attacker.com"><br><br>
            
            <div class="url-preview" id="url_preview">
                URL 미리보기: <span id="preview_text">URL을 입력하면 여기에 표시됩니다.</span>
            </div>
            
            <input type="hidden" name="test_redirect" value="1">
            <input type="submit" value="Open Redirect 테스트" class="btn">
        </form>

        <?php if (!empty($result)): ?>
            <div style="margin-top: 20px;">
                <h2>📊 테스트 결과:</h2>
                <pre style="background: #f1f3f4; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545;"><?php echo htmlspecialchars($result); ?></pre>
            </div>
        <?php endif; ?>

        <div class="attack-examples">
            <h4>⚠️ Open Redirect 공격 기법</h4>
            <p><strong>1. 기본 공격:</strong> <code>?redirect=https://evil.com</code></p>
            <p><strong>2. 프로토콜 상대 URL:</strong> <code>?redirect=//evil.com</code></p>
            <p><strong>3. URL 인코딩:</strong> <code>?redirect=https%3A%2F%2Fevil.com</code></p>
            <p><strong>4. IP 주소 변형:</strong> <code>?redirect=http://0x7f000001</code> (127.0.0.1)</p>
            <p><strong>5. 서브도메인 스푸핑:</strong> <code>?redirect=https://legitimate.evil.com</code></p>
            <p><strong>6. 경로 조작:</strong> <code>?redirect=../../../evil.com</code></p>
            <p><strong>7. JavaScript 프로토콜:</strong> <code>?redirect=javascript:alert('XSS')</code></p>
            <p><strong>8. Data URI:</strong> <code>?redirect=data:text/html,&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
        </div>

        <div class="mitigation-guide">
            <h2>🛡️ 방어 방법</h2>
            <ul>
                <li><strong>화이트리스트 검증:</strong> 허용된 도메인/경로만 리다이렉트 허용</li>
                <li><strong>절대 URL 금지:</strong> 상대 경로만 허용하거나 도메인 검증 필수</li>
                <li><strong>URL 파싱:</strong> parse_url() 등으로 URL 구성 요소 검증</li>
                <li><strong>프로토콜 제한:</strong> HTTP/HTTPS만 허용, javascript:, data: 등 차단</li>
                <li><strong>사용자 확인:</strong> 외부 리다이렉트 시 경고 메시지 표시</li>
                <li><strong>토큰 검증:</strong> 리다이렉트 URL에 서명된 토큰 포함</li>
                <li><strong>Referrer 검증:</strong> 요청 출처 확인</li>
                <li><strong>Rate Limiting:</strong> 리다이렉트 요청 빈도 제한</li>
            </ul>
            
            <h4>🔧 안전한 리다이렉트 구현 예제:</h4>
            <pre style="background: #e8f5e8; padding: 10px; border-radius: 4px; font-size: 12px;">
// PHP 안전한 리다이렉트 구현
function safeRedirect($url) {
    // 화이트리스트 검증
    $allowed_hosts = ['example.com', 'api.example.com'];
    
    $parsed = parse_url($url);
    
    // 호스트 검증
    if (!isset($parsed['host']) || !in_array($parsed['host'], $allowed_hosts)) {
        return false;
    }
    
    // 프로토콜 검증
    if (isset($parsed['scheme']) && !in_array($parsed['scheme'], ['http', 'https'])) {
        return false;
    }
    
    // 상대 URL 처리
    if (strpos($url, '/') === 0 && strpos($url, '//') !== 0) {
        header('Location: ' . $url);
        return true;
    }
    
    return false;
}
            </pre>
        </div>

        <div style="margin-top: 20px; text-align: center;">
            <a href="index.php" class="btn">← 웹해킹 테스트 메뉴로 돌아가기</a>
        </div>
    </div>

    <script>
        function testRedirect(type, url) {
            if (confirm('⚠️ 교육 목적의 Open Redirect 테스트를 실행하시겠습니까?\n\n유형: ' + type + '\nURL: ' + url)) {
                document.getElementById('attack_type').value = type;
                document.getElementById('redirect_url').value = url;
                updatePreview();
            }
        }

        function updatePreview() {
            const url = document.getElementById('redirect_url').value;
            const previewText = document.getElementById('preview_text');
            
            if (url) {
                previewText.textContent = url;
                previewText.style.color = '#333';
            } else {
                previewText.textContent = 'URL을 입력하면 여기에 표시됩니다.';
                previewText.style.color = '#999';
            }
        }

        // 실시간 URL 미리보기
        document.getElementById('redirect_url').addEventListener('input', updatePreview);

        // 위험 패턴 경고
        document.getElementById('redirect_url').addEventListener('input', function() {
            const value = this.value.toLowerCase();
            const warningPatterns = [
                '//', 'javascript:', 'data:', 'vbscript:', 
                'evil', 'malicious', 'phishing', 'fake', 
                '0x', '%2f%2f', '%3a%2f%2f'
            ];
            
            let isRisky = warningPatterns.some(pattern => value.includes(pattern));
            
            if (isRisky) {
                this.style.borderColor = '#dc3545';
                this.style.backgroundColor = '#fff5f5';
            } else if (value.includes('http') && !value.includes('example.com') && !value.includes('localhost')) {
                this.style.borderColor = '#ffc107';
                this.style.backgroundColor = '#fffbf0';
            } else {
                this.style.borderColor = '#ddd';
                this.style.backgroundColor = 'white';
            }
        });

        // URL 분석 도구
        function analyzeUrl() {
            const url = document.getElementById('redirect_url').value;
            if (!url) {
                alert('URL을 먼저 입력해주세요.');
                return;
            }

            try {
                const urlObj = new URL(url);
                let analysis = `URL 분석 결과:\n\n`;
                analysis += `프로토콜: ${urlObj.protocol}\n`;
                analysis += `호스트: ${urlObj.hostname}\n`;
                analysis += `포트: ${urlObj.port || '기본값'}\n`;
                analysis += `경로: ${urlObj.pathname}\n`;
                analysis += `쿼리: ${urlObj.search}\n`;
                analysis += `프래그먼트: ${urlObj.hash}\n\n`;
                
                // 위험도 평가
                const dangerousProtocols = ['javascript', 'data', 'vbscript', 'file'];
                const suspiciousWords = ['evil', 'malicious', 'phishing', 'fake', 'scam'];
                
                let riskLevel = '낮음';
                let risks = [];
                
                if (dangerousProtocols.includes(urlObj.protocol.replace(':', ''))) {
                    risks.push('위험한 프로토콜 사용');
                    riskLevel = '높음';
                }
                
                if (suspiciousWords.some(word => urlObj.hostname.includes(word))) {
                    risks.push('의심스러운 도메인명');
                    riskLevel = '높음';
                }
                
                if (urlObj.hostname !== 'example.com' && urlObj.hostname !== 'localhost' && urlObj.hostname !== '127.0.0.1') {
                    risks.push('외부 도메인');
                    if (riskLevel === '낮음') riskLevel = '중간';
                }
                
                analysis += `위험도: ${riskLevel}\n`;
                if (risks.length > 0) {
                    analysis += `위험 요소: ${risks.join(', ')}`;
                }
                
                alert(analysis);
                
            } catch (e) {
                alert('유효하지 않은 URL 형식입니다.\n\n상대 경로나 프로토콜 상대 URL(//)의 경우 정확한 분석이 어려울 수 있습니다.');
            }
        }

        // URL 분석 버튼 추가
        document.addEventListener('DOMContentLoaded', function() {
            const analyzeBtn = document.createElement('button');
            analyzeBtn.textContent = 'URL 분석';
            analyzeBtn.type = 'button';
            analyzeBtn.className = 'btn';
            analyzeBtn.style.marginLeft = '10px';
            analyzeBtn.onclick = analyzeUrl;
            
            const submitBtn = document.querySelector('input[type="submit"]');
            submitBtn.parentNode.insertBefore(analyzeBtn, submitBtn.nextSibling);
        });
    </script>
</body>
</html>