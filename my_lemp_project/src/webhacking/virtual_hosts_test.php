<?php
require_once '../config.php';
require_once '../db.php';

$vulnerability_enabled = isVulnerabilityEnabled('virtual_hosts', $_GET);

// 모의 가상 호스트 설정
$virtual_hosts_config = [
    'production' => [
        'domain' => 'example.com',
        'document_root' => '/var/www/production',
        'ssl_enabled' => true,
        'access_level' => 'public',
        'admin_panel' => false,
        'debug_mode' => false,
        'server_info' => false
    ],
    'staging' => [
        'domain' => 'staging.example.com',
        'document_root' => '/var/www/staging',
        'ssl_enabled' => true,
        'access_level' => 'restricted',
        'admin_panel' => true,
        'debug_mode' => true,
        'server_info' => true
    ],
    'development' => [
        'domain' => 'dev.example.com',
        'document_root' => '/var/www/development',
        'ssl_enabled' => false,
        'access_level' => 'internal',
        'admin_panel' => true,
        'debug_mode' => true,
        'server_info' => true
    ],
    'admin' => [
        'domain' => 'admin.example.com',
        'document_root' => '/var/www/admin',
        'ssl_enabled' => true,
        'access_level' => 'admin_only',
        'admin_panel' => true,
        'debug_mode' => false,
        'server_info' => true
    ],
    'backup' => [
        'domain' => 'backup.example.com',
        'document_root' => '/var/www/backup',
        'ssl_enabled' => false,
        'access_level' => 'internal',
        'admin_panel' => false,
        'debug_mode' => true,
        'server_info' => true
    ]
];

function simulateVirtualHost($host_header, $vulnerable = false) {
    global $virtual_hosts_config;
    
    $result = [
        'requested_host' => $host_header,
        'matched_vhost' => null,
        'response_data' => [],
        'security_issues' => [],
        'exposed_info' => []
    ];
    
    // 기본 호스트 매칭 로직
    $matched_config = null;
    $matched_name = 'production'; // 기본값
    
    foreach ($virtual_hosts_config as $name => $config) {
        if ($config['domain'] === $host_header) {
            $matched_config = $config;
            $matched_name = $name;
            break;
        }
    }
    
    if ($vulnerable) {
        // 취약한 설정: Host 헤더 검증 없이 처리
        
        // 1. 잘못된 Host 헤더로 내부 호스트 접근 시도
        if (!$matched_config) {
            // 기본 호스트로 폴백하거나 첫 번째 설정 사용
            $matched_config = $virtual_hosts_config['development']; // 개발 환경 노출
            $matched_name = 'development';
            $result['security_issues'][] = "Invalid Host header defaulted to development environment";
        }
        
        // 2. 내부 호스트명으로 접근 허용
        $internal_hosts = ['localhost', '127.0.0.1', 'internal.local', 'dev.local'];
        if (in_array($host_header, $internal_hosts)) {
            $matched_config = $virtual_hosts_config['development'];
            $matched_name = 'development';
            $result['security_issues'][] = "Internal host access allowed: $host_header";
        }
        
        // 3. 와일드카드 호스트명 처리 취약점
        if (strpos($host_header, '.example.com') !== false) {
            $subdomain = explode('.', $host_header)[0];
            if (isset($virtual_hosts_config[$subdomain])) {
                $matched_config = $virtual_hosts_config[$subdomain];
                $matched_name = $subdomain;
            } else {
                // 존재하지 않는 서브도메인도 개발 환경으로 처리
                $matched_config = $virtual_hosts_config['development'];
                $matched_name = 'development';
                $result['security_issues'][] = "Unknown subdomain defaulted to development: $subdomain";
            }
        }
        
        // 4. Host 헤더 조작으로 관리자 패널 접근
        if (strpos($host_header, 'admin') !== false) {
            $matched_config = $virtual_hosts_config['admin'];
            $matched_name = 'admin';
            $result['security_issues'][] = "Admin panel accessed via Host header manipulation";
        }
        
    } else {
        // 안전한 설정: 엄격한 Host 헤더 검증
        
        if (!$matched_config) {
            // 허용되지 않은 Host 헤더는 차단
            $result['response_data'] = [
                'error' => 'Invalid Host header',
                'status_code' => 400,
                'message' => 'The requested host is not allowed'
            ];
            return $result;
        }
        
        // IP 주소나 내부 호스트명 차단
        if (filter_var($host_header, FILTER_VALIDATE_IP) || 
            in_array($host_header, ['localhost', 'internal.local', 'dev.local'])) {
            $result['response_data'] = [
                'error' => 'Direct IP/internal access blocked',
                'status_code' => 403,
                'message' => 'Access via IP address or internal hostname is not allowed'
            ];
            return $result;
        }
    }
    
    $result['matched_vhost'] = $matched_name;
    
    // 매칭된 가상 호스트 설정에 따른 응답 생성
    $response = [
        'host' => $matched_config['domain'],
        'environment' => $matched_name,
        'ssl_required' => $matched_config['ssl_enabled']
    ];
    
    // 접근 수준에 따른 정보 노출
    if ($matched_config['access_level'] === 'public') {
        $response['content'] = 'Welcome to our production website!';
        
    } elseif ($matched_config['access_level'] === 'restricted') {
        $response['content'] = 'Staging environment - Limited access';
        if ($vulnerable || $matched_config['debug_mode']) {
            $response['debug_info'] = [
                'database' => 'staging_db',
                'cache_enabled' => true,
                'api_endpoints' => ['/api/v1/users', '/api/v1/orders']
            ];
            $result['exposed_info'][] = 'debug_info';
        }
        
    } elseif ($matched_config['access_level'] === 'internal') {
        $response['content'] = 'Internal development environment';
        if ($vulnerable || $matched_config['debug_mode']) {
            $response['debug_info'] = [
                'database' => 'dev_db',
                'database_password' => 'dev_password_123',
                'api_keys' => [
                    'stripe_test' => 'sk_test_123456789',
                    'mailgun' => 'key-abcdef123456'
                ],
                'internal_urls' => [
                    'phpmyadmin' => 'http://dev.example.com/phpmyadmin',
                    'adminer' => 'http://dev.example.com/adminer'
                ]
            ];
            $result['exposed_info'][] = 'sensitive_credentials';
            $result['security_issues'][] = "Development environment credentials exposed";
        }
        
    } elseif ($matched_config['access_level'] === 'admin_only') {
        if ($vulnerable) {
            $response['content'] = 'Administrative panel access granted';
            $response['admin_functions'] = [
                'user_management' => '/admin/users',
                'system_config' => '/admin/config',
                'database_admin' => '/admin/db',
                'log_viewer' => '/admin/logs'
            ];
            $result['exposed_info'][] = 'admin_functions';
            $result['security_issues'][] = "Administrative functions exposed without authentication";
        } else {
            $response['error'] = 'Authentication required';
            $response['status_code'] = 401;
        }
    }
    
    // 서버 정보 노출
    if ($matched_config['server_info'] && ($vulnerable || $matched_config['debug_mode'])) {
        $response['server_info'] = [
            'server_software' => 'Apache/2.4.41 (Ubuntu)',
            'php_version' => '7.4.3',
            'document_root' => $matched_config['document_root'],
            'server_admin' => 'admin@example.com',
            'modules' => ['mod_rewrite', 'mod_ssl', 'mod_php'],
            'config_files' => [
                'apache_config' => '/etc/apache2/sites-available/' . $matched_name . '.conf',
                'php_config' => '/etc/php/7.4/apache2/php.ini'
            ]
        ];
        $result['exposed_info'][] = 'server_info';
    }
    
    $result['response_data'] = $response;
    
    return $result;
}

function generateHostHeaderPayloads() {
    return [
        [
            'name' => 'Production Host',
            'host' => 'example.com',
            'description' => '정상적인 프로덕션 호스트 접근'
        ],
        [
            'name' => 'Staging Access',
            'host' => 'staging.example.com',
            'description' => '스테이징 환경 접근 시도'
        ],
        [
            'name' => 'Development Bypass',
            'host' => 'dev.example.com',
            'description' => '개발 환경 직접 접근'
        ],
        [
            'name' => 'Admin Panel Access',
            'host' => 'admin.example.com',
            'description' => 'Host 헤더 조작으로 관리자 패널 접근'
        ],
        [
            'name' => 'Localhost Bypass',
            'host' => 'localhost',
            'description' => 'localhost로 내부 접근 시도'
        ],
        [
            'name' => 'IP Address Access',
            'host' => '127.0.0.1',
            'description' => 'IP 주소로 직접 접근'
        ],
        [
            'name' => 'Internal Host',
            'host' => 'internal.local',
            'description' => '내부 호스트명으로 접근'
        ],
        [
            'name' => 'Wildcard Subdomain',
            'host' => 'test.example.com',
            'description' => '존재하지 않는 서브도메인 접근'
        ],
        [
            'name' => 'Backup Server',
            'host' => 'backup.example.com',
            'description' => '백업 서버 접근 시도'
        ],
        [
            'name' => 'Invalid Host',
            'host' => 'malicious.com',
            'description' => '완전히 다른 도메인으로 접근'
        ]
    ];
}

$test_results = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    
    if ($test_type === 'host_header_test') {
        $host_header = $_POST['host_header'] ?? '';
        
        if (!empty($host_header)) {
            $result = simulateVirtualHost($host_header, $vulnerability_enabled);
            $test_results[] = $result;
        }
    } elseif ($test_type === 'batch_test') {
        $payloads = generateHostHeaderPayloads();
        
        foreach ($payloads as $payload) {
            $result = simulateVirtualHost($payload['host'], $vulnerability_enabled);
            $result['payload_info'] = $payload;
            $test_results[] = $result;
        }
    }
}

$vhost_vulnerabilities = [
    [
        'name' => 'Host Header Injection',
        'description' => '잘못된 Host 헤더 검증으로 내부 시스템 접근',
        'impact' => '개발/스테이징 환경 노출, 관리자 패널 접근'
    ],
    [
        'name' => 'Default VHost Fallback',
        'description' => '매칭되지 않는 호스트 요청 시 기본 호스트로 폴백',
        'impact' => '의도하지 않은 애플리케이션 접근'
    ],
    [
        'name' => 'Internal Hostname Access',
        'description' => 'localhost, 내부 IP 등으로 직접 접근 허용',
        'impact' => '방화벽 우회, 내부 서비스 노출'
    ],
    [
        'name' => 'Information Disclosure',
        'description' => '개발 환경에서 디버그 정보, 서버 설정 노출',
        'impact' => '민감한 설정 정보, 데이터베이스 크리덴셜 노출'
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Virtual Hosts 취약점 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .vhost-simulator {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .vhost-config {
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .config-item {
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
        }
        
        .config-name {
            font-weight: bold;
            color: #1976d2;
            margin-bottom: 8px;
        }
        
        .config-detail {
            font-size: 0.9em;
            margin: 3px 0;
        }
        
        .config-detail .label {
            font-weight: bold;
            color: #666;
        }
        
        .config-detail .value {
            color: #333;
        }
        
        .test-controls {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .result-display {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            font-family: monospace;
        }
        
        .result-safe {
            border-color: #28a745;
            background: #d4edda;
        }
        
        .result-vulnerable {
            border-color: #dc3545;
            background: #f8d7da;
        }
        
        .result-warning {
            border-color: #ffc107;
            background: #fff3cd;
        }
        
        .security-issues {
            background: #ffebee;
            border: 1px solid #f44336;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .issue-item {
            color: #d32f2f;
            margin: 5px 0;
            font-weight: bold;
        }
        
        .exposed-info {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .info-tag {
            display: inline-block;
            background: #ff9800;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            margin: 2px;
            font-size: 0.8em;
        }
        
        .payload-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        
        .payload-button {
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            cursor: pointer;
            transition: all 0.3s;
            text-align: left;
        }
        
        .payload-button:hover {
            background: #e9ecef;
            border-color: #007bff;
        }
        
        .payload-name {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }
        
        .payload-host {
            font-family: monospace;
            background: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
            margin: 3px 0;
        }
        
        .payload-desc {
            font-size: 0.8em;
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
        
        .form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            font-family: monospace;
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
        
        .vulnerability-examples {
            background: #fff3e0;
            border: 1px solid #ffb74d;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }
        
        .vuln-item {
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .vuln-name {
            font-weight: bold;
            color: #d32f2f;
            margin-bottom: 5px;
        }
        
        .vuln-description {
            font-size: 0.9em;
            color: #666;
            margin: 5px 0;
        }
        
        .vuln-impact {
            font-size: 0.9em;
            color: #d32f2f;
            font-style: italic;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Virtual Hosts 취약점 테스트</h1>
        
        <div class="vulnerability-status <?php echo $vulnerability_enabled ? 'vulnerability-enabled' : 'vulnerability-disabled'; ?>">
            상태: <?php echo $vulnerability_enabled ? '취약한 가상 호스트 설정 (Host 헤더 검증 없음)' : '안전한 가상 호스트 설정 (엄격한 검증)'; ?>
        </div>
        
        <div class="description">
            <h2>📋 Virtual Hosts 취약점이란?</h2>
            <p><strong>Virtual Hosts 취약점</strong>은 웹 서버의 가상 호스트 설정 오류로 인해 의도하지 않은 애플리케이션이나 관리 인터페이스에 접근할 수 있는 취약점입니다.</p>
            
            <h3>공격 유형</h3>
            <ul>
                <li><strong>Host Header Injection</strong>: HTTP Host 헤더 조작으로 다른 가상 호스트 접근</li>
                <li><strong>Default VHost Abuse</strong>: 기본 가상 호스트로 폴백하여 내부 애플리케이션 접근</li>
                <li><strong>Internal Hostname Access</strong>: localhost, 내부 IP 등으로 방화벽 우회</li>
                <li><strong>Subdomain Enumeration</strong>: 와일드카드 설정을 악용한 서브도메인 탐지</li>
            </ul>
            
            <h3>노출 위험</h3>
            <ul>
                <li>개발/스테이징 환경의 민감한 정보</li>
                <li>관리자 패널 및 디버그 인터페이스</li>
                <li>데이터베이스 크리덴셜 및 API 키</li>
                <li>서버 설정 정보 및 내부 경로</li>
                <li>백업 시스템 및 내부 도구</li>
            </ul>
            
            <h3>방어 방법</h3>
            <ul>
                <li>엄격한 Host 헤더 검증</li>
                <li>화이트리스트 기반 도메인 허용</li>
                <li>내부 호스트명/IP 접근 차단</li>
                <li>개발 환경 외부 노출 금지</li>
                <li>기본 가상 호스트 비활성화</li>
            </ul>
        </div>

        <div class="vhost-config">
            <h2>🏗️ 가상 호스트 설정 현황</h2>
            <div class="config-grid">
                <?php foreach ($virtual_hosts_config as $name => $config): ?>
                <div class="config-item">
                    <div class="config-name"><?php echo ucfirst($name); ?></div>
                    <div class="config-detail">
                        <span class="label">도메인:</span> 
                        <span class="value"><?php echo htmlspecialchars($config['domain']); ?></span>
                    </div>
                    <div class="config-detail">
                        <span class="label">경로:</span> 
                        <span class="value"><?php echo htmlspecialchars($config['document_root']); ?></span>
                    </div>
                    <div class="config-detail">
                        <span class="label">접근 수준:</span> 
                        <span class="value"><?php echo htmlspecialchars($config['access_level']); ?></span>
                    </div>
                    <div class="config-detail">
                        <span class="label">SSL:</span> 
                        <span class="value"><?php echo $config['ssl_enabled'] ? 'Yes' : 'No'; ?></span>
                    </div>
                    <div class="config-detail">
                        <span class="label">관리 패널:</span> 
                        <span class="value"><?php echo $config['admin_panel'] ? 'Yes' : 'No'; ?></span>
                    </div>
                    <div class="config-detail">
                        <span class="label">디버그:</span> 
                        <span class="value"><?php echo $config['debug_mode'] ? 'Yes' : 'No'; ?></span>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="vhost-simulator">
            <h2>🧪 Host 헤더 조작 테스트</h2>
            
            <div class="test-controls">
                <h3>수동 Host 헤더 테스트</h3>
                <form method="POST" action="">
                    <input type="hidden" name="test_type" value="host_header_test">
                    
                    <div class="form-group">
                        <label for="host_header">Host 헤더 값:</label>
                        <input type="text" name="host_header" id="host_header" 
                               value="<?php echo htmlspecialchars($_POST['host_header'] ?? 'example.com'); ?>" 
                               placeholder="접근하려는 호스트명 입력">
                    </div>
                    
                    <div class="btn-group">
                        <button type="submit" class="btn">Host 헤더 테스트</button>
                        <button type="submit" name="test_type" value="batch_test" class="btn-secondary">전체 페이로드 테스트</button>
                    </div>
                </form>
                
                <h3>빠른 페이로드 선택</h3>
                <div class="payload-grid">
                    <?php foreach (generateHostHeaderPayloads() as $payload): ?>
                    <div class="payload-button" onclick="setHostHeader('<?php echo addslashes($payload['host']); ?>')">
                        <div class="payload-name"><?php echo htmlspecialchars($payload['name']); ?></div>
                        <div class="payload-host"><?php echo htmlspecialchars($payload['host']); ?></div>
                        <div class="payload-desc"><?php echo htmlspecialchars($payload['description']); ?></div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
            
            <?php if (!empty($test_results)): ?>
                <h3>테스트 결과</h3>
                <?php foreach ($test_results as $result): ?>
                <div class="result-display <?php 
                    if (!empty($result['security_issues'])) echo 'result-vulnerable';
                    elseif (isset($result['response_data']['error'])) echo 'result-warning';
                    else echo 'result-safe';
                ?>">
                    <?php if (isset($result['payload_info'])): ?>
                    <h4><?php echo htmlspecialchars($result['payload_info']['name']); ?></h4>
                    <p><strong>설명:</strong> <?php echo htmlspecialchars($result['payload_info']['description']); ?></p>
                    <?php endif; ?>
                    
                    <p><strong>요청 Host:</strong> <code><?php echo htmlspecialchars($result['requested_host']); ?></code></p>
                    <p><strong>매칭된 VHost:</strong> <?php echo htmlspecialchars($result['matched_vhost'] ?? 'None'); ?></p>
                    
                    <?php if (!empty($result['security_issues'])): ?>
                    <div class="security-issues">
                        <strong>🚨 보안 이슈:</strong>
                        <?php foreach ($result['security_issues'] as $issue): ?>
                        <div class="issue-item"><?php echo htmlspecialchars($issue); ?></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    
                    <?php if (!empty($result['exposed_info'])): ?>
                    <div class="exposed-info">
                        <strong>🔓 노출된 정보:</strong><br>
                        <?php foreach ($result['exposed_info'] as $info): ?>
                        <span class="info-tag"><?php echo htmlspecialchars($info); ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    
                    <details style="margin-top: 15px;">
                        <summary><strong>응답 데이터</strong></summary>
                        <pre style="margin-top: 10px; white-space: pre-wrap; background: #f5f5f5; padding: 10px; border-radius: 3px;"><?php echo htmlspecialchars(json_encode($result['response_data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                    </details>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="vulnerability-examples">
            <h3>🎯 Virtual Hosts 취약점 시나리오</h3>
            <?php foreach ($vhost_vulnerabilities as $vuln): ?>
            <div class="vuln-item">
                <div class="vuln-name"><?php echo htmlspecialchars($vuln['name']); ?></div>
                <div class="vuln-description"><?php echo htmlspecialchars($vuln['description']); ?></div>
                <div class="vuln-impact"><strong>영향:</strong> <?php echo htmlspecialchars($vuln['impact']); ?></div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="mitigation">
            <h2>🛡️ 완화 방안</h2>
            <div class="code-block">
                <h3>안전한 Virtual Hosts 설정</h3>
                <pre><code># Apache Virtual Host 안전 설정
# /etc/apache2/sites-available/secure.conf

# ❌ 위험한 기본 설정
&lt;VirtualHost *:80&gt;
    # ServerName이 없으면 첫 번째 VHost가 기본값이 됨
    DocumentRoot /var/www/html
&lt;/VirtualHost&gt;

# ✅ 안전한 설정 - 명시적 기본 호스트
&lt;VirtualHost *:80&gt;
    ServerName _default_
    DocumentRoot /var/www/default
    # 기본 호스트는 에러 페이지만 제공
    RedirectMatch 404 ^/.*$
&lt;/VirtualHost&gt;

# 프로덕션 호스트 - 엄격한 설정
&lt;VirtualHost *:80&gt;
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/production
    
    # Host 헤더 검증
    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^(example\.com|www\.example\.com)$ [NC]
    RewriteRule ^(.*)$ - [F,L]
    
    # 내부 경로 차단
    &lt;Directory "/var/www/production"&gt;
        AllowOverride None
        Require all granted
    &lt;/Directory&gt;
&lt;/VirtualHost&gt;

# 관리자 호스트 - IP 제한
&lt;VirtualHost *:80&gt;
    ServerName admin.example.com
    DocumentRoot /var/www/admin
    
    # IP 화이트리스트
    &lt;Directory "/var/www/admin"&gt;
        Require ip 192.168.1.0/24
        Require ip 10.0.0.0/8
    &lt;/Directory&gt;
    
    # 외부 접근 차단
    RewriteEngine On
    RewriteCond %{REMOTE_ADDR} !^(192\.168\.|10\.|127\.0\.0\.1)
    RewriteRule ^(.*)$ - [F,L]
&lt;/VirtualHost&gt;

# Nginx 안전 설정
# /etc/nginx/sites-available/secure

# 기본 서버 블록 - 알 수 없는 호스트 차단
server {
    listen 80 default_server;
    server_name _;
    return 444; # 연결 종료
}

# 프로덕션 서버
server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/production;
    
    # Host 헤더 검증
    if ($host !~ ^(example\.com|www\.example\.com)$) {
        return 403;
    }
    
    # 내부 파일 접근 차단
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(htaccess|htpasswd|ini|log|sh|sql)$ {
        deny all;
    }
}

# PHP 애플리케이션 Host 헤더 검증
function validateHostHeader($allowedHosts) {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    
    // 포트 번호 제거
    $host = preg_replace('/:\d+$/', '', $host);
    
    if (!in_array($host, $allowedHosts, true)) {
        http_response_code(400);
        die('Invalid Host header');
    }
}

// 허용된 호스트 목록
$allowedHosts = [
    'example.com',
    'www.example.com'
];

validateHostHeader($allowedHosts);

// 환경별 접근 제어
function checkEnvironmentAccess() {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    
    // 개발 환경은 로컬에서만 접근
    if (strpos($host, 'dev.') === 0) {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!in_array($remoteAddr, ['127.0.0.1', '::1'])) {
            http_response_code(403);
            die('Development environment access denied');
        }
    }
    
    // 관리자 패널은 인증 필요
    if (strpos($host, 'admin.') === 0) {
        if (!isAdminAuthenticated()) {
            http_response_code(401);
            die('Authentication required');
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

    <script>
        function setHostHeader(host) {
            document.getElementById('host_header').value = host;
        }
    </script>
</body>
</html>