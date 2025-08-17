<?php
require_once '../config.php';
require_once '../db.php';

$vulnerability_enabled = isVulnerabilityEnabled('orm_leak', $_GET);

// 모의 사용자 데이터
$mock_users = [
    1 => [
        'id' => 1,
        'username' => 'admin',
        'email' => 'admin@example.com',
        'password_hash' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
        'api_key' => 'admin_key_123456789',
        'role' => 'administrator',
        'salary' => 75000,
        'ssn' => '123-45-6789',
        'created_at' => '2024-01-01 10:00:00',
        'last_login' => '2024-08-17 15:30:00',
        'is_active' => true,
        'internal_notes' => 'System administrator with full access'
    ],
    2 => [
        'id' => 2,
        'username' => 'john_doe',
        'email' => 'john@example.com',
        'password_hash' => '$2y$10$TKh8H1.PfQx37YgCzwiKb.KjNyWgaHb9cbcoQgdIVFlYg7B77UdFm',
        'api_key' => 'user_key_987654321',
        'role' => 'user',
        'salary' => 45000,
        'ssn' => '987-65-4321',
        'created_at' => '2024-02-15 09:15:00',
        'last_login' => '2024-08-16 14:20:00',
        'is_active' => true,
        'internal_notes' => 'Regular user, good performance'
    ],
    3 => [
        'id' => 3,
        'username' => 'jane_smith',
        'email' => 'jane@example.com',
        'password_hash' => '$2y$10$86YNFyENziMQVObUkPa.u.bGOxb07vcZzk.iiMDvxI3qQREqxinqK',
        'api_key' => 'user_key_456789123',
        'role' => 'user',
        'salary' => 52000,
        'ssn' => '456-78-9123',
        'created_at' => '2024-03-10 11:30:00',
        'last_login' => '2024-08-17 09:45:00',
        'is_active' => false,
        'internal_notes' => 'User on temporary leave'
    ]
];

function simulateORMQuery($query_type, $params = [], $vulnerable = false) {
    global $mock_users;
    
    $result = [
        'query_type' => $query_type,
        'vulnerable' => $vulnerable,
        'data' => [],
        'leaked_fields' => [],
        'warnings' => []
    ];
    
    switch ($query_type) {
        case 'user_profile':
            $user_id = $params['user_id'] ?? 1;
            
            if ($vulnerable) {
                // 취약한 방법: 모든 필드 반환 (민감한 정보 포함)
                if (isset($mock_users[$user_id])) {
                    $result['data'] = $mock_users[$user_id];
                    $result['leaked_fields'] = ['password_hash', 'api_key', 'salary', 'ssn', 'internal_notes'];
                    $result['warnings'][] = "All database fields exposed including sensitive data!";
                }
            } else {
                // 안전한 방법: 필요한 필드만 선택적으로 반환
                if (isset($mock_users[$user_id])) {
                    $safe_fields = ['id', 'username', 'email', 'role', 'created_at', 'last_login', 'is_active'];
                    $result['data'] = array_intersect_key($mock_users[$user_id], array_flip($safe_fields));
                }
            }
            break;
            
        case 'user_list':
            $include_inactive = $params['include_inactive'] ?? false;
            
            if ($vulnerable) {
                // 취약한 방법: 전체 테이블 덤프
                $result['data'] = $mock_users;
                $result['leaked_fields'] = ['password_hash', 'api_key', 'salary', 'ssn', 'internal_notes'];
                $result['warnings'][] = "Complete user table dumped with sensitive information!";
                $result['warnings'][] = "Password hashes, API keys, and personal data exposed!";
            } else {
                // 안전한 방법: 공개 필드만 포함
                $safe_fields = ['id', 'username', 'email', 'role', 'created_at', 'is_active'];
                
                foreach ($mock_users as $user) {
                    if ($user['is_active'] || $include_inactive) {
                        $result['data'][] = array_intersect_key($user, array_flip($safe_fields));
                    }
                }
            }
            break;
            
        case 'search_users':
            $search_term = $params['search'] ?? '';
            
            if ($vulnerable) {
                // 취약한 방법: 전체 필드에서 검색하며 모든 정보 노출
                foreach ($mock_users as $user) {
                    foreach ($user as $field => $value) {
                        if (stripos($value, $search_term) !== false) {
                            $result['data'][] = $user;
                            $result['leaked_fields'] = array_merge($result['leaked_fields'], 
                                ['password_hash', 'api_key', 'salary', 'ssn', 'internal_notes']);
                            break;
                        }
                    }
                }
                $result['leaked_fields'] = array_unique($result['leaked_fields']);
                $result['warnings'][] = "Search performed on sensitive fields including passwords and SSN!";
            } else {
                // 안전한 방법: 공개 필드에서만 검색
                $safe_fields = ['username', 'email', 'role'];
                
                foreach ($mock_users as $user) {
                    foreach ($safe_fields as $field) {
                        if (isset($user[$field]) && stripos($user[$field], $search_term) !== false) {
                            $result['data'][] = array_intersect_key($user, array_flip(['id', 'username', 'email', 'role', 'is_active']));
                            break;
                        }
                    }
                }
            }
            break;
            
        case 'debug_mode':
            if ($vulnerable) {
                // 취약한 방법: 디버그 모드에서 ORM 메타데이터 노출
                $result['data'] = [
                    'table_schema' => [
                        'users' => [
                            'columns' => ['id', 'username', 'email', 'password_hash', 'api_key', 'role', 'salary', 'ssn', 'created_at', 'last_login', 'is_active', 'internal_notes'],
                            'sensitive_columns' => ['password_hash', 'api_key', 'salary', 'ssn', 'internal_notes'],
                            'indexes' => ['id', 'username', 'email'],
                            'foreign_keys' => []
                        ],
                        'admin_logs' => [
                            'columns' => ['id', 'admin_id', 'action', 'target_user_id', 'ip_address', 'timestamp'],
                            'sensitive_columns' => ['ip_address'],
                        ]
                    ],
                    'database_config' => [
                        'host' => 'localhost',
                        'database' => 'webapp_db',
                        'username' => 'db_user',
                        'connection_pool_size' => 10,
                        'cache_enabled' => true
                    ]
                ];
                $result['leaked_fields'] = ['database_schema', 'table_structure', 'connection_info'];
                $result['warnings'][] = "Database schema and configuration exposed in debug mode!";
                $result['warnings'][] = "Internal table structure and sensitive column information leaked!";
            } else {
                // 안전한 방법: 디버그 정보 제한
                $result['data'] = [
                    'query_count' => 5,
                    'cache_hits' => 3,
                    'execution_time' => '45ms',
                    'memory_usage' => '2.1MB'
                ];
            }
            break;
            
        case 'api_response':
            $user_id = $params['user_id'] ?? 1;
            
            if ($vulnerable) {
                // 취약한 방법: API에서 내부 모델 객체 직접 반환
                if (isset($mock_users[$user_id])) {
                    $result['data'] = [
                        'user' => $mock_users[$user_id],
                        'internal_metadata' => [
                            'model_class' => 'App\\Models\\User',
                            'loaded_relations' => ['profile', 'permissions', 'audit_logs'],
                            'dirty_attributes' => [],
                            'original_attributes' => $mock_users[$user_id],
                            'hidden_attributes' => ['password_hash', 'api_key'],
                            'database_connection' => 'mysql',
                            'query_log' => [
                                'SELECT * FROM users WHERE id = ' . $user_id,
                                'SELECT * FROM user_profiles WHERE user_id = ' . $user_id,
                                'SELECT * FROM permissions WHERE user_id = ' . $user_id
                            ]
                        ]
                    ];
                    $result['leaked_fields'] = ['internal_metadata', 'query_log', 'model_internals'];
                    $result['warnings'][] = "ORM model internals exposed in API response!";
                    $result['warnings'][] = "Database queries and connection information leaked!";
                }
            } else {
                // 안전한 방법: DTO(Data Transfer Object) 사용
                if (isset($mock_users[$user_id])) {
                    $result['data'] = [
                        'user' => [
                            'id' => $mock_users[$user_id]['id'],
                            'username' => $mock_users[$user_id]['username'],
                            'email' => $mock_users[$user_id]['email'],
                            'role' => $mock_users[$user_id]['role'],
                            'is_active' => $mock_users[$user_id]['is_active']
                        ]
                    ];
                }
            }
            break;
    }
    
    return $result;
}

$test_results = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $query_type = $_POST['query_type'] ?? '';
    $params = [];
    
    switch ($query_type) {
        case 'user_profile':
            $params['user_id'] = (int)($_POST['user_id'] ?? 1);
            break;
            
        case 'user_list':
            $params['include_inactive'] = isset($_POST['include_inactive']);
            break;
            
        case 'search_users':
            $params['search'] = $_POST['search'] ?? '';
            break;
            
        case 'debug_mode':
            // 디버그 모드는 별도 파라미터 불필요
            break;
            
        case 'api_response':
            $params['user_id'] = (int)($_POST['user_id'] ?? 1);
            break;
    }
    
    $result = simulateORMQuery($query_type, $params, $vulnerability_enabled);
    $test_results[] = $result;
}

$orm_attack_scenarios = [
    [
        'name' => 'Mass Assignment Leak',
        'description' => 'ORM의 mass assignment 기능으로 민감한 필드까지 일괄 노출',
        'impact' => '관리자 권한, 패스워드 해시 등 중요 정보 노출'
    ],
    [
        'name' => 'Debug Mode Information Disclosure',
        'description' => 'ORM 디버그 모드에서 데이터베이스 스키마와 쿼리 정보 노출',
        'impact' => '데이터베이스 구조, 연결 정보, 내부 로직 노출'
    ],
    [
        'name' => 'Serialization Leak',
        'description' => 'ORM 모델 객체 직렬화 시 내부 속성과 메타데이터 노출',
        'impact' => '모델 내부 상태, 데이터베이스 연결 정보 노출'
    ],
    [
        'name' => 'API Response Over-exposure',
        'description' => 'API에서 ORM 모델을 직접 반환하여 불필요한 필드 노출',
        'impact' => '민감한 사용자 정보, 내부 메타데이터 노출'
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ORM Leak 취약점 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .orm-simulator {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .query-selector {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .query-card {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .query-card:hover {
            background: #f8f9fa;
            border-color: #007bff;
        }
        
        .query-card.selected {
            background: #e3f2fd;
            border-color: #2196f3;
        }
        
        .query-title {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 8px;
        }
        
        .query-description {
            font-size: 0.9em;
            color: #666;
        }
        
        .query-form {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            display: none;
        }
        
        .query-form.active {
            display: block;
        }
        
        .data-display {
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
        
        .data-safe {
            border-color: #28a745;
            background: #d4edda;
        }
        
        .data-vulnerable {
            border-color: #dc3545;
            background: #f8d7da;
        }
        
        .leaked-fields {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .leaked-field {
            display: inline-block;
            background: #dc3545;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            margin: 2px;
            font-size: 0.8em;
        }
        
        .warnings-list {
            background: #ffebee;
            border: 1px solid #f44336;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .warning-item {
            color: #d32f2f;
            margin: 5px 0;
            font-weight: bold;
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
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        .scenario-examples {
            background: #fff3e0;
            border: 1px solid #ffb74d;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }
        
        .scenario-item {
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .scenario-name {
            font-weight: bold;
            color: #d32f2f;
            margin-bottom: 5px;
        }
        
        .scenario-description {
            font-size: 0.9em;
            color: #666;
            margin: 5px 0;
        }
        
        .scenario-impact {
            font-size: 0.9em;
            color: #d32f2f;
            font-style: italic;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🗄️ ORM Leak 취약점 테스트</h1>
        
        <div class="vulnerability-status <?php echo $vulnerability_enabled ? 'vulnerability-enabled' : 'vulnerability-disabled'; ?>">
            상태: <?php echo $vulnerability_enabled ? '취약한 ORM 설정 (정보 누출 가능)' : '안전한 ORM 설정 (필드 제한)'; ?>
        </div>
        
        <div class="description">
            <h2>📋 ORM Leak이란?</h2>
            <p><strong>ORM Leak</strong>은 Object-Relational Mapping 시스템에서 의도하지 않은 데이터베이스 정보나 민감한 필드가 노출되는 취약점입니다.</p>
            
            <h3>주요 유형</h3>
            <ul>
                <li><strong>Mass Assignment Leak</strong>: 모든 모델 속성이 자동으로 노출</li>
                <li><strong>Debug Information Disclosure</strong>: 디버그 모드에서 ORM 메타데이터 노출</li>
                <li><strong>Serialization Leak</strong>: 객체 직렬화 시 내부 속성 노출</li>
                <li><strong>API Over-exposure</strong>: API 응답에서 불필요한 필드 포함</li>
                <li><strong>Query Log Exposure</strong>: 데이터베이스 쿼리 정보 노출</li>
            </ul>
            
            <h3>노출될 수 있는 정보</h3>
            <ul>
                <li>패스워드 해시, API 키, 토큰</li>
                <li>개인정보 (SSN, 급여, 내부 메모)</li>
                <li>데이터베이스 스키마 및 테이블 구조</li>
                <li>내부 시스템 설정 및 연결 정보</li>
                <li>ORM 모델의 내부 상태 및 메타데이터</li>
            </ul>
            
            <h3>방어 방법</h3>
            <ul>
                <li>명시적 필드 선택 (select specific fields)</li>
                <li>DTO(Data Transfer Object) 패턴 사용</li>
                <li>Hidden/Protected 속성 설정</li>
                <li>API 응답 필터링 및 변환</li>
                <li>프로덕션에서 디버그 모드 비활성화</li>
            </ul>
        </div>

        <div class="orm-simulator">
            <h2>🧪 ORM 쿼리 시뮬레이터</h2>
            
            <div class="query-selector">
                <div class="query-card" onclick="selectQuery('user_profile')">
                    <div class="query-title">사용자 프로필 조회</div>
                    <div class="query-description">특정 사용자의 프로필 정보 조회</div>
                </div>
                
                <div class="query-card" onclick="selectQuery('user_list')">
                    <div class="query-title">사용자 목록 조회</div>
                    <div class="query-description">전체 사용자 목록 및 필터링</div>
                </div>
                
                <div class="query-card" onclick="selectQuery('search_users')">
                    <div class="query-title">사용자 검색</div>
                    <div class="query-description">키워드로 사용자 검색</div>
                </div>
                
                <div class="query-card" onclick="selectQuery('debug_mode')">
                    <div class="query-title">디버그 모드</div>
                    <div class="query-description">ORM 디버그 정보 및 메타데이터</div>
                </div>
                
                <div class="query-card" onclick="selectQuery('api_response')">
                    <div class="query-title">API 응답</div>
                    <div class="query-description">API에서 사용자 모델 반환</div>
                </div>
            </div>
            
            <!-- 사용자 프로필 조회 -->
            <div id="user_profile-form" class="query-form">
                <h3>사용자 프로필 조회</h3>
                <form method="POST" action="">
                    <input type="hidden" name="query_type" value="user_profile">
                    
                    <div class="form-group">
                        <label for="user_id">사용자 ID:</label>
                        <select name="user_id" id="user_id">
                            <option value="1">1 - admin</option>
                            <option value="2">2 - john_doe</option>
                            <option value="3">3 - jane_smith</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn">프로필 조회</button>
                </form>
            </div>
            
            <!-- 사용자 목록 조회 -->
            <div id="user_list-form" class="query-form">
                <h3>사용자 목록 조회</h3>
                <form method="POST" action="">
                    <input type="hidden" name="query_type" value="user_list">
                    
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" name="include_inactive" id="include_inactive">
                            <label for="include_inactive">비활성 사용자 포함</label>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn">목록 조회</button>
                </form>
            </div>
            
            <!-- 사용자 검색 -->
            <div id="search_users-form" class="query-form">
                <h3>사용자 검색</h3>
                <form method="POST" action="">
                    <input type="hidden" name="query_type" value="search_users">
                    
                    <div class="form-group">
                        <label for="search">검색어:</label>
                        <input type="text" name="search" id="search" placeholder="사용자명, 이메일, 역할 등" value="admin">
                    </div>
                    
                    <button type="submit" class="btn">검색 실행</button>
                </form>
            </div>
            
            <!-- 디버그 모드 -->
            <div id="debug_mode-form" class="query-form">
                <h3>ORM 디버그 정보</h3>
                <form method="POST" action="">
                    <input type="hidden" name="query_type" value="debug_mode">
                    
                    <p>ORM의 디버그 모드에서 노출되는 내부 정보를 확인합니다.</p>
                    
                    <button type="submit" class="btn">디버그 정보 조회</button>
                </form>
            </div>
            
            <!-- API 응답 -->
            <div id="api_response-form" class="query-form">
                <h3>API 사용자 응답</h3>
                <form method="POST" action="">
                    <input type="hidden" name="query_type" value="api_response">
                    
                    <div class="form-group">
                        <label for="api_user_id">사용자 ID:</label>
                        <select name="user_id" id="api_user_id">
                            <option value="1">1 - admin</option>
                            <option value="2">2 - john_doe</option>
                            <option value="3">3 - jane_smith</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn">API 호출</button>
                </form>
            </div>
            
            <?php if (!empty($test_results)): ?>
                <?php foreach ($test_results as $result): ?>
                <div class="data-display <?php echo $result['vulnerable'] ? 'data-vulnerable' : 'data-safe'; ?>">
                    <h4>ORM 쿼리 결과 - <?php echo htmlspecialchars($result['query_type']); ?></h4>
                    <p><strong>모드:</strong> <?php echo $result['vulnerable'] ? '취약한 모드' : '안전한 모드'; ?></p>
                    
                    <?php if (!empty($result['warnings'])): ?>
                    <div class="warnings-list">
                        <strong>⚠️ 보안 경고:</strong>
                        <?php foreach ($result['warnings'] as $warning): ?>
                        <div class="warning-item"><?php echo htmlspecialchars($warning); ?></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    
                    <?php if (!empty($result['leaked_fields'])): ?>
                    <div class="leaked-fields">
                        <strong>🔓 노출된 민감 정보:</strong><br>
                        <?php foreach ($result['leaked_fields'] as $field): ?>
                        <span class="leaked-field"><?php echo htmlspecialchars($field); ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    
                    <strong>데이터:</strong>
                    <?php echo htmlspecialchars(json_encode($result['data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="scenario-examples">
            <h3>🎯 ORM Leak 공격 시나리오</h3>
            <?php foreach ($orm_attack_scenarios as $scenario): ?>
            <div class="scenario-item">
                <div class="scenario-name"><?php echo htmlspecialchars($scenario['name']); ?></div>
                <div class="scenario-description"><?php echo htmlspecialchars($scenario['description']); ?></div>
                <div class="scenario-impact"><strong>영향:</strong> <?php echo htmlspecialchars($scenario['impact']); ?></div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="mitigation">
            <h2>🛡️ 완화 방안</h2>
            <div class="code-block">
                <h3>안전한 ORM 사용법</h3>
                <pre><code>// ❌ 위험한 방법: 모든 필드 노출
class User extends Model {
    // 보호되지 않는 필드들
    public function toArray() {
        return parent::toArray(); // 모든 필드 반환
    }
}

// API에서 직접 모델 반환
return response()->json($user); // 민감한 정보 포함

// ✅ 안전한 방법: 명시적 필드 선택
class User extends Model {
    // 숨겨진 필드 지정
    protected $hidden = [
        'password_hash', 'api_key', 'ssn', 'salary', 'internal_notes'
    ];
    
    // 또는 공개 필드만 지정
    protected $visible = [
        'id', 'username', 'email', 'role', 'created_at', 'is_active'
    ];
    
    // API 리소스 변환
    public function toPublicArray() {
        return [
            'id' => $this->id,
            'username' => $this->username,
            'email' => $this->email,
            'role' => $this->role,
            'is_active' => $this->is_active
        ];
    }
}

// DTO 패턴 사용
class UserDTO {
    public function __construct(User $user) {
        $this->id = $user->id;
        $this->username = $user->username;
        $this->email = $user->email;
        $this->role = $user->role;
        // 민감한 필드는 제외
    }
}

// 명시적 필드 선택
$users = User::select(['id', 'username', 'email', 'role'])
             ->where('is_active', true)
             ->get();

// API 리소스 클래스 사용 (Laravel 예시)
class UserResource extends JsonResource {
    public function toArray($request) {
        return [
            'id' => $this->id,
            'username' => $this->username,
            'email' => $this->email,
            'role' => $this->role,
            'profile_url' => route('users.show', $this->id),
            'created_at' => $this->created_at->toDateString(),
        ];
    }
}

// 프로덕션 환경 설정
// .env 파일에서
APP_DEBUG=false
DB_LOG_QUERIES=false

// 설정에서 민감한 정보 제거
config(['database.connections.mysql.password' => '***']);</code></pre>
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
        function selectQuery(queryType) {
            // 모든 카드에서 선택 상태 제거
            document.querySelectorAll('.query-card').forEach(card => {
                card.classList.remove('selected');
            });
            
            // 모든 폼 숨기기
            document.querySelectorAll('.query-form').forEach(form => {
                form.classList.remove('active');
            });
            
            // 선택된 카드 활성화
            event.target.closest('.query-card').classList.add('selected');
            
            // 해당 폼 표시
            document.getElementById(queryType + '-form').classList.add('active');
        }
        
        // 페이지 로드 시 첫 번째 쿼리 선택
        document.addEventListener('DOMContentLoaded', function() {
            selectQuery('user_profile');
        });
    </script>
</body>
</html>