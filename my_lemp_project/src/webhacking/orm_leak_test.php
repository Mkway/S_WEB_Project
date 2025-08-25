
<?php
require_once 'TestPage.php';

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
    ]
];

// 1. 페이지 설정
$page_title = 'ORM Leak';
$description = '<p><strong>ORM Leak</strong>은 Object-Relational Mapping 시스템에서 의도하지 않은 데이터베이스 정보나 민감한 필드가 노출되는 취약점입니다.</p>
<p>이는 ORM의 잘못된 설정, 디버그 모드 활성화, 또는 API 응답 처리 오류 등으로 발생할 수 있습니다.</p>';

// 2. 페이로드 정의 (공격 시나리오 설명)
$payloads = [
    'user_profile' => [
        'title' => '사용자 프로필 조회',
        'description' => '특정 사용자의 프로필 정보를 조회하여 민감한 필드가 노출되는지 확인합니다.',
        'payloads' => []
    ],
    'debug_mode' => [
        'title' => '디버그 모드 정보 노출',
        'description' => 'ORM 디버그 모드에서 데이터베이스 스키마와 쿼리 정보가 노출되는지 확인합니다.',
        'payloads' => []
    ],
    'api_response' => [
        'title' => 'API 응답 과다 노출',
        'description' => 'API에서 ORM 모델을 직접 반환하여 불필요한 필드가 포함되는지 확인합니다.',
        'payloads' => []
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>명시적 필드 선택:</strong> ORM 쿼리 시 필요한 필드만 명시적으로 선택하여 반환합니다.",
    "<strong>DTO(Data Transfer Object) 패턴 사용:</strong> API 응답 시 ORM 모델 객체 대신 DTO를 사용하여 노출될 데이터를 제어합니다.",
    "<strong>프로덕션에서 디버그 모드 비활성화:</strong> 운영 환경에서는 ORM의 디버그 모드를 반드시 비활성화하여 내부 정보 노출을 방지합니다.",
    "<strong>Hidden/Protected 속성 설정:</strong> ORM 모델에 민감한 필드를 숨김 처리하는 속성을 설정합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - ORM Leak" => "https://owasp.org/www-community/attacks/ORM_Leak",
    "PortSwigger - ORM vulnerabilities" => "https://portswigger.net/web-security/orm"
];

// 5. 테스트 폼 UI 정의
$query_type_selected = htmlspecialchars($_POST['query_type'] ?? 'user_profile');
$user_id_input = htmlspecialchars($_POST['user_id'] ?? 1);
$search_term_input = htmlspecialchars($_POST['search'] ?? 'admin');

$test_form_ui = <<<HTML
<form method="post" class="test-form">
    <h3>🧪 ORM 쿼리 시뮬레이터</h3>
    <label for="query_type">쿼리 유형 선택:</label>
    <select name="query_type" id="query_type">
        <option value="user_profile" {$query_type_selected === 'user_profile' ? 'selected' : ''}>사용자 프로필 조회</option>
        <option value="debug_mode" {$query_type_selected === 'debug_mode' ? 'selected' : ''}>디버그 모드 정보 노출</option>
        <option value="api_response" {$query_type_selected === 'api_response' ? 'selected' : ''}>API 응답 과다 노출</option>
    </select><br><br>

    <div id="user_profile_fields" style="display: {$query_type_selected === 'user_profile' ? 'block' : 'none';}">
        <label for="user_id">사용자 ID:</label>
        <input type="number" name="user_id" id="user_id" value="{$user_id_input}" min="1" required>
    </div>

    <div id="api_response_fields" style="display: {$query_type_selected === 'api_response' ? 'block' : 'none';}">
        <label for="api_user_id">API 사용자 ID:</label>
        <input type="number" name="api_user_id" id="api_user_id" value="{$user_id_input}" min="1" required>
    </div>

    <button type="submit" class="btn">쿼리 실행</button>
</form>

<script>
    document.getElementById('query_type').addEventListener('change', function() {
        const selectedType = this.value;
        document.getElementById('user_profile_fields').style.display = selectedType === 'user_profile' ? 'block' : 'none';
        document.getElementById('api_response_fields').style.display = selectedType === 'api_response' ? 'block' : 'none';
    });
</script>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) use ($mock_users) {
    $result_html = '';
    $error = '';
    $query_type = $form_data['query_type'] ?? 'user_profile';

    $response_data = [];
    $leaked_fields = [];
    $warnings = [];

    switch ($query_type) {
        case 'user_profile':
            $user_id = (int)($form_data['user_id'] ?? 1);
            if (isset($mock_users[$user_id])) {
                // 취약한 방법: 모든 필드 반환
                $response_data = $mock_users[$user_id];
                $leaked_fields = ['password_hash', 'api_key', 'salary', 'ssn', 'internal_notes'];
                $warnings[] = "모든 데이터베이스 필드가 민감한 정보를 포함하여 노출되었습니다!";
            } else {
                $error = "사용자 ID를 찾을 수 없습니다.";
            }
            break;

        case 'debug_mode':
            // 취약한 방법: 디버그 모드에서 ORM 메타데이터 노출
            $response_data = [
                'table_schema' => [
                    'users' => [
                        'columns' => ['id', 'username', 'email', 'password_hash', 'api_key', 'role', 'salary', 'ssn', 'internal_notes'],
                        'sensitive_columns' => ['password_hash', 'api_key', 'salary', 'ssn', 'internal_notes'],
                    ]
                ],
                'database_config' => [
                    'host' => 'localhost',
                    'database' => 'webapp_db',
                    'username' => 'db_user',
                    'password' => 'db_pass' // 민감 정보
                ]
            ];
            $leaked_fields = ['database_schema', 'table_structure', 'connection_info', 'password'];
            $warnings[] = "데이터베이스 스키마와 설정이 디버그 모드에서 노출되었습니다!";
            break;

        case 'api_response':
            $user_id = (int)($form_data['api_user_id'] ?? 1);
            if (isset($mock_users[$user_id])) {
                // 취약한 방법: API에서 내부 모델 객체 직접 반환
                $response_data = [
                    'user' => $mock_users[$user_id],
                    'internal_metadata' => [
                        'model_class' => 'App\\Models\\User',
                        'loaded_relations' => ['profile', 'permissions'],
                        'query_log' => ['SELECT * FROM users WHERE id = ' . $user_id]
                    ]
                ];
                $leaked_fields = ['internal_metadata', 'query_log', 'model_internals'];
                $warnings[] = "ORM 모델 내부 정보가 API 응답에 노출되었습니다!";
            } else {
                $error = "사용자 ID를 찾을 수 없습니다.";
            }
            break;
    }

    $result_html = "<pre><h4>ORM 쿼리 결과 - " . htmlspecialchars($query_type) . "</h4>";
    $result_html .= "<p><strong>데이터:</strong></p>";
    $result_html .= htmlspecialchars(json_encode($response_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    
    if (!empty($leaked_fields)) {
        $result_html .= "\n\n<p><strong>🔓 노출된 민감 정보:</strong></p>";
        foreach ($leaked_fields as $field) {
            $result_html .= "<span style=\"background-color:#f8d7da; padding:2px 5px; border-radius:3px; margin-right:5px;\">" . htmlspecialchars($field) . "</span>";
        }
    }
    if (!empty($warnings)) {
        $result_html .= "\n\n<p><strong>⚠️ 경고:</strong></p><ul>";
        foreach ($warnings as $warning) {
            $result_html .= "<li>" . htmlspecialchars($warning) . "</li>";
        }
        $result_html .= "</ul>";
    }
    $result_html .= "</pre>";

    return ['result' => $result_html, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references);
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
