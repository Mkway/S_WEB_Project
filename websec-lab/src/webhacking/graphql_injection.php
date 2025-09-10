<?php
session_start();
include_once '../db_connection.php';

class GraphQLInjectionTest {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
        $this->initializeDatabase();
    }
    
    private function initializeDatabase() {
        // GraphQL 테스트용 테이블 생성
        $tables = [
            "CREATE TABLE IF NOT EXISTS gql_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                email VARCHAR(100) NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            "CREATE TABLE IF NOT EXISTS gql_posts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                content TEXT,
                author_id INT,
                is_public BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_id) REFERENCES gql_users(id)
            )",
            "CREATE TABLE IF NOT EXISTS gql_comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                post_id INT,
                author_id INT,
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (post_id) REFERENCES gql_posts(id),
                FOREIGN KEY (author_id) REFERENCES gql_users(id)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->db->exec($sql);
        }
        
        // 테스트 데이터 삽입
        $this->db->exec("INSERT IGNORE INTO gql_users (id, username, email, password, role) VALUES 
            (1, 'admin', 'admin@test.com', 'admin123', 'admin'),
            (2, 'user1', 'user1@test.com', 'user123', 'user'),
            (3, 'moderator', 'mod@test.com', 'mod123', 'moderator'),
            (4, 'secret_user', 'secret@hidden.com', 'topsecret', 'admin')");
            
        $this->db->exec("INSERT IGNORE INTO gql_posts (id, title, content, author_id, is_public) VALUES 
            (1, 'Public Post', 'This is a public post content', 2, TRUE),
            (2, 'Private Admin Post', 'This contains sensitive admin information', 1, FALSE),
            (3, 'Secret Document', 'TOP SECRET: Critical system information', 4, FALSE),
            (4, 'User Post', 'Regular user post', 2, TRUE)");
            
        $this->db->exec("INSERT IGNORE INTO gql_comments (id, post_id, author_id, comment) VALUES 
            (1, 1, 1, 'Admin comment on public post'),
            (2, 2, 1, 'Admin internal note: System vulnerability exists'),
            (3, 1, 2, 'User comment'),
            (4, 3, 4, 'Secret: Database password is admin123!')");
    }
    
    public function vulnerableGraphQLQuery($query, $variables = []) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 취약한 GraphQL 쿼리 실행</h4>";
            $result .= "<p><strong>쿼리:</strong></p>";
            $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px;'>" . htmlspecialchars($query) . "</pre>";
            
            if (!empty($variables)) {
                $result .= "<p><strong>변수:</strong> " . htmlspecialchars(json_encode($variables)) . "</p>";
            }
            
            // 🚨 취약한 GraphQL 파싱 - 입력 검증 없음
            $parsedQuery = $this->parseGraphQLQuery($query);
            
            if ($parsedQuery) {
                $queryResult = $this->executeGraphQLQuery($parsedQuery, $variables, false);
                
                $result .= "<p><strong>⚠️ 쿼리 실행 결과:</strong></p>";
                $result .= "<div style='background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 4px; max-height: 300px; overflow-y: auto;'>";
                $result .= "<pre>" . htmlspecialchars(json_encode($queryResult, JSON_PRETTY_PRINT)) . "</pre>";
                $result .= "</div>";
                
                // 보안 위험 감지
                if ($this->detectSecurityRisks($queryResult)) {
                    $result .= "<p class='alert-danger'><strong>🚨 보안 위험 감지!</strong></p>";
                    $result .= "<p>민감한 정보가 노출되었거나 권한 우회가 발생했을 수 있습니다.</p>";
                }
                
            } else {
                $result .= "<p class='alert-warning'><strong>❌ GraphQL 쿼리 파싱 실패</strong></p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function secureGraphQLQuery($query, $variables = []) {
        $result = '';
        
        try {
            $result .= "<div class='safe-output'>";
            $result .= "<h4>🔒 보안 강화된 GraphQL 쿼리 실행</h4>";
            $result .= "<p><strong>쿼리:</strong></p>";
            $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px;'>" . htmlspecialchars($query) . "</pre>";
            
            // 🔒 보안 검증
            $securityCheck = $this->validateGraphQLQuery($query);
            
            if (!$securityCheck['safe']) {
                $result .= "<p class='alert-warning'><strong>🛡️ 보안 정책으로 차단됨:</strong></p>";
                $result .= "<ul>";
                foreach ($securityCheck['violations'] as $violation) {
                    $result .= "<li>" . htmlspecialchars($violation) . "</li>";
                }
                $result .= "</ul>";
                $result .= "<p>이는 정상적인 보안 동작입니다.</p>";
            } else {
                $parsedQuery = $this->parseGraphQLQuery($query);
                if ($parsedQuery) {
                    $queryResult = $this->executeGraphQLQuery($parsedQuery, $variables, true);
                    
                    $result .= "<p><strong>✅ 안전한 쿼리 실행 결과:</strong></p>";
                    $result .= "<div style='background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 4px; max-height: 300px; overflow-y: auto;'>";
                    $result .= "<pre>" . htmlspecialchars(json_encode($queryResult, JSON_PRETTY_PRINT)) . "</pre>";
                    $result .= "</div>";
                    $result .= "<p class='alert-success'><strong>🔒 보안 검증 통과!</strong> 권한과 접근 제한이 적절히 적용되었습니다.</p>";
                }
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    private function parseGraphQLQuery($query) {
        // 간단한 GraphQL 쿼리 파서 (실제 환경에서는 전용 파서 사용)
        $query = trim($query);
        
        // 쿼리 타입 감지
        if (preg_match('/^\\s*(query|mutation|subscription)\\s*\\{/', $query, $matches)) {
            $type = $matches[1];
        } else if (preg_match('/^\\s*\\{/', $query)) {
            $type = 'query';
        } else {
            return false;
        }
        
        // 필드 추출 (간단한 정규식 사용)
        preg_match_all('/\\b(users|posts|comments)\\s*(?:\\([^)]*\\))?\\s*\\{([^}]*)\\}/', $query, $matches, PREG_SET_ORDER);
        
        $fields = [];
        foreach ($matches as $match) {
            $entity = $match[1];
            $fieldList = preg_split('/[,\\s]+/', trim($match[2]));
            $fields[$entity] = array_filter($fieldList);
        }
        
        return [
            'type' => $type,
            'fields' => $fields,
            'raw' => $query
        ];
    }
    
    private function executeGraphQLQuery($parsedQuery, $variables = [], $secure = false) {
        $results = [];
        
        foreach ($parsedQuery['fields'] as $entity => $fields) {
            switch ($entity) {
                case 'users':
                    $results['users'] = $this->getUsersData($fields, $secure);
                    break;
                case 'posts':
                    $results['posts'] = $this->getPostsData($fields, $secure);
                    break;
                case 'comments':
                    $results['comments'] = $this->getCommentsData($fields, $secure);
                    break;
            }
        }
        
        return $results;
    }
    
    private function getUsersData($fields, $secure = false) {
        $selectFields = [];
        
        // 필드 매핑
        $fieldMap = [
            'id' => 'id',
            'username' => 'username',
            'email' => 'email',
            'password' => 'password',
            'role' => 'role',
            'isActive' => 'is_active',
            'createdAt' => 'created_at'
        ];
        
        foreach ($fields as $field) {
            if (isset($fieldMap[$field])) {
                if ($secure && in_array($field, ['password'])) {
                    // 보안 모드에서는 민감한 필드 제외
                    continue;
                }
                $selectFields[] = $fieldMap[$field];
            }
        }
        
        if (empty($selectFields)) {
            $selectFields = ['id', 'username', 'email'];
        }
        
        $sql = "SELECT " . implode(', ', $selectFields) . " FROM gql_users";
        
        if ($secure) {
            // 보안 모드에서는 공개 정보만
            $sql .= " WHERE is_active = 1 LIMIT 10";
        }
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    private function getPostsData($fields, $secure = false) {
        $selectFields = [];
        
        $fieldMap = [
            'id' => 'p.id',
            'title' => 'p.title',
            'content' => 'p.content',
            'authorId' => 'p.author_id',
            'isPublic' => 'p.is_public',
            'createdAt' => 'p.created_at',
            'author' => 'u.username'
        ];
        
        foreach ($fields as $field) {
            if (isset($fieldMap[$field])) {
                $selectFields[] = $fieldMap[$field];
            }
        }
        
        if (empty($selectFields)) {
            $selectFields = ['p.id', 'p.title', 'u.username'];
        }
        
        $sql = "SELECT " . implode(', ', $selectFields) . " FROM gql_posts p 
                LEFT JOIN gql_users u ON p.author_id = u.id";
        
        if ($secure) {
            // 보안 모드에서는 공개 게시물만
            $sql .= " WHERE p.is_public = 1";
        }
        
        $sql .= " ORDER BY p.created_at DESC LIMIT 20";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    private function getCommentsData($fields, $secure = false) {
        $selectFields = [];
        
        $fieldMap = [
            'id' => 'c.id',
            'postId' => 'c.post_id',
            'authorId' => 'c.author_id',
            'comment' => 'c.comment',
            'createdAt' => 'c.created_at',
            'author' => 'u.username',
            'postTitle' => 'p.title'
        ];
        
        foreach ($fields as $field) {
            if (isset($fieldMap[$field])) {
                $selectFields[] = $fieldMap[$field];
            }
        }
        
        if (empty($selectFields)) {
            $selectFields = ['c.id', 'c.comment', 'u.username'];
        }
        
        $sql = "SELECT " . implode(', ', $selectFields) . " FROM gql_comments c 
                LEFT JOIN gql_users u ON c.author_id = u.id
                LEFT JOIN gql_posts p ON c.post_id = p.id";
        
        if ($secure) {
            // 보안 모드에서는 공개 게시물의 댓글만
            $sql .= " WHERE p.is_public = 1";
        }
        
        $sql .= " ORDER BY c.created_at DESC LIMIT 20";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    private function validateGraphQLQuery($query) {
        $violations = [];
        $safe = true;
        
        // 깊이 검사 (Depth Limiting)
        $depth = substr_count($query, '{') - substr_count($query, '}');
        if (abs($depth) > 5) {
            $violations[] = "쿼리 깊이 제한 초과 (최대 5단계)";
            $safe = false;
        }
        
        // 복잡도 검사 (Query Complexity)
        $complexity = substr_count($query, '{') + substr_count($query, '(');
        if ($complexity > 10) {
            $violations[] = "쿼리 복잡도 제한 초과 (최대 10)";
            $safe = false;
        }
        
        // 민감한 필드 검사
        $sensitiveFields = ['password', 'secret', 'token', 'key'];
        foreach ($sensitiveFields as $field) {
            if (stripos($query, $field) !== false) {
                $violations[] = "민감한 필드 접근 시도: $field";
                $safe = false;
            }
        }
        
        // 인트로스펙션 쿼리 검사
        if (stripos($query, '__schema') !== false || stripos($query, '__type') !== false) {
            $violations[] = "인트로스펙션 쿼리는 운영 환경에서 비활성화됨";
            $safe = false;
        }
        
        return ['safe' => $safe, 'violations' => $violations];
    }
    
    private function detectSecurityRisks($result) {
        $riskDetected = false;
        $resultString = json_encode($result);
        
        // 민감한 정보 패턴 감지
        $sensitivePatterns = [
            'password',
            'secret',
            'admin123',
            'topsecret',
            'TOP SECRET',
            'vulnerability',
            'Database password'
        ];
        
        foreach ($sensitivePatterns as $pattern) {
            if (stripos($resultString, $pattern) !== false) {
                $riskDetected = true;
                break;
            }
        }
        
        return $riskDetected;
    }
    
    public function generateComplexQuery() {
        return '
{
  users {
    id
    username
    email
    password
    role
    posts {
      id
      title
      content
      isPublic
      comments {
        id
        comment
        author {
          username
          email
          password
        }
      }
    }
  }
}';
    }
    
    public function generateIntrospectionQuery() {
        return '
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}';
    }
}

$graphqlTest = new GraphQLInjectionTest($pdo);
$result = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'vulnerable_query':
            $query = $_POST['query'] ?? '';
            $variables = $_POST['variables'] ?? '';
            $variablesArray = [];
            
            if (!empty($variables)) {
                $variablesArray = json_decode($variables, true) ?: [];
            }
            
            if (!empty($query)) {
                $result = $graphqlTest->vulnerableGraphQLQuery($query, $variablesArray);
            } else {
                $result = "<div class='error-output'>❌ GraphQL 쿼리를 입력해주세요.</div>";
            }
            break;
            
        case 'secure_query':
            $query = $_POST['query'] ?? '';
            $variables = $_POST['variables'] ?? '';
            $variablesArray = [];
            
            if (!empty($variables)) {
                $variablesArray = json_decode($variables, true) ?: [];
            }
            
            if (!empty($query)) {
                $result = $graphqlTest->secureGraphQLQuery($query, $variablesArray);
            } else {
                $result = "<div class='error-output'>❌ GraphQL 쿼리를 입력해주세요.</div>";
            }
            break;
            
        case 'load_complex':
            $complexQuery = $graphqlTest->generateComplexQuery();
            $result = "<div class='info-output'><h4>복잡한 중첩 쿼리가 로드되었습니다</h4><p>아래 쿼리 입력창에서 확인하세요.</p></div>";
            break;
            
        case 'load_introspection':
            $introspectionQuery = $graphqlTest->generateIntrospectionQuery();
            $result = "<div class='info-output'><h4>인트로스펙션 쿼리가 로드되었습니다</h4><p>아래 쿼리 입력창에서 확인하세요.</p></div>";
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GraphQL Injection 취약점 테스트</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        .container {
            background-color: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        
        .description {
            background-color: #e8f4fd;
            padding: 20px;
            border-left: 5px solid #2196F3;
            margin-bottom: 30px;
            border-radius: 5px;
        }
        
        .test-section {
            margin-bottom: 40px;
            padding: 20px;
            border: 2px solid #ddd;
            border-radius: 10px;
            background-color: #fafafa;
        }
        
        .test-section h3 {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        
        input, select, button, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }
        
        textarea {
            height: 200px;
            font-family: monospace;
            resize: vertical;
        }
        
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
            font-weight: bold;
            margin-top: 10px;
            transition: background-color 0.3s;
        }
        
        button:hover {
            background-color: #45a049;
        }
        
        .dangerous-btn {
            background-color: #f44336;
        }
        
        .dangerous-btn:hover {
            background-color: #da190b;
        }
        
        .safe-btn {
            background-color: #2196F3;
        }
        
        .safe-btn:hover {
            background-color: #1976D2;
        }
        
        .sample-btn {
            background-color: #FF9800;
        }
        
        .sample-btn:hover {
            background-color: #F57C00;
        }
        
        .vulnerable-output {
            background-color: #ffebee;
            border: 2px solid #f44336;
            color: #c62828;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .safe-output {
            background-color: #e8f5e8;
            border: 2px solid #4caf50;
            color: #2e7d32;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .info-output {
            background-color: #e3f2fd;
            border: 2px solid #2196f3;
            color: #1565c0;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .error-output {
            background-color: #fff3e0;
            border: 2px solid #ff9800;
            color: #ef6c00;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .alert-danger {
            color: #d32f2f !important;
            font-weight: bold;
        }
        
        .alert-success {
            color: #2e7d32 !important;
            font-weight: bold;
        }
        
        .alert-warning {
            color: #f57c00 !important;
            font-weight: bold;
        }
        
        .two-column {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .sample-queries {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .sample-query {
            background-color: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .sample-query:hover {
            background-color: #e9ecef;
        }
        
        .sample-query h5 {
            margin: 0 0 5px 0;
            color: #495057;
        }
        
        .sample-query code {
            font-size: 12px;
            color: #6c757d;
        }
        
        @media (max-width: 768px) {
            .two-column {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 GraphQL Injection 취약점 테스트</h1>
        
        <div class="description">
            <h3>🎯 GraphQL Injection이란?</h3>
            <p><strong>GraphQL</strong>은 API를 위한 쿼리 언어이자 런타임입니다. 부적절한 입력 검증, 권한 제어, 쿼리 복잡도 제한이 없을 때 다양한 보안 취약점이 발생할 수 있습니다.</p>
            
            <h4>🔍 주요 공격 벡터:</h4>
            <ul>
                <li><strong>인트로스펙션 남용</strong>: 스키마 정보 노출로 내부 구조 파악</li>
                <li><strong>깊은 중첩 쿼리</strong>: DoS 공격을 위한 복잡한 쿼리</li>
                <li><strong>권한 우회</strong>: 부적절한 접근 제어로 민감한 데이터 노출</li>
                <li><strong>쿼리 복잡도 공격</strong>: 서버 리소스 고갈 유발</li>
            </ul>
            
            <p><strong>⚠️ 실제 테스트:</strong> 이 페이지는 실제 GraphQL 파싱과 데이터베이스 쿼리를 수행하여 취약점을 시연합니다.</p>
        </div>

        <!-- 샘플 쿼리 -->
        <div class="test-section">
            <h3>📝 샘플 GraphQL 쿼리</h3>
            <div class="sample-queries">
                <div class="sample-query" onclick="loadSampleQuery('basic')">
                    <h5>🟢 기본 쿼리</h5>
                    <code>{ users { id username email } }</code>
                </div>
                
                <div class="sample-query" onclick="loadSampleQuery('sensitive')">
                    <h5>🔴 민감한 정보 접근</h5>
                    <code>{ users { id username email password role } }</code>
                </div>
                
                <div class="sample-query" onclick="loadSampleQuery('complex')">
                    <h5>🔴 복잡한 중첩 쿼리</h5>
                    <code>{ users { posts { comments { author { password } } } } }</code>
                </div>
                
                <div class="sample-query" onclick="loadSampleQuery('introspection')">
                    <h5>🔴 인트로스펙션 쿼리</h5>
                    <code>{ __schema { types { name fields { name } } } }</code>
                </div>
            </div>
        </div>

        <!-- GraphQL 쿼리 테스트 -->
        <div class="test-section">
            <h3>🧪 GraphQL 쿼리 실행</h3>
            
            <form method="post">
                <div class="form-group">
                    <label for="query">GraphQL 쿼리:</label>
                    <textarea name="query" id="query" placeholder="GraphQL 쿼리를 입력하세요...
예시:
{
  users {
    id
    username
    email
  }
}"><?php echo isset($_POST['query']) ? htmlspecialchars($_POST['query']) : ''; ?></textarea>
                </div>
                
                <div class="form-group">
                    <label for="variables">변수 (JSON 형식, 선택사항):</label>
                    <textarea name="variables" id="variables" style="height: 80px;" placeholder='{"limit": 10, "userId": 1}'><?php echo isset($_POST['variables']) ? htmlspecialchars($_POST['variables']) : ''; ?></textarea>
                </div>
                
                <div style="display: flex; gap: 10px;">
                    <button type="submit" name="action" value="vulnerable_query" class="dangerous-btn" style="flex: 1;">
                        🔓 취약한 실행 (검증 없음)
                    </button>
                    <button type="submit" name="action" value="secure_query" class="safe-btn" style="flex: 1;">
                        🔒 보안 강화 실행 (검증 적용)
                    </button>
                </div>
            </form>
        </div>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="test-section">
                <h3>📋 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <!-- 보안 권장사항 -->
        <div class="test-section">
            <h3>🛡️ GraphQL 보안 권장사항</h3>
            <div class="safe-output">
                <h4>GraphQL 보안 강화 방법:</h4>
                
                <h5>1. 쿼리 복잡도 제한:</h5>
                <pre><code>// Query Complexity Analysis
const depthLimit = require('graphql-depth-limit');
const costAnalysis = require('graphql-cost-analysis');

const server = new GraphQLServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(7),
    costAnalysis({
      maximumCost: 1000,
      createError: (max, actual) => {
        return new Error(`Query cost ${actual} exceeds maximum cost ${max}`);
      }
    })
  ]
});</code></pre>
                
                <h5>2. 인트로스펙션 비활성화:</h5>
                <pre><code>// 운영 환경에서 인트로스펙션 비활성화
const server = new GraphQLServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production'
});</code></pre>
                
                <h5>3. 필드 수준 권한 제어:</h5>
                <pre><code>// GraphQL Shield 사용
import { rule, shield, and, or } from 'graphql-shield';

const isAuthenticated = rule()(async (parent, args, ctx) => {
  return ctx.user !== null;
});

const isAdmin = rule()(async (parent, args, ctx) => {
  return ctx.user.role === 'admin';
});

export default shield({
  Query: {
    users: isAuthenticated,
    adminData: isAdmin
  },
  User: {
    email: isAuthenticated,
    password: isAdmin  // 패스워드는 관리자만
  }
});</code></pre>
                
                <h5>4. 쿼리 화이트리스트:</h5>
                <pre><code>// 허용된 쿼리만 실행
const allowedQueries = new Set([
  'query GetUsers { users { id username } }',
  'query GetPosts { posts { id title } }'
]);

if (!allowedQueries.has(query)) {
  throw new Error('Unauthorized query');
}</code></pre>
                
                <h5>5. 타임아웃 설정:</h5>
                <pre><code>// 쿼리 실행 시간 제한
const server = new GraphQLServer({
  typeDefs,
  resolvers,
  plugins: [
    {
      requestDidStart() {
        return {
          willSendResponse(requestContext) {
            // 5초 타임아웃
            setTimeout(() => {
              throw new Error('Query timeout');
            }, 5000);
          }
        };
      }
    }
  ]
});</code></pre>
                
                <p><strong>✅ 핵심 원칙:</strong> GraphQL은 강력한 도구이지만 적절한 보안 제어 없이는 심각한 취약점을 야기할 수 있습니다. 항상 입력 검증, 권한 제어, 복잡도 제한을 적용하세요.</p>
            </div>
        </div>
    </div>

    <script>
        const sampleQueries = {
            basic: `{
  users {
    id
    username
    email
  }
}`,
            sensitive: `{
  users {
    id
    username
    email
    password
    role
  }
}`,
            complex: `{
  users {
    id
    username
    email
    password
    posts {
      id
      title
      content
      isPublic
      comments {
        id
        comment
        author {
          id
          username
          email
          password
        }
      }
    }
  }
}`,
            introspection: `{
  __schema {
    types {
      name
      description
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}`
        };
        
        function loadSampleQuery(type) {
            if (sampleQueries[type]) {
                document.getElementById('query').value = sampleQueries[type];
            }
        }
        
        // 페이지 로드 시 기본 쿼리 설정
        document.addEventListener('DOMContentLoaded', function() {
            if (document.getElementById('query').value === '') {
                loadSampleQuery('basic');
            }
        });
    </script>
</body>
</html>