<?php
session_start();
include_once '../db_connection.php';

class JWTVulnerabilityTest {
    private $nodeServerUrl = 'http://localhost:3000';
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
        $this->ensureNodeServer();
        $this->initializeDatabase();
    }
    
    private function ensureNodeServer() {
        // Node.js 서버가 실행되고 있는지 확인
        $response = @file_get_contents($this->nodeServerUrl . '/health');
        if ($response === false) {
            throw new Exception("Node.js 서버가 실행되고 있지 않습니다. 'npm start'로 서버를 시작해주세요.");
        }
    }
    
    private function initializeDatabase() {
        // JWT 테스트용 테이블 생성
        $tables = [
            "CREATE TABLE IF NOT EXISTS jwt_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                email VARCHAR(100) NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            "CREATE TABLE IF NOT EXISTS jwt_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                token VARCHAR(1000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                is_valid BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES jwt_users(id)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->db->exec($sql);
        }
        
        // 테스트 데이터 삽입
        $this->db->exec("INSERT IGNORE INTO jwt_users (id, username, email, password, role) VALUES 
            (1, 'admin', 'admin@test.com', 'admin123', 'admin'),
            (2, 'user', 'user@test.com', 'user123', 'user'),
            (3, 'moderator', 'mod@test.com', 'mod123', 'moderator')");
    }
    
    public function generateJWT($userId, $vulnerable = true) {
        $result = '';
        
        try {
            $result .= "<div class='" . ($vulnerable ? 'vulnerable' : 'safe') . "-output'>";
            $result .= "<h4>" . ($vulnerable ? '🔓 취약한 JWT 생성' : '🔒 안전한 JWT 생성') . "</h4>";
            
            // 사용자 정보 조회
            $stmt = $this->db->prepare("SELECT * FROM jwt_users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                return "<div class='error-output'>❌ 사용자를 찾을 수 없습니다.</div>";
            }
            
            // Node.js 서버로 JWT 생성 요청
            $postData = json_encode([
                'action' => 'generate_jwt',
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role'],
                    'email' => $user['email']
                ],
                'vulnerable' => $vulnerable
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/jwt', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                $result .= "<p><strong>사용자:</strong> {$user['username']} ({$user['role']})</p>";
                $result .= "<p><strong>생성된 JWT:</strong></p>";
                $result .= "<textarea readonly style='width: 100%; height: 120px; font-family: monospace; font-size: 12px; word-break: break-all;'>" . $responseData['token'] . "</textarea>";
                
                if (isset($responseData['header'])) {
                    $result .= "<p><strong>헤더:</strong></p>";
                    $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px;'>" . 
                              htmlspecialchars(json_encode($responseData['header'], JSON_PRETTY_PRINT)) . "</pre>";
                }
                
                if (isset($responseData['payload'])) {
                    $result .= "<p><strong>페이로드:</strong></p>";
                    $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px;'>" . 
                              htmlspecialchars(json_encode($responseData['payload'], JSON_PRETTY_PRINT)) . "</pre>";
                }
                
                if ($vulnerable && isset($responseData['vulnerabilities'])) {
                    $result .= "<p class='alert-danger'><strong>🚨 탐지된 취약점:</strong></p>";
                    $result .= "<ul>";
                    foreach ($responseData['vulnerabilities'] as $vuln) {
                        $result .= "<li>" . htmlspecialchars($vuln) . "</li>";
                    }
                    $result .= "</ul>";
                }
                
                // JWT를 데이터베이스에 저장
                $stmt = $this->db->prepare("INSERT INTO jwt_sessions (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))");
                $stmt->execute([$user['id'], $responseData['token']]);
                
            } else {
                $result .= "<p class='alert-danger'><strong>❌ JWT 생성 실패:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function manipulateJWT($token, $manipulation) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 JWT 조작 공격</h4>";
            $result .= "<p><strong>조작 유형:</strong> " . htmlspecialchars($manipulation) . "</p>";
            
            // Node.js 서버로 JWT 조작 요청
            $postData = json_encode([
                'action' => 'manipulate_jwt',
                'token' => $token,
                'manipulation' => $manipulation
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/jwt', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                $result .= "<p><strong>원본 JWT:</strong></p>";
                $result .= "<textarea readonly style='width: 100%; height: 60px; font-family: monospace; font-size: 10px;'>" . htmlspecialchars($token) . "</textarea>";
                
                $result .= "<p><strong>조작된 JWT:</strong></p>";
                $result .= "<textarea readonly style='width: 100%; height: 60px; font-family: monospace; font-size: 10px;'>" . htmlspecialchars($responseData['manipulated_token']) . "</textarea>";
                
                if (isset($responseData['changes'])) {
                    $result .= "<p><strong>변경 사항:</strong></p>";
                    $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px;'>" . 
                              htmlspecialchars(json_encode($responseData['changes'], JSON_PRETTY_PRINT)) . "</pre>";
                }
                
                if (isset($responseData['attack_explanation'])) {
                    $result .= "<p><strong>공격 설명:</strong></p>";
                    $result .= "<p>" . htmlspecialchars($responseData['attack_explanation']) . "</p>";
                }
                
                $result .= "<p class='alert-danger'><strong>⚠️ 경고:</strong> 조작된 JWT로 권한 상승이나 인증 우회가 가능할 수 있습니다!</p>";
                
            } else {
                $result .= "<p class='alert-danger'><strong>❌ JWT 조작 실패:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function verifyJWT($token, $vulnerable = true) {
        $result = '';
        
        try {
            $result .= "<div class='" . ($vulnerable ? 'vulnerable' : 'safe') . "-output'>";
            $result .= "<h4>" . ($vulnerable ? '🔓 취약한 JWT 검증' : '🔒 안전한 JWT 검증') . "</h4>";
            
            // Node.js 서버로 JWT 검증 요청
            $postData = json_encode([
                'action' => 'verify_jwt',
                'token' => $token,
                'vulnerable' => $vulnerable
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/jwt', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                if ($responseData['valid']) {
                    $result .= "<p class='" . ($vulnerable ? "alert-danger" : "alert-success") . "'>";
                    $result .= "<strong>" . ($vulnerable ? "🚨 취약한 검증 통과!" : "✅ 안전한 검증 통과") . "</strong></p>";
                    
                    if (isset($responseData['decoded'])) {
                        $result .= "<p><strong>디코딩된 정보:</strong></p>";
                        $result .= "<pre style='background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px;'>" . 
                                  htmlspecialchars(json_encode($responseData['decoded'], JSON_PRETTY_PRINT)) . "</pre>";
                    }
                    
                    if ($vulnerable && isset($responseData['security_issues'])) {
                        $result .= "<p class='alert-danger'><strong>🔍 보안 이슈:</strong></p>";
                        $result .= "<ul>";
                        foreach ($responseData['security_issues'] as $issue) {
                            $result .= "<li>" . htmlspecialchars($issue) . "</li>";
                        }
                        $result .= "</ul>";
                    }
                    
                } else {
                    $result .= "<p class='alert-warning'><strong>❌ JWT 검증 실패:</strong> " . htmlspecialchars($responseData['reason']) . "</p>";
                }
                
            } else {
                $result .= "<p class='alert-danger'><strong>❌ 검증 과정 오류:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function crackJWT($token) {
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 JWT 크랙킹 공격</h4>";
            
            // Node.js 서버로 JWT 크랙킹 요청
            $postData = json_encode([
                'action' => 'crack_jwt',
                'token' => $token
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/json',
                    'content' => $postData,
                    'timeout' => 30
                ]
            ]);
            
            $response = file_get_contents($this->nodeServerUrl . '/jwt', false, $context);
            
            if ($response === false) {
                throw new Exception("Node.js 서버 통신 실패");
            }
            
            $responseData = json_decode($response, true);
            
            if ($responseData['success']) {
                $result .= "<p><strong>🔍 크랙킹 결과:</strong></p>";
                
                if (isset($responseData['cracked_secret'])) {
                    $result .= "<p class='alert-danger'><strong>🚨 비밀 키 크랙 성공!</strong></p>";
                    $result .= "<p><strong>발견된 키:</strong> " . htmlspecialchars($responseData['cracked_secret']) . "</p>";
                    $result .= "<p><strong>크랙 방법:</strong> " . htmlspecialchars($responseData['crack_method']) . "</p>";
                    $result .= "<p><strong>소요 시간:</strong> " . htmlspecialchars($responseData['time_taken']) . "</p>";
                } else {
                    $result .= "<p class='alert-warning'><strong>🛡️ 크랙킹 실패</strong></p>";
                    $result .= "<p>비밀 키가 충분히 강력하여 크랙할 수 없었습니다.</p>";
                }
                
                if (isset($responseData['attempts'])) {
                    $result .= "<p><strong>시도된 공격:</strong></p>";
                    $result .= "<ul>";
                    foreach ($responseData['attempts'] as $attempt) {
                        $result .= "<li>" . htmlspecialchars($attempt) . "</li>";
                    }
                    $result .= "</ul>";
                }
                
            } else {
                $result .= "<p class='alert-danger'><strong>❌ 크랙킹 과정 오류:</strong> " . htmlspecialchars($responseData['error']) . "</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function getStoredTokens() {
        $result = '';
        
        try {
            $result .= "<div class='info-output'>";
            $result .= "<h4>💾 저장된 JWT 토큰</h4>";
            
            $stmt = $this->db->prepare("SELECT s.*, u.username, u.role FROM jwt_sessions s 
                                     JOIN jwt_users u ON s.user_id = u.id 
                                     WHERE s.is_valid = 1 AND s.expires_at > NOW() 
                                     ORDER BY s.created_at DESC LIMIT 10");
            $stmt->execute();
            $sessions = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if (empty($sessions)) {
                $result .= "<p>저장된 유효한 토큰이 없습니다.</p>";
            } else {
                $result .= "<table style='width: 100%; border-collapse: collapse; margin: 10px 0;'>";
                $result .= "<tr style='background: #f8f9fa; border-bottom: 1px solid #ddd;'>";
                $result .= "<th style='padding: 8px; text-align: left;'>사용자</th>";
                $result .= "<th style='padding: 8px; text-align: left;'>역할</th>";
                $result .= "<th style='padding: 8px; text-align: left;'>토큰 (앞 30자)</th>";
                $result .= "<th style='padding: 8px; text-align: left;'>만료일</th>";
                $result .= "</tr>";
                
                foreach ($sessions as $session) {
                    $result .= "<tr style='border-bottom: 1px solid #eee;'>";
                    $result .= "<td style='padding: 8px;'>" . htmlspecialchars($session['username']) . "</td>";
                    $result .= "<td style='padding: 8px;'><span class='role-badge role-" . $session['role'] . "'>" . htmlspecialchars($session['role']) . "</span></td>";
                    $result .= "<td style='padding: 8px; font-family: monospace; font-size: 10px;'>" . htmlspecialchars(substr($session['token'], 0, 30)) . "...</td>";
                    $result .= "<td style='padding: 8px;'>" . htmlspecialchars($session['expires_at']) . "</td>";
                    $result .= "</tr>";
                }
                
                $result .= "</table>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
}

$jwtTest = new JWTVulnerabilityTest($pdo);
$result = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'generate_vulnerable':
            $userId = (int)($_POST['user_id'] ?? 1);
            $result = $jwtTest->generateJWT($userId, true);
            break;
            
        case 'generate_secure':
            $userId = (int)($_POST['user_id'] ?? 1);
            $result = $jwtTest->generateJWT($userId, false);
            break;
            
        case 'manipulate':
            $token = $_POST['token'] ?? '';
            $manipulation = $_POST['manipulation'] ?? 'none_algorithm';
            if (!empty($token)) {
                $result = $jwtTest->manipulateJWT($token, $manipulation);
            } else {
                $result = "<div class='error-output'>❌ JWT 토큰을 입력해주세요.</div>";
            }
            break;
            
        case 'verify_vulnerable':
            $token = $_POST['token'] ?? '';
            if (!empty($token)) {
                $result = $jwtTest->verifyJWT($token, true);
            } else {
                $result = "<div class='error-output'>❌ JWT 토큰을 입력해주세요.</div>";
            }
            break;
            
        case 'verify_secure':
            $token = $_POST['token'] ?? '';
            if (!empty($token)) {
                $result = $jwtTest->verifyJWT($token, false);
            } else {
                $result = "<div class='error-output'>❌ JWT 토큰을 입력해주세요.</div>";
            }
            break;
            
        case 'crack':
            $token = $_POST['token'] ?? '';
            if (!empty($token)) {
                $result = $jwtTest->crackJWT($token);
            } else {
                $result = "<div class='error-output'>❌ JWT 토큰을 입력해주세요.</div>";
            }
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JWT 취약점 테스트</title>
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
            height: 120px;
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
        
        .crack-btn {
            background-color: #FF9800;
        }
        
        .crack-btn:hover {
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
        
        .three-column {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 15px;
        }
        
        .role-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        
        .role-admin {
            background-color: #f44336;
        }
        
        .role-moderator {
            background-color: #ff9800;
        }
        
        .role-user {
            background-color: #4caf50;
        }
        
        @media (max-width: 768px) {
            .two-column, .three-column {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 JWT 취약점 테스트</h1>
        
        <div class="description">
            <h3>🎯 JWT (JSON Web Token) 취약점이란?</h3>
            <p><strong>JWT</strong>는 웹 애플리케이션에서 사용자 인증과 정보 전달을 위한 토큰 기반 표준입니다. 부적절한 구현 시 심각한 보안 취약점이 발생할 수 있습니다.</p>
            
            <h4>🔍 주요 공격 벡터:</h4>
            <ul>
                <li><strong>None 알고리즘 공격</strong>: 서명 검증을 우회하여 토큰 조작</li>
                <li><strong>알고리즘 혼동 공격</strong>: 비대칭 키를 대칭 키로 사용하도록 속이기</li>
                <li><strong>약한 비밀 키</strong>: 브루트포스로 HMAC 키 크랙킹</li>
                <li><strong>키 혼동 공격</strong>: 공개 키를 비밀 키로 사용</li>
                <li><strong>페이로드 조작</strong>: 권한이나 사용자 정보 변경</li>
            </ul>
            
            <p><strong>⚠️ 실제 테스트:</strong> 이 페이지는 Node.js 서버를 통해 실제 JWT 생성, 조작, 검증을 수행합니다.</p>
        </div>

        <!-- 저장된 토큰 표시 -->
        <div class="test-section">
            <h3>💾 JWT 토큰 관리</h3>
            <?php echo $jwtTest->getStoredTokens(); ?>
        </div>

        <!-- JWT 생성 -->
        <div class="test-section">
            <h3>🔑 JWT 토큰 생성</h3>
            <div class="two-column">
                <div>
                    <h4>🔓 취약한 JWT 생성</h4>
                    <form method="post">
                        <div class="form-group">
                            <label for="user_id_vuln">사용자 선택:</label>
                            <select name="user_id" id="user_id_vuln">
                                <option value="1">admin (관리자)</option>
                                <option value="2">user (일반 사용자)</option>
                                <option value="3">moderator (중재자)</option>
                            </select>
                        </div>
                        
                        <input type="hidden" name="action" value="generate_vulnerable">
                        <button type="submit" class="dangerous-btn">🔓 취약한 JWT 생성</button>
                    </form>
                </div>
                
                <div>
                    <h4>🔒 안전한 JWT 생성</h4>
                    <form method="post">
                        <div class="form-group">
                            <label for="user_id_safe">사용자 선택:</label>
                            <select name="user_id" id="user_id_safe">
                                <option value="1">admin (관리자)</option>
                                <option value="2">user (일반 사용자)</option>
                                <option value="3">moderator (중재자)</option>
                            </select>
                        </div>
                        
                        <input type="hidden" name="action" value="generate_secure">
                        <button type="submit" class="safe-btn">🔒 안전한 JWT 생성</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- JWT 조작 -->
        <div class="test-section">
            <h3>🛠️ JWT 토큰 조작</h3>
            <form method="post">
                <div class="form-group">
                    <label for="token_manipulate">JWT 토큰:</label>
                    <textarea name="token" id="token_manipulate" placeholder="JWT 토큰을 입력하세요..."></textarea>
                </div>
                
                <div class="form-group">
                    <label for="manipulation">조작 유형:</label>
                    <select name="manipulation" id="manipulation">
                        <option value="none_algorithm">None 알고리즘 공격</option>
                        <option value="algorithm_confusion">알고리즘 혼동 (RS256 → HS256)</option>
                        <option value="role_elevation">권한 상승 (user → admin)</option>
                        <option value="expiry_extension">만료 시간 연장</option>
                        <option value="signature_stripping">서명 제거</option>
                    </select>
                </div>
                
                <input type="hidden" name="action" value="manipulate">
                <button type="submit" class="dangerous-btn">⚡ JWT 조작 실행</button>
            </form>
        </div>

        <!-- JWT 검증 -->
        <div class="test-section">
            <h3>🔍 JWT 토큰 검증</h3>
            <form method="post">
                <div class="form-group">
                    <label for="token_verify">JWT 토큰:</label>
                    <textarea name="token" id="token_verify" placeholder="검증할 JWT 토큰을 입력하세요..."></textarea>
                </div>
                
                <div style="display: flex; gap: 10px;">
                    <button type="submit" name="action" value="verify_vulnerable" class="dangerous-btn" style="flex: 1;">
                        🔓 취약한 검증
                    </button>
                    <button type="submit" name="action" value="verify_secure" class="safe-btn" style="flex: 1;">
                        🔒 안전한 검증
                    </button>
                </div>
            </form>
        </div>

        <!-- JWT 크랙킹 -->
        <div class="test-section">
            <h3>💥 JWT 크랙킹 공격</h3>
            <p>약한 비밀 키로 서명된 JWT 토큰에 대해 브루트포스 공격을 수행합니다.</p>
            
            <form method="post">
                <div class="form-group">
                    <label for="token_crack">JWT 토큰:</label>
                    <textarea name="token" id="token_crack" placeholder="크랙킹할 JWT 토큰을 입력하세요..."></textarea>
                </div>
                
                <input type="hidden" name="action" value="crack">
                <button type="submit" class="crack-btn">💥 비밀 키 크랙킹 시도</button>
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
            <h3>🛡️ JWT 보안 권장사항</h3>
            <div class="safe-output">
                <h4>JWT 보안 강화 방법:</h4>
                
                <h5>1. 강력한 비밀 키 사용:</h5>
                <pre><code>// 최소 32바이트의 랜덤 키 사용
const crypto = require('crypto');
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// 환경 변수로 관리
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters');
}</code></pre>
                
                <h5>2. 알고리즘 명시적 지정:</h5>
                <pre><code>// 취약한 예시 (알고리즘 검증 없음)
jwt.verify(token, secret); // ❌

// 안전한 예시 (알고리즘 명시)
jwt.verify(token, secret, { algorithms: ['HS256'] }); // ✅

// None 알고리즘 차단
jwt.verify(token, secret, { 
    algorithms: ['HS256', 'RS256'], 
    ignoreNotBefore: false 
});</code></pre>
                
                <h5>3. 토큰 만료 시간 설정:</h5>
                <pre><code>// 짧은 만료 시간 설정
const token = jwt.sign(payload, secret, { 
    expiresIn: '15m',  // 15분
    issuer: 'your-app',
    audience: 'your-users'
});

// 리프레시 토큰 패턴 사용
const accessToken = jwt.sign(payload, secret, { expiresIn: '15m' });
const refreshToken = jwt.sign(payload, refreshSecret, { expiresIn: '7d' });</code></pre>
                
                <h5>4. 클레임 검증:</h5>
                <pre><code>// 모든 클레임 검증
jwt.verify(token, secret, {
    algorithms: ['HS256'],
    issuer: 'your-app',
    audience: 'your-users',
    clockTolerance: 30, // 30초 클록 편차 허용
    maxAge: '1h' // 최대 1시간
}, (err, decoded) => {
    if (err) {
        // 토큰 검증 실패 처리
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    // 추가 검증 (사용자 존재 여부, 권한 등)
    if (!decoded.sub || decoded.role !== 'admin') {
        return res.status(403).json({ error: 'Insufficient privileges' });
    }
});</code></pre>
                
                <h5>5. 보안 헤더와 쿠키 설정:</h5>
                <pre><code>// HTTP-Only 쿠키로 JWT 저장
res.cookie('token', token, {
    httpOnly: true,     // XSS 방지
    secure: true,       // HTTPS only
    sameSite: 'strict', // CSRF 방지
    maxAge: 15 * 60 * 1000 // 15분
});

// Authorization 헤더 사용 시
app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    // 토큰 검증...
});</code></pre>
                
                <p><strong>✅ 핵심 원칙:</strong> JWT는 단순해 보이지만 올바르지 않게 구현하면 심각한 보안 취약점이 발생합니다. 항상 알고리즘을 명시하고, 강력한 키를 사용하며, 모든 클레임을 검증하세요.</p>
            </div>
        </div>
    </div>

    <script>
        // 토큰 복사 기능
        document.addEventListener('DOMContentLoaded', function() {
            const textareas = document.querySelectorAll('textarea[readonly]');
            textareas.forEach(textarea => {
                textarea.addEventListener('click', function() {
                    this.select();
                    navigator.clipboard.writeText(this.value).then(() => {
                        // 임시 피드백 표시
                        const originalBorder = this.style.border;
                        this.style.border = '2px solid #4CAF50';
                        setTimeout(() => {
                            this.style.border = originalBorder;
                        }, 1000);
                    });
                });
            });
        });

        // 토큰 자동 복사 기능 (생성된 토큰을 다른 입력창에)
        function copyTokenToFields(token) {
            document.getElementById('token_manipulate').value = token;
            document.getElementById('token_verify').value = token;
            document.getElementById('token_crack').value = token;
        }
    </script>
</body>
</html>