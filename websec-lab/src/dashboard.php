<?php
session_start();
require_once __DIR__ . '/db.php';

class VulnerabilityDashboard {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
        $this->initializeDashboardDatabase();
    }
    
    private function initializeDashboardDatabase() {
        // 대시보드용 테이블 생성
        $tables = [
            "CREATE TABLE IF NOT EXISTS dashboard_tests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                test_name VARCHAR(100) NOT NULL,
                test_category VARCHAR(50) NOT NULL,
                test_file VARCHAR(200) NOT NULL,
                description TEXT,
                difficulty ENUM('basic', 'intermediate', 'advanced') DEFAULT 'basic',
                status ENUM('available', 'maintenance', 'deprecated') DEFAULT 'available',
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                test_count INT DEFAULT 0
            )",
            "CREATE TABLE IF NOT EXISTS dashboard_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                test_name VARCHAR(100) NOT NULL,
                result_type ENUM('vulnerable', 'safe', 'error') NOT NULL,
                execution_time DECIMAL(8,3) DEFAULT 0.000,
                payload_used TEXT,
                result_data LONGTEXT,
                user_agent VARCHAR(255),
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            "CREATE TABLE IF NOT EXISTS dashboard_stats (
                id INT AUTO_INCREMENT PRIMARY KEY,
                stat_date DATE NOT NULL,
                total_tests INT DEFAULT 0,
                vulnerable_results INT DEFAULT 0,
                safe_results INT DEFAULT 0,
                error_results INT DEFAULT 0,
                unique_visitors INT DEFAULT 0,
                UNIQUE KEY unique_date (stat_date)
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->db->exec($sql);
        }
        
        // 기본 테스트 데이터 삽입
        $this->initializeTestData();
    }
    
    private function initializeTestData() {
        $tests = [
            // 기본 취약점
            ['SQL Injection', 'Web Application', 'webhacking/sql_injection.php', 'SQL 쿼리 주입을 통한 데이터베이스 조작', 'basic'],
            ['XSS (Cross-Site Scripting)', 'Web Application', 'webhacking/xss.php', '악성 스크립트 주입을 통한 사용자 공격', 'basic'],
            ['Command Injection', 'System', 'webhacking/command_injection.php', '시스템 명령어 주입을 통한 서버 제어', 'basic'],
            ['File Upload Vulnerability', 'File System', 'webhacking/file_upload.php', '위험한 파일 업로드를 통한 서버 장악', 'basic'],
            ['CSRF Attack', 'Web Application', 'webhacking/csrf.php', '사용자 권한을 악용한 요청 위조', 'basic'],
            ['Directory Traversal', 'File System', 'webhacking/directory_traversal.php', '경로 순회를 통한 시스템 파일 접근', 'basic'],
            ['File Inclusion (LFI/RFI)', 'File System', 'webhacking/file_inclusion.php', '파일 포함을 통한 코드 실행', 'basic'],
            ['Authentication Bypass', 'Authentication', 'webhacking/auth_bypass.php', '인증 우회를 통한 권한 상승', 'basic'],
            
            // 중간 우선순위
            ['XXE (XML External Entity)', 'XML Processing', 'webhacking/xxe.php', 'XML 외부 엔티티를 통한 정보 유출', 'intermediate'],
            ['SSRF (Server-Side Request Forgery)', 'Network', 'webhacking/ssrf.php', '서버측 요청 위조를 통한 내부망 접근', 'intermediate'],
            ['SSTI (Server-Side Template Injection)', 'Template Engine', 'webhacking/ssti.php', '템플릿 엔진 취약점을 통한 코드 실행', 'intermediate'],
            ['Open Redirect', 'Web Application', 'webhacking/open_redirect.php', '오픈 리다이렉트를 통한 피싱 공격', 'intermediate'],
            ['XPath Injection', 'XML Processing', 'webhacking/xpath_injection.php', 'XPath 쿼리 조작을 통한 데이터 추출', 'intermediate'],
            
            // 고급 환경
            ['NoSQL Injection', 'Database', 'webhacking/nosql_injection.php', 'NoSQL 데이터베이스 조작 및 우회', 'advanced'],
            ['Cache Injection', 'Caching System', 'webhacking/cache_injection.php', 'Redis 캐시 조작 및 데이터 오염', 'advanced'],
            ['Java Deserialization', 'Serialization', 'webhacking/java_deserialization.php', 'Java 객체 직렬화를 통한 RCE', 'advanced'],
            
            // Advanced 모듈
            ['Business Logic Vulnerability', 'Business Logic', 'webhacking/business_logic.php', '비즈니스 로직 취약점을 통한 우회', 'advanced'],
            ['Race Condition', 'Concurrency', 'webhacking/race_condition.php', '동시성 취약점을 통한 데이터 조작', 'advanced'],
            ['Advanced Deserialization', 'Serialization', 'webhacking/advanced_deserialization.php', '다양한 언어의 직렬화 취약점', 'advanced'],
            
            // API Security Testing
            ['API Security Testing', 'API Security', 'webhacking/api_security.php', 'REST API, GraphQL, JWT 등 API 보안 종합 테스트', 'advanced']
        ];
        
        $stmt = $this->db->prepare("INSERT IGNORE INTO dashboard_tests (test_name, test_category, test_file, description, difficulty) VALUES (?, ?, ?, ?, ?)");
        
        foreach ($tests as $test) {
            $stmt->execute($test);
        }
    }
    
    public function getAllTests() {
        $stmt = $this->db->prepare("SELECT * FROM dashboard_tests WHERE status = 'available' ORDER BY 
            FIELD(difficulty, 'basic', 'intermediate', 'advanced'), test_name ASC");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function getTestsByCategory() {
        $stmt = $this->db->prepare("SELECT test_category, COUNT(*) as count FROM dashboard_tests WHERE status = 'available' GROUP BY test_category ORDER BY count DESC");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function getDashboardStats() {
        $stats = [];
        
        // 총 테스트 수
        $stmt = $this->db->prepare("SELECT COUNT(*) as total_tests FROM dashboard_tests WHERE status = 'available'");
        $stmt->execute();
        $stats['total_tests'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_tests'];
        
        // 난이도별 분포
        $stmt = $this->db->prepare("SELECT difficulty, COUNT(*) as count FROM dashboard_tests WHERE status = 'available' GROUP BY difficulty");
        $stmt->execute();
        $difficulty_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $stats['basic'] = 0;
        $stats['intermediate'] = 0;
        $stats['advanced'] = 0;
        
        foreach ($difficulty_stats as $stat) {
            $stats[$stat['difficulty']] = $stat['count'];
        }
        
        // 최근 30일간 테스트 결과 통계
        $stmt = $this->db->prepare("SELECT 
            COUNT(*) as total_results,
            SUM(CASE WHEN result_type = 'vulnerable' THEN 1 ELSE 0 END) as vulnerable_count,
            SUM(CASE WHEN result_type = 'safe' THEN 1 ELSE 0 END) as safe_count,
            SUM(CASE WHEN result_type = 'error' THEN 1 ELSE 0 END) as error_count
            FROM dashboard_results 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)");
        $stmt->execute();
        $result_stats = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $stats = array_merge($stats, $result_stats);
        
        return $stats;
    }
    
    public function logTestResult($test_name, $result_type, $execution_time, $payload_used = '', $result_data = '') {
        $stmt = $this->db->prepare("INSERT INTO dashboard_results 
            (test_name, result_type, execution_time, payload_used, result_data, user_agent, ip_address) 
            VALUES (?, ?, ?, ?, ?, ?, ?)");
            
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        
        $stmt->execute([$test_name, $result_type, $execution_time, $payload_used, $result_data, $user_agent, $ip_address]);
        
        // 테스트 카운트 증가
        $stmt = $this->db->prepare("UPDATE dashboard_tests SET test_count = test_count + 1 WHERE test_name = ?");
        $stmt->execute([$test_name]);
    }
    
    public function getRecentResults($limit = 10) {
        $stmt = $this->db->prepare("SELECT test_name, result_type, execution_time, created_at 
            FROM dashboard_results 
            ORDER BY created_at DESC 
            LIMIT ?");
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function executeVulnerabilityTest($test_file, $payload = '') {
        $start_time = microtime(true);
        $result = [];
        
        try {
            $file_path = __DIR__ . '/' . $test_file;
            
            if (!file_exists($file_path)) {
                throw new Exception("테스트 파일을 찾을 수 없습니다: $test_file");
            }
            
            // 대신 파일 URL로 리다이렉트하는 방식으로 변경
            $execution_time = microtime(true) - $start_time;
            
            // 테스트 파일의 웹 경로 생성
            $web_path = str_replace(__DIR__ . '/', '', $file_path);
            $web_url = '/' . $web_path;
            
            $result = [
                'success' => true,
                'redirect_url' => $web_url,
                'execution_time' => round($execution_time * 1000, 3),
                'message' => '테스트 페이지로 이동합니다.'
            ];
            
        } catch (Exception $e) {
            $execution_time = microtime(true) - $start_time;
            
            $result = [
                'success' => false,
                'output' => '',
                'execution_time' => round($execution_time * 1000, 3),
                'message' => '테스트 실행 중 오류 발생: ' . $e->getMessage()
            ];
        }
        
        return $result;
    }
    
    public function generateVulnerabilityReport($test_name = '', $date_from = '', $date_to = '') {
        $where_conditions = [];
        $params = [];
        
        if (!empty($test_name)) {
            $where_conditions[] = "test_name = ?";
            $params[] = $test_name;
        }
        
        if (!empty($date_from)) {
            $where_conditions[] = "created_at >= ?";
            $params[] = $date_from . ' 00:00:00';
        }
        
        if (!empty($date_to)) {
            $where_conditions[] = "created_at <= ?";
            $params[] = $date_to . ' 23:59:59';
        }
        
        $where_sql = !empty($where_conditions) ? 'WHERE ' . implode(' AND ', $where_conditions) : '';
        
        $sql = "SELECT 
            test_name,
            result_type,
            COUNT(*) as count,
            AVG(execution_time) as avg_execution_time,
            MIN(created_at) as first_test,
            MAX(created_at) as last_test
            FROM dashboard_results 
            $where_sql
            GROUP BY test_name, result_type 
            ORDER BY test_name, result_type";
            
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

// 메인 처리
global $pdo;
if (!isset($pdo) || !$pdo) {
    die("데이터베이스 연결에 실패했습니다. 설정을 확인해주세요.");
}
$dashboard = new VulnerabilityDashboard($pdo);
$result = '';
$ajax_response = null;

// AJAX 요청 처리
if (isset($_POST['ajax_action'])) {
    header('Content-Type: application/json');
    
    switch ($_POST['ajax_action']) {
        case 'execute_test':
            $test_file = $_POST['test_file'] ?? '';
            $payload = $_POST['payload'] ?? '';
            $test_name = $_POST['test_name'] ?? '';
            
            $test_result = $dashboard->executeVulnerabilityTest($test_file, $payload);
            
            // 결과 로깅
            $result_type = $test_result['success'] ? 'vulnerable' : 'error';
            $dashboard->logTestResult($test_name, $result_type, $test_result['execution_time'], $payload, $test_result['output']);
            
            echo json_encode($test_result);
            exit;
            
        case 'get_stats':
            $stats = $dashboard->getDashboardStats();
            echo json_encode($stats);
            exit;
            
        case 'get_recent_results':
            $recent = $dashboard->getRecentResults(20);
            echo json_encode($recent);
            exit;
            
        case 'log_result':
            $test_name = $_POST['test_name'] ?? '';
            $result_type = $_POST['result_type'] ?? 'vulnerable';
            $execution_time = (float)($_POST['execution_time'] ?? 0);
            
            $dashboard->logTestResult($test_name, $result_type, $execution_time);
            echo json_encode(['success' => true]);
            exit;
    }
}

// 일반 POST 요청 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['ajax_action'])) {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'generate_report') {
        $test_name = $_POST['test_name'] ?? '';
        $date_from = $_POST['date_from'] ?? '';
        $date_to = $_POST['date_to'] ?? '';
        
        $report_data = $dashboard->generateVulnerabilityReport($test_name, $date_from, $date_to);
        $result = $dashboard->formatReportHTML($report_data, $test_name, $date_from, $date_to);
    }
}

$all_tests = $dashboard->getAllTests();
$test_categories = $dashboard->getTestsByCategory();
$stats = $dashboard->getDashboardStats();
$recent_results = $dashboard->getRecentResults(10);
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ WebSec-Lab 통합 대시보드</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --danger-color: #e74c3c;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --info-color: #17a2b8;
            --light-bg: #ecf0f1;
            --dark-bg: #34495e;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--light-bg);
            color: var(--primary-color);
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 30px;
            margin-top: 30px;
        }
        
        .sidebar {
            background: white;
            border-radius: 10px;
            padding: 25px;
            height: fit-content;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            position: sticky;
            top: 20px;
        }
        
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 30px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.basic {
            border-left: 5px solid var(--success-color);
        }
        
        .stat-card.intermediate {
            border-left: 5px solid var(--warning-color);
        }
        
        .stat-card.advanced {
            border-left: 5px solid var(--danger-color);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: #666;
            font-weight: 500;
        }
        
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        
        .test-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .test-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.15);
        }
        
        .test-card.basic::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--success-color);
        }
        
        .test-card.intermediate::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--warning-color);
        }
        
        .test-card.advanced::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--danger-color);
        }
        
        .test-card h3 {
            margin-bottom: 1rem;
            color: var(--primary-color);
            font-size: 1.3rem;
        }
        
        .test-card p {
            color: #666;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }
        
        .test-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            font-size: 0.85rem;
        }
        
        .difficulty-badge {
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.75rem;
        }
        
        .difficulty-badge.basic {
            background: var(--success-color);
        }
        
        .difficulty-badge.intermediate {
            background: var(--warning-color);
        }
        
        .difficulty-badge.advanced {
            background: var(--danger-color);
        }
        
        .test-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
            font-size: 0.9rem;
        }
        
        .btn-primary {
            background: var(--secondary-color);
            color: white;
        }
        
        .btn-primary:hover {
            background: #2980b9;
        }
        
        .btn-danger {
            background: var(--danger-color);
            color: white;
        }
        
        .btn-danger:hover {
            background: #c0392b;
        }
        
        .btn-success {
            background: var(--success-color);
            color: white;
        }
        
        .btn-success:hover {
            background: #219a52;
        }
        
        .sidebar h3 {
            margin-bottom: 1rem;
            color: var(--primary-color);
            font-size: 1.2rem;
        }
        
        .category-list {
            list-style: none;
            margin-bottom: 2rem;
        }
        
        .category-list li {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .category-count {
            background: var(--secondary-color);
            color: white;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .recent-results {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .result-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }
        
        .result-item:last-child {
            border-bottom: none;
        }
        
        .result-status {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .result-status.vulnerable {
            background: #ffebee;
            color: var(--danger-color);
        }
        
        .result-status.safe {
            background: #e8f5e8;
            color: var(--success-color);
        }
        
        .result-status.error {
            background: #fff3e0;
            color: var(--warning-color);
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            border-radius: 10px;
            padding: 30px;
            max-width: 800px;
            width: 90%;
            max-height: 90%;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #eee;
        }
        
        .close {
            font-size: 28px;
            cursor: pointer;
            color: #999;
        }
        
        .close:hover {
            color: #333;
        }
        
        .test-output {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 20px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid var(--secondary-color);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .filter-section {
            margin-bottom: 2rem;
        }
        
        .filter-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid var(--secondary-color);
            background: white;
            color: var(--secondary-color);
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .filter-btn.active {
            background: var(--secondary-color);
            color: white;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
            
            .test-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .container {
                padding: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WebSec-Lab 통합 대시보드</h1>
        <p>종합적인 웹 보안 취약점 테스트 플랫폼</p>
    </div>
    
    <div class="container">
        <!-- 통계 카드 -->
        <div class="stats-grid">
            <div class="stat-card basic">
                <div class="stat-number"><?php echo $stats['basic']; ?></div>
                <div class="stat-label">기본 취약점</div>
            </div>
            <div class="stat-card intermediate">
                <div class="stat-number"><?php echo $stats['intermediate']; ?></div>
                <div class="stat-label">중급 취약점</div>
            </div>
            <div class="stat-card advanced">
                <div class="stat-number"><?php echo $stats['advanced']; ?></div>
                <div class="stat-label">고급 취약점</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $stats['total_results'] ?? 0; ?></div>
                <div class="stat-label">총 테스트 실행</div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <!-- 사이드바 -->
            <div class="sidebar">
                <h3>📊 카테고리별 분류</h3>
                <ul class="category-list">
                    <?php foreach ($test_categories as $category): ?>
                    <li>
                        <span><?php echo htmlspecialchars($category['test_category']); ?></span>
                        <span class="category-count"><?php echo $category['count']; ?></span>
                    </li>
                    <?php endforeach; ?>
                </ul>
                
                <h3>🕒 최근 테스트 결과</h3>
                <div class="recent-results">
                    <?php foreach ($recent_results as $result): ?>
                    <div class="result-item">
                        <div>
                            <div style="font-weight: bold; font-size: 0.9rem;">
                                <?php echo htmlspecialchars($result['test_name']); ?>
                            </div>
                            <div style="font-size: 0.8rem; color: #666;">
                                <?php echo date('m/d H:i', strtotime($result['created_at'])); ?>
                            </div>
                        </div>
                        <span class="result-status <?php echo $result['result_type']; ?>">
                            <?php 
                            $status_text = [
                                'vulnerable' => '취약',
                                'safe' => '안전',
                                'error' => '오류'
                            ];
                            echo $status_text[$result['result_type']] ?? $result['result_type'];
                            ?>
                        </span>
                    </div>
                    <?php endforeach; ?>
                </div>
                
                <div style="margin-top: 2rem;">
                    <button class="btn btn-success" onclick="refreshStats()">
                        🔄 통계 새로고침
                    </button>
                </div>
            </div>
            
            <!-- 메인 콘텐츠 -->
            <div class="main-content">
                <!-- 필터 섹션 -->
                <div class="filter-section">
                    <h3>🔍 필터링</h3>
                    <div class="filter-buttons">
                        <button class="filter-btn active" data-filter="all">전체</button>
                        <button class="filter-btn" data-filter="basic">기본</button>
                        <button class="filter-btn" data-filter="intermediate">중급</button>
                        <button class="filter-btn" data-filter="advanced">고급</button>
                        <button class="filter-btn" data-filter="Web Application">웹 애플리케이션</button>
                        <button class="filter-btn" data-filter="Database">데이터베이스</button>
                        <button class="filter-btn" data-filter="System">시스템</button>
                    </div>
                </div>
                
                <!-- 취약점 테스트 카드 -->
                <div class="test-grid">
                    <?php foreach ($all_tests as $test): ?>
                    <div class="test-card <?php echo $test['difficulty']; ?>" 
                         data-difficulty="<?php echo $test['difficulty']; ?>" 
                         data-category="<?php echo $test['test_category']; ?>">
                        <h3><?php echo htmlspecialchars($test['test_name']); ?></h3>
                        <p><?php echo htmlspecialchars($test['description']); ?></p>
                        
                        <div class="test-meta">
                            <span class="difficulty-badge <?php echo $test['difficulty']; ?>">
                                <?php 
                                $difficulty_text = [
                                    'basic' => '기본',
                                    'intermediate' => '중급', 
                                    'advanced' => '고급'
                                ];
                                echo $difficulty_text[$test['difficulty']];
                                ?>
                            </span>
                            <span style="color: #666;">
                                📂 <?php echo htmlspecialchars($test['test_category']); ?>
                            </span>
                        </div>
                        
                        <div style="font-size: 0.85rem; color: #666; margin-bottom: 1rem;">
                            🧪 실행 횟수: <?php echo number_format($test['test_count']); ?>회
                        </div>
                        
                        <div class="test-actions">
                            <a href="<?php echo $test['test_file']; ?>" 
                               target="_blank" 
                               class="btn btn-primary">
                                🔗 직접 접속
                            </a>
                            <button class="btn btn-danger" 
                                    onclick="executeTest('<?php echo htmlspecialchars($test['test_name']); ?>', '<?php echo $test['test_file']; ?>')">
                                ⚡ 실행 테스트
                            </button>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 테스트 실행 모달 -->
    <div id="testModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">취약점 테스트 실행</h2>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <div id="modalBody">
                <div class="loading" id="loadingSpinner">
                    <div class="spinner"></div>
                    <p>테스트를 실행하고 있습니다...</p>
                </div>
                <div id="testResults" style="display: none;">
                    <h4>🎯 테스트 결과:</h4>
                    <div id="executionInfo" style="margin-bottom: 15px;"></div>
                    <div class="test-output" id="testOutput"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // 전역 변수
        let currentTests = <?php echo json_encode($all_tests); ?>;
        
        // 필터링 기능
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                // 활성 버튼 업데이트
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                
                const filter = this.getAttribute('data-filter');
                filterTests(filter);
            });
        });
        
        function filterTests(filter) {
            const testCards = document.querySelectorAll('.test-card');
            
            testCards.forEach(card => {
                const difficulty = card.getAttribute('data-difficulty');
                const category = card.getAttribute('data-category');
                
                if (filter === 'all') {
                    card.style.display = 'block';
                } else if (filter === difficulty || filter === category) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }
        
        // 테스트 실행 함수
        async function executeTest(testName, testFile) {
            const modal = document.getElementById('testModal');
            const modalTitle = document.getElementById('modalTitle');
            const loading = document.getElementById('loadingSpinner');
            const results = document.getElementById('testResults');
            
            modalTitle.textContent = `🧪 ${testName} 실행 중`;
            loading.style.display = 'block';
            results.style.display = 'none';
            modal.style.display = 'block';
            
            try {
                const formData = new FormData();
                formData.append('ajax_action', 'execute_test');
                formData.append('test_name', testName);
                formData.append('test_file', testFile);
                formData.append('payload', ''); // 기본 페이로드
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                loading.style.display = 'none';
                
                if (result.success && result.redirect_url) {
                    // 새 탭에서 테스트 페이지 열기
                    window.open(result.redirect_url, '_blank');
                    closeModal();
                    
                    // 결과 로깅
                    const resultType = 'vulnerable'; // 기본값
                    logTestResult(testName, resultType, result.execution_time);
                    
                } else if (result.success) {
                    results.style.display = 'block';
                    modalTitle.textContent = `📊 ${testName} 실행 결과`;
                    
                    const executionInfo = document.getElementById('executionInfo');
                    const testOutput = document.getElementById('testOutput');
                    
                    executionInfo.innerHTML = `
                        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                            <span><strong>🎯 상태:</strong> ✅ 성공</span>
                            <span><strong>⏱️ 실행 시간:</strong> ${result.execution_time}ms</span>
                            <span><strong>📝 메시지:</strong> ${result.message}</span>
                        </div>
                    `;
                    
                    testOutput.innerHTML = result.output || '출력 데이터가 없습니다.';
                } else {
                    // 오류 표시
                    results.style.display = 'block';
                    modalTitle.textContent = `❌ ${testName} 실행 오류`;
                    
                    const executionInfo = document.getElementById('executionInfo');
                    const testOutput = document.getElementById('testOutput');
                    
                    executionInfo.innerHTML = `
                        <div style="color: #e74c3c;">
                            <span><strong>❌ 오류:</strong> ${result.message}</span>
                            <span><strong>⏱️ 실행 시간:</strong> ${result.execution_time}ms</span>
                        </div>
                    `;
                    
                    testOutput.innerHTML = '테스트 실행 중 오류가 발생했습니다.';
                }
                
                // 통계 새로고침
                refreshStats();
                
            } catch (error) {
                loading.style.display = 'none';
                results.style.display = 'block';
                
                modalTitle.textContent = `❌ ${testName} 실행 오류`;
                
                document.getElementById('executionInfo').innerHTML = `
                    <span style="color: #e74c3c;"><strong>오류:</strong> ${error.message}</span>
                `;
                document.getElementById('testOutput').innerHTML = '테스트 실행 중 오류가 발생했습니다.';
            }
        }
        
        // 모달 닫기
        function closeModal() {
            document.getElementById('testModal').style.display = 'none';
        }
        
        // 모달 외부 클릭 시 닫기
        window.onclick = function(event) {
            const modal = document.getElementById('testModal');
            if (event.target === modal) {
                closeModal();
            }
        }
        
        // 테스트 결과 로깅
        async function logTestResult(testName, resultType, executionTime) {
            try {
                const formData = new FormData();
                formData.append('ajax_action', 'log_result');
                formData.append('test_name', testName);
                formData.append('result_type', resultType);
                formData.append('execution_time', executionTime);
                
                await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });
            } catch (error) {
                console.error('결과 로깅 오류:', error);
            }
        }
        
        // 통계 새로고침
        async function refreshStats() {
            try {
                const formData = new FormData();
                formData.append('ajax_action', 'get_recent_results');
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });
                
                const recentResults = await response.json();
                updateRecentResults(recentResults);
                
            } catch (error) {
                console.error('통계 새로고침 오류:', error);
            }
        }
        
        function updateRecentResults(results) {
            const container = document.querySelector('.recent-results');
            const statusText = {
                'vulnerable': '취약',
                'safe': '안전',
                'error': '오류'
            };
            
            container.innerHTML = results.map(result => `
                <div class="result-item">
                    <div>
                        <div style="font-weight: bold; font-size: 0.9rem;">
                            ${result.test_name}
                        </div>
                        <div style="font-size: 0.8rem; color: #666;">
                            ${new Date(result.created_at).toLocaleDateString('ko-KR', {
                                month: '2-digit', 
                                day: '2-digit', 
                                hour: '2-digit', 
                                minute: '2-digit'
                            })}
                        </div>
                    </div>
                    <span class="result-status ${result.result_type}">
                        ${statusText[result.result_type] || result.result_type}
                    </span>
                </div>
            `).join('');
        }
        
        // 키보드 이벤트
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeModal();
            }
        });
        
        // 페이지 로드 시 초기화
        document.addEventListener('DOMContentLoaded', function() {
            // 3분마다 통계 자동 새로고침
            setInterval(refreshStats, 180000);
        });
    </script>
</body>
</html>