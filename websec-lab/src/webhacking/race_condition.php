<?php
session_start();
include_once '../db_connection.php';

class RaceConditionTest {
    private $db;
    private $redis;
    
    public function __construct($db, $redis = null) {
        $this->db = $db;
        $this->redis = $redis;
        $this->initializeDatabase();
    }
    
    private function initializeDatabase() {
        // Race condition 테스트용 테이블 생성
        $tables = [
            "CREATE TABLE IF NOT EXISTS rc_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                balance DECIMAL(10,2) DEFAULT 1000.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            "CREATE TABLE IF NOT EXISTS rc_transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                amount DECIMAL(10,2),
                transaction_type ENUM('debit', 'credit'),
                status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES rc_users(id)
            )",
            "CREATE TABLE IF NOT EXISTS rc_counters (
                id INT AUTO_INCREMENT PRIMARY KEY,
                counter_name VARCHAR(50) UNIQUE,
                counter_value INT DEFAULT 0
            )"
        ];
        
        foreach ($tables as $sql) {
            $this->db->exec($sql);
        }
        
        // 테스트 데이터 삽입
        $this->db->exec("INSERT IGNORE INTO rc_users (id, username, balance) VALUES 
            (1, 'testuser', 1000.00),
            (2, 'victim', 500.00)");
        $this->db->exec("INSERT IGNORE INTO rc_counters (counter_name, counter_value) VALUES 
            ('clicks', 0),
            ('downloads', 0)");
    }
    
    public function vulnerableTOCTOU($user_id, $amount) {
        // TOCTOU (Time-of-Check-Time-of-Use) 취약한 구현
        $result = '';
        
        try {
            // Step 1: Check 단계
            $stmt = $this->db->prepare("SELECT balance FROM rc_users WHERE id = ?");
            $stmt->execute([$user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                return "<div class='error-output'>❌ 사용자를 찾을 수 없습니다.</div>";
            }
            
            $current_balance = (float)$user['balance'];
            
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 취약한 TOCTOU 구현</h4>";
            $result .= "<p><strong>Step 1 - Check:</strong> 현재 잔액: $" . number_format($current_balance, 2) . "</p>";
            
            // 잔액 확인
            if ($current_balance >= $amount) {
                $result .= "<p><strong>✅ 잔액 충분:</strong> 거래 승인</p>";
                
                // 🚨 CRITICAL VULNERABILITY: 시간 지연으로 Race Condition 유발
                $result .= "<p><strong>⏰ Processing...</strong> (2초 대기 - Race Condition 유발)</p>";
                sleep(2); // 실제 공격에서는 네트워크 지연이나 처리 시간
                
                // Step 2: Use 단계 (이 시점에서 다른 요청이 잔액을 변경했을 수 있음)
                $stmt = $this->db->prepare("UPDATE rc_users SET balance = balance - ? WHERE id = ?");
                $stmt->execute([$amount, $user_id]);
                
                // 변경된 잔액 조회
                $stmt = $this->db->prepare("SELECT balance FROM rc_users WHERE id = ?");
                $stmt->execute([$user_id]);
                $updated_user = $stmt->fetch(PDO::FETCH_ASSOC);
                $new_balance = (float)$updated_user['balance'];
                
                $result .= "<p><strong>Step 2 - Use:</strong> $" . number_format($amount, 2) . " 차감 완료</p>";
                $result .= "<p><strong>⚠️ 최종 잔액:</strong> $" . number_format($new_balance, 2) . "</p>";
                
                if ($new_balance < 0) {
                    $result .= "<p class='alert-danger'><strong>🚨 Race Condition 성공!</strong> 잔액이 음수가 되었습니다!</p>";
                }
                
                // 거래 기록
                $stmt = $this->db->prepare("INSERT INTO rc_transactions (user_id, amount, transaction_type, status) VALUES (?, ?, 'debit', 'completed')");
                $stmt->execute([$user_id, $amount]);
                
            } else {
                $result .= "<p class='alert-warning'><strong>❌ 잔액 부족:</strong> 거래 거부</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function safeTOCTOU($user_id, $amount) {
        // 안전한 원자적 구현
        $result = '';
        
        try {
            $this->db->beginTransaction();
            
            $result .= "<div class='safe-output'>";
            $result .= "<h4>🔒 안전한 원자적 거래 구현</h4>";
            
            // 원자적 업데이트 (한 번의 쿼리로 확인과 차감을 동시에)
            $stmt = $this->db->prepare("UPDATE rc_users SET balance = balance - ? WHERE id = ? AND balance >= ?");
            $stmt->execute([$amount, $user_id, $amount]);
            
            $affected_rows = $stmt->rowCount();
            
            if ($affected_rows > 0) {
                // 성공적으로 차감됨
                $stmt = $this->db->prepare("SELECT balance FROM rc_users WHERE id = ?");
                $stmt->execute([$user_id]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                $new_balance = (float)$user['balance'];
                
                // 거래 기록
                $stmt = $this->db->prepare("INSERT INTO rc_transactions (user_id, amount, transaction_type, status) VALUES (?, ?, 'debit', 'completed')");
                $stmt->execute([$user_id, $amount]);
                
                $this->db->commit();
                
                $result .= "<p><strong>✅ 원자적 거래 완료:</strong> $" . number_format($amount, 2) . " 차감</p>";
                $result .= "<p><strong>현재 잔액:</strong> $" . number_format($new_balance, 2) . "</p>";
                $result .= "<p class='alert-success'><strong>🔒 Race Condition 방지 성공!</strong> 잔액이 음수가 되지 않았습니다.</p>";
                
            } else {
                // 잔액 부족으로 실패
                $this->db->rollback();
                $result .= "<p class='alert-warning'><strong>❌ 거래 실패:</strong> 잔액이 부족하거나 동시 요청으로 인해 차감할 수 없습니다.</p>";
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $this->db->rollback();
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function vulnerableCounter($counter_name) {
        // 취약한 카운터 증가 (Race Condition 유발)
        $result = '';
        
        try {
            $result .= "<div class='vulnerable-output'>";
            $result .= "<h4>🔓 취약한 카운터 증가</h4>";
            
            // Step 1: 현재 값 읽기
            $stmt = $this->db->prepare("SELECT counter_value FROM rc_counters WHERE counter_name = ?");
            $stmt->execute([$counter_name]);
            $counter = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$counter) {
                return "<div class='error-output'>❌ 카운터를 찾을 수 없습니다.</div>";
            }
            
            $current_value = (int)$counter['counter_value'];
            $result .= "<p><strong>현재 값:</strong> $current_value</p>";
            
            // 🚨 Race Condition 유발을 위한 의도적 지연
            usleep(100000); // 0.1초 대기
            
            // Step 2: 값 증가 (다른 요청이 동시에 수행될 수 있음)
            $new_value = $current_value + 1;
            $stmt = $this->db->prepare("UPDATE rc_counters SET counter_value = ? WHERE counter_name = ?");
            $stmt->execute([$new_value, $counter_name]);
            
            $result .= "<p><strong>증가 후 값:</strong> $new_value</p>";
            $result .= "<p class='alert-warning'><strong>⚠️ 동시 요청 시 값이 손실될 수 있습니다!</strong></p>";
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function safeCounter($counter_name) {
        // 안전한 원자적 카운터 증가
        $result = '';
        
        try {
            $result .= "<div class='safe-output'>";
            $result .= "<h4>🔒 안전한 원자적 카운터 증가</h4>";
            
            // 원자적 증가 연산
            $stmt = $this->db->prepare("UPDATE rc_counters SET counter_value = counter_value + 1 WHERE counter_name = ?");
            $stmt->execute([$counter_name]);
            
            // 업데이트된 값 조회
            $stmt = $this->db->prepare("SELECT counter_value FROM rc_counters WHERE counter_name = ?");
            $stmt->execute([$counter_name]);
            $counter = $stmt->fetch(PDO::FETCH_ASSOC);
            $new_value = (int)$counter['counter_value'];
            
            $result .= "<p><strong>✅ 원자적 증가 완료:</strong> $new_value</p>";
            $result .= "<p class='alert-success'><strong>🔒 동시 요청에도 안전합니다!</strong></p>";
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function getCurrentStatus() {
        $result = '';
        
        try {
            $result .= "<div class='info-output'>";
            $result .= "<h4>📊 현재 상태</h4>";
            
            // 사용자 잔액 조회
            $stmt = $this->db->prepare("SELECT id, username, balance FROM rc_users ORDER BY id");
            $stmt->execute();
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $result .= "<h5>💰 사용자 잔액:</h5>";
            foreach ($users as $user) {
                $balance_color = $user['balance'] < 0 ? 'color: red; font-weight: bold;' : '';
                $result .= "<p><strong>{$user['username']} (ID: {$user['id']}):</strong> <span style='$balance_color'>$" . number_format($user['balance'], 2) . "</span></p>";
            }
            
            // 카운터 상태 조회
            $stmt = $this->db->prepare("SELECT counter_name, counter_value FROM rc_counters ORDER BY counter_name");
            $stmt->execute();
            $counters = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $result .= "<h5>🔢 카운터 상태:</h5>";
            foreach ($counters as $counter) {
                $result .= "<p><strong>{$counter['counter_name']}:</strong> {$counter['counter_value']}</p>";
            }
            
            // 최근 거래 내역
            $stmt = $this->db->prepare("SELECT t.*, u.username FROM rc_transactions t 
                                     JOIN rc_users u ON t.user_id = u.id 
                                     ORDER BY t.created_at DESC LIMIT 5");
            $stmt->execute();
            $transactions = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if (!empty($transactions)) {
                $result .= "<h5>📝 최근 거래 내역:</h5>";
                foreach ($transactions as $tx) {
                    $result .= "<p><strong>{$tx['username']}:</strong> {$tx['transaction_type']} $" . 
                              number_format($tx['amount'], 2) . " ({$tx['status']}) - {$tx['created_at']}</p>";
                }
            }
            
            $result .= "</div>";
            
        } catch (Exception $e) {
            $result .= "<div class='error-output'>❌ 상태 조회 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
        
        return $result;
    }
    
    public function resetData() {
        try {
            $this->db->exec("UPDATE rc_users SET balance = 1000.00 WHERE id IN (1, 2)");
            $this->db->exec("UPDATE rc_counters SET counter_value = 0");
            $this->db->exec("DELETE FROM rc_transactions");
            return "<div class='success-output'>✅ 데이터가 초기화되었습니다.</div>";
        } catch (Exception $e) {
            return "<div class='error-output'>❌ 초기화 오류: " . htmlspecialchars($e->getMessage()) . "</div>";
        }
    }
}

// Redis 연결 시도
$redis = null;
try {
    if (class_exists('Redis')) {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379);
    }
} catch (Exception $e) {
    // Redis가 없어도 MySQL로 동작
}

$raceTest = new RaceConditionTest($pdo, $redis);
$result = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'vulnerable_toctou':
            $user_id = (int)($_POST['user_id'] ?? 1);
            $amount = (float)($_POST['amount'] ?? 100);
            $result = $raceTest->vulnerableTOCTOU($user_id, $amount);
            break;
            
        case 'safe_toctou':
            $user_id = (int)($_POST['user_id'] ?? 1);
            $amount = (float)($_POST['amount'] ?? 100);
            $result = $raceTest->safeTOCTOU($user_id, $amount);
            break;
            
        case 'vulnerable_counter':
            $counter_name = $_POST['counter_name'] ?? 'clicks';
            $result = $raceTest->vulnerableCounter($counter_name);
            break;
            
        case 'safe_counter':
            $counter_name = $_POST['counter_name'] ?? 'clicks';
            $result = $raceTest->safeCounter($counter_name);
            break;
            
        case 'reset':
            $result = $raceTest->resetData();
            break;
            
        case 'concurrent_attack':
            $result = "<div class='info-output'><h4>🔄 동시 공격 실행 중...</h4><p>JavaScript가 동시 요청을 실행합니다. 결과를 확인하세요.</p></div>";
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Race Condition 취약점 테스트</title>
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
        
        input, select, button {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
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
        
        .concurrent-btn {
            background-color: #FF9800;
        }
        
        .concurrent-btn:hover {
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
        
        .success-output {
            background-color: #f1f8e9;
            border: 2px solid #8bc34a;
            color: #33691e;
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
        
        .concurrent-results {
            margin-top: 20px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background-color: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background-color: #4CAF50;
            width: 0%;
            transition: width 0.3s ease;
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
        <h1>⚡ Race Condition 취약점 테스트</h1>
        
        <div class="description">
            <h3>🎯 Race Condition이란?</h3>
            <p><strong>Race Condition</strong>은 두 개 이상의 프로세스나 스레드가 공유 자원에 동시에 접근할 때 발생하는 취약점입니다. 실행 순서나 타이밍에 따라 예기치 않은 결과가 발생할 수 있습니다.</p>
            
            <h4>🔍 주요 공격 시나리오:</h4>
            <ul>
                <li><strong>TOCTOU (Time-of-Check-Time-of-Use)</strong>: 검증과 사용 사이의 시간 간격을 악용</li>
                <li><strong>Double Spending</strong>: 잔액 확인과 차감 사이의 동시 요청</li>
                <li><strong>Counter Race</strong>: 카운터 증가 시 동시성 문제</li>
                <li><strong>File Race</strong>: 파일 작업 시 경쟁 상태</li>
            </ul>
            
            <p><strong>⚠️ 교육 목적:</strong> 이 테스트는 실제 Race Condition 공격을 시뮬레이션합니다. 실제 운영 환경에서는 원자적 연산과 적절한 락 메커니즘을 사용해야 합니다.</p>
        </div>

        <!-- 현재 상태 표시 -->
        <div class="test-section">
            <h3>📊 현재 데이터 상태</h3>
            <?php echo $raceTest->getCurrentStatus(); ?>
            
            <form method="post" style="margin-top: 15px;">
                <input type="hidden" name="action" value="reset">
                <button type="submit" class="safe-btn">🔄 데이터 초기화</button>
            </form>
        </div>

        <div class="two-column">
            <!-- TOCTOU 공격 테스트 -->
            <div class="test-section">
                <h3>⏰ TOCTOU 공격 테스트</h3>
                <p>잔액 확인과 차감 사이의 시간차를 악용하는 공격입니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="user_id">사용자 ID:</label>
                        <select name="user_id" id="user_id">
                            <option value="1">testuser (ID: 1)</option>
                            <option value="2">victim (ID: 2)</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="amount">차감할 금액:</label>
                        <input type="number" name="amount" id="amount" value="100" step="0.01" min="0.01">
                    </div>
                    
                    <input type="hidden" name="action" value="vulnerable_toctou">
                    <button type="submit" class="dangerous-btn">🔓 취약한 TOCTOU 실행</button>
                </form>
                
                <form method="post" style="margin-top: 10px;">
                    <input type="hidden" name="user_id" value="1">
                    <input type="hidden" name="amount" value="100">
                    <input type="hidden" name="action" value="safe_toctou">
                    <button type="submit" class="safe-btn">🔒 안전한 원자적 실행</button>
                </form>
            </div>

            <!-- 카운터 Race Condition -->
            <div class="test-section">
                <h3>🔢 카운터 Race Condition</h3>
                <p>카운터 증가 시 발생하는 동시성 문제를 테스트합니다.</p>
                
                <form method="post">
                    <div class="form-group">
                        <label for="counter_name">카운터 선택:</label>
                        <select name="counter_name" id="counter_name">
                            <option value="clicks">클릭 카운터</option>
                            <option value="downloads">다운로드 카운터</option>
                        </select>
                    </div>
                    
                    <input type="hidden" name="action" value="vulnerable_counter">
                    <button type="submit" class="dangerous-btn">🔓 취약한 카운터 증가</button>
                </form>
                
                <form method="post" style="margin-top: 10px;">
                    <input type="hidden" name="counter_name" value="clicks">
                    <input type="hidden" name="action" value="safe_counter">
                    <button type="submit" class="safe-btn">🔒 안전한 원자적 증가</button>
                </form>
            </div>
        </div>

        <!-- 동시 공격 시뮬레이션 -->
        <div class="test-section">
            <h3>⚡ 동시 공격 시뮬레이션</h3>
            <p>JavaScript를 사용해 여러 요청을 동시에 보내서 Race Condition을 유발합니다.</p>
            
            <div class="form-group">
                <label for="concurrent_requests">동시 요청 수:</label>
                <input type="number" id="concurrent_requests" value="10" min="1" max="50">
            </div>
            
            <div class="form-group">
                <label for="attack_type">공격 타입:</label>
                <select id="attack_type">
                    <option value="toctou">TOCTOU 공격</option>
                    <option value="counter">카운터 Race</option>
                </select>
            </div>
            
            <button onclick="startConcurrentAttack()" class="concurrent-btn">⚡ 동시 공격 시작</button>
            
            <div class="progress-bar" id="progress-container" style="display: none;">
                <div class="progress-fill" id="progress-bar"></div>
            </div>
            
            <div id="concurrent-results" class="concurrent-results" style="display: none;">
                <h4>📊 동시 공격 결과:</h4>
                <div id="results-content"></div>
            </div>
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
            <h3>🛡️ 보안 권장사항</h3>
            <div class="safe-output">
                <h4>Race Condition 방지 방법:</h4>
                
                <h5>1. 원자적 연산 사용:</h5>
                <pre><code>// MySQL 원자적 업데이트
UPDATE users SET balance = balance - 100 
WHERE id = 1 AND balance >= 100;

// Redis 원자적 연산
DECRBY balance:user1 100</code></pre>
                
                <h5>2. 트랜잭션 격리 수준 설정:</h5>
                <pre><code>// SERIALIZABLE 격리 수준 사용
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
BEGIN;
-- 트랜잭션 작업
COMMIT;</code></pre>
                
                <h5>3. 락(Lock) 메커니즘 활용:</h5>
                <pre><code>// Redis 분산 락
$lock = $redis->set("lock:user:$user_id", time(), ['NX', 'EX' => 30]);
if ($lock) {
    // 안전한 작업 수행
    $redis->del("lock:user:$user_id");
}</code></pre>
                
                <h5>4. Optimistic Locking:</h5>
                <pre><code>// 버전 기반 낙관적 락
UPDATE users SET balance = balance - 100, version = version + 1
WHERE id = 1 AND version = $expected_version;</code></pre>
                
                <p><strong>✅ 핵심 원칙:</strong> 공유 자원에 대한 접근은 항상 원자적이어야 하며, 동시성 제어 메커니즘을 적절히 사용해야 합니다.</p>
            </div>
        </div>
    </div>

    <script>
        let currentAttack = null;
        
        async function startConcurrentAttack() {
            const requestCount = parseInt(document.getElementById('concurrent_requests').value);
            const attackType = document.getElementById('attack_type').value;
            
            const progressContainer = document.getElementById('progress-container');
            const progressBar = document.getElementById('progress-bar');
            const resultsDiv = document.getElementById('concurrent-results');
            const resultsContent = document.getElementById('results-content');
            
            // UI 초기화
            progressContainer.style.display = 'block';
            progressBar.style.width = '0%';
            resultsDiv.style.display = 'none';
            resultsContent.innerHTML = '';
            
            const results = [];
            const startTime = Date.now();
            
            try {
                console.log(`🚀 ${requestCount}개 동시 요청 시작 (${attackType})`);
                
                // 동시 요청 생성
                const requests = Array.from({length: requestCount}, (_, i) => {
                    return makeRequest(attackType, i);
                });
                
                // Promise.all로 모든 요청을 동시에 실행
                const responses = await Promise.all(requests);
                
                const endTime = Date.now();
                const totalTime = endTime - startTime;
                
                // 진행률 100%
                progressBar.style.width = '100%';
                
                // 결과 분석
                let successCount = 0;
                let errorCount = 0;
                
                responses.forEach((response, index) => {
                    if (response.success) {
                        successCount++;
                    } else {
                        errorCount++;
                    }
                    results.push({
                        index: index + 1,
                        success: response.success,
                        message: response.message,
                        time: response.time
                    });
                });
                
                // 결과 표시
                displayResults({
                    totalRequests: requestCount,
                    successCount,
                    errorCount,
                    totalTime,
                    attackType,
                    results: results.slice(0, 5) // 처음 5개만 표시
                });
                
            } catch (error) {
                console.error('동시 공격 오류:', error);
                resultsContent.innerHTML = `<div class="alert-danger">❌ 공격 실행 중 오류 발생: ${error.message}</div>`;
                resultsDiv.style.display = 'block';
            }
        }
        
        async function makeRequest(attackType, index) {
            const requestStart = Date.now();
            
            try {
                const formData = new FormData();
                
                if (attackType === 'toctou') {
                    formData.append('action', 'vulnerable_toctou');
                    formData.append('user_id', '1');
                    formData.append('amount', '50');
                } else if (attackType === 'counter') {
                    formData.append('action', 'vulnerable_counter');
                    formData.append('counter_name', 'clicks');
                }
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });
                
                const responseText = await response.text();
                const requestTime = Date.now() - requestStart;
                
                // 성공 여부 판단 (간단한 문자열 검사)
                const isSuccess = response.ok && !responseText.includes('오류') && !responseText.includes('❌');
                
                return {
                    success: isSuccess,
                    message: isSuccess ? `요청 #${index + 1} 성공` : `요청 #${index + 1} 실패`,
                    time: requestTime
                };
                
            } catch (error) {
                const requestTime = Date.now() - requestStart;
                return {
                    success: false,
                    message: `요청 #${index + 1} 오류: ${error.message}`,
                    time: requestTime
                };
            }
        }
        
        function displayResults(data) {
            const resultsDiv = document.getElementById('concurrent-results');
            const resultsContent = document.getElementById('results-content');
            
            const successRate = ((data.successCount / data.totalRequests) * 100).toFixed(1);
            const avgTime = data.totalTime / data.totalRequests;
            
            let html = `
                <div class="info-output">
                    <h5>📊 공격 통계:</h5>
                    <p><strong>총 요청 수:</strong> ${data.totalRequests}</p>
                    <p><strong>성공한 요청:</strong> ${data.successCount} (${successRate}%)</p>
                    <p><strong>실패한 요청:</strong> ${data.errorCount}</p>
                    <p><strong>총 실행 시간:</strong> ${data.totalTime}ms</p>
                    <p><strong>평균 응답 시간:</strong> ${avgTime.toFixed(1)}ms</p>
                    <p><strong>공격 타입:</strong> ${data.attackType === 'toctou' ? 'TOCTOU 공격' : '카운터 Race'}</p>
                </div>
                
                <div class="vulnerable-output">
                    <h5>🚨 Race Condition 분석:</h5>
            `;
            
            if (data.successCount > data.errorCount) {
                html += `<p class="alert-danger"><strong>⚠️ Race Condition 취약점 발견!</strong></p>`;
                html += `<p>동시 요청 중 ${successRate}%가 성공했습니다. 이는 동시성 제어가 부적절함을 의미합니다.</p>`;
            } else {
                html += `<p class="alert-success"><strong>✅ Race Condition이 적절히 차단되었습니다.</strong></p>`;
                html += `<p>대부분의 동시 요청이 실패했습니다. 동시성 제어가 작동하고 있습니다.</p>`;
            }
            
            html += `
                    <h6>처음 5개 요청 결과:</h6>
                    <ul>
            `;
            
            data.results.forEach(result => {
                const statusIcon = result.success ? '✅' : '❌';
                html += `<li>${statusIcon} ${result.message} (${result.time}ms)</li>`;
            });
            
            html += `
                    </ul>
                </div>
                
                <div class="safe-output">
                    <h5>🛡️ 권장사항:</h5>
                    <p><strong>원자적 연산:</strong> 여러 단계의 작업을 하나의 원자적 연산으로 결합하세요.</p>
                    <p><strong>락 메커니즘:</strong> 공유 자원에 대한 동시 접근을 제어하세요.</p>
                    <p><strong>트랜잭션 격리:</strong> 적절한 격리 수준을 설정하세요.</p>
                </div>
                
                <button onclick="window.location.reload()" class="safe-btn" style="margin-top: 15px;">
                    🔄 페이지 새로고침하여 현재 상태 확인
                </button>
            `;
            
            resultsContent.innerHTML = html;
            resultsDiv.style.display = 'block';
        }
        
        // 진행률 표시 (시각적 효과)
        function updateProgress(current, total) {
            const percentage = (current / total) * 100;
            const progressBar = document.getElementById('progress-bar');
            progressBar.style.width = percentage + '%';
        }
    </script>
</body>
</html>