<?php
require_once '../config.php';
require_once '../db.php';

$vulnerability_enabled = isVulnerabilityEnabled('race_condition', $_GET);

function simulateFileOperation($filename, $content, $operation_type = 'write') {
    $file_path = sys_get_temp_dir() . '/' . $filename;
    
    switch ($operation_type) {
        case 'write':
            file_put_contents($file_path, $content);
            return "File written: $filename";
            
        case 'read':
            if (file_exists($file_path)) {
                return file_get_contents($file_path);
            }
            return "File not found: $filename";
            
        case 'delete':
            if (file_exists($file_path)) {
                unlink($file_path);
                return "File deleted: $filename";
            }
            return "File not found: $filename";
            
        case 'append':
            file_put_contents($file_path, $content, FILE_APPEND);
            return "Content appended to: $filename";
            
        default:
            return "Unknown operation";
    }
}

function vulnerableCounterIncrement($counter_name = 'default') {
    $counter_file = sys_get_temp_dir() . '/counter_' . $counter_name . '.txt';
    
    // 취약한 방법: TOCTOU (Time of Check to Time of Use)
    if (!file_exists($counter_file)) {
        // 여기서 다른 스레드가 파일을 생성할 수 있음
        usleep(rand(100, 1000)); // 경합 조건을 증가시키기 위한 지연
        file_put_contents($counter_file, '0');
        $current_value = 0;
    } else {
        $current_value = (int)file_get_contents($counter_file);
    }
    
    // 여기서도 다른 스레드가 값을 변경할 수 있음
    usleep(rand(100, 1000)); // 경합 조건을 증가시키기 위한 지연
    
    $new_value = $current_value + 1;
    file_put_contents($counter_file, $new_value);
    
    return [
        'previous_value' => $current_value,
        'new_value' => $new_value,
        'file' => $counter_file
    ];
}

function secureCounterIncrement($counter_name = 'default') {
    $counter_file = sys_get_temp_dir() . '/secure_counter_' . $counter_name . '.txt';
    $lock_file = $counter_file . '.lock';
    
    // 안전한 방법: 파일 잠금 사용
    $lock = fopen($lock_file, 'c');
    
    if (flock($lock, LOCK_EX)) { // 배타적 잠금
        try {
            if (!file_exists($counter_file)) {
                file_put_contents($counter_file, '0');
                $current_value = 0;
            } else {
                $current_value = (int)file_get_contents($counter_file);
            }
            
            $new_value = $current_value + 1;
            file_put_contents($counter_file, $new_value);
            
            return [
                'previous_value' => $current_value,
                'new_value' => $new_value,
                'file' => $counter_file,
                'locked' => true
            ];
        } finally {
            flock($lock, LOCK_UN); // 잠금 해제
            fclose($lock);
        }
    } else {
        return [
            'error' => 'Could not acquire lock',
            'file' => $counter_file,
            'locked' => false
        ];
    }
}

function simulateBankTransfer($from_account, $to_account, $amount, $secure = false) {
    $accounts_file = sys_get_temp_dir() . '/bank_accounts.json';
    
    // 초기 계좌 설정
    if (!file_exists($accounts_file)) {
        $initial_accounts = [
            'account_1' => 1000,
            'account_2' => 500,
            'account_3' => 750
        ];
        file_put_contents($accounts_file, json_encode($initial_accounts));
    }
    
    if ($secure) {
        // 안전한 방법: 원자적 연산
        $lock = fopen($accounts_file . '.lock', 'c');
        
        if (flock($lock, LOCK_EX)) {
            try {
                $accounts = json_decode(file_get_contents($accounts_file), true);
                
                if (!isset($accounts[$from_account]) || !isset($accounts[$to_account])) {
                    return ['error' => 'Account not found'];
                }
                
                if ($accounts[$from_account] < $amount) {
                    return ['error' => 'Insufficient funds'];
                }
                
                $accounts[$from_account] -= $amount;
                $accounts[$to_account] += $amount;
                
                file_put_contents($accounts_file, json_encode($accounts));
                
                return [
                    'success' => true,
                    'from_account' => $from_account,
                    'to_account' => $to_account,
                    'amount' => $amount,
                    'from_balance' => $accounts[$from_account],
                    'to_balance' => $accounts[$to_account]
                ];
            } finally {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
    } else {
        // 취약한 방법: TOCTOU 패턴
        $accounts = json_decode(file_get_contents($accounts_file), true);
        
        if (!isset($accounts[$from_account]) || !isset($accounts[$to_account])) {
            return ['error' => 'Account not found'];
        }
        
        // 잔액 확인
        if ($accounts[$from_account] < $amount) {
            return ['error' => 'Insufficient funds'];
        }
        
        // 여기서 경합 조건 발생 가능 - 다른 거래가 잔액을 변경할 수 있음
        usleep(rand(100, 2000));
        
        // 잔액 업데이트 (경합 조건으로 인해 일관성 깨질 수 있음)
        $accounts = json_decode(file_get_contents($accounts_file), true); // 다시 읽기
        $accounts[$from_account] -= $amount;
        $accounts[$to_account] += $amount;
        
        file_put_contents($accounts_file, json_encode($accounts));
        
        return [
            'success' => true,
            'from_account' => $from_account,
            'to_account' => $to_account,
            'amount' => $amount,
            'from_balance' => $accounts[$from_account],
            'to_balance' => $accounts[$to_account],
            'warning' => 'Race condition possible!'
        ];
    }
}

function checkCurrentAccounts() {
    $accounts_file = sys_get_temp_dir() . '/bank_accounts.json';
    
    if (file_exists($accounts_file)) {
        return json_decode(file_get_contents($accounts_file), true);
    }
    
    return [];
}

function resetAccounts() {
    $accounts_file = sys_get_temp_dir() . '/bank_accounts.json';
    $initial_accounts = [
        'account_1' => 1000,
        'account_2' => 500,
        'account_3' => 750
    ];
    file_put_contents($accounts_file, json_encode($initial_accounts));
    return $initial_accounts;
}

$test_results = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $test_type = $_POST['test_type'] ?? '';
    
    switch ($test_type) {
        case 'counter':
            $counter_name = $_POST['counter_name'] ?? 'test';
            
            if ($vulnerability_enabled) {
                $result = vulnerableCounterIncrement($counter_name);
            } else {
                $result = secureCounterIncrement($counter_name);
            }
            
            $test_results[] = [
                'type' => 'counter',
                'vulnerable' => $vulnerability_enabled,
                'result' => $result
            ];
            break;
            
        case 'bank_transfer':
            $from_account = $_POST['from_account'] ?? 'account_1';
            $to_account = $_POST['to_account'] ?? 'account_2';
            $amount = (float)($_POST['amount'] ?? 100);
            
            $result = simulateBankTransfer($from_account, $to_account, $amount, !$vulnerability_enabled);
            
            $test_results[] = [
                'type' => 'bank_transfer',
                'vulnerable' => $vulnerability_enabled,
                'result' => $result,
                'accounts_after' => checkCurrentAccounts()
            ];
            break;
            
        case 'file_operation':
            $filename = $_POST['filename'] ?? 'test.txt';
            $content = $_POST['content'] ?? 'Test content';
            $operation = $_POST['operation'] ?? 'write';
            
            $result = simulateFileOperation($filename, $content, $operation);
            
            $test_results[] = [
                'type' => 'file_operation',
                'result' => $result,
                'operation' => $operation,
                'filename' => $filename
            ];
            break;
            
        case 'reset_accounts':
            $result = resetAccounts();
            $test_results[] = [
                'type' => 'reset_accounts',
                'result' => $result
            ];
            break;
    }
}

$race_condition_examples = [
    [
        'name' => 'Counter Race Condition',
        'description' => '여러 프로세스가 동시에 카운터를 증가시킬 때 발생하는 경합 조건',
        'scenario' => 'TOCTOU (Time of Check to Time of Use) 패턴'
    ],
    [
        'name' => 'Bank Transfer Race',
        'description' => '은행 거래에서 잔액 확인과 업데이트 사이의 경합 조건',
        'scenario' => '동시 거래 시 잔액 일관성 문제'
    ],
    [
        'name' => 'File Creation Race',
        'description' => '파일 존재 확인 후 생성까지 시간 차이로 인한 경합',
        'scenario' => '임시 파일 생성 시 보안 문제'
    ],
    [
        'name' => 'Session Fixation',
        'description' => '세션 생성과 검증 사이의 경합으로 인한 세션 고정',
        'scenario' => '로그인 프로세스에서의 경합 조건'
    ]
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Race Condition 취약점 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .race-simulator {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .test-scenario {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .scenario-tabs {
            display: flex;
            background: #e9ecef;
            border-radius: 8px 8px 0 0;
            margin: -15px -15px 15px -15px;
        }
        
        .tab-button {
            flex: 1;
            padding: 12px;
            background: transparent;
            border: none;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .tab-button:first-child {
            border-radius: 8px 0 0 0;
        }
        
        .tab-button:last-child {
            border-radius: 0 8px 0 0;
        }
        
        .tab-button.active {
            background: white;
            border-bottom: 2px solid #007bff;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .result-display {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            font-family: monospace;
        }
        
        .result-success {
            border-color: #28a745;
            background: #d4edda;
            color: #155724;
        }
        
        .result-warning {
            border-color: #ffc107;
            background: #fff3cd;
            color: #856404;
        }
        
        .result-error {
            border-color: #dc3545;
            background: #f8d7da;
            color: #721c24;
        }
        
        .accounts-display {
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .account-item {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #ddd;
        }
        
        .account-item:last-child {
            border-bottom: none;
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
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        
        .example-scenarios {
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🏃‍♂️ Race Condition 취약점 테스트</h1>
        
        <div class="vulnerability-status <?php echo $vulnerability_enabled ? 'vulnerability-enabled' : 'vulnerability-disabled'; ?>">
            상태: <?php echo $vulnerability_enabled ? '취약한 모드 (Race Condition 가능)' : '보안 모드 (동기화된 접근)'; ?>
        </div>
        
        <div class="description">
            <h2>📋 Race Condition이란?</h2>
            <p><strong>Race Condition</strong>은 여러 프로세스나 스레드가 공유 리소스에 동시에 접근할 때 실행 순서에 따라 결과가 달라지는 취약점입니다.</p>
            
            <h3>주요 유형</h3>
            <ul>
                <li><strong>TOCTOU (Time of Check to Time of Use)</strong>: 확인과 사용 사이의 시간 차이 악용</li>
                <li><strong>File System Race</strong>: 파일 생성/삭제 시 경합 조건</li>
                <li><strong>Database Race</strong>: 동시 트랜잭션으로 인한 데이터 일관성 문제</li>
                <li><strong>Counter Race</strong>: 공유 카운터 증가/감소 시 경합</li>
            </ul>
            
            <h3>방어 방법</h3>
            <ul>
                <li>원자적 연산 (Atomic Operations) 사용</li>
                <li>파일 잠금 (File Locking) 적용</li>
                <li>트랜잭션 격리 수준 설정</li>
                <li>세마포어, 뮤텍스 등 동기화 메커니즘</li>
                <li>큐 시스템을 통한 순차 처리</li>
            </ul>
        </div>

        <div class="race-simulator">
            <h2>🧪 Race Condition 시뮬레이터</h2>
            
            <div class="test-scenario">
                <div class="scenario-tabs">
                    <button class="tab-button active" onclick="switchTab('counter')">카운터 경합</button>
                    <button class="tab-button" onclick="switchTab('bank')">은행 거래</button>
                    <button class="tab-button" onclick="switchTab('file')">파일 조작</button>
                </div>
                
                <!-- 카운터 테스트 -->
                <div id="counter-tab" class="tab-content active">
                    <h3>카운터 Race Condition 테스트</h3>
                    <form method="POST" action="">
                        <input type="hidden" name="test_type" value="counter">
                        
                        <div class="form-group">
                            <label for="counter_name">카운터 이름:</label>
                            <input type="text" name="counter_name" id="counter_name" value="test_counter" placeholder="카운터 식별자">
                        </div>
                        
                        <button type="submit" class="btn">카운터 증가</button>
                    </form>
                </div>
                
                <!-- 은행 거래 테스트 -->
                <div id="bank-tab" class="tab-content">
                    <h3>은행 거래 Race Condition 테스트</h3>
                    
                    <div class="accounts-display">
                        <h4>현재 계좌 잔액</h4>
                        <?php 
                        $current_accounts = checkCurrentAccounts();
                        if (empty($current_accounts)) {
                            $current_accounts = resetAccounts();
                        }
                        foreach ($current_accounts as $account => $balance): ?>
                        <div class="account-item">
                            <span><?php echo htmlspecialchars($account); ?></span>
                            <span>$<?php echo number_format($balance, 2); ?></span>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <form method="POST" action="">
                        <input type="hidden" name="test_type" value="bank_transfer">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="from_account">출금 계좌:</label>
                                <select name="from_account" id="from_account">
                                    <option value="account_1">Account 1</option>
                                    <option value="account_2">Account 2</option>
                                    <option value="account_3">Account 3</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label for="to_account">입금 계좌:</label>
                                <select name="to_account" id="to_account">
                                    <option value="account_1">Account 1</option>
                                    <option value="account_2" selected>Account 2</option>
                                    <option value="account_3">Account 3</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="amount">이체 금액:</label>
                            <input type="number" name="amount" id="amount" value="100" min="1" step="0.01">
                        </div>
                        
                        <div class="btn-group">
                            <button type="submit" class="btn">이체 실행</button>
                            <button type="submit" name="test_type" value="reset_accounts" class="btn-secondary">계좌 초기화</button>
                        </div>
                    </form>
                </div>
                
                <!-- 파일 조작 테스트 -->
                <div id="file-tab" class="tab-content">
                    <h3>파일 Race Condition 테스트</h3>
                    <form method="POST" action="">
                        <input type="hidden" name="test_type" value="file_operation">
                        
                        <div class="form-group">
                            <label for="filename">파일명:</label>
                            <input type="text" name="filename" id="filename" value="race_test.txt" placeholder="파일명 입력">
                        </div>
                        
                        <div class="form-group">
                            <label for="content">내용:</label>
                            <input type="text" name="content" id="content" value="Test content" placeholder="파일 내용">
                        </div>
                        
                        <div class="form-group">
                            <label for="operation">작업:</label>
                            <select name="operation" id="operation">
                                <option value="write">파일 쓰기</option>
                                <option value="read">파일 읽기</option>
                                <option value="append">내용 추가</option>
                                <option value="delete">파일 삭제</option>
                            </select>
                        </div>
                        
                        <button type="submit" class="btn">파일 작업 실행</button>
                    </form>
                </div>
            </div>
            
            <?php if (!empty($test_results)): ?>
                <?php foreach ($test_results as $result): ?>
                <div class="result-display <?php 
                    if (isset($result['result']['error'])) echo 'result-error';
                    elseif (isset($result['result']['warning'])) echo 'result-warning';
                    else echo 'result-success';
                ?>">
                    <h4>테스트 결과 - <?php echo htmlspecialchars($result['type']); ?></h4>
                    
                    <?php if ($result['type'] === 'counter'): ?>
                        <p><strong>이전 값:</strong> <?php echo $result['result']['previous_value'] ?? 'N/A'; ?></p>
                        <p><strong>새 값:</strong> <?php echo $result['result']['new_value'] ?? 'N/A'; ?></p>
                        <p><strong>보안 모드:</strong> <?php echo $result['vulnerable'] ? 'No' : 'Yes'; ?></p>
                        <?php if (isset($result['result']['locked'])): ?>
                        <p><strong>파일 잠금:</strong> <?php echo $result['result']['locked'] ? 'Yes' : 'No'; ?></p>
                        <?php endif; ?>
                        
                    <?php elseif ($result['type'] === 'bank_transfer'): ?>
                        <?php if (isset($result['result']['success'])): ?>
                        <p><strong>이체 성공:</strong> $<?php echo $result['result']['amount']; ?> (<?php echo $result['result']['from_account']; ?> → <?php echo $result['result']['to_account']; ?>)</p>
                        <p><strong>출금 계좌 잔액:</strong> $<?php echo number_format($result['result']['from_balance'], 2); ?></p>
                        <p><strong>입금 계좌 잔액:</strong> $<?php echo number_format($result['result']['to_balance'], 2); ?></p>
                        <?php if (isset($result['result']['warning'])): ?>
                        <p class="text-warning"><strong>⚠️ 경고:</strong> <?php echo $result['result']['warning']; ?></p>
                        <?php endif; ?>
                        <?php else: ?>
                        <p><strong>오류:</strong> <?php echo $result['result']['error']; ?></p>
                        <?php endif; ?>
                        
                    <?php elseif ($result['type'] === 'file_operation'): ?>
                        <p><strong>작업:</strong> <?php echo htmlspecialchars($result['operation']); ?></p>
                        <p><strong>결과:</strong> <?php echo htmlspecialchars($result['result']); ?></p>
                        
                    <?php elseif ($result['type'] === 'reset_accounts'): ?>
                        <p><strong>계좌 초기화 완료</strong></p>
                        <?php foreach ($result['result'] as $account => $balance): ?>
                        <p><?php echo htmlspecialchars($account); ?>: $<?php echo number_format($balance, 2); ?></p>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="example-scenarios">
            <h3>🎯 Race Condition 시나리오 예제</h3>
            <?php foreach ($race_condition_examples as $example): ?>
            <div class="scenario-item">
                <div class="scenario-name"><?php echo htmlspecialchars($example['name']); ?></div>
                <div class="scenario-description"><?php echo htmlspecialchars($example['description']); ?></div>
                <div style="font-style: italic; color: #007bff; font-size: 0.9em; margin-top: 5px;">
                    시나리오: <?php echo htmlspecialchars($example['scenario']); ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="mitigation">
            <h2>🛡️ 완화 방안</h2>
            <div class="code-block">
                <h3>안전한 Race Condition 방어</h3>
                <pre><code>// ❌ 위험한 TOCTOU 패턴
function vulnerableFileCreate($filename) {
    if (!file_exists($filename)) {
        // 여기서 다른 프로세스가 파일을 생성할 수 있음
        sleep(1);
        file_put_contents($filename, 'content');
    }
}

// ✅ 안전한 원자적 파일 생성
function secureFileCreate($filename) {
    $handle = fopen($filename, 'x'); // 'x' 모드는 파일이 없을 때만 생성
    if ($handle) {
        fwrite($handle, 'content');
        fclose($handle);
        return true;
    }
    return false; // 파일이 이미 존재
}

// ❌ 위험한 카운터 증가
function vulnerableCounter() {
    $count = (int)file_get_contents('counter.txt');
    $count++;
    file_put_contents('counter.txt', $count);
    return $count;
}

// ✅ 안전한 잠금 기반 카운터
function secureCounter() {
    $lock = fopen('counter.lock', 'c');
    
    if (flock($lock, LOCK_EX)) {
        $count = (int)file_get_contents('counter.txt');
        $count++;
        file_put_contents('counter.txt', $count);
        flock($lock, LOCK_UN);
        fclose($lock);
        return $count;
    }
    
    fclose($lock);
    return false;
}

// ✅ 데이터베이스 트랜잭션 사용
function secureBankTransfer($from, $to, $amount) {
    $pdo->beginTransaction();
    
    try {
        // 배타적 잠금으로 계좌 조회
        $stmt = $pdo->prepare("SELECT balance FROM accounts WHERE id = ? FOR UPDATE");
        $stmt->execute([$from]);
        $fromBalance = $stmt->fetchColumn();
        
        if ($fromBalance < $amount) {
            throw new Exception("Insufficient funds");
        }
        
        // 원자적 업데이트
        $pdo->prepare("UPDATE accounts SET balance = balance - ? WHERE id = ?")
            ->execute([$amount, $from]);
        $pdo->prepare("UPDATE accounts SET balance = balance + ? WHERE id = ?")
            ->execute([$amount, $to]);
            
        $pdo->commit();
        return true;
        
    } catch (Exception $e) {
        $pdo->rollback();
        throw $e;
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
        function switchTab(tabName) {
            // 모든 탭 버튼과 콘텐츠 숨기기
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // 선택된 탭 활성화
            document.querySelector(`button[onclick="switchTab('${tabName}')"]`).classList.add('active');
            document.getElementById(`${tabName}-tab`).classList.add('active');
        }
    </script>
</body>
</html>