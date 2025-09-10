<?php
// 출력 버퍼링 시작 (헤더 전송 문제 방지)
ob_start();

// 세션 시작 (TestPage 전에)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

require_once 'TestPage.php';

// 1. 페이지 설정
$page_title = 'Race Condition';
$description = '<p><strong>Race Condition</strong>은 여러 프로세스나 스레드가 공유 리소스에 동시에 접근할 때 실행 순서에 따라 결과가 달라지는 취약점입니다.</p>
<p>이는 데이터 불일치, 권한 상승, 서비스 거부 등 심각한 보안 문제로 이어질 수 있습니다.</p>';

// 2. 페이로드 정의 (시나리오 설명)
$payloads = [
    'counter' => [
        'title' => '카운터 경합',
        'description' => '여러 프로세스가 동시에 카운터를 증가시킬 때 발생하는 경합 조건',
        'payloads' => []
    ],
    'bank' => [
        'title' => '은행 거래 경합',
        'description' => '은행 거래에서 잔액 확인과 업데이트 사이의 경합 조건',
        'payloads' => []
    ],
    'file' => [
        'title' => '파일 조작 경합',
        'description' => '파일 생성/삭제 시 경합 조건',
        'payloads' => []
    ]
];

// 3. 방어 방법 정의
$defense_methods = [
    "<strong>원자적 연산 (Atomic Operations) 사용:</strong> 데이터베이스 트랜잭션, 파일 잠금 등 원자성을 보장하는 메커니즘을 사용합니다.",
    "<strong>파일 잠금 (File Locking) 적용:</strong> 파일 접근 시 `flock()`과 같은 함수를 사용하여 동시 접근을 제어합니다.",
    "<strong>트랜잭션 격리 수준 설정:</strong> 데이터베이스에서 적절한 트랜잭션 격리 수준을 설정하여 데이터 일관성을 유지합니다.",
    "<strong>큐 시스템을 통한 순차 처리:</strong> 중요한 작업은 큐에 넣어 순차적으로 처리하여 동시성 문제를 방지합니다.",
    "<strong>세마포어, 뮤텍스 등 동기화 메커니즘:</strong> 공유 리소스에 대한 접근을 제어하는 동기화 도구를 사용합니다."
];

// 4. 참고 자료 정의
$references = [
    "OWASP - Race Condition" => "https://owasp.org/www-community/attacks/Race_Condition",
    "PortSwigger - Race conditions" => "https://portswigger.net/web-security/race-conditions"
];

// 5. 테스트 폼 UI 정의
$test_form_ui = <<<HTML
<div class="test-form">
    <h3>🧪 Race Condition 시뮬레이터</h3>
    
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
        
        <div class="info-box" style="background: #e3f2fd; border-color: #2196f3;">
            <h4>현재 계좌 잔액</h4>
            <div id="bank_accounts_display">
                <!-- 계좌 정보가 여기에 표시됩니다 -->
            </div>
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

<script>
    function switchTab(tabName) {
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        document.querySelector(\`button[onclick="switchTab('\${tabName}')"]\`).classList.add('active');
        document.getElementById(\`\${tabName}-tab\`).classList.add('active');
    }

    // 초기 로드 시 첫 번째 탭 활성화
    document.addEventListener('DOMContentLoaded', () => {
        switchTab('counter');
        updateBankAccounts();
    });

    // 은행 계좌 정보 업데이트 함수
    function updateBankAccounts() {
        fetch(window.location.pathname + '?action=get_accounts')
            .then(response => response.json())
            .then(data => {
                const display = document.getElementById('bank_accounts_display');
                display.innerHTML = '';
                for (const account in data) {
                    const item = document.createElement('div');
                    item.className = 'account-item';
                    item.innerHTML = '<span>' + account + '</span><span>$' + data[account].toFixed(2) + '</span>';
                    display.appendChild(item);
                }
            })
            .catch(error => console.error('Error fetching accounts:', error));
    }
</script>
HTML;

// 6. 테스트 로직 콜백 정의
$test_logic_callback = function($form_data) {
    $result_html = '';
    $error = '';
    $test_type = $form_data['test_type'] ?? '';

    // 헬퍼 함수들 (이 파일 내에서만 사용)
    function vulnerableCounterIncrement($counter_name = 'default') {
        $counter_file = sys_get_temp_dir() . '/counter_' . $counter_name . '.txt';
        if (!file_exists($counter_file)) { 
            file_put_contents($counter_file, '0'); 
            $current_value = 0; 
        } else { 
            $current_value = (int)file_get_contents($counter_file); 
        }
        $new_value = $current_value + 1; 
        file_put_contents($counter_file, $new_value);
        return ['previous_value' => $current_value, 'new_value' => $new_value, 'file' => $counter_file];
    }
    
    function secureCounterIncrement($counter_name = 'default') {
        $counter_file = sys_get_temp_dir() . '/secure_counter_' . $counter_name . '.txt'; 
        $lock_file = $counter_file . '.lock';
        $lock = fopen($lock_file, 'c');
        if (flock($lock, LOCK_EX)) { 
            try { 
                if (!file_exists($counter_file)) { 
                    file_put_contents($counter_file, '0'); 
                    $current_value = 0; 
                } else { 
                    $current_value = (int)file_get_contents($counter_file); 
                } 
                $new_value = $current_value + 1; 
                file_put_contents($counter_file, $new_value); 
                return ['previous_value' => $current_value, 'new_value' => $new_value, 'file' => $counter_file, 'locked' => true]; 
            } finally { 
                flock($lock, LOCK_UN); 
                fclose($lock); 
            } 
        } else { 
            return ['error' => 'Could not acquire lock', 'file' => $counter_file, 'locked' => false]; 
        } 
    }
    
    function simulateBankTransfer($from_account, $to_account, $amount, $secure = false) {
        $accounts_file = sys_get_temp_dir() . '/bank_accounts.json';
        if (!file_exists($accounts_file)) { 
            $initial_accounts = ['account_1' => 1000,'account_2' => 500,'account_3' => 750]; 
            file_put_contents($accounts_file, json_encode($initial_accounts)); 
        }
        $accounts = json_decode(file_get_contents($accounts_file), true);
        if (!isset($accounts[$from_account]) || !isset($accounts[$to_account])) { 
            return ['error' => 'Account not found']; 
        }
        if ($accounts[$from_account] < $amount) { 
            return ['error' => 'Insufficient funds']; 
        }
        if ($secure) { 
            /* 안전한 로직 */ 
            $accounts[$from_account] -= $amount; 
            $accounts[$to_account] += $amount; 
            file_put_contents($accounts_file, json_encode($accounts)); 
            return ['success' => true, 'from_account' => $from_account, 'to_account' => $to_account, 'amount' => $amount, 'from_balance' => $accounts[$from_account], 'to_balance' => $accounts[$to_account]]; 
        } else { 
            /* 취약한 로직 */ 
            usleep(rand(100, 2000)); 
            $accounts = json_decode(file_get_contents($accounts_file), true); 
            $accounts[$from_account] -= $amount; 
            $accounts[$to_account] += $amount; 
            file_put_contents($accounts_file, json_encode($accounts)); 
            return ['success' => true, 'from_account' => $from_account, 'to_account' => $to_account, 'amount' => $amount, 'from_balance' => $accounts[$from_account], 'to_balance' => $accounts[$to_account], 'warning' => 'Race condition possible!']; 
        } 
    }
    
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
    
    function resetAccounts() {
        $accounts_file = sys_get_temp_dir() . '/bank_accounts.json';
        $initial_accounts = ['account_1' => 1000,'account_2' => 500,'account_3' => 750];
        file_put_contents($accounts_file, json_encode($initial_accounts));
        return $initial_accounts;
    }

    // VULNERABILITY_MODE는 config.php에서 정의됨
    $vulnerability_enabled = defined('VULNERABILITY_MODE') && VULNERABILITY_MODE === true;

    switch ($test_type) {
        case 'counter':
            $counter_name = $form_data['counter_name'] ?? 'test';
            if ($vulnerability_enabled) { 
                $result_data = vulnerableCounterIncrement($counter_name); 
            } else { 
                $result_data = secureCounterIncrement($counter_name); 
            }
            $result_html .= "<p><strong>이전 값:</strong> " . ($result_data['previous_value'] ?? 'N/A') . "</p>";
            $result_html .= "<p><strong>새 값:</strong> " . ($result_data['new_value'] ?? 'N/A') . "</p>";
            $result_html .= "<p><strong>보안 모드:</strong> " . ($vulnerability_enabled ? 'No' : 'Yes') . "</p>";
            if (isset($result_data['locked'])) { 
                $result_html .= "<p><strong>파일 잠금:</strong> " . ($result_data['locked'] ? 'Yes' : 'No') . "</p>"; 
            }
            break;
            
        case 'bank_transfer':
            $from_account = $form_data['from_account'] ?? 'account_1';
            $to_account = $form_data['to_account'] ?? 'account_2';
            $amount = (float)($form_data['amount'] ?? 100);
            $result_data = simulateBankTransfer($from_account, $to_account, $amount, !$vulnerability_enabled);
            if (isset($result_data['success'])) {
                $result_html .= "<p><strong>이체 성공:</strong> $" . $result_data['amount'] . " (" . $result_data['from_account'] . " → " . $result_data['to_account'] . ")</p>";
                $result_html .= "<p><strong>출금 계좌 잔액:</strong> $" . number_format($result_data['from_balance'], 2) . "</p>";
                $result_html .= "<p><strong>입금 계좌 잔액:</strong> $" . number_format($result_data['to_balance'], 2) . "</p>";
                if (isset($result_data['warning'])) { 
                    $result_html .= "<p style=\"color:orange;\"><strong>⚠️ 경고:</strong> " . $result_data['warning'] . "</p>"; 
                }
            } else { 
                $result_html .= "<p><strong>오류:</strong> " . $result_data['error'] . "</p>"; 
            }
            break;
            
        case 'file_operation':
            $filename = $form_data['filename'] ?? 'race_test.txt';
            $content = $form_data['content'] ?? 'Test content';
            $operation = $form_data['operation'] ?? 'write';
            $result_data = simulateFileOperation($filename, $content, $operation);
            $result_html .= "<p><strong>작업:</strong> " . htmlspecialchars($operation) . "</p>";
            $result_html .= "<p><strong>결과:</strong> " . htmlspecialchars($result_data) . "</p>";
            break;
            
        case 'reset_accounts':
            $result_data = resetAccounts();
            $result_html .= "<p><strong>계좌 초기화 완료</strong></p>";
            foreach ($result_data as $account => $balance) { 
                $result_html .= "<p>" . htmlspecialchars($account) . ": $" . number_format($balance, 2) . "</p>"; 
            }
            break;
    }

    return ['result' => $result_html, 'error' => $error];
};

// 7. TestPage 인스턴스 생성 및 실행
$test_page = new TestPage($page_title, $description, $payloads, $defense_methods, $references, "Race_Condition_Analysis.md");
$test_page->set_test_form($test_form_ui);
$test_page->set_test_logic($test_logic_callback);
$test_page->run();
?>