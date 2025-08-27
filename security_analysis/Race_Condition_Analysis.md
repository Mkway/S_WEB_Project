# Race Condition 취약점 분석

## 📋 취약점 개요

**Race Condition 취약점**은 여러 프로세스나 스레드가 공유 리소스에 동시에 접근할 때 실행 순서나 타이밍에 따라 예상치 못한 결과가 발생하는 취약점입니다. 웹 애플리케이션에서는 동시 요청 처리 시 데이터 일관성 문제를 야기할 수 있습니다.

### 🎯 공격 원리

1. **동시 요청**: 같은 리소스에 대한 여러 동시 요청 전송
2. **타이밍 조작**: 특정 시점에 요청이 처리되도록 조작
3. **상태 조작**: 중간 상태에서의 데이터 불일치 악용
4. **검증 우회**: 동시성으로 인한 검증 로직 우회

### 🔍 주요 위험성

- **CVSS 점수**: 6.8 (Medium-High)
- **데이터 무결성 손상**: 잘못된 데이터 상태 생성
- **비즈니스 로직 우회**: 중요한 검증 과정 건너뛰기
- **권한 상승**: 동시성을 악용한 권한 획득

## 🚨 공격 시나리오

### 시나리오 1: 잔액 확인 Race Condition

```php
<?php
// 취약한 코드 - 잔액 차감 로직
function withdrawMoney($user_id, $amount) {
    // 1. 현재 잔액 확인
    $current_balance = getCurrentBalance($user_id);
    
    // 2. 잔액 충분성 검증 (취약점: 동시 요청 시 문제)
    if ($current_balance >= $amount) {
        // 3. 잔액 차감 (다른 요청이 이미 차감했을 수 있음)
        updateBalance($user_id, $current_balance - $amount);
        return true;
    }
    
    return false;
}

// 공격자가 동시에 여러 출금 요청을 보내면
// 모든 요청이 초기 잔액 기준으로 검증되어
// 실제 잔액보다 많은 금액이 출금될 수 있음
?>
```

### 시나리오 2: 파일 업로드 Race Condition

```php
<?php
// 취약한 파일 업로드 처리
function uploadFile($file) {
    $filename = basename($file['name']);
    $temp_path = '/tmp/' . $filename;
    $final_path = '/uploads/' . $filename;
    
    // 1. 임시 저장
    move_uploaded_file($file['tmp_name'], $temp_path);
    
    // 2. 바이러스 검사 (시간 소요)
    if (scanForVirus($temp_path)) {
        unlink($temp_path);
        return false;
    }
    
    // 3. 최종 위치로 이동
    // 문제: 검사 중에 공격자가 파일을 교체할 수 있음
    rename($temp_path, $final_path);
    return true;
}
?>
```

### 시나리오 3: 쿠폰/할인 코드 Race Condition

```php
<?php
// 취약한 쿠폰 사용 처리
function useCoupon($coupon_code, $user_id) {
    // 1. 쿠폰 유효성 확인
    $coupon = getCoupon($coupon_code);
    if (!$coupon || $coupon['used_count'] >= $coupon['max_uses']) {
        return false;
    }
    
    // 2. 쿠폰 사용 처리
    // 문제: 동시 요청 시 사용 횟수 증가가 제대로 반영 안됨
    applyCouponDiscount($user_id, $coupon['discount']);
    incrementCouponUsage($coupon_code);
    
    return true;
}
?>
```

### 시나리오 4: 계정 생성 Race Condition

```php
<?php
// 취약한 계정 생성 로직
function createAccount($username, $email) {
    // 1. 중복 확인
    if (userExists($username) || emailExists($email)) {
        return false;
    }
    
    // 2. 계정 생성
    // 문제: 확인과 생성 사이에 다른 요청이 같은 정보로 계정 생성 가능
    $user_id = insertUser($username, $email);
    
    return $user_id;
}
?>
```

## 🛡️ 방어 방법

### 1. 데이터베이스 트랜잭션과 락 사용

```php
<?php
class SafeBankingOperations {
    private $pdo;
    
    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }
    
    public function withdrawMoney($user_id, $amount) {
        try {
            // 트랜잭션 시작
            $this->pdo->beginTransaction();
            
            // 행 단위 잠금으로 잔액 조회
            $stmt = $this->pdo->prepare("
                SELECT balance FROM accounts 
                WHERE user_id = ? 
                FOR UPDATE
            ");
            $stmt->execute([$user_id]);
            $account = $stmt->fetch();
            
            if (!$account || $account['balance'] < $amount) {
                $this->pdo->rollBack();
                return false;
            }
            
            // 잔액 차감
            $stmt = $this->pdo->prepare("
                UPDATE accounts 
                SET balance = balance - ? 
                WHERE user_id = ?
            ");
            $stmt->execute([$amount, $user_id]);
            
            // 트랜잭션 커밋
            $this->pdo->commit();
            return true;
            
        } catch (Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }
    
    public function transferMoney($from_user, $to_user, $amount) {
        try {
            $this->pdo->beginTransaction();
            
            // 데드락 방지를 위해 ID 순서로 잠금
            $users = [$from_user, $to_user];
            sort($users);
            
            foreach ($users as $user_id) {
                $stmt = $this->pdo->prepare("
                    SELECT balance FROM accounts 
                    WHERE user_id = ? 
                    FOR UPDATE
                ");
                $stmt->execute([$user_id]);
                $accounts[$user_id] = $stmt->fetch();
            }
            
            if ($accounts[$from_user]['balance'] < $amount) {
                $this->pdo->rollBack();
                return false;
            }
            
            // 송금자 잔액 차감
            $stmt = $this->pdo->prepare("
                UPDATE accounts 
                SET balance = balance - ? 
                WHERE user_id = ?
            ");
            $stmt->execute([$amount, $from_user]);
            
            // 수취자 잔액 증가
            $stmt = $this->pdo->prepare("
                UPDATE accounts 
                SET balance = balance + ? 
                WHERE user_id = ?
            ");
            $stmt->execute([$amount, $to_user]);
            
            $this->pdo->commit();
            return true;
            
        } catch (Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }
}
?>
```

### 2. 파일 시스템 락 사용

```php
<?php
class SecureFileOperations {
    private $lock_dir = '/var/locks/';
    
    public function __construct() {
        if (!is_dir($this->lock_dir)) {
            mkdir($this->lock_dir, 0755, true);
        }
    }
    
    public function safeFileOperation($filename, $operation) {
        $lock_file = $this->lock_dir . md5($filename) . '.lock';
        $lock_handle = fopen($lock_file, 'w');
        
        if (!flock($lock_handle, LOCK_EX)) {
            fclose($lock_handle);
            throw new Exception('Could not acquire file lock');
        }
        
        try {
            $result = $operation($filename);
            return $result;
        } finally {
            flock($lock_handle, LOCK_UN);
            fclose($lock_handle);
            unlink($lock_file);
        }
    }
    
    public function atomicFileUpload($file) {
        $filename = basename($file['name']);
        $temp_filename = uniqid('upload_') . '_' . $filename;
        $temp_path = sys_get_temp_dir() . '/' . $temp_filename;
        $final_path = '/uploads/' . $filename;
        
        return $this->safeFileOperation($final_path, function($final_path) use ($file, $temp_path) {
            // 1. 임시 위치에 저장
            if (!move_uploaded_file($file['tmp_name'], $temp_path)) {
                throw new Exception('Upload failed');
            }
            
            // 2. 파일 검증
            if (!$this->validateFile($temp_path)) {
                unlink($temp_path);
                throw new Exception('File validation failed');
            }
            
            // 3. 원자적 이동 (rename은 원자적 연산)
            if (!rename($temp_path, $final_path)) {
                unlink($temp_path);
                throw new Exception('File move failed');
            }
            
            return true;
        });
    }
    
    private function validateFile($filepath) {
        // 파일 타입, 크기, 내용 검증
        if (!file_exists($filepath)) return false;
        if (filesize($filepath) > 10 * 1024 * 1024) return false; // 10MB 제한
        
        // 추가 보안 검증 로직
        return true;
    }
}
?>
```

### 3. Redis를 활용한 분산 락

```php
<?php
class RedisDistributedLock {
    private $redis;
    private $lock_timeout;
    
    public function __construct($redis_host = '127.0.0.1', $lock_timeout = 10) {
        $this->redis = new Redis();
        $this->redis->connect($redis_host);
        $this->lock_timeout = $lock_timeout;
    }
    
    public function acquireLock($resource, $timeout = null) {
        $timeout = $timeout ?: $this->lock_timeout;
        $identifier = uniqid();
        $lockname = 'lock:' . $resource;
        
        $end_time = time() + $timeout;
        
        while (time() < $end_time) {
            // SET 명령어의 NX, EX 옵션 사용
            if ($this->redis->set($lockname, $identifier, ['NX', 'EX' => $this->lock_timeout])) {
                return $identifier; // 락 획득 성공
            }
            
            usleep(1000); // 1ms 대기
        }
        
        return false; // 락 획득 실패
    }
    
    public function releaseLock($resource, $identifier) {
        $lockname = 'lock:' . $resource;
        
        // Lua 스크립트로 원자적 락 해제
        $script = "
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end
        ";
        
        return $this->redis->eval($script, [$lockname, $identifier], 1);
    }
    
    public function withLock($resource, $callback, $timeout = null) {
        $identifier = $this->acquireLock($resource, $timeout);
        
        if (!$identifier) {
            throw new Exception('Could not acquire lock for resource: ' . $resource);
        }
        
        try {
            return $callback();
        } finally {
            $this->releaseLock($resource, $identifier);
        }
    }
}

// 사용 예제
class SafeCouponManager {
    private $distributedLock;
    private $pdo;
    
    public function __construct(RedisDistributedLock $lock, PDO $pdo) {
        $this->distributedLock = $lock;
        $this->pdo = $pdo;
    }
    
    public function useCoupon($coupon_code, $user_id) {
        return $this->distributedLock->withLock("coupon:" . $coupon_code, function() use ($coupon_code, $user_id) {
            // 쿠폰 정보 조회
            $stmt = $this->pdo->prepare("SELECT * FROM coupons WHERE code = ?");
            $stmt->execute([$coupon_code]);
            $coupon = $stmt->fetch();
            
            if (!$coupon || $coupon['used_count'] >= $coupon['max_uses']) {
                return false;
            }
            
            // 사용 횟수 증가
            $stmt = $this->pdo->prepare("
                UPDATE coupons 
                SET used_count = used_count + 1 
                WHERE code = ?
            ");
            $stmt->execute([$coupon_code]);
            
            // 사용 기록 추가
            $stmt = $this->pdo->prepare("
                INSERT INTO coupon_usage (coupon_code, user_id, used_at) 
                VALUES (?, ?, NOW())
            ");
            $stmt->execute([$coupon_code, $user_id]);
            
            return true;
        });
    }
}
?>
```

### 4. 멱등성(Idempotency) 구현

```php
<?php
class IdempotentOperationManager {
    private $pdo;
    
    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }
    
    public function executeIdempotentOperation($operation_id, $user_id, $operation_type, $callback) {
        try {
            $this->pdo->beginTransaction();
            
            // 이미 실행된 작업인지 확인
            $stmt = $this->pdo->prepare("
                SELECT result FROM idempotent_operations 
                WHERE operation_id = ? AND user_id = ? AND operation_type = ?
            ");
            $stmt->execute([$operation_id, $user_id, $operation_type]);
            $existing = $stmt->fetch();
            
            if ($existing) {
                // 이미 실행된 작업 - 저장된 결과 반환
                $this->pdo->rollBack();
                return json_decode($existing['result'], true);
            }
            
            // 작업 실행
            $result = $callback();
            
            // 결과 저장
            $stmt = $this->pdo->prepare("
                INSERT INTO idempotent_operations 
                (operation_id, user_id, operation_type, result, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->execute([$operation_id, $user_id, $operation_type, json_encode($result)]);
            
            $this->pdo->commit();
            return $result;
            
        } catch (Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }
    
    // 결제 처리 예제
    public function processPayment($payment_id, $user_id, $amount) {
        return $this->executeIdempotentOperation(
            $payment_id, 
            $user_id, 
            'payment',
            function() use ($user_id, $amount) {
                // 실제 결제 처리 로직
                $payment_result = $this->chargeUser($user_id, $amount);
                
                return [
                    'success' => $payment_result['success'],
                    'transaction_id' => $payment_result['transaction_id'],
                    'amount' => $amount,
                    'timestamp' => time()
                ];
            }
        );
    }
    
    private function chargeUser($user_id, $amount) {
        // 실제 결제 처리 로직
        return [
            'success' => true,
            'transaction_id' => uniqid('txn_')
        ];
    }
}
?>
```

## 🧪 테스트 방법

### 1. 동시 요청 테스트

```python
import requests
import threading
import time

def concurrent_request_test():
    url = "http://target.com/withdraw"
    
    def make_request():
        data = {'amount': 100}
        response = requests.post(url, data=data, 
                               cookies={'session': 'valid_session'})
        print(f"Response: {response.status_code} - {response.text}")
    
    # 10개의 동시 요청
    threads = []
    for i in range(10):
        thread = threading.Thread(target=make_request)
        threads.append(thread)
    
    # 모든 스레드 거의 동시에 시작
    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()

concurrent_request_test()
```

### 2. 타이밍 공격 테스트

```python
import requests
import time
from multiprocessing import Process

def timing_attack_test():
    def slow_request():
        # 파일 업로드 등 처리 시간이 긴 요청
        files = {'file': ('large.zip', b'A' * 1000000)}
        response = requests.post('http://target.com/upload', files=files)
        print(f"Upload response: {response.status_code}")
    
    def fast_request():
        # 빠른 요청 (파일 교체 시도)
        time.sleep(0.1)  # 약간의 지연
        data = {'action': 'replace_file', 'filename': 'large.zip'}
        response = requests.post('http://target.com/file_action', data=data)
        print(f"Replace response: {response.status_code}")
    
    # 프로세스로 동시 실행
    p1 = Process(target=slow_request)
    p2 = Process(target=fast_request)
    
    p1.start()
    p2.start()
    
    p1.join()
    p2.join()

timing_attack_test()
```

### 3. 쿠폰 Race Condition 테스트

```bash
#!/bin/bash
# 여러 curl 명령을 백그라운드로 동시 실행

COUPON_CODE="SAVE50"
SESSION="valid_session_cookie"

for i in {1..20}; do
    curl -X POST \
         -H "Cookie: session=${SESSION}" \
         -d "coupon_code=${COUPON_CODE}" \
         http://target.com/apply_coupon &
done

# 모든 백그라운드 작업 완료 대기
wait
echo "All requests completed"
```

## 📚 참고 자료

### 공식 문서
- [OWASP Race Condition Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Race_condition)
- [MySQL InnoDB Locking](https://dev.mysql.com/doc/refman/8.0/en/innodb-locking.html)

### 보안 가이드
- [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions)
- [NIST Concurrency Control Guidelines](https://csrc.nist.gov/publications)

### 도구 및 리소스
- [Burp Suite Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)
- [Redis Distributed Locking](https://redis.io/topics/distlock)

---

## 🎯 핵심 요약

1. **원자적 연산**: 데이터베이스 트랜잭션과 락 활용
2. **분산 락**: Redis 등을 활용한 애플리케이션 레벨 락
3. **멱등성**: 동일한 요청의 중복 실행 방지
4. **테스트**: 동시성 시나리오에 대한 충분한 테스트

**⚠️ 주의**: Race Condition은 재현이 어려울 수 있으므로 예방적 보안 조치가 매우 중요합니다.