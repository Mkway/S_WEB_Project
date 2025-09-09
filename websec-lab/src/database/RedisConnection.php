<?php
/**
 * Redis 연결 및 Cache Injection 테스트 클래스
 * 
 * Redis 연결 관리와 캐시 보안 테스트를 위한 취약점 및 안전한 메서드 제공
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Predis\Client;
use Redis;
use Exception;

class RedisConnection {
    private $predisClient;
    private $redisClient;
    private $isConnected = false;
    private $connectionType = 'predis'; // 'predis' 또는 'phpredis'
    
    // 연결 설정  
    private $host = '172.17.0.1';
    private $port = 6379;
    private $database = 0;
    
    public function __construct($usePhpRedis = false) {
        $this->connectionType = $usePhpRedis ? 'phpredis' : 'predis';
        $this->connect();
    }
    
    /**
     * Redis 연결 설정
     */
    private function connect() {
        try {
            if ($this->connectionType === 'phpredis') {
                // PHP Redis 확장 사용
                $this->redisClient = new Redis();
                $this->redisClient->connect($this->host, $this->port);
                $this->redisClient->select($this->database);
                $this->isConnected = true;
            } else {
                // Predis 라이브러리 사용
                $this->predisClient = new Client([
                    'scheme' => 'tcp',
                    'host' => $this->host,
                    'port' => $this->port,
                    'database' => $this->database,
                ]);
                
                // 연결 테스트
                $this->predisClient->ping();
                $this->isConnected = true;
            }
            
        } catch (Exception $e) {
            $this->isConnected = false;
            throw new Exception("Redis 연결 실패: " . $e->getMessage());
        }
    }
    
    /**
     * 연결 상태 확인
     */
    public function isConnected(): bool {
        return $this->isConnected;
    }
    
    /**
     * 사용 중인 클라이언트 반환
     */
    private function getClient() {
        if (!$this->isConnected) {
            throw new Exception("Redis 연결이 되어있지 않습니다.");
        }
        return $this->connectionType === 'phpredis' ? $this->redisClient : $this->predisClient;
    }
    
    // ==================== 취약한 Redis 캐시 메서드 ====================
    
    /**
     * 취약한 세션 데이터 조회 (Session Hijacking)
     * 
     * @param string $sessionKey 세션 키 (사용자 입력 - 취약점)
     * @return string|null
     */
    public function vulnerableGetSession($sessionKey) {
        $client = $this->getClient();
        
        // 취약점: 사용자 입력을 그대로 Redis 키로 사용
        // 공격 예시: "../session:admin_123" 또는 "*" 등으로 다른 세션 접근 가능
        $result = $client->get($sessionKey);
        
        return $result;
    }
    
    /**
     * 취약한 캐시 데이터 검색 (Cache Key Injection)
     * 
     * @param string $pattern 검색 패턴 (사용자 입력)
     * @return array
     */
    public function vulnerableCacheSearch($pattern) {
        $client = $this->getClient();
        
        // 취약점: 사용자 입력을 KEYS 명령어에 직접 사용
        // 공격 예시: "*" 입력으로 모든 캐시 키 노출 가능
        $keys = $client->keys($pattern);
        
        $results = [];
        foreach ($keys as $key) {
            $value = $client->get($key);
            $results[$key] = $value;
        }
        
        return $results;
    }
    
    /**
     * 취약한 사용자 데이터 업데이트 (Cache Poisoning)
     * 
     * @param string $userId 사용자 ID
     * @param array $userData 사용자 데이터 (사용자 입력)
     * @return bool
     */
    public function vulnerableUpdateUserCache($userId, $userData) {
        $client = $this->getClient();
        
        // 취약점: 사용자 입력 데이터를 검증 없이 캐시에 저장
        // 공격 예시: {"role": "administrator", "premium": true} 등으로 권한 상승
        $cacheKey = "user:{$userId}:profile";
        $result = $client->set($cacheKey, json_encode($userData));
        
        return (bool)$result;
    }
    
    /**
     * 취약한 캐시 설정 값 변경 (Configuration Injection)
     * 
     * @param string $configKey 설정 키 (사용자 입력)
     * @param string $configValue 설정 값 (사용자 입력)
     * @return bool
     */
    public function vulnerableUpdateConfig($configKey, $configValue) {
        $client = $this->getClient();
        
        // 취약점: 설정 키와 값을 검증 없이 직접 저장
        // 공격 예시: configKey = "config:app:debug_mode", configValue = "true"
        $fullKey = "config:app:" . $configKey;
        $result = $client->set($fullKey, $configValue);
        
        return (bool)$result;
    }
    
    /**
     * 취약한 큐 데이터 조작 (Queue Injection)
     * 
     * @param string $queueName 큐 이름
     * @param string $message 메시지 (사용자 입력)
     * @return bool
     */
    public function vulnerableAddToQueue($queueName, $message) {
        $client = $this->getClient();
        
        // 취약점: 사용자 입력을 검증 없이 큐에 추가
        // 공격 예시: 악성 스크립트나 명령어가 포함된 메시지 삽입
        $queueKey = "queue:" . $queueName;
        $result = $client->lpush($queueKey, $message);
        
        return $result > 0;
    }
    
    /**
     * 취약한 레디스 명령어 실행 (Command Injection)
     * 
     * @param string $command Redis 명령어 (사용자 입력)
     * @param array $args 명령어 인자들
     * @return mixed
     */
    public function vulnerableExecuteCommand($command, $args = []) {
        $client = $this->getClient();
        
        // 취약점: 사용자 입력 명령어를 직접 실행
        // 공격 예시: "FLUSHALL", "CONFIG GET *", "EVAL" 등 위험한 명령어 실행 가능
        try {
            if ($this->connectionType === 'phpredis') {
                // PHP Redis의 경우 동적 메서드 호출 사용
                return call_user_func_array([$client, strtolower($command)], $args);
            } else {
                // Predis의 경우 executeCommand 사용
                return $client->executeCommand($client->createCommand($command, $args));
            }
        } catch (Exception $e) {
            return "ERROR: " . $e->getMessage();
        }
    }
    
    // ==================== 안전한 Redis 캐시 메서드 ====================
    
    /**
     * 안전한 세션 데이터 조회
     * 
     * @param string $sessionId 세션 ID (검증됨)
     * @return string|null
     */
    public function safeGetSession($sessionId) {
        // 입력 검증
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $sessionId)) {
            return null;
        }
        
        if (strlen($sessionId) > 64) {
            return null;
        }
        
        $client = $this->getClient();
        
        // 안전한 키 생성: 고정 접두사 사용
        $sessionKey = "session:" . $sessionId;
        $result = $client->get($sessionKey);
        
        return $result;
    }
    
    /**
     * 안전한 사용자 프로필 캐시 조회
     * 
     * @param int $userId 사용자 ID (정수만 허용)
     * @return array|null
     */
    public function safeGetUserProfile($userId) {
        // 입력 검증: 정수만 허용
        if (!is_numeric($userId) || $userId <= 0) {
            return null;
        }
        
        $client = $this->getClient();
        
        // 안전한 키 생성
        $cacheKey = "user:" . intval($userId) . ":profile";
        $result = $client->get($cacheKey);
        
        if ($result) {
            return json_decode($result, true);
        }
        
        return null;
    }
    
    /**
     * 안전한 사용자 프로필 캐시 업데이트
     * 
     * @param int $userId 사용자 ID
     * @param array $allowedData 허용된 사용자 데이터
     * @return bool
     */
    public function safeUpdateUserProfile($userId, $allowedData) {
        // 입력 검증
        if (!is_numeric($userId) || $userId <= 0) {
            return false;
        }
        
        // 허용된 필드만 추출 (화이트리스트 방식)
        $whitelistedFields = ['name', 'email', 'theme', 'language'];
        $safeData = [];
        
        foreach ($whitelistedFields as $field) {
            if (isset($allowedData[$field]) && is_string($allowedData[$field])) {
                // 추가 검증
                $value = trim($allowedData[$field]);
                if (strlen($value) <= 255) {
                    $safeData[$field] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                }
            }
        }
        
        if (empty($safeData)) {
            return false;
        }
        
        $client = $this->getClient();
        
        // 안전한 키 생성 및 TTL 설정
        $cacheKey = "user:" . intval($userId) . ":profile";
        $result = $client->setex($cacheKey, 3600, json_encode($safeData)); // 1시간 TTL
        
        return (bool)$result;
    }
    
    /**
     * 안전한 캐시 통계 조회
     * 
     * @param string $statType 통계 타입 (사전 정의된 값만 허용)
     * @return array|null
     */
    public function safeGetCacheStats($statType) {
        // 허용된 통계 타입만 접근
        $allowedTypes = ['daily', 'weekly', 'monthly'];
        if (!in_array($statType, $allowedTypes)) {
            return null;
        }
        
        $client = $this->getClient();
        
        // 안전한 키 생성
        $statsKey = "api:stats:" . $statType;
        $result = $client->get($statsKey);
        
        if ($result) {
            return json_decode($result, true);
        }
        
        return null;
    }
    
    /**
     * 안전한 레디스 정보 조회 (제한된 명령어만 허용)
     * 
     * @param string $infoType 정보 타입
     * @return mixed
     */
    public function safeGetRedisInfo($infoType = 'server') {
        // 허용된 INFO 섹션만 접근
        $allowedSections = ['server', 'memory', 'stats'];
        if (!in_array($infoType, $allowedSections)) {
            return null;
        }
        
        $client = $this->getClient();
        
        try {
            if ($this->connectionType === 'phpredis') {
                return $client->info($infoType);
            } else {
                return $client->info($infoType);
            }
        } catch (Exception $e) {
            return null;
        }
    }
    
    /**
     * 캐시 키 존재 여부 확인 (안전한 방식)
     * 
     * @param string $keyPattern 키 패턴 (검증됨)
     * @return int
     */
    public function safeCountKeys($keyPattern) {
        // 패턴 검증: 안전한 패턴만 허용
        $allowedPatterns = [
            'session:*',
            'user:*:profile',
            'product:*',
            'config:app:*',
            'api:stats:*'
        ];
        
        if (!in_array($keyPattern, $allowedPatterns)) {
            return 0;
        }
        
        $client = $this->getClient();
        
        try {
            $keys = $client->keys($keyPattern);
            return count($keys);
        } catch (Exception $e) {
            return 0;
        }
    }
    
    /**
     * 연결 종료
     */
    public function close() {
        if ($this->connectionType === 'phpredis' && $this->redisClient) {
            $this->redisClient->close();
        }
        $this->predisClient = null;
        $this->redisClient = null;
        $this->isConnected = false;
    }
    
    /**
     * 소멸자
     */
    public function __destruct() {
        $this->close();
    }
}