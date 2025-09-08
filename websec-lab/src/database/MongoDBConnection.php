<?php
/**
 * MongoDB 연결 및 NoSQL Injection 테스트 클래스
 * 
 * MongoDB 연결 관리와 NoSQL 보안 테스트를 위한 취약점 및 안전한 쿼리 메서드 제공
 */

require_once __DIR__ . '/../vendor/autoload.php';

use MongoDB\Client;
use MongoDB\Database;
use MongoDB\Collection;
use Exception;

class MongoDBConnection {
    private $client;
    private $database;
    private $isConnected = false;
    
    // 연결 설정
    private $host = 'mongodb';
    private $port = 27017;
    private $username = 'admin';
    private $password = 'admin123';
    private $databaseName = 'security_test';
    
    public function __construct() {
        $this->connect();
    }
    
    /**
     * MongoDB 연결 설정
     */
    private function connect() {
        try {
            $uri = "mongodb://{$this->username}:{$this->password}@{$this->host}:{$this->port}";
            $this->client = new Client($uri, [
                'connectTimeoutMS' => 3000,
                'serverSelectionTimeoutMS' => 5000
            ]);
            
            $this->database = $this->client->selectDatabase($this->databaseName);
            
            // 연결 테스트
            $this->database->command(['ping' => 1]);
            $this->isConnected = true;
            
        } catch (Exception $e) {
            $this->isConnected = false;
            throw new Exception("MongoDB 연결 실패: " . $e->getMessage());
        }
    }
    
    /**
     * 연결 상태 확인
     */
    public function isConnected(): bool {
        return $this->isConnected;
    }
    
    /**
     * 컬렉션 선택
     */
    public function getCollection(string $collectionName): Collection {
        if (!$this->isConnected) {
            throw new Exception("MongoDB 연결이 되어있지 않습니다.");
        }
        return $this->database->selectCollection($collectionName);
    }
    
    /**
     * 데이터베이스 객체 반환
     */
    public function getDatabase(): Database {
        if (!$this->isConnected) {
            throw new Exception("MongoDB 연결이 되어있지 않습니다.");
        }
        return $this->database;
    }
    
    // ==================== 취약한 NoSQL 쿼리 메서드 ====================
    
    /**
     * 취약한 사용자 로그인 (NoSQL Operator Injection)
     * 
     * @param mixed $username 사용자명 (배열 공격 가능)
     * @param mixed $password 패스워드 (배열 공격 가능)
     * @return array|null
     */
    public function vulnerableLogin($username, $password) {
        $users = $this->getCollection('users');
        
        // 취약점: 사용자 입력을 그대로 쿼리에 사용
        // 공격 예시: username = {"$ne": null}, password = {"$ne": null}
        $result = $users->findOne([
            'username' => $username,
            'password' => $password,
            'active' => true
        ]);
        
        return $result ? $result->toArray() : null;
    }
    
    /**
     * 취약한 제품 검색 (JavaScript Expression Injection)
     * 
     * @param string $searchTerm 검색어
     * @param string $category 카테고리
     * @return array
     */
    public function vulnerableProductSearch($searchTerm, $category = '') {
        $products = $this->getCollection('products');
        
        // 취약점: JavaScript 표현식을 직접 사용
        $whereClause = "this.name.includes('{$searchTerm}')";
        if (!empty($category)) {
            $whereClause .= " && this.category == '{$category}'";
        }
        
        $results = $products->find([
            '$where' => $whereClause,
            'active' => true
        ]);
        
        return iterator_to_array($results);
    }
    
    /**
     * 취약한 정보 수집 (MongoDB Operator 남용)
     * 
     * @param array $filters 필터 조건
     * @return array
     */
    public function vulnerableDataCollection($filters) {
        $logs = $this->getCollection('logs');
        
        // 취약점: 사용자 입력을 필터로 직접 사용
        // 공격 예시: {"level": {"$regex": ".*"}, "$where": "sleep(5000)"}
        $results = $logs->find($filters);
        
        return iterator_to_array($results);
    }
    
    /**
     * 취약한 사용자 정보 업데이트 (Update Operator Injection)
     * 
     * @param string $userId 사용자 ID
     * @param array $updateData 업데이트할 데이터
     * @return bool
     */
    public function vulnerableUserUpdate($userId, $updateData) {
        $users = $this->getCollection('users');
        
        // 취약점: 업데이트 데이터를 그대로 사용
        // 공격 예시: {"$set": {"role": "administrator"}}
        $result = $users->updateOne(
            ['_id' => new \MongoDB\BSON\ObjectId($userId)],
            $updateData
        );
        
        return $result->getModifiedCount() > 0;
    }
    
    // ==================== 안전한 NoSQL 쿼리 메서드 ====================
    
    /**
     * 안전한 사용자 로그인
     * 
     * @param string $username 사용자명
     * @param string $password 패스워드
     * @return array|null
     */
    public function safeLogin($username, $password) {
        // 입력 검증
        if (!is_string($username) || !is_string($password)) {
            return null;
        }
        
        // 문자열 길이 제한
        if (strlen($username) > 50 || strlen($password) > 100) {
            return null;
        }
        
        $users = $this->getCollection('users');
        
        // 안전한 쿼리: 명시적 타입 지정
        $result = $users->findOne([
            'username' => (string)$username,
            'password' => (string)$password,
            'active' => true
        ]);
        
        return $result ? $result->toArray() : null;
    }
    
    /**
     * 안전한 제품 검색
     * 
     * @param string $searchTerm 검색어
     * @param string $category 카테고리
     * @return array
     */
    public function safeProductSearch($searchTerm, $category = '') {
        // 입력 검증 및 정제
        $searchTerm = filter_var($searchTerm, FILTER_SANITIZE_STRING);
        $category = filter_var($category, FILTER_SANITIZE_STRING);
        
        if (strlen($searchTerm) > 100) {
            return [];
        }
        
        $products = $this->getCollection('products');
        
        // 안전한 검색: 정규식 사용 ($where 절 대신)
        $filter = [
            'active' => true,
            '$or' => [
                ['name' => new \MongoDB\BSON\Regex($searchTerm, 'i')],
                ['description' => new \MongoDB\BSON\Regex($searchTerm, 'i')]
            ]
        ];
        
        if (!empty($category)) {
            $filter['category'] = $category;
        }
        
        $results = $products->find($filter);
        
        return iterator_to_array($results);
    }
    
    /**
     * 안전한 사용자 정보 업데이트
     * 
     * @param string $userId 사용자 ID
     * @param array $allowedFields 허용된 필드만 업데이트
     * @return bool
     */
    public function safeUserUpdate($userId, $allowedFields) {
        // 입력 검증
        if (!preg_match('/^[0-9a-f]{24}$/i', $userId)) {
            return false;
        }
        
        // 허용된 필드만 추출 (화이트리스트 방식)
        $whitelistedFields = ['email', 'username'];
        $updateData = [];
        
        foreach ($whitelistedFields as $field) {
            if (isset($allowedFields[$field]) && is_string($allowedFields[$field])) {
                $updateData[$field] = filter_var($allowedFields[$field], FILTER_SANITIZE_STRING);
            }
        }
        
        if (empty($updateData)) {
            return false;
        }
        
        $users = $this->getCollection('users');
        
        $result = $users->updateOne(
            ['_id' => new \MongoDB\BSON\ObjectId($userId)],
            ['$set' => $updateData]
        );
        
        return $result->getModifiedCount() > 0;
    }
    
    /**
     * 연결 종료
     */
    public function close() {
        $this->client = null;
        $this->database = null;
        $this->isConnected = false;
    }
    
    /**
     * 소멸자
     */
    public function __destruct() {
        $this->close();
    }
}