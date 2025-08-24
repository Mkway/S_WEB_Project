# 🗄️ Phase 1: 다중 데이터베이스 환경 구축

**목표**: SQL 테스트를 위한 다양한 데이터베이스 환경 추가  
**우선순위**: HIGH  
**예상 기간**: 2-3주  

## 🎯 **1단계: PostgreSQL 환경 추가**

### Docker 설정 확장
```yaml
# docker-compose.yml에 추가
postgres:
  image: postgres:15
  container_name: security_postgres
  environment:
    POSTGRES_DB: security_test
    POSTGRES_USER: test_user
    POSTGRES_PASSWORD: test_pass
    POSTGRES_MULTIPLE_DATABASES: "vuln_db,safe_db"
  ports:
    - "5432:5432"
  volumes:
    - ./sql-challenges/postgres/init:/docker-entrypoint-initdb.d
    - postgres_data:/var/lib/postgresql/data
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U test_user -d security_test"]
    interval: 10s
    timeout: 5s
    retries: 5
```

### PostgreSQL 전용 취약점 테스트
```sql
-- 1. PL/pgSQL Injection
CREATE OR REPLACE FUNCTION vulnerable_search(search_term TEXT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
  -- 취약한 동적 쿼리 실행
  RETURN QUERY EXECUTE 'SELECT id, name FROM users WHERE name LIKE ''%' || search_term || '%''';
END;
$$ LANGUAGE plpgsql;

-- 2. COPY FROM PROGRAM 공격
-- 악용 가능한 COPY 명령어 테스트
```

### PHP PostgreSQL 연결 설정
```php
// PostgreSQL 연결 클래스 추가
class PostgreSQLConnection {
    private $pdo;
    
    public function __construct() {
        $dsn = "pgsql:host=postgres;port=5432;dbname=security_test";
        $this->pdo = new PDO($dsn, 'test_user', 'test_pass');
    }
    
    // PostgreSQL 특화 취약점 테스트 메서드들
    public function testPlpgsqlInjection($input) { ... }
    public function testCopyFromProgram($input) { ... }
}
```

## 🎯 **2단계: MongoDB 환경 추가**

### MongoDB 컨테이너 설정
```yaml
mongodb:
  image: mongo:7
  container_name: security_mongo
  environment:
    MONGO_INITDB_ROOT_USERNAME: admin
    MONGO_INITDB_ROOT_PASSWORD: admin123
    MONGO_INITDB_DATABASE: security_test
  ports:
    - "27017:27017"
  volumes:
    - ./nosql-challenges/mongo/init:/docker-entrypoint-initdb.d
    - mongodb_data:/data/db
```

### NoSQL Injection 시나리오 구성
```javascript
// MongoDB 초기 데이터 설정
db = db.getSiblingDB('security_test');

// 취약한 사용자 인증 컬렉션
db.users.insertMany([
  { username: "admin", password: "secret123", role: "admin" },
  { username: "user1", password: "pass123", role: "user" },
  { username: "guest", password: "guest123", role: "guest" }
]);

// 취약한 제품 검색 컬렉션
db.products.insertMany([
  { name: "Product A", price: 100, category: "electronics" },
  { name: "Product B", price: 200, category: "books" }
]);
```

### PHP MongoDB 드라이버 설정
```php
// MongoDB 연결 및 취약점 테스트 클래스
class MongoDBInjection {
    private $collection;
    
    public function __construct() {
        $client = new MongoDB\Client("mongodb://admin:admin123@mongodb:27017");
        $this->collection = $client->security_test->users;
    }
    
    // NoSQL Operator Injection
    public function vulnerableLogin($username, $password) {
        // 취약한 쿼리: {"username": {"$ne": null}, "password": {"$ne": null}}
        return $this->collection->findOne([
            'username' => $username,
            'password' => $password
        ]);
    }
}
```

## 🎯 **3단계: Redis 캐시 레이어**

### Redis 보안 테스트 환경
```yaml
redis:
  image: redis:7-alpine
  container_name: security_redis
  ports:
    - "6379:6379"
  volumes:
    - ./redis-challenges/redis.conf:/usr/local/etc/redis/redis.conf
    - redis_data:/data
  command: redis-server /usr/local/etc/redis/redis.conf
```

### Redis 취약점 시나리오
```php
// Redis 인젝션 및 악용 테스트
class RedisSecurityTest {
    private $redis;
    
    public function __construct() {
        $this->redis = new Redis();
        $this->redis->connect('redis', 6379);
    }
    
    // Lua 스크립트 인젝션 테스트
    public function testLuaInjection($userInput) {
        $script = "return redis.call('GET', KEYS[1]) .. '" . $userInput . "'";
        return $this->redis->eval($script, ['user:session'], 1);
    }
}
```

## 🛠️ **구현 계획**

### Week 1: PostgreSQL 환경
- [ ] Docker Compose 확장 및 PostgreSQL 컨테이너 추가
- [ ] PostgreSQL 전용 스키마 및 테스트 데이터 생성
- [ ] PHP PostgreSQL PDO 연결 구현
- [ ] PL/pgSQL Injection 테스트 모듈 개발

### Week 2: MongoDB 환경  
- [ ] MongoDB 컨테이너 및 초기 데이터 설정
- [ ] PHP MongoDB 드라이버 설치 및 연결
- [ ] NoSQL Operator Injection 모듈 개발
- [ ] JavaScript Expression Injection 테스트

### Week 3: Redis & 통합
- [ ] Redis 컨테이너 및 보안 설정
- [ ] Redis 취약점 테스트 모듈 개발
- [ ] 전체 환경 통합 테스트
- [ ] 문서화 및 사용자 가이드 작성

## 📊 **예상 성과**

### 새로운 테스트 모듈 (예상 15개 추가)
1. **PostgreSQL 모듈 (5개)**
   - PL/pgSQL Injection
   - COPY FROM PROGRAM
   - PostgreSQL Function Injection
   - Array/JSON Injection
   - Extension 악용

2. **MongoDB 모듈 (7개)**
   - Operator Injection ($ne, $gt, $regex)
   - JavaScript Injection
   - Aggregation Pipeline Injection
   - GridFS 악용
   - Map-Reduce Injection
   - BSON Injection
   - Authentication Bypass

3. **Redis 모듈 (3개)**  
   - Lua Script Injection
   - Command Injection
   - Data Structure 악용

### 기술적 성과
- **다중 DB 지원**: 총 4개 DB 환경 (MySQL, PostgreSQL, MongoDB, Redis)
- **실제 환경 근접**: 각 DB별 실제 취약점 시뮬레이션
- **확장 가능한 구조**: 추후 다른 DB 쉽게 추가 가능

## 🚀 **시작 제안**

**즉시 시작 가능한 첫 번째 작업:**
PostgreSQL 컨테이너를 docker-compose.yml에 추가하고 간단한 SQL Injection 테스트부터 시작하는 것이 어떨까요?

이 Phase 1이 완료되면 **업계 최고 수준의 다중 DB 보안 테스트 환경**이 완성됩니다! 🎯