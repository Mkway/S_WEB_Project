<?php
/**
 * PostgreSQL 데이터베이스 연결 및 보안 테스트 클래스
 * 취약한 구현과 안전한 구현을 모두 제공
 */
class PostgreSQLConnection {
    private $vulnerable_pdo;
    private $safe_pdo;
    private $host = 'postgres';
    private $port = '5432';
    private $username = 'test_user';
    private $password = 'test_pass';

    public function __construct() {
        $this->connectVulnerable();
        $this->connectSafe();
    }

    /**
     * 취약한 데이터베이스 연결 (vuln_db)
     */
    private function connectVulnerable() {
        try {
            $dsn = "pgsql:host={$this->host};port={$this->port};dbname=vuln_db";
            $this->vulnerable_pdo = new PDO($dsn, $this->username, $this->password);
            $this->vulnerable_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            // 취약한 설정: 에러 정보 노출
            $this->vulnerable_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);
        } catch (PDOException $e) {
            throw new Exception("취약한 PostgreSQL 연결 실패: " . $e->getMessage());
        }
    }

    /**
     * 안전한 데이터베이스 연결 (safe_db)
     */
    private function connectSafe() {
        try {
            $dsn = "pgsql:host={$this->host};port={$this->port};dbname=safe_db";
            $this->safe_pdo = new PDO($dsn, $this->username, $this->password);
            $this->safe_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            // 안전한 설정
            $this->safe_pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            $this->safe_pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("안전한 PostgreSQL 연결 실패: " . $e->getMessage());
            throw new Exception("데이터베이스 연결에 실패했습니다.");
        }
    }

    /**
     * 취약한 PL/pgSQL Injection 테스트
     */
    public function testVulnerablePlpgsqlInjection($searchTerm) {
        $result = [];
        
        try {
            // 취약한 저장 프로시저 호출
            $query = "SELECT * FROM vulnerable_search('$searchTerm')";
            $stmt = $this->vulnerable_pdo->query($query);
            $result['success'] = true;
            $result['data'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $result['query'] = $query;
            $result['type'] = 'vulnerable';
            
        } catch (PDOException $e) {
            $result['success'] = false;
            $result['error'] = $e->getMessage();
            $result['query'] = $query ?? 'Query failed';
        }
        
        return $result;
    }

    /**
     * 안전한 검색 구현
     */
    public function testSafeSearch($searchTerm) {
        $result = [];
        
        try {
            // 안전한 파라미터화된 쿼리
            $query = "SELECT * FROM safe_search_products($1)";
            $stmt = $this->safe_pdo->prepare($query);
            $stmt->execute([$searchTerm]);
            
            $result['success'] = true;
            $result['data'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $result['query'] = $query;
            $result['type'] = 'safe';
            
        } catch (PDOException $e) {
            error_log("Safe search error: " . $e->getMessage());
            $result['success'] = false;
            $result['error'] = "검색 중 오류가 발생했습니다.";
        }
        
        return $result;
    }

    /**
     * 취약한 로그인 테스트 (SQL Injection 가능)
     */
    public function testVulnerableLogin($username, $password) {
        $result = [];
        
        try {
            // 취약한 저장 프로시저 호출
            $query = "SELECT * FROM vulnerable_login('$username', '$password')";
            $stmt = $this->vulnerable_pdo->query($query);
            
            $result['success'] = true;
            $result['data'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $result['query'] = $query;
            $result['type'] = 'vulnerable';
            
        } catch (PDOException $e) {
            $result['success'] = false;
            $result['error'] = $e->getMessage();
            $result['query'] = $query ?? 'Query failed';
        }
        
        return $result;
    }

    /**
     * 안전한 로그인 구현
     */
    public function testSafeLogin($username, $password) {
        $result = [];
        
        try {
            // 안전한 파라미터화된 쿼리
            $query = "SELECT * FROM safe_authenticate_user($1, $2)";
            $stmt = $this->safe_pdo->prepare($query);
            $stmt->execute([$username, $password]);
            
            $result['success'] = true;
            $result['data'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $result['query'] = $query;
            $result['type'] = 'safe';
            
        } catch (PDOException $e) {
            error_log("Safe login error: " . $e->getMessage());
            $result['success'] = false;
            $result['error'] = "인증 중 오류가 발생했습니다.";
        }
        
        return $result;
    }

    /**
     * 취약한 COPY FROM PROGRAM 테스트
     */
    public function testVulnerableCopyFromProgram($command) {
        $result = [];
        
        try {
            // 매우 위험한 COPY FROM PROGRAM 실행
            $query = "SELECT vulnerable_log_insert('$command')";
            $stmt = $this->vulnerable_pdo->query($query);
            
            $result['success'] = true;
            $result['message'] = "명령어가 실행되었습니다.";
            $result['query'] = $query;
            $result['type'] = 'vulnerable';
            
        } catch (PDOException $e) {
            $result['success'] = false;
            $result['error'] = $e->getMessage();
            $result['query'] = $query ?? 'Query failed';
        }
        
        return $result;
    }

    /**
     * PostgreSQL 버전 정보 조회 (정보 수집)
     */
    public function getPostgreSQLVersion() {
        try {
            $stmt = $this->vulnerable_pdo->query("SELECT version()");
            return $stmt->fetchColumn();
        } catch (PDOException $e) {
            return "Version information unavailable";
        }
    }

    /**
     * 데이터베이스 목록 조회 (정보 수집)
     */
    public function getDatabaseList() {
        try {
            $query = "SELECT datname FROM pg_database WHERE datistemplate = false";
            $stmt = $this->vulnerable_pdo->query($query);
            return $stmt->fetchAll(PDO::FETCH_COLUMN);
        } catch (PDOException $e) {
            return [];
        }
    }

    /**
     * 테이블 목록 조회 (정보 수집)
     */
    public function getTableList($database = 'current') {
        try {
            $query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'";
            $pdo = $database === 'safe' ? $this->safe_pdo : $this->vulnerable_pdo;
            $stmt = $pdo->query($query);
            return $stmt->fetchAll(PDO::FETCH_COLUMN);
        } catch (PDOException $e) {
            return [];
        }
    }

    /**
     * 연결 상태 확인
     */
    public function isConnected() {
        try {
            $vuln_status = $this->vulnerable_pdo && $this->vulnerable_pdo->query("SELECT 1") !== false;
            $safe_status = $this->safe_pdo && $this->safe_pdo->query("SELECT 1") !== false;
            
            return [
                'vulnerable_db' => $vuln_status,
                'safe_db' => $safe_status,
                'overall' => $vuln_status && $safe_status
            ];
        } catch (PDOException $e) {
            return [
                'vulnerable_db' => false,
                'safe_db' => false,
                'overall' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * 연결 종료
     */
    public function disconnect() {
        $this->vulnerable_pdo = null;
        $this->safe_pdo = null;
    }

    /**
     * 소멸자
     */
    public function __destruct() {
        $this->disconnect();
    }
}
?>