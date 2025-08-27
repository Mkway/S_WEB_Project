<?php
/**
 * 데이터베이스 연결 파일
 * PDO를 사용하여 MySQL 데이터베이스에 연결합니다.
 */

require_once 'config.php';
require_once 'Logger.php';

/**
 * 데이터베이스 연결 생성
 * @return PDO 데이터베이스 연결 객체
 */
function create_database_connection() {
    $dsn = sprintf(
        "mysql:host=%s;dbname=%s;charset=%s",
        DB_HOST,
        DB_NAME,
        DB_CHARSET
    );
    
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET
    ];
    
    try {
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        log_info("Database connection established", [
            'host' => DB_HOST,
            'database' => DB_NAME
        ]);
        return $pdo;
    } catch (PDOException $e) {
        log_critical("Database connection failed", [
            'host' => DB_HOST,
            'database' => DB_NAME,
            'error' => $e->getMessage()
        ]);
        
        if (DEBUG_MODE) {
            die("Database connection failed: " . $e->getMessage());
        } else {
            error_log("Database connection failed: " . $e->getMessage());
            die("서비스에 일시적인 문제가 발생했습니다. 잠시 후 다시 시도해주세요.");
        }
    }
}

// 전역 데이터베이스 연결 생성
$pdo = create_database_connection();

/**
 * 데이터베이스 연결 상태 확인
 * @param PDO $pdo 데이터베이스 연결
 * @return bool 연결 상태
 */
function is_database_connected($pdo) {
    try {
        $pdo->query('SELECT 1');
        return true;
    } catch (PDOException $e) {
        return false;
    }
}

/**
 * 트랜잭션 시작
 * @param PDO $pdo 데이터베이스 연결
 */
function begin_transaction($pdo) {
    $pdo->beginTransaction();
}

/**
 * 트랜잭션 커밋
 * @param PDO $pdo 데이터베이스 연결
 */
function commit_transaction($pdo) {
    $pdo->commit();
}

/**
 * 트랜잭션 롤백
 * @param PDO $pdo 데이터베이스 연결
 */
function rollback_transaction($pdo) {
    $pdo->rollback();
}
?>