<?php

// 테스트 환경 설정

// CI 환경 감지 및 데이터베이스 연결 설정
$isCI = getenv('CI') || getenv('GITHUB_ACTIONS');

if ($isCI) {
    // GitHub Actions CI 환경
    $host = '127.0.0.1';
    $dbname = 'test_database';
    $user = 'test_user';
    $pass = 'test_password';
} else {
    // 로컬 개발 환경
    $host = 'db';
    $dbname = 'my_database';
    $user = 'my_user';
    $pass = 'my_password';
}

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    if ($isCI) {
        echo "Test Database connection failed: " . $e->getMessage();
        exit(1);
    } else {
        // 로컬에서는 데이터베이스 없이 테스트 진행
        echo "Database not available locally, skipping database-dependent tests\n";
        $pdo = null;
    }
}

// 테스트 데이터베이스 초기화 및 샘플 데이터 삽입
// 실제 운영 환경에 영향을 주지 않도록 주의
function setupTestDatabase($pdo) {
    // 외래 키 제약 조건 일시 비활성화
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 0;");

    // 기존 테이블 삭제 (테스트용)
    $pdo->exec("DROP TABLE IF EXISTS password_reset_tokens");
    $pdo->exec("DROP TABLE IF EXISTS comments");
    $pdo->exec("DROP TABLE IF EXISTS posts");
    $pdo->exec("DROP TABLE IF EXISTS users");
    $pdo->exec("DROP TABLE IF EXISTS notifications"); // notifications 테이블 추가

    // 외래 키 제약 조건 다시 활성화
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 1;");

    // users 테이블 생성
    $pdo->exec("CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(255) DEFAULT '',
        password VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // posts 테이블 생성
    $pdo->exec("CREATE TABLE posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        image_path VARCHAR(255),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    // comments 테이블 생성
    $pdo->exec("CREATE TABLE comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id INT NOT NULL,
        user_id INT NOT NULL,
        comment_text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    // notifications 테이블 생성
    $pdo->exec("CREATE TABLE notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        type VARCHAR(50) NOT NULL,
        source_id INT,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    // password_reset_tokens 테이블 생성
    $pdo->exec("CREATE TABLE password_reset_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(255) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    // 샘플 사용자 데이터 삽입
    $password = password_hash('password123', PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)");
    $stmt->execute(['testuser', 'test@example.com', $password, 0]);
    $stmt->execute(['adminuser', 'admin@example.com', $password, 1]);
}

// 데이터베이스가 사용 가능한 경우에만 초기화
if ($pdo !== null) {
    setupTestDatabase($pdo);
}

// PDO 객체를 전역으로 사용하거나, 테스트 클래스에 주입할 수 있도록 설정
// 여기서는 간단하게 전역 변수로 설정 (실제 프로젝트에서는 DI를 고려)
$GLOBALS['pdo'] = $pdo;

?>