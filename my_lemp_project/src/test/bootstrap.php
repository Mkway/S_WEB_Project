<?php

// 테스트 환경 설정

// 데이터베이스 연결 설정 (테스트용)
$host = 'db';
$dbname = 'my_database'; // 실제 애플리케이션과 동일한 DB 사용
$user = 'my_user';
$pass = 'my_password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Test Database connection failed: " . $e->getMessage();
    exit(1);
}

// 테스트 데이터베이스 초기화 및 샘플 데이터 삽입
// 실제 운영 환경에 영향을 주지 않도록 주의
function setupTestDatabase($pdo) {
    // 기존 테이블 삭제 (테스트용)
    $pdo->exec("DROP TABLE IF EXISTS comments");
    $pdo->exec("DROP TABLE IF EXISTS posts");
    $pdo->exec("DROP TABLE IF EXISTS users");

    // users 테이블 생성
    $pdo->exec("CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
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

    // 샘플 사용자 데이터 삽입
    $password = password_hash('password123', PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)");
    $stmt->execute(['testuser', $password, 0]);
    $stmt->execute(['adminuser', $password, 1]);
}

setupTestDatabase($pdo);

// PDO 객체를 전역으로 사용하거나, 테스트 클래스에 주입할 수 있도록 설정
// 여기서는 간단하게 전역 변수로 설정 (실제 프로젝트에서는 DI를 고려)
$GLOBALS['pdo'] = $pdo;

?>