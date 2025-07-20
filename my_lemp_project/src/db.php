<?php
$host = 'db'; // docker-compose에 정의된 DB 서비스 이름
$dbname = 'my_database';
$user = 'my_user';
$pass = 'my_password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}
?>