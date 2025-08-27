<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../db.php'; // db.php 파일 포함

class UserAuthTest extends TestCase
{
    protected static $pdo;

    public static function setUpBeforeClass(): void
    {
        // bootstrap.php에서 설정된 PDO 객체 사용
        self::$pdo = $GLOBALS['pdo'];
    }

    protected function setUp(): void
    {
        // 각 테스트 전에 데이터베이스 초기화 및 샘플 데이터 삽입
        setupTestDatabase(self::$pdo);
    }

    public function testUserRegistrationSuccess()
    {
        $username = 'newuser';
        $password = 'newpassword123';

        // 사용자 등록 로직 시뮬레이션 (실제 register.php의 핵심 로직)
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $result = $stmt->execute([$username, $hashed_password]);

        $this->assertTrue($result, "User registration should be successful.");

        // 등록된 사용자 확인
        $stmt = self::$pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($user, "Registered user should exist in the database.");
        $this->assertEquals($username, $user['username'], "Username should match.");
        $this->assertTrue(password_verify($password, $user['password']), "Password should be correctly hashed and verifiable.");
    }

    public function testUserRegistrationDuplicateUsername()
    {
        $username = 'testuser'; // bootstrap.php에서 이미 존재하는 사용자
        $password = 'anotherpassword';

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");

        // 중복 사용자 이름으로 등록 시 예외 발생 확인
        $this->expectException(PDOException::class);
        $stmt->execute([$username, $hashed_password]);
    }

    public function testUserLoginSuccess()
    {
        $username = 'testuser';
        $password = 'password123';

        // 로그인 로직 시뮬레이션 (실제 login.php의 핵심 로직)
        $stmt = self::$pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($user, "User should exist for login.");
        $this->assertTrue(password_verify($password, $user['password']), "Password should match for login.");
    }

    public function testUserLoginWrongPassword()
    {
        $username = 'testuser';
        $password = 'wrongpassword';

        $stmt = self::$pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($user, "User should exist for login attempt.");
        $this->assertFalse(password_verify($password, $user['password']), "Wrong password should not match.");
    }

    public function testUserLoginNonExistentUser()
    {
        $username = 'nonexistent';
        $password = 'anypassword';

        $stmt = self::$pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($user, "Non-existent user should not be found.");
    }

    // 로그아웃은 세션 관련이므로 백엔드 테스트로는 직접 검증하기 어려움.
    // 실제 웹 요청을 시뮬레이션하는 통합 테스트에서 검증하는 것이 적합.
    // 여기서는 세션 관련 로직이 없으므로 생략.
}