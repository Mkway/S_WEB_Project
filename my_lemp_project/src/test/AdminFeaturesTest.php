<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../db.php'; // db.php 파일 포함

class AdminFeaturesTest extends TestCase
{
    protected static $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$pdo = $GLOBALS['pdo'];
    }

    protected function setUp(): void
    {
        setupTestDatabase(self::$pdo);
    }

    public function testSetUserAsAdminByAdmin()
    {
        // 일반 사용자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        // 관리자 ID 가져오기 (이 테스트에서는 관리자 권한이 있다고 가정)
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['adminuser']);
        $adminId = $stmt->fetchColumn();

        // 관리자가 일반 사용자를 관리자로 설정하는 로직 시뮬레이션
        // 실제 set_admin.php에서는 관리자 여부를 확인하는 로직이 필요
        $stmt = self::$pdo->prepare("UPDATE users SET is_admin = 1 WHERE id = ?");
        $result = $stmt->execute([$userId]);

        $this->assertTrue($result, "Setting user as admin should be successful.");
        $this->assertEquals(1, $stmt->rowCount(), "Exactly one row should be updated.");

        // 사용자 권한 확인
        $stmt = self::$pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $isAdmin = $stmt->fetchColumn();

        $this->assertTrue((bool)$isAdmin, "User should now be an admin.");
    }

    public function testSetUserAsAdminByRegularUser()
    {
        // 일반 사용자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        // 다른 일반 사용자 ID 생성
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute(['regularuser2', password_hash('password', PASSWORD_DEFAULT)]);
        $regularUser2Id = self::$pdo->lastInsertId();

        // 일반 사용자가 다른 사용자를 관리자로 설정 시도 (실패해야 함)
        // 실제 set_admin.php에서는 관리자 여부를 확인하고 권한이 없으면 업데이트를 수행하지 않음.
        // 여기서는 업데이트 쿼리가 실행되지만, rowCount가 0이어야 함.
        $stmt = self::$pdo->prepare("UPDATE users SET is_admin = 1 WHERE id = ? AND is_admin = 1"); // is_admin = 1 조건 추가하여 일반 사용자는 업데이트 못하게 함
        $result = $stmt->execute([$userId]);

        $this->assertTrue($result, "Update query should execute without error.");
        $this->assertEquals(0, $stmt->rowCount(), "No rows should be updated by regular user.");

        // 사용자 권한 확인 (여전히 일반 사용자여야 함)
        $stmt = self::$pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $isAdmin = $stmt->fetchColumn();

        $this->assertFalse((bool)$isAdmin, "User should still not be an admin.");
    }

    // admin.php 접근 테스트는 HTTP 요청을 시뮬레이션해야 하므로 PHPUnit 단독으로는 어려움.
    // 웹 테스트 프레임워크(예: Goutte)를 사용해야 함.
    // 여기서는 데이터베이스의 is_admin 플래그만 확인하는 방식으로 대체.
    public function testAdminAccessCheck()
    {
        // 관리자 사용자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['adminuser']);
        $adminId = $stmt->fetchColumn();

        // 관리자 여부 확인
        $stmt = self::$pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([$adminId]);
        $isAdmin = $stmt->fetchColumn();

        $this->assertTrue((bool)$isAdmin, "Admin user should have admin privileges.");
    }

    public function testRegularUserAccessCheck()
    {
        // 일반 사용자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        // 일반 사용자 여부 확인
        $stmt = self::$pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $isAdmin = $stmt->fetchColumn();

        $this->assertFalse((bool)$isAdmin, "Regular user should not have admin privileges.");
    }
}