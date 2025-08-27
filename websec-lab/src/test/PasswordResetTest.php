<?php

use PHPUnit\Framework\TestCase;

class PasswordResetTest extends TestCase
{
    protected static $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$pdo = $GLOBALS['pdo'];
    }

    protected function setUp(): void
    {
        setupTestDatabase(self::$pdo);
        
        // Create password_reset_tokens table for testing
        self::$pdo->exec("DROP TABLE IF EXISTS password_reset_tokens");
        self::$pdo->exec("CREATE TABLE password_reset_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token VARCHAR(100) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )");
    }

    public function testPasswordResetTokenGeneration()
    {
        $token1 = $this->generatePasswordResetToken();
        $token2 = $this->generatePasswordResetToken();
        
        $this->assertNotEmpty($token1, "Token should not be empty.");
        $this->assertNotEmpty($token2, "Token should not be empty.");
        $this->assertNotEquals($token1, $token2, "Tokens should be unique.");
        $this->assertEquals(100, strlen($token1), "Token should be 100 characters long.");
        $this->assertEquals(100, strlen($token2), "Token should be 100 characters long.");
    }

    public function testPasswordResetRequestWithValidEmail()
    {
        // Get existing user
        $stmt = self::$pdo->prepare("SELECT id, username FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $this->assertNotEmpty($user, "Test user should exist.");

        // Update user to have an email
        $email = 'testuser@example.com';
        $stmt = self::$pdo->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->execute([$email, $user['id']]);

        // Simulate password reset request
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $userForReset = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($userForReset, "User should be found by email.");

        // Generate reset token and expiry
        $token = $this->generatePasswordResetToken();
        $expires = date('Y-m-d H:i:s', time() + 1800); // 30 minutes

        // Insert password reset record
        $stmt = self::$pdo->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
        $result = $stmt->execute([$userForReset['id'], $token, $expires]);

        $this->assertTrue($result, "Password reset record should be created successfully.");

        // Verify the record was created
        $stmt = self::$pdo->prepare("SELECT * FROM password_reset_tokens WHERE user_id = ? AND token = ?");
        $stmt->execute([$userForReset['id'], $token]);
        $resetRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($resetRecord, "Password reset record should exist.");
        $this->assertEquals($token, $resetRecord['token'], "Token should match.");
        $this->assertEquals($expires, $resetRecord['expires_at'], "Expiry should match.");
    }

    public function testPasswordResetRequestWithInvalidEmail()
    {
        $invalidEmail = 'nonexistent@example.com';
        
        // Try to find user with invalid email
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$invalidEmail]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($user, "No user should be found with invalid email.");
    }

    public function testPasswordResetTokenValidation()
    {
        // Create user with email
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();
        
        $email = 'testuser@example.com';
        $stmt = self::$pdo->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->execute([$email, $userId]);

        // Create valid reset token
        $validToken = $this->generatePasswordResetToken();
        $validExpiry = date('Y-m-d H:i:s', time() + 1800); // 30 minutes from now
        
        $stmt = self::$pdo->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $validToken, $validExpiry]);

        // Test valid token
        $stmt = self::$pdo->prepare("SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()");
        $stmt->execute([$validToken]);
        $validReset = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($validReset, "Valid token should be found.");
        $this->assertEquals($userId, $validReset['user_id'], "User ID should match.");

        // Test invalid token
        $invalidToken = 'invalid_token_12345';
        $stmt = self::$pdo->prepare("SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()");
        $stmt->execute([$invalidToken]);
        $invalidReset = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($invalidReset, "Invalid token should not be found.");
    }

    public function testExpiredPasswordResetToken()
    {
        // Create user with email
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();
        
        // Clean up any existing tokens for this user
        $stmt = self::$pdo->prepare("DELETE FROM password_reset_tokens WHERE user_id = ?");
        $stmt->execute([$userId]);

        // Create expired reset token
        $expiredToken = $this->generatePasswordResetToken();
        $expiredTime = date('Y-m-d H:i:s', time() - 86400); // 24 hours ago (definitely expired)
        
        $stmt = self::$pdo->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $expiredToken, $expiredTime]);

        // Try to find expired token
        $stmt = self::$pdo->prepare("SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()");
        $stmt->execute([$expiredToken]);
        $expiredReset = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($expiredReset, "Expired token should not be valid.");

        // Verify the record exists but is expired
        $stmt = self::$pdo->prepare("SELECT * FROM password_reset_tokens WHERE token = ?");
        $stmt->execute([$expiredToken]);
        $existingRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($existingRecord, "Expired record should still exist in database.");
    }

    public function testPasswordUpdate()
    {
        // Get user
        $stmt = self::$pdo->prepare("SELECT id, password FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $originalPassword = $user['password'];

        // Create valid reset token
        $token = $this->generatePasswordResetToken();
        $expiry = date('Y-m-d H:i:s', time() + 1800);
        
        $stmt = self::$pdo->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$user['id'], $token, $expiry]);

        // Simulate password reset
        $newPassword = 'newpassword123';
        $hashedNewPassword = password_hash($newPassword, PASSWORD_DEFAULT);

        // Verify token is valid first
        $stmt = self::$pdo->prepare("SELECT user_id FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()");
        $stmt->execute([$token]);
        $resetUserId = $stmt->fetchColumn();

        $this->assertEquals($user['id'], $resetUserId, "Token should be valid for the user.");

        // Update password
        $stmt = self::$pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $result = $stmt->execute([$hashedNewPassword, $resetUserId]);

        $this->assertTrue($result, "Password update should be successful.");

        // Verify password was updated
        $stmt = self::$pdo->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->execute([$user['id']]);
        $updatedPassword = $stmt->fetchColumn();

        $this->assertNotEquals($originalPassword, $updatedPassword, "Password should be different from original.");
        $this->assertTrue(password_verify($newPassword, $updatedPassword), "New password should be verifiable.");

        // Clean up - delete used token
        $stmt = self::$pdo->prepare("DELETE FROM password_reset_tokens WHERE token = ?");
        $deleteResult = $stmt->execute([$token]);

        $this->assertTrue($deleteResult, "Used token should be deleted.");
    }

    public function testPasswordResetTokenCleanup()
    {
        // Create user
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();
        
        // Clean up any existing tokens for this user
        $stmt = self::$pdo->prepare("DELETE FROM password_reset_tokens WHERE user_id = ?");
        $stmt->execute([$userId]);

        // Create multiple reset tokens (old and new)
        $oldToken = $this->generatePasswordResetToken();
        $newToken = $this->generatePasswordResetToken();
        
        $oldExpiry = date('Y-m-d H:i:s', time() - 86400); // 24 hours ago (definitely expired)
        $newExpiry = date('Y-m-d H:i:s', time() + 1800); // 30 minutes from now

        $stmt = self::$pdo->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $oldToken, $oldExpiry]);
        $stmt->execute([$userId, $newToken, $newExpiry]);

        // Count total records
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ?");
        $stmt->execute([$userId]);
        $totalCount = $stmt->fetchColumn();
        $this->assertEquals(2, $totalCount, "Should have 2 reset records.");

        // Clean up expired tokens
        $stmt = self::$pdo->prepare("DELETE FROM password_reset_tokens WHERE expires_at <= NOW()");
        $cleanupResult = $stmt->execute();

        $this->assertTrue($cleanupResult, "Cleanup should execute successfully.");

        // Count remaining records
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ?");
        $stmt->execute([$userId]);
        $remainingCount = $stmt->fetchColumn();
        $this->assertEquals(1, $remainingCount, "Should have 1 remaining record after cleanup.");

        // Verify the remaining record is the non-expired one
        $stmt = self::$pdo->prepare("SELECT token FROM password_reset_tokens WHERE user_id = ?");
        $stmt->execute([$userId]);
        $remainingToken = $stmt->fetchColumn();
        $this->assertEquals($newToken, $remainingToken, "Remaining token should be the non-expired one.");
    }

    public function testResetLinkGeneration()
    {
        $token = $this->generatePasswordResetToken();
        $baseUrl = 'http://example.com';
        
        $resetLink = $this->generateResetLink($baseUrl, $token);
        $expectedLink = $baseUrl . '/reset_password.php?token=' . $token;
        
        $this->assertEquals($expectedLink, $resetLink, "Reset link should be properly formatted.");
        $this->assertStringContainsString($token, $resetLink, "Reset link should contain the token.");
        $this->assertStringContainsString('reset_password.php', $resetLink, "Reset link should point to reset_password.php.");
    }

    // Helper methods
    private function generatePasswordResetToken()
    {
        return bin2hex(random_bytes(50));
    }

    private function generateResetLink($baseUrl, $token)
    {
        return $baseUrl . '/reset_password.php?token=' . $token;
    }
}