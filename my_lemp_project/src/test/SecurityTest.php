<?php

use PHPUnit\Framework\TestCase;

class SecurityTest extends TestCase
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

    public function testCSRFTokenValidation()
    {
        // Generate valid token
        $validToken = bin2hex(random_bytes(32));
        
        // Test valid token comparison
        $this->assertTrue($this->validateCSRFToken($validToken, $validToken), "Identical tokens should validate.");
        
        // Test invalid token comparison
        $invalidToken = bin2hex(random_bytes(32));
        $this->assertFalse($this->validateCSRFToken($validToken, $invalidToken), "Different tokens should not validate.");
        
        // Test empty tokens
        $this->assertFalse($this->validateCSRFToken('', $validToken), "Empty session token should not validate.");
        $this->assertFalse($this->validateCSRFToken($validToken, ''), "Empty submitted token should not validate.");
        $this->assertFalse($this->validateCSRFToken('', ''), "Both empty tokens should not validate.");
    }

    public function testSQLInjectionPrevention()
    {
        // Test with malicious input
        $maliciousUsername = "admin'; DROP TABLE users; --";
        
        // This should not cause any issues due to prepared statements
        $stmt = self::$pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$maliciousUsername]);
        $result = $stmt->fetch();
        
        $this->assertFalse($result, "Malicious SQL should not return results.");
        
        // Verify the users table still exists
        $stmt = self::$pdo->query("SELECT COUNT(*) FROM users");
        $userCount = $stmt->fetchColumn();
        
        $this->assertGreaterThan(0, $userCount, "Users table should still exist and have data.");
    }

    public function testXSSPrevention()
    {
        // Test XSS payload escaping
        $xssPayload = '<script>alert("XSS")</script>';
        $escapedPayload = htmlspecialchars($xssPayload);
        
        $this->assertNotEquals($xssPayload, $escapedPayload, "XSS payload should be escaped.");
        $this->assertStringNotContains('<script>', $escapedPayload, "Script tags should be escaped.");
        $this->assertStringContains('&lt;script&gt;', $escapedPayload, "Script tags should be HTML-encoded.");
        
        // Test various XSS vectors
        $xssVectors = [
            '<img src="x" onerror="alert(1)">',
            '<svg onload="alert(1)">',
            'javascript:alert(1)',
            '"><script>alert(1)</script>',
            '\'-alert(1)-\'',
        ];
        
        foreach ($xssVectors as $vector) {
            $escaped = htmlspecialchars($vector);
            $this->assertNotContains('<script>', $escaped, "XSS vector should be neutralized: " . $vector);
            $this->assertNotContains('javascript:', $escaped, "JavaScript protocol should be escaped: " . $vector);
        }
    }

    public function testSessionSecurity()
    {
        // Test session data validation
        $validSessionData = [
            'user_id' => 123,
            'username' => 'testuser',
            'is_admin' => false
        ];
        
        $this->assertTrue($this->isValidSessionData($validSessionData), "Valid session data should pass validation.");
        
        // Test invalid session data
        $invalidSessionData = [
            'user_id' => 'not_a_number',
            'username' => '',
            'is_admin' => 'maybe'
        ];
        
        $this->assertFalse($this->isValidSessionData($invalidSessionData), "Invalid session data should fail validation.");
    }

    public function testFileUploadSecurity()
    {
        // Test safe file names
        $safeFiles = [
            'image.jpg',
            'photo.png',
            'document.pdf',
            'file_name.txt'
        ];
        
        foreach ($safeFiles as $filename) {
            $this->assertTrue($this->isSafeFilename($filename), "Safe filename should pass: " . $filename);
        }
        
        // Test dangerous file names
        $dangerousFiles = [
            '../../../etc/passwd',
            '..\\..\\windows\\system32\\config\\sam',
            'file.php.jpg',
            '.htaccess',
            'web.config',
            'file.exe',
            'script.php',
            'shell.sh'
        ];
        
        foreach ($dangerousFiles as $filename) {
            $this->assertFalse($this->isSafeFilename($filename), "Dangerous filename should be rejected: " . $filename);
        }
    }

    public function testPasswordStrength()
    {
        // Test strong passwords
        $strongPasswords = [
            'StrongPass123!',
            'MySecureP@ssw0rd',
            'C0mpl3x_P@ssw0rd!',
            'Sup3r_S3cur3_2023!'
        ];
        
        foreach ($strongPasswords as $password) {
            $this->assertTrue($this->isStrongPassword($password), "Strong password should pass: " . $password);
        }
        
        // Test weak passwords
        $weakPasswords = [
            'password',
            '123456',
            'qwerty',
            'admin',
            'password123',
            'admin123',
            'test',
            '12345678'
        ];
        
        foreach ($weakPasswords as $password) {
            $this->assertFalse($this->isStrongPassword($password), "Weak password should fail: " . $password);
        }
    }

    public function testInputLengthLimits()
    {
        // Test username length limits
        $this->assertTrue($this->isValidUsernameLength('user'), "Normal username should be valid.");
        $this->assertTrue($this->isValidUsernameLength('a_very_long_username'), "Long but valid username should pass.");
        
        $this->assertFalse($this->isValidUsernameLength('ab'), "Too short username should fail.");
        $this->assertFalse($this->isValidUsernameLength(str_repeat('a', 51)), "Too long username should fail.");
        
        // Test content length limits
        $normalContent = 'This is normal content for a post.';
        $this->assertTrue($this->isValidContentLength($normalContent), "Normal content should be valid.");
        
        $tooLongContent = str_repeat('This is a very long content. ', 1000);
        $this->assertFalse($this->isValidContentLength($tooLongContent), "Excessively long content should be rejected.");
    }

    public function testAdvancedSQLInjectionPayloads()
    {
        // UNION-based SQL injection payloads
        $unionPayloads = [
            "1' UNION SELECT null,username,password FROM users--",
            "1' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT null,null,null--",
            "1' UNION ALL SELECT null,null,null--"
        ];
        
        foreach ($unionPayloads as $payload) {
            $stmt = self::$pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$payload]);
            $result = $stmt->fetch();
            $this->assertFalse($result, "UNION injection should not return results: " . $payload);
        }
        
        // Boolean-based blind SQL injection payloads
        $booleanPayloads = [
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
            "1' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>64--",
            "1' AND SLEEP(5)--"
        ];
        
        foreach ($booleanPayloads as $payload) {
            $stmt = self::$pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$payload]);
            $result = $stmt->fetch();
            $this->assertFalse($result, "Boolean injection should not return results: " . $payload);
        }
        
        // Time-based blind SQL injection payloads
        $timePayloads = [
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT SLEEP(5))--",
            "1'; SELECT pg_sleep(5)--",
            "1' AND BENCHMARK(5000000,MD5(1))--"
        ];
        
        foreach ($timePayloads as $payload) {
            $startTime = microtime(true);
            $stmt = self::$pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$payload]);
            $result = $stmt->fetch();
            $endTime = microtime(true);
            
            $this->assertFalse($result, "Time-based injection should not return results: " . $payload);
            $this->assertLessThan(1, $endTime - $startTime, "Time-based injection should not cause delays: " . $payload);
        }
        
        // Error-based SQL injection payloads
        $errorPayloads = [
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "1' AND EXP(~(SELECT * FROM (SELECT version())a))--"
        ];
        
        foreach ($errorPayloads as $payload) {
            $stmt = self::$pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$payload]);
            $result = $stmt->fetch();
            $this->assertFalse($result, "Error-based injection should not return results: " . $payload);
        }
        
        // Verify data integrity after all injection attempts
        $stmt = self::$pdo->query("SELECT COUNT(*) FROM users");
        $userCount = $stmt->fetchColumn();
        $this->assertEquals(2, $userCount, "User count should remain unchanged after injection attempts.");
    }

    public function testDatabaseInjectionWithPreparedStatements()
    {
        // Test that prepared statements prevent injection
        $maliciousInputs = [
            "'; DELETE FROM users; --",
            "1' OR '1'='1",
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'pass'); --",
            "1'; UPDATE users SET is_admin=1; --"
        ];
        
        foreach ($maliciousInputs as $input) {
            // This should safely handle the malicious input
            $stmt = self::$pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$input]);
            $result = $stmt->fetch();
            
            // Should not find any results with non-numeric ID
            $this->assertFalse($result, "Malicious input should not return results: " . $input);
        }
        
        // Verify data integrity
        $stmt = self::$pdo->query("SELECT COUNT(*) FROM users");
        $userCount = $stmt->fetchColumn();
        $this->assertEquals(2, $userCount, "User count should remain unchanged after injection attempts.");
    }

    public function testUserAuthorizationChecks()
    {
        // Create test users
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $user1Id = $stmt->fetchColumn();
        
        $stmt->execute(['adminuser']);
        $adminId = $stmt->fetchColumn();
        
        // Create a post by user1
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$user1Id, 'User1 Post', 'Content by user1']);
        $postId = self::$pdo->lastInsertId();
        
        // Test that user can access their own post
        $this->assertTrue($this->canUserAccessPost($user1Id, $postId), "User should be able to access their own post.");
        
        // Test that admin can access any post
        $this->assertTrue($this->canAdminAccessPost($adminId, $postId), "Admin should be able to access any post.");
        
        // Create another user who shouldn't access the post
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute(['otheruser', password_hash('password', PASSWORD_DEFAULT)]);
        $otherUserId = self::$pdo->lastInsertId();
        
        $this->assertFalse($this->canUserAccessPost($otherUserId, $postId), "Other user should not access post they don't own.");
    }

    // Helper methods for security testing
    private function validateCSRFToken($sessionToken, $submittedToken)
    {
        return !empty($sessionToken) && !empty($submittedToken) && hash_equals($sessionToken, $submittedToken);
    }

    private function isValidSessionData($data)
    {
        return isset($data['user_id']) && 
               is_numeric($data['user_id']) && 
               isset($data['username']) && 
               !empty($data['username']) &&
               isset($data['is_admin']) &&
               is_bool($data['is_admin']);
    }

    private function isSafeFilename($filename)
    {
        // Check for directory traversal
        if (strpos($filename, '..') !== false) return false;
        if (strpos($filename, '/') !== false) return false;
        if (strpos($filename, '\\') !== false) return false;
        
        // Check for dangerous extensions
        $dangerousExts = ['php', 'exe', 'sh', 'bat', 'com', 'scr', 'vbs', 'js'];
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (in_array($ext, $dangerousExts)) return false;
        
        // Check for hidden files and system files
        if (strpos($filename, '.ht') === 0) return false;
        if ($filename === 'web.config') return false;
        
        return true;
    }

    private function isStrongPassword($password)
    {
        // Minimum 8 characters
        if (strlen($password) < 8) return false;
        
        // Must contain uppercase, lowercase, number
        if (!preg_match('/[A-Z]/', $password)) return false;
        if (!preg_match('/[a-z]/', $password)) return false;
        if (!preg_match('/[0-9]/', $password)) return false;
        
        // Common weak passwords
        $commonPasswords = ['password', '123456', 'qwerty', 'admin', 'test', 'user'];
        if (in_array(strtolower($password), $commonPasswords)) return false;
        
        return true;
    }

    private function isValidUsernameLength($username)
    {
        return strlen($username) >= 3 && strlen($username) <= 50;
    }

    private function isValidContentLength($content)
    {
        return strlen($content) <= 10000; // 10KB limit
    }

    private function canUserAccessPost($userId, $postId)
    {
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM posts WHERE id = ? AND user_id = ?");
        $stmt->execute([$postId, $userId]);
        return $stmt->fetchColumn() > 0;
    }

    private function canAdminAccessPost($adminId, $postId)
    {
        // Check if user is admin
        $stmt = self::$pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([$adminId]);
        $isAdmin = $stmt->fetchColumn();
        
        if (!$isAdmin) return false;
        
        // Admin can access any post
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        return $stmt->fetchColumn() > 0;
    }
}