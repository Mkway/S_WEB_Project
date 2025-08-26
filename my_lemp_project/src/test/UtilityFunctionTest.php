<?php

use PHPUnit\Framework\TestCase;

class UtilityFunctionTest extends TestCase
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

    public function testHtmlSpecialCharsEscaping()
    {
        // Test basic HTML escaping
        $input = '<script>alert("xss")</script>';
        $expected = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;';
        $actual = htmlspecialchars($input);
        
        $this->assertEquals($expected, $actual, "HTML special characters should be escaped.");

        // Test with quotes
        $input = 'Hello "World" & \'Test\'';
        $expected = 'Hello &quot;World&quot; &amp; &#039;Test&#039;';
        $actual = htmlspecialchars($input);
        
        $this->assertEquals($expected, $actual, "Quotes and ampersands should be escaped.");

        // Test empty string
        $this->assertEquals('', htmlspecialchars(''), "Empty string should remain empty.");

        // Test normal text
        $normalText = 'Normal text without special characters';
        $this->assertEquals($normalText, htmlspecialchars($normalText), "Normal text should remain unchanged.");
    }

    public function testPasswordHashing()
    {
        $password = 'testpassword123';
        
        // Test password hashing
        $hash1 = password_hash($password, PASSWORD_DEFAULT);
        $hash2 = password_hash($password, PASSWORD_DEFAULT);
        
        $this->assertNotEmpty($hash1, "Hash should not be empty.");
        $this->assertNotEmpty($hash2, "Hash should not be empty.");
        $this->assertNotEquals($hash1, $hash2, "Two hashes of the same password should be different (salt).");
        
        // Test password verification
        $this->assertTrue(password_verify($password, $hash1), "Password should verify against its hash.");
        $this->assertTrue(password_verify($password, $hash2), "Password should verify against its hash.");
        $this->assertFalse(password_verify('wrongpassword', $hash1), "Wrong password should not verify.");
    }

    public function testSessionIdRegeneration()
    {
        // This simulates the session_regenerate_id functionality
        $oldSessionId = 'old_session_123';
        $newSessionId = $this->regenerateSessionId();
        
        $this->assertNotEmpty($newSessionId, "New session ID should not be empty.");
        $this->assertNotEquals($oldSessionId, $newSessionId, "New session ID should be different from old one.");
        $this->assertGreaterThan(20, strlen($newSessionId), "Session ID should be sufficiently long.");
    }

    public function testFileExtensionValidation()
    {
        // Valid extensions
        $this->assertTrue($this->isValidImageExtension('image.jpg'));
        $this->assertTrue($this->isValidImageExtension('photo.jpeg'));
        $this->assertTrue($this->isValidImageExtension('picture.png'));
        $this->assertTrue($this->isValidImageExtension('avatar.gif'));
        
        // Invalid extensions
        $this->assertFalse($this->isValidImageExtension('file.txt'));
        $this->assertFalse($this->isValidImageExtension('script.php'));
        $this->assertFalse($this->isValidImageExtension('document.pdf'));
        $this->assertFalse($this->isValidImageExtension('archive.zip'));
        
        // Case insensitive
        $this->assertTrue($this->isValidImageExtension('image.JPG'));
        $this->assertTrue($this->isValidImageExtension('photo.PNG'));
        
        // Edge cases
        $this->assertFalse($this->isValidImageExtension(''));
        $this->assertFalse($this->isValidImageExtension('noextension'));
        $this->assertFalse($this->isValidImageExtension('.jpg'));
    }

    public function testDatabaseConnectionValidation()
    {
        $this->assertInstanceOf(PDO::class, self::$pdo, "Database connection should be a PDO instance.");
        
        // Test a simple query
        $stmt = self::$pdo->query("SELECT 1 as test");
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $this->assertEquals(1, $result['test'], "Database should be accessible and functional.");
    }

    public function testUserExistenceCheck()
    {
        // Check existing user
        $existingUser = $this->userExists('testuser');
        $this->assertTrue($existingUser, "Test user should exist.");
        
        // Check non-existing user
        $nonExistingUser = $this->userExists('nonexistentuser12345');
        $this->assertFalse($nonExistingUser, "Non-existent user should not exist.");
        
        // Check with empty username
        $emptyUser = $this->userExists('');
        $this->assertFalse($emptyUser, "Empty username should not exist.");
    }

    public function testPostExistenceCheck()
    {
        // Create a test post
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();
        
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, 'Test Post', 'Test Content']);
        $postId = self::$pdo->lastInsertId();
        
        // Check existing post
        $existingPost = $this->postExists($postId);
        $this->assertTrue($existingPost, "Created post should exist.");
        
        // Check non-existing post
        $nonExistingPost = $this->postExists(99999);
        $this->assertFalse($nonExistingPost, "Non-existent post should not exist.");
        
        // Check with invalid ID
        $invalidPost = $this->postExists(-1);
        $this->assertFalse($invalidPost, "Invalid post ID should not exist.");
    }

    public function testUserPermissionCheck()
    {
        // Get regular user
        $stmt = self::$pdo->prepare("SELECT id, is_admin FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $regularUser = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Get admin user
        $stmt->execute(['adminuser']);
        $adminUser = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Test admin permission
        $this->assertTrue($this->isAdmin($adminUser['is_admin']), "Admin user should have admin permissions.");
        $this->assertFalse($this->isAdmin($regularUser['is_admin']), "Regular user should not have admin permissions.");
    }

    public function testDateFormatting()
    {
        $timestamp = '2023-12-25 15:30:45';
        
        // Test date formatting
        $formattedDate = $this->formatDate($timestamp);
        $this->assertNotEmpty($formattedDate, "Formatted date should not be empty.");
        $this->assertStringContainsString('2023', $formattedDate, "Formatted date should contain year.");
        
        // Test relative time formatting
        $now = date('Y-m-d H:i:s');
        $relativeTime = $this->getRelativeTime($now);
        $this->assertStringContainsString('now', strtolower($relativeTime), "Current time should show as 'now' or similar.");
    }

    public function testStringTruncation()
    {
        $longText = 'This is a very long text that should be truncated when it exceeds the maximum length limit';
        
        $truncated = $this->truncateString($longText, 50);
        $this->assertLessThanOrEqual(53, strlen($truncated), "Truncated string should not exceed max length + ellipsis.");
        $this->assertStringEndsWith('...', $truncated, "Truncated string should end with ellipsis.");
        
        $shortText = 'Short text';
        $notTruncated = $this->truncateString($shortText, 50);
        $this->assertEquals($shortText, $notTruncated, "Short text should not be truncated.");
    }

    public function testArraySanitization()
    {
        $dirtyArray = [
            'name' => '  John Doe  ',
            'email' => ' john@example.com ',
            'comment' => '  This is a comment with extra spaces  '
        ];
        
        $cleanArray = $this->sanitizeArray($dirtyArray);
        
        $this->assertEquals('John Doe', $cleanArray['name'], "Array values should be trimmed.");
        $this->assertEquals('john@example.com', $cleanArray['email'], "Array values should be trimmed.");
        $this->assertEquals('This is a comment with extra spaces', $cleanArray['comment'], "Array values should be trimmed.");
    }

    public function testLogFilePathGeneration()
    {
        $logPath = $this->generateLogFilePath('error');
        
        $this->assertStringContainsString('error', $logPath, "Log path should contain log type.");
        $this->assertStringContainsString(date('Y-m-d'), $logPath, "Log path should contain current date.");
        $this->assertStringEndsWith('.log', $logPath, "Log path should end with .log extension.");
    }

    // Helper methods that simulate utility functions
    private function regenerateSessionId()
    {
        return bin2hex(random_bytes(32));
    }

    private function isValidImageExtension($filename)
    {
        if (empty($filename)) return false;
        
        // Check if filename starts with dot (hidden file or no base name)
        if (strpos($filename, '.') === 0) return false;
        
        $validExtensions = ['jpg', 'jpeg', 'png', 'gif'];
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        return in_array($extension, $validExtensions);
    }

    private function userExists($username)
    {
        if (empty($username)) return false;
        
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetchColumn() > 0;
    }

    private function postExists($postId)
    {
        if (!is_numeric($postId) || $postId <= 0) return false;
        
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        return $stmt->fetchColumn() > 0;
    }

    private function isAdmin($isAdminFlag)
    {
        return (bool)$isAdminFlag;
    }

    private function formatDate($timestamp)
    {
        return date('M j, Y g:i A', strtotime($timestamp));
    }

    private function getRelativeTime($timestamp)
    {
        $diff = time() - strtotime($timestamp);
        
        if ($diff < 60) return 'just now';
        if ($diff < 3600) return floor($diff / 60) . ' minutes ago';
        if ($diff < 86400) return floor($diff / 3600) . ' hours ago';
        return floor($diff / 86400) . ' days ago';
    }

    private function truncateString($text, $maxLength)
    {
        if (strlen($text) <= $maxLength) return $text;
        return substr($text, 0, $maxLength) . '...';
    }

    private function sanitizeArray($array)
    {
        return array_map('trim', $array);
    }

    private function generateLogFilePath($type)
    {
        return 'logs/' . $type . '_' . date('Y-m-d') . '.log';
    }
}