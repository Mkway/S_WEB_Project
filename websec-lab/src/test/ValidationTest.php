<?php

use PHPUnit\Framework\TestCase;

class ValidationTest extends TestCase
{
    public function testUsernameValidation()
    {
        // Valid usernames
        $this->assertTrue($this->isValidUsername('testuser'));
        $this->assertTrue($this->isValidUsername('user123'));
        $this->assertTrue($this->isValidUsername('test_user'));
        $this->assertTrue($this->isValidUsername('a1b'));
        $this->assertTrue($this->isValidUsername('12345678901234567890'));
        
        // Invalid usernames
        $this->assertFalse($this->isValidUsername(''));
        $this->assertFalse($this->isValidUsername('ab'));
        $this->assertFalse($this->isValidUsername('123456789012345678901'));
        $this->assertFalse($this->isValidUsername('user-name'));
        $this->assertFalse($this->isValidUsername('user name'));
        $this->assertFalse($this->isValidUsername('user@name'));
        $this->assertFalse($this->isValidUsername('user.name'));
    }
    
    public function testEmailValidation()
    {
        // Valid emails
        $this->assertTrue($this->isValidEmail('test@example.com'));
        $this->assertTrue($this->isValidEmail('user.name@domain.co.uk'));
        $this->assertTrue($this->isValidEmail('user+tag@example.org'));
        $this->assertTrue($this->isValidEmail('123@456.com'));
        
        // Invalid emails
        $this->assertFalse($this->isValidEmail(''));
        $this->assertFalse($this->isValidEmail('invalid'));
        $this->assertFalse($this->isValidEmail('invalid@'));
        $this->assertFalse($this->isValidEmail('@example.com'));
        $this->assertFalse($this->isValidEmail('invalid.email'));
        $this->assertFalse($this->isValidEmail('user@'));
        $this->assertFalse($this->isValidEmail('user@domain'));
    }
    
    public function testPasswordValidation()
    {
        // Valid passwords
        $this->assertTrue($this->isValidPassword('password123'));
        $this->assertTrue($this->isValidPassword('12345678'));
        $this->assertTrue($this->isValidPassword('verylongpasswordwithmorethan8characters'));
        
        // Invalid passwords
        $this->assertFalse($this->isValidPassword(''));
        $this->assertFalse($this->isValidPassword('short'));
        $this->assertFalse($this->isValidPassword('1234567'));
    }
    
    public function testPasswordMatchValidation()
    {
        $this->assertTrue($this->passwordsMatch('password123', 'password123'));
        $this->assertTrue($this->passwordsMatch('', ''));
        
        $this->assertFalse($this->passwordsMatch('password123', 'different123'));
        $this->assertFalse($this->passwordsMatch('password123', ''));
        $this->assertFalse($this->passwordsMatch('', 'password123'));
    }
    
    public function testInputSanitization()
    {
        $this->assertEquals('testuser', $this->sanitizeInput('  testuser  '));
        $this->assertEquals('test user', $this->sanitizeInput('  test user  '));
        $this->assertEquals('', $this->sanitizeInput('   '));
        $this->assertEquals('normaltext', $this->sanitizeInput('normaltext'));
    }
    
    public function testCSRFTokenGeneration()
    {
        $token1 = $this->generateCSRFToken();
        $token2 = $this->generateCSRFToken();
        
        $this->assertNotEmpty($token1);
        $this->assertNotEmpty($token2);
        $this->assertNotEquals($token1, $token2);
        $this->assertEquals(64, strlen($token1)); // 32 bytes = 64 hex chars
        $this->assertEquals(64, strlen($token2));
    }
    
    public function testFileUploadValidation()
    {
        // Simulate valid file upload data
        $validFile = [
            'name' => 'test.jpg',
            'type' => 'image/jpeg',
            'size' => 1024000, // 1MB
            'tmp_name' => '/tmp/test',
            'error' => UPLOAD_ERR_OK
        ];
        
        $this->assertTrue($this->isValidFileUpload($validFile));
        
        // Test file too large
        $largeFile = $validFile;
        $largeFile['size'] = 10 * 1024 * 1024; // 10MB
        $this->assertFalse($this->isValidFileUpload($largeFile));
        
        // Test upload error
        $errorFile = $validFile;
        $errorFile['error'] = UPLOAD_ERR_PARTIAL;
        $this->assertFalse($this->isValidFileUpload($errorFile));
        
        // Test invalid file type
        $invalidTypeFile = $validFile;
        $invalidTypeFile['name'] = 'test.exe';
        $invalidTypeFile['type'] = 'application/exe';
        $this->assertFalse($this->isValidFileUpload($invalidTypeFile));
    }
    
    // Helper methods that simulate the validation logic from the PHP files
    private function isValidUsername($username)
    {
        return !empty($username) && preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username);
    }
    
    private function isValidEmail($email)
    {
        return !empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    private function isValidPassword($password)
    {
        return !empty($password) && strlen($password) >= 8;
    }
    
    private function passwordsMatch($password, $confirmPassword)
    {
        return $password === $confirmPassword;
    }
    
    private function sanitizeInput($input)
    {
        return trim($input);
    }
    
    private function generateCSRFToken()
    {
        return bin2hex(random_bytes(32));
    }
    
    private function isValidFileUpload($file)
    {
        $maxSize = 5 * 1024 * 1024; // 5MB
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain'];
        
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return false;
        }
        
        if ($file['size'] > $maxSize) {
            return false;
        }
        
        if (!in_array($file['type'], $allowedTypes)) {
            return false;
        }
        
        return true;
    }
}