<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../db.php'; // db.php 파일 포함

class FileUploadTest extends TestCase
{
    protected static $pdo;
    protected static $uploadDir;

    public static function setUpBeforeClass(): void
    {
        self::$pdo = $GLOBALS['pdo'];
        self::$uploadDir = __DIR__ . '/../uploads/';

        // uploads 디렉토리가 없으면 생성
        if (!is_dir(self::$uploadDir)) {
            mkdir(self::$uploadDir, 0777, true);
        }
    }

    protected function setUp(): void
    {
        setupTestDatabase(self::$pdo);
        // 테스트 전에 uploads 디렉토리 비우기 및 임시 파일 삭제
        $files = glob(self::$uploadDir . '*');
        foreach ($files as $file) {
            if (is_file($file)) {
                echo "Deleting file in setUp: " . $file . "\n";
                unlink($file);
            }
        }
        // 임시 파일도 삭제 (테스트에서 생성된)
        if (file_exists('/tmp/test_image.jpg')) {
            echo "Deleting /tmp/test_image.jpg in setUp: " . '/tmp/test_image.jpg' . "\n";
            unlink('/tmp/test_image.jpg');
        }
        if (file_exists('/tmp/test_document.txt')) {
            echo "Deleting /tmp/test_document.txt in setUp: " . '/tmp/test_document.txt' . "\n";
            unlink('/tmp/test_document.txt');
        }
    }

    public function testImageUploadSuccess()
    {
        // 샘플 사용자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $this->assertNotEmpty($userId, "Test user should exist.");

        $title = 'Post with Image';
        $content = 'Content with image upload.';

        // 가상의 $_FILES 배열 생성
        $testFileName = 'test_image.jpg';
        $tmpFilePath = '/tmp/' . $testFileName; // 임시 파일 경로를 /tmp로 변경
        file_put_contents($tmpFilePath, 'dummy image content'); // 더미 파일 생성

        $_FILES = [
            'image' => [
                'name' => $testFileName,
                'type' => 'image/jpeg',
                'tmp_name' => $tmpFilePath,
                'error' => UPLOAD_ERR_OK,
                'size' => filesize($tmpFilePath)
            ]
        ];

        // 파일 업로드 및 게시글 생성 로직 시뮬레이션
        $imagePath = null;
        if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
            $uploadFile = self::$uploadDir . basename($_FILES['image']['name']);
            if (copy($_FILES['image']['tmp_name'], $uploadFile)) {
                $imagePath = 'uploads/' . basename($_FILES['image']['name']);
                echo "File copied successfully. ImagePath: " . $imagePath . "\n";
            } else {
                echo "File copy failed: " . error_get_last()['message'] . "\n";
            }
        }

        $this->assertNotNull($imagePath, "Image should be uploaded successfully.");
        $this->assertFileExists(self::$uploadDir . $testFileName, "Uploaded file should exist in the uploads directory.");

        // 데이터베이스에 게시글 정보 저장
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content, image_path) VALUES (?, ?, ?, ?)");
        $result = $stmt->execute([$userId, $title, $content, $imagePath]);

        $this->assertTrue($result, "Post with image should be created successfully.");

        // 데이터베이스에서 이미지 경로 확인
        $postId = self::$pdo->lastInsertId();
        $stmt = self::$pdo->prepare("SELECT image_path FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $dbImagePath = $stmt->fetchColumn();

        $this->assertEquals($imagePath, $dbImagePath, "Image path in database should match uploaded path.");
    }

    public function testImageUploadInvalidType()
    {
        // 샘플 사용자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $title = 'Post with Invalid Image';
        $content = 'Content with invalid image upload.';

        // 가상의 $_FILES 배열 생성 (유효하지 않은 타입)
        $testFileName = 'test_document.txt';
        $tmpFilePath = '/tmp/' . $testFileName; // 임시 파일 경로를 /tmp로 변경
        file_put_contents($tmpFilePath, 'dummy text content'); // 더미 파일 생성

        $_FILES = [
            'image' => [
                'name' => $testFileName,
                'type' => 'text/plain',
                'tmp_name' => $tmpFilePath,
                'error' => UPLOAD_ERR_OK,
                'size' => filesize($tmpFilePath)
            ]
        ];

        // 파일 업로드 로직 시뮬레이션 (실제 애플리케이션에서는 파일 타입 검증 로직이 있어야 함)
        $imagePath = null;
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif']; // 허용된 타입

        if (isset($_FILES['image']) && $_FILES['image']['error'] == UPLOAD_ERR_OK) {
            if (in_array($_FILES['image']['type'], $allowedTypes)) {
                $uploadFile = self::$uploadDir . basename($_FILES['image']['name']);
                if (move_uploaded_file($_FILES['image']['tmp_name'], $uploadFile)) {
                    $imagePath = 'uploads/' . basename($_FILES['image']['name']);
                }
            }
        }

        $this->assertNull($imagePath, "Image should not be uploaded due to invalid type.");
        $this->assertFileDoesNotExist(self::$uploadDir . $testFileName, "Invalid file should not exist in the uploads directory.");
    }

    protected function tearDown(): void
    {
        // 각 테스트 후 uploads 디렉토리 비우기 및 임시 파일 삭제
        $files = glob(self::$uploadDir . '*');
        foreach ($files as $file) {
            if (is_file($file)) {
                echo "Deleting file in tearDown: " . $file . "\n";
                unlink($file);
            }
        }
        // 임시 파일도 삭제 (테스트에서 생성된)
        if (file_exists('/tmp/test_image.jpg')) {
            echo "Deleting /tmp/test_image.jpg in tearDown: " . '/tmp/test_image.jpg' . "\n";
            unlink('/tmp/test_image.jpg');
        }
        if (file_exists('/tmp/test_document.txt')) {
            echo "Deleting /tmp/test_document.txt in tearDown: " . '/tmp/test_document.txt' . "\n";
            unlink('/tmp/test_document.txt');
        }
    }
}