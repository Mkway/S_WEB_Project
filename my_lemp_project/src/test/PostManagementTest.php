<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../db.php'; // db.php 파일 포함

class PostManagementTest extends TestCase
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

    public function testCreatePostSuccess()
    {
        // 샘플 사용자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $this->assertNotEmpty($userId, "Test user should exist.");

        $title = 'Test Post Title';
        $content = 'This is the content of the test post.';
        $imagePath = 'uploads/test_image.jpg';

        // 게시글 생성 로직 시뮬레이션
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content, image_path) VALUES (?, ?, ?, ?)");
        $result = $stmt->execute([$userId, $title, $content, $imagePath]);

        $this->assertTrue($result, "Post creation should be successful.");

        // 생성된 게시글 확인
        $postId = self::$pdo->lastInsertId();
        $stmt = self::$pdo->prepare("SELECT * FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $post = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($post, "Created post should exist in the database.");
        $this->assertEquals($title, $post['title'], "Post title should match.");
        $this->assertEquals($content, $post['content'], "Post content should match.");
        $this->assertEquals($imagePath, $post['image_path'], "Post image path should match.");
    }

    public function testGetPostById()
    {
        // 샘플 게시글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $title = 'Existing Post';
        $content = 'Content of existing post.';
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $title, $content]);
        $postId = self::$pdo->lastInsertId();

        // 게시글 조회 로직 시뮬레이션
        $stmt = self::$pdo->prepare("SELECT * FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $post = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($post, "Post should be found by ID.");
        $this->assertEquals($postId, $post['id'], "Post ID should match.");
        $this->assertEquals($title, $post['title'], "Post title should match.");
    }

    public function testUpdatePostSuccess()
    {
        // 샘플 게시글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $title = 'Original Title';
        $content = 'Original Content';
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $title, $content]);
        $postId = self::$pdo->lastInsertId();

        $newTitle = 'Updated Title';
        $newContent = 'Updated Content';

        // 게시글 수정 로직 시뮬레이션
        $stmt = self::$pdo->prepare("UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$newTitle, $newContent, $postId, $userId]);

        $this->assertTrue($result, "Post update should be successful.");
        $this->assertEquals(1, $stmt->rowCount(), "Exactly one row should be updated.");

        // 수정된 게시글 확인
        $stmt = self::$pdo->prepare("SELECT * FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $updatedPost = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertEquals($newTitle, $updatedPost['title'], "Post title should be updated.");
        $this->assertEquals($newContent, $updatedPost['content'], "Post content should be updated.");
    }

    public function testUpdatePostUnauthorized()
    {
        // 사용자 1이 게시글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId1 = $stmt->fetchColumn();

        $title = 'Post by User1';
        $content = 'Content by User1';
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId1, $title, $content]);
        $postId = self::$pdo->lastInsertId();

        // 사용자 2 (다른 사용자) ID 가져오기
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute(['anotheruser', password_hash('password', PASSWORD_DEFAULT)]);
        $userId2 = self::$pdo->lastInsertId();

        $newTitle = 'Attempted Update';
        $newContent = 'Attempted Content';

        // 사용자 2가 사용자 1의 게시글 수정 시도
        $stmt = self::$pdo->prepare("UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$newTitle, $newContent, $postId, $userId2]);

        $this->assertTrue($result, "Update query should execute without error.");
        $this->assertEquals(0, $stmt->rowCount(), "No rows should be updated for unauthorized user.");

        // 게시글 내용이 변경되지 않았는지 확인
        $stmt = self::$pdo->prepare("SELECT * FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $originalPost = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertEquals($title, $originalPost['title'], "Post title should not be updated by unauthorized user.");
        $this->assertEquals($content, $originalPost['content'], "Post content should not be updated by unauthorized user.");
    }

    public function testDeletePostSuccess()
    {
        // 샘플 게시글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $title = 'Post to Delete';
        $content = 'Content to Delete';
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $title, $content]);
        $postId = self::$pdo->lastInsertId();

        // 게시글 삭제 로직 시뮬레이션
        $stmt = self::$pdo->prepare("DELETE FROM posts WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$postId, $userId]);

        $this->assertTrue($result, "Post deletion should be successful.");
        $this->assertEquals(1, $stmt->rowCount(), "Exactly one row should be deleted.");

        // 삭제된 게시글 확인
        $stmt = self::$pdo->prepare("SELECT * FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $deletedPost = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($deletedPost, "Deleted post should not exist in the database.");
    }

    public function testDeletePostUnauthorized()
    {
        // 사용자 1이 게시글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId1 = $stmt->fetchColumn();

        $title = 'Post by User1 to be deleted';
        $content = 'Content by User1 to be deleted';
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId1, $title, $content]);
        $postId = self::$pdo->lastInsertId();

        // 사용자 2 (다른 사용자) ID 가져오기
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute(['anotheruser2', password_hash('password', PASSWORD_DEFAULT)]);
        $userId2 = self::$pdo->lastInsertId();

        // 사용자 2가 사용자 1의 게시글 삭제 시도
        $stmt = self::$pdo->prepare("DELETE FROM posts WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$postId, $userId2]);

        $this->assertTrue($result, "Delete query should execute without error.");
        $this->assertEquals(0, $stmt->rowCount(), "No rows should be deleted for unauthorized user.");

        // 게시글이 삭제되지 않았는지 확인
        $stmt = self::$pdo->prepare("SELECT * FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $existingPost = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($existingPost, "Post should not be deleted by unauthorized user.");
    }

    public function testAdminDeleteAnyPost()
    {
        // 일반 사용자가 게시글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $title = 'Post by Regular User';
        $content = 'Content by Regular User';
        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $title, $content]);
        $postId = self::$pdo->lastInsertId();

        // 관리자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['adminuser']);
        $adminId = $stmt->fetchColumn();

        // 관리자가 게시글 삭제 (user_id 조건 없이)
        // 실제 delete_post.php에서는 관리자 여부를 확인 후 user_id 조건 없이 삭제 가능해야 함.
        // 여기서는 관리자 권한을 가진 사용자가 삭제를 시도하는 상황을 가정.
        // 실제 구현에 따라 이 테스트는 변경될 수 있음.
        $stmt = self::$pdo->prepare("DELETE FROM posts WHERE id = ?"); // 관리자는 user_id 조건 없이 삭제 가능
        $result = $stmt->execute([$postId]);

        $this->assertTrue($result, "Admin should be able to delete any post.");
        $this->assertEquals(1, $stmt->rowCount(), "Exactly one row should be deleted by admin.");

        // 삭제된 게시글 확인
        $stmt = self::$pdo->prepare("SELECT * FROM posts WHERE id = ?");
        $stmt->execute([$postId]);
        $deletedPost = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($deletedPost, "Post should be deleted by admin.");
    }
}