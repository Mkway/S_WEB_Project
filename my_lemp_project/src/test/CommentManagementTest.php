<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../db.php'; // db.php 파일 포함

class CommentManagementTest extends TestCase
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

    public function testAddCommentSuccess()
    {
        // 샘플 사용자 및 게시글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, 'Test Post for Comment', 'Content for comment.']);
        $postId = self::$pdo->lastInsertId();

        $commentText = 'This is a test comment.';

        // 댓글 추가 로직 시뮬레이션
        $stmt = self::$pdo->prepare("INSERT INTO comments (post_id, user_id, comment_text) VALUES (?, ?, ?)");
        $result = $stmt->execute([$postId, $userId, $commentText]);

        $this->assertTrue($result, "Comment addition should be successful.");

        // 추가된 댓글 확인
        $commentId = self::$pdo->lastInsertId();
        $stmt = self::$pdo->prepare("SELECT * FROM comments WHERE id = ?");
        $stmt->execute([$commentId]);
        $comment = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($comment, "Added comment should exist in the database.");
        $this->assertEquals($commentText, $comment['comment_text'], "Comment text should match.");
        $this->assertEquals($postId, $comment['post_id'], "Comment post ID should match.");
        $this->assertEquals($userId, $comment['user_id'], "Comment user ID should match.");
    }

    public function testDeleteCommentSuccess()
    {
        // 샘플 사용자, 게시글, 댓글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, 'Post for Comment Deletion', 'Content.']);
        $postId = self::$pdo->lastInsertId();

        $commentText = 'Comment to be deleted.';
        $stmt = self::$pdo->prepare("INSERT INTO comments (post_id, user_id, comment_text) VALUES (?, ?, ?)");
        $stmt->execute([$postId, $userId, $commentText]);
        $commentId = self::$pdo->lastInsertId();

        // 댓글 삭제 로직 시뮬레이션
        $stmt = self::$pdo->prepare("DELETE FROM comments WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$commentId, $userId]);

        $this->assertTrue($result, "Comment deletion should be successful.");
        $this->assertEquals(1, $stmt->rowCount(), "Exactly one row should be deleted.");

        // 삭제된 댓글 확인
        $stmt = self::$pdo->prepare("SELECT * FROM comments WHERE id = ?");
        $stmt->execute([$commentId]);
        $deletedComment = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($deletedComment, "Deleted comment should not exist in the database.");
    }

    public function testDeleteCommentUnauthorized()
    {
        // 사용자 1이 댓글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId1 = $stmt->fetchColumn();

        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId1, 'Post for Unauthorized Comment Deletion', 'Content.']);
        $postId = self::$pdo->lastInsertId();

        $commentText = 'Comment by User1.';
        $stmt = self::$pdo->prepare("INSERT INTO comments (post_id, user_id, comment_text) VALUES (?, ?, ?)");
        $stmt->execute([$postId, $userId1, $commentText]);
        $commentId = self::$pdo->lastInsertId();

        // 사용자 2 (다른 사용자) ID 가져오기
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute(['anotheruser3', password_hash('password', PASSWORD_DEFAULT)]);
        $userId2 = self::$pdo->lastInsertId();

        // 사용자 2가 사용자 1의 댓글 삭제 시도
        $stmt = self::$pdo->prepare("DELETE FROM comments WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$commentId, $userId2]);

        $this->assertTrue($result, "Delete query should execute without error.");
        $this->assertEquals(0, $stmt->rowCount(), "No rows should be deleted for unauthorized user.");

        // 댓글이 삭제되지 않았는지 확인
        $stmt = self::$pdo->prepare("SELECT * FROM comments WHERE id = ?");
        $stmt->execute([$commentId]);
        $existingComment = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($existingComment, "Comment should not be deleted by unauthorized user.");
    }

    public function testAdminDeleteAnyComment()
    {
        // 일반 사용자가 댓글 생성
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, 'Post for Admin Comment Deletion', 'Content.']);
        $postId = self::$pdo->lastInsertId();

        $commentText = 'Comment by Regular User.';
        $stmt = self::$pdo->prepare("INSERT INTO comments (post_id, user_id, comment_text) VALUES (?, ?, ?)");
        $stmt->execute([$postId, $userId, $commentText]);
        $commentId = self::$pdo->lastInsertId();

        // 관리자 ID 가져오기
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['adminuser']);
        $adminId = $stmt->fetchColumn();

        // 관리자가 댓글 삭제 (user_id 조건 없이)
        $stmt = self::$pdo->prepare("DELETE FROM comments WHERE id = ?"); // 관리자는 user_id 조건 없이 삭제 가능
        $result = $stmt->execute([$commentId]);

        $this->assertTrue($result, "Admin should be able to delete any comment.");
        $this->assertEquals(1, $stmt->rowCount(), "Exactly one row should be deleted by admin.");

        // 삭제된 댓글 확인
        $stmt = self::$pdo->prepare("SELECT * FROM comments WHERE id = ?");
        $stmt->execute([$commentId]);
        $deletedComment = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertFalse($deletedComment, "Comment should be deleted by admin.");
    }
}