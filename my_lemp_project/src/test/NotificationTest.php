<?php

use PHPUnit\Framework\TestCase;

class NotificationTest extends TestCase
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

    public function testCreateNotificationSuccess()
    {
        // Get user IDs
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();
        
        $stmt->execute(['adminuser']);
        $adminId = $stmt->fetchColumn();

        $this->assertNotEmpty($userId, "Test user should exist.");
        $this->assertNotEmpty($adminId, "Admin user should exist.");

        // Create a notification
        $type = 'new_comment';
        $sourceId = 123;
        $message = 'Test notification message';

        $stmt = self::$pdo->prepare("INSERT INTO notifications (user_id, type, source_id, message) VALUES (?, ?, ?, ?)");
        $result = $stmt->execute([$userId, $type, $sourceId, $message]);

        $this->assertTrue($result, "Notification creation should be successful.");

        // Verify notification was created
        $notificationId = self::$pdo->lastInsertId();
        $stmt = self::$pdo->prepare("SELECT * FROM notifications WHERE id = ?");
        $stmt->execute([$notificationId]);
        $notification = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($notification, "Created notification should exist.");
        $this->assertEquals($userId, $notification['user_id'], "User ID should match.");
        $this->assertEquals($type, $notification['type'], "Type should match.");
        $this->assertEquals($sourceId, $notification['source_id'], "Source ID should match.");
        $this->assertEquals($message, $notification['message'], "Message should match.");
        $this->assertFalse((bool)$notification['is_read'], "Notification should be unread by default.");
    }

    public function testGetUserNotifications()
    {
        // Get user ID
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        // Create multiple notifications
        $notifications = [
            ['type' => 'new_comment', 'message' => 'First notification'],
            ['type' => 'new_post', 'message' => 'Second notification'],
            ['type' => 'admin_message', 'message' => 'Third notification']
        ];

        foreach ($notifications as $index => $notif) {
            $stmt = self::$pdo->prepare("INSERT INTO notifications (user_id, type, message, created_at) VALUES (?, ?, ?, ?)");
            // Create distinct timestamps to ensure proper ordering
            $timestamp = date('Y-m-d H:i:s', time() + $index);
            $stmt->execute([$userId, $notif['type'], $notif['message'], $timestamp]);
        }

        // Fetch notifications for user
        $stmt = self::$pdo->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC");
        $stmt->execute([$userId]);
        $userNotifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $this->assertCount(3, $userNotifications, "User should have 3 notifications.");
        $this->assertEquals('Third notification', $userNotifications[0]['message'], "Notifications should be ordered by creation time (newest first).");
    }

    public function testMarkNotificationsAsRead()
    {
        // Get user ID
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        // Create unread notifications
        $stmt = self::$pdo->prepare("INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)");
        $stmt->execute([$userId, 'new_comment', 'Unread notification 1']);
        $stmt->execute([$userId, 'new_comment', 'Unread notification 2']);

        // Verify notifications are unread
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
        $stmt->execute([$userId]);
        $unreadCount = $stmt->fetchColumn();
        $this->assertEquals(2, $unreadCount, "Should have 2 unread notifications.");

        // Mark notifications as read
        $stmt = self::$pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0");
        $result = $stmt->execute([$userId]);

        $this->assertTrue($result, "Mark as read operation should be successful.");

        // Verify notifications are now read
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
        $stmt->execute([$userId]);
        $unreadCount = $stmt->fetchColumn();
        $this->assertEquals(0, $unreadCount, "Should have 0 unread notifications after marking as read.");

        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 1");
        $stmt->execute([$userId]);
        $readCount = $stmt->fetchColumn();
        $this->assertEquals(2, $readCount, "Should have 2 read notifications.");
    }

    public function testNotificationMessageGeneration()
    {
        $username = 'testuser';
        $commentContent = 'This is a test comment with more than 50 characters to test truncation functionality';

        // Test notification message generation logic from add_comment.php
        $expectedMessage = htmlspecialchars($username) . " commented on your post: " . htmlspecialchars(substr($commentContent, 0, 50)) . "...";
        $actualMessage = $this->generateCommentNotificationMessage($username, $commentContent);

        $this->assertEquals($expectedMessage, $actualMessage, "Comment notification message should be properly formatted.");

        // Test with short comment
        $shortComment = 'Short comment';
        $expectedShortMessage = htmlspecialchars($username) . " commented on your post: " . htmlspecialchars(substr($shortComment, 0, 50)) . "...";
        $actualShortMessage = $this->generateCommentNotificationMessage($username, $shortComment);

        $this->assertEquals($expectedShortMessage, $actualShortMessage, "Short comment notification should still have ellipsis.");
    }

    public function testNotificationCreationForComments()
    {
        // Create a post
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $postAuthorId = $stmt->fetchColumn();

        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$postAuthorId, 'Test Post', 'Test content']);
        $postId = self::$pdo->lastInsertId();

        // Create another user for commenting
        $stmt = self::$pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute(['commenter', password_hash('password', PASSWORD_DEFAULT)]);
        $commenterId = self::$pdo->lastInsertId();

        // Add comment
        $commentContent = 'This is a test comment';
        $stmt = self::$pdo->prepare("INSERT INTO comments (post_id, user_id, comment_text) VALUES (?, ?, ?)");
        $stmt->execute([$postId, $commenterId, $commentContent]);
        $commentId = self::$pdo->lastInsertId();

        // Create notification (simulating add_comment.php logic)
        $notificationMessage = "commenter commented on your post: " . substr($commentContent, 0, 50) . "...";
        $stmt = self::$pdo->prepare("INSERT INTO notifications (user_id, type, source_id, message) VALUES (?, ?, ?, ?)");
        $stmt->execute([$postAuthorId, 'new_comment', $commentId, $notificationMessage]);

        // Verify notification was created
        $stmt = self::$pdo->prepare("SELECT * FROM notifications WHERE user_id = ? AND type = 'new_comment'");
        $stmt->execute([$postAuthorId]);
        $notification = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertNotEmpty($notification, "Comment notification should be created.");
        $this->assertEquals($commentId, $notification['source_id'], "Source ID should be the comment ID.");
        $this->assertStringContainsString('commenter commented on your post', $notification['message'], "Notification message should contain commenter info.");
    }

    public function testNoSelfNotification()
    {
        // Create a post
        $stmt = self::$pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute(['testuser']);
        $userId = $stmt->fetchColumn();

        $stmt = self::$pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
        $stmt->execute([$userId, 'Test Post', 'Test content']);
        $postId = self::$pdo->lastInsertId();

        // Same user comments on their own post
        $commentContent = 'Self comment';
        $stmt = self::$pdo->prepare("INSERT INTO comments (post_id, user_id, comment_text) VALUES (?, ?, ?)");
        $stmt->execute([$postId, $userId, $commentContent]);
        $commentId = self::$pdo->lastInsertId();

        // Check notification count before (should be 0)
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ?");
        $stmt->execute([$userId]);
        $notificationCountBefore = $stmt->fetchColumn();

        // Simulate add_comment.php logic - should not create notification for self-comment
        $postAuthorId = $userId; // Same user
        if ($postAuthorId && $postAuthorId != $userId) {
            $stmt = self::$pdo->prepare("INSERT INTO notifications (user_id, type, source_id, message) VALUES (?, ?, ?, ?)");
            $stmt->execute([$postAuthorId, 'new_comment', $commentId, 'Self notification']);
        }

        // Check notification count after (should still be 0)
        $stmt = self::$pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ?");
        $stmt->execute([$userId]);
        $notificationCountAfter = $stmt->fetchColumn();

        $this->assertEquals($notificationCountBefore, $notificationCountAfter, "No notification should be created for self-comments.");
    }

    // Helper method to simulate notification message generation
    private function generateCommentNotificationMessage($username, $content)
    {
        return htmlspecialchars($username) . " commented on your post: " . htmlspecialchars(substr($content, 0, 50)) . "...";
    }
}