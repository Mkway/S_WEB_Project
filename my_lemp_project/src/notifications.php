<?php
session_start();
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Mark all notifications as read when the page is accessed
$mark_read_stmt = $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0");
$mark_read_stmt->execute([$user_id]);

// Fetch all notifications for the user, newest first
$notifications_stmt = $pdo->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC");
$notifications_stmt->execute([$user_id]);
$notifications = $notifications_stmt->fetchAll();

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifications</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Your Notifications</h1>

        <?php if (empty($notifications)): ?>
            <p>No notifications yet.</p>
        <?php else: ?>
            <div class="notifications-list">
                <?php foreach ($notifications as $notification): ?>
                    <div class="notification-item <?php echo $notification['is_read'] ? 'read' : 'unread'; ?>">
                        <p><?php echo safe_output($notification['message']); ?></p>
                        <span class="timestamp"><?php echo $notification['created_at']; ?></span>
                        <?php if ($notification['type'] === 'new_comment' && $notification['source_id']): ?>
                            <a href="view_post.php?id=<?php echo $notification['source_id']; ?>" class="btn btn-sm">View Post</a>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <div class="nav">
            <a href="index.php" class="btn">Back to Home</a>
        </div>
    </div>
</body>
</html>