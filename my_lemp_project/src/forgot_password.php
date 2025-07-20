<?php
session_start();
require_once 'db.php';

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed.');
    }

    $email = $_POST['email'];

    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user) {
        $token = bin2hex(random_bytes(50));
        $expires = date('Y-m-d H:i:s', time() + 1800); // 30 minutes

        $stmt = $pdo->prepare("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$user['id'], $token, $expires]);

        $reset_link = "http://" . $_SERVER['HTTP_HOST'] . "/reset_password.php?token=" . $token;
        
        // For development, we'll display the link. In production, this would be sent via email.
        echo "Password reset link: <a href='{$reset_link}'>{$reset_link}</a>";
        // In a real application, you would use a library like PHPMailer to send an email.
        // $subject = "Password Reset Request";
        // $message = "Click the following link to reset your password: " . $reset_link;
        // mail($email, $subject, $message);
    } else {
        echo "No user found with that email address.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forgot Password</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Forgot Password</h1>
        <form action="forgot_password.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <label for="email">Enter your email address:</label>
            <input type="email" name="email" id="email" required>
            <button type="submit">Send Reset Link</button>
        </form>
    </div>
</body>
</html>
