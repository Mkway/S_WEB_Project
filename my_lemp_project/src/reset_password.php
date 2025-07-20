<?php
session_start();
require_once 'db.php';

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!isset($_GET['token'])) {
    die('Token not provided.');
}

$token = $_GET['token'];

$stmt = $pdo->prepare("SELECT user_id, expires_at FROM password_resets WHERE token = ?");
$stmt->execute([$token]);
$reset_request = $stmt->fetch();

if (!$reset_request || strtotime($reset_request['expires_at']) < time()) {
    die('Token is invalid or has expired.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed.');
    }

    $password = $_POST['password'];
    $password_confirm = $_POST['password_confirm'];

    if ($password !== $password_confirm) {
        echo "Passwords do not match.";
    } else {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$hashed_password, $reset_request['user_id']]);

        $stmt = $pdo->prepare("DELETE FROM password_resets WHERE token = ?");
        $stmt->execute([$token]);

        echo "Password has been reset successfully. You can now <a href='login.php'>login</a>.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Reset Password</h1>
        <form action="reset_password.php?token=<?php echo htmlspecialchars($token); ?>" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <label for="password">New Password:</label>
            <input type="password" name="password" id="password" required>
            <label for="password_confirm">Confirm New Password:</label>
            <input type="password" name="password_confirm" id="password_confirm" required>
            <button type="submit">Reset Password</button>
        </form>
    </div>
</body>
</html>
