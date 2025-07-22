<?php
session_start();
require_once '../my_lemp_project/src/db.php';

$message = '';
$error = '';

// 테스트를 위한 더미 로그인 (실제 환경에서는 로그인 세션이 있어야 함)
// 여기서는 user_id 1번을 로그인된 사용자로 가정합니다.
if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = 1; // 테스트를 위해 임시로 user_id 1번을 사용
    $_SESSION['username'] = 'testuser'; // 임시 사용자 이름
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user_id = $_SESSION['user_id'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    if (empty($new_password) || empty($confirm_password)) {
        $error = "새 비밀번호와 확인 비밀번호를 모두 입력해주세요.";
    } elseif ($new_password !== $confirm_password) {
        $error = "새 비밀번호와 확인 비밀번호가 일치하지 않습니다.";
    } elseif (strlen($new_password) < 8) {
        $error = "비밀번호는 최소 8자 이상이어야 합니다.";
    } else {
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        try {
            // !!! 경고: 이 코드는 CSRF에 취약합니다. !!!
            // CSRF 토큰 검증이 없습니다.
            $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
            $stmt->execute([$hashed_password, $user_id]);
            $message = "비밀번호가 성공적으로 변경되었습니다!";
        } catch (PDOException $e) {
            $error = "비밀번호 변경 중 오류가 발생했습니다: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>CSRF Test</title>
    <link rel="stylesheet" href="../my_lemp_project/src/style.css">
    <style>
        .container { max-width: 600px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CSRF (Cross-Site Request Forgery) Challenge</h1>
        <p>이 페이지는 로그인된 사용자의 비밀번호를 변경할 수 있습니다. CSRF 토큰이 없어 외부 사이트의 악성 요청에 취약합니다.</p>
        <p>현재 로그인된 사용자 (테스트용): <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></p>

        <?php if ($message): ?>
            <p style="color:green;"><?php echo htmlspecialchars($message); ?></p>
        <?php endif; ?>
        <?php if ($error): ?>
            <p style="color:red;"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>

        <form action="csrf.php" method="POST">
            <label for="new_password">새 비밀번호:</label>
            <input type="password" id="new_password" name="new_password" required>
            <label for="confirm_password">새 비밀번호 확인:</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
            <button type="submit">비밀번호 변경</button>
        </form>

        <hr style="margin-top: 30px;">

        <div>
            <h3>테스트 아이디어</h3>
            <ul>
                <li>이 페이지의 폼을 그대로 복사하여 다른 웹사이트(예: `attacker.html`)에 붙여넣고, 해당 페이지를 방문하면 비밀번호가 변경되는지 확인해보세요.</li>
                <li>`&lt;img&gt;` 태그의 `src` 속성을 이용하여 GET 요청으로 비밀번호를 변경할 수 있을까요? (이 페이지는 POST 요청을 사용하므로 직접적인 이미지 태그 공격은 어렵습니다.)</li>
            </ul>
        </div>
        <a href="index.php" style="display: block; margin-top: 20px;"> &laquo; 뒤로 가기</a>
    </div>
</body>
</html>
