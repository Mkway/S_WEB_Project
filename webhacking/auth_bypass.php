<?php
session_start();

$is_admin_bypassed = false;
$message = '';

// !!! 경고: 이 코드는 인증 우회에 매우 취약합니다. !!!
// HTTP 헤더나 특정 쿠키 값만으로 관리자 권한을 부여합니다.
if (isset($_SERVER['HTTP_X_ADMIN_BYPASS']) && $_SERVER['HTTP_X_ADMIN_BYPASS'] === 'true') {
    $is_admin_bypassed = true;
    $message = "<p style=\"color:green;\">HTTP 헤더를 통해 관리자 권한으로 우회되었습니다!</p>";
} elseif (isset($_COOKIE['admin_bypass']) && $_COOKIE['admin_bypass'] === 'true') {
    $is_admin_bypassed = true;
    $message = "<p style=\"color:green;\">쿠키를 통해 관리자 권한으로 우회되었습니다!</p>";
}

// 실제 로그인 로직 (여기서는 단순화)
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    $message .= "<p>정상적으로 로그인된 사용자입니다.</p>";
} else {
    $message .= "<p>로그인되지 않은 사용자입니다.</p>";
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Authentication Bypass Test</title>
    <link rel="stylesheet" href="../my_lemp_project/src/style.css">
    <style>
        .container { max-width: 800px; }
        .admin-content {
            background-color: #e0ffe0;
            border: 1px solid #008000;
            padding: 20px;
            margin-top: 20px;
            border-radius: 5px;
        }
        .restricted-content {
            background-color: #ffe0e0;
            border: 1px solid #800000;
            padding: 20px;
            margin-top: 20px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authentication Bypass Challenge</h1>
        <p>이 페이지는 특정 HTTP 헤더나 쿠키 값만으로 관리자 권한을 우회할 수 있는 취약점을 가지고 있습니다.</p>

        <?php echo $message; ?>

        <?php if ($is_admin_bypassed): ?>
            <div class="admin-content">
                <h2>관리자 전용 콘텐츠</h2>
                <p>축하합니다! 관리자 권한으로 이 페이지에 접근했습니다.</p>
                <p>여기에 민감한 관리자 정보나 기능이 있다고 가정합니다.</p>
                <p>예: 사용자 목록, 시스템 설정 변경 등</p>
            </div>
        <?php else: ?>
            <div class="restricted-content">
                <h2>일반 사용자 콘텐츠</h2>
                <p>이곳은 일반 사용자에게만 보이는 콘텐츠입니다. 관리자 권한으로 우회하여 관리자 전용 콘텐츠를 확인해보세요.</p>
            </div>
        <?php endif; ?>

        <hr style="margin-top: 30px;">

        <div>
            <h3>테스트 아이디어</h3>
            <ul>
                <li>브라우저 확장 프로그램(예: ModHeader)을 사용하여 `X-Admin-Bypass: true` 헤더를 추가하고 페이지에 접근해보세요.</li>
                <li>브라우저 개발자 도구(F12)를 사용하여 `admin_bypass=true` 쿠키를 추가하고 페이지를 새로고침해보세요.</li>
                <li>URL 파라미터나 다른 HTTP 헤더를 조작하여 우회할 수 있을까요?</li>
            </ul>
        </div>
        <a href="index.php" style="display: block; margin-top: 20px;"> &laquo; 뒤로 가기</a>
    </div>
</body>
</html>