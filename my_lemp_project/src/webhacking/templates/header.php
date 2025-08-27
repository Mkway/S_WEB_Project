
<?php
// 변수들이 설정되지 않은 경우 기본값 설정
$page_title = $page_title ?? '보안 테스트';
$base_path = $base_path ?? '../';
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?> - S_WEB_Project</title>
    <link rel="stylesheet" href="<?php echo $base_path; ?>assets/style.css?v=<?php echo time(); ?>">
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1><?php echo htmlspecialchars($page_title); ?></h1>
            <div class="nav-links">
                <a href="<?php echo $base_path; ?>webhacking/index.php" class="btn">보안 테스트 메인</a>
                <a href="<?php echo $base_path; ?>index.php" class="btn">홈</a>
            </div>
        </nav>
