
<?php
$page_title = $page_title ?? '현재 페이지';
$base_path = $base_path ?? '../';
?>
<!-- 브레드크럼 -->
<nav class="breadcrumb">
    <a href="<?php echo $base_path; ?>index.php">홈</a> &gt; 
    <a href="<?php echo $base_path; ?>webhacking/index.php">보안 테스트</a> &gt; 
    <span><?php echo htmlspecialchars($page_title); ?></span>
</nav>
