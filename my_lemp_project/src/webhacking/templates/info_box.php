
<?php
$title = $title ?? '정보';
$description = $description ?? '설명이 없습니다.';
?>
<div class="info-box">
    <h3><?php echo htmlspecialchars($title); ?></h3>
    <?php echo $description; // HTML 허용을 위해 htmlspecialchars 제외 ?>
</div>
