
<?php
// $defense_methods (array of strings)
?>
<div class="info-box">
    <h3>🛡️ 방어 방법</h3>
    <ul>
        <?php foreach ($defense_methods as $method): ?>
            <li><?php echo $method; // HTML 허용 ?></li>
        <?php endforeach; ?>
    </ul>
</div>
