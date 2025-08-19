
<?php
// $references (associative array 'Title' => 'URL')
?>
<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
    <h3>📚 참고 자료</h3>
    <ul>
        <?php foreach ($references as $title => $url): ?>
            <li><a href="<?php echo htmlspecialchars($url); ?>" target="_blank"><?php echo htmlspecialchars($title); ?></a></li>
        <?php endforeach; ?>
    </ul>
</div>
