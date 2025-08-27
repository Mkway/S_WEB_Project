
<?php
// $section_title, $section_description, $payloads_array, $onclick_handler
?>
<div class="payload-section">
    <h3><?php echo htmlspecialchars($section_title); ?></h3>
    <p><?php echo htmlspecialchars($section_description); ?></p>
    <div class="payload-buttons">
        <?php foreach ($payloads_array as $p): ?>
            <button class="payload-btn" onclick="<?php echo sprintf("%s('%s')", $onclick_handler, addslashes(htmlspecialchars($p))); ?>">
                <?php echo htmlspecialchars(substr($p, 0, 40)) . (strlen($p) > 40 ? '...' : ''); ?>
            </button>
        <?php endforeach; ?>
    </div>
</div>
