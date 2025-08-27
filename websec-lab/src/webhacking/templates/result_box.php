
<?php if (!empty($result) || !empty($error)): ?>
    <?php if (!empty($result)): ?>
        <div class="result-box">
            <h3>📊 테스트 결과</h3>
            <?php echo $result; // HTML 허용 ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($error)): ?>
        <div class="error-box">
            <h3>❌ 오류</h3>
            <p><?php echo htmlspecialchars($error); ?></p>
        </div>
    <?php endif; ?>
<?php endif; ?>
