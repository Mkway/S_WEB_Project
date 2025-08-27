
<?php
// $references (associative array 'Title' => 'URL')
// $analysis_file (optional - path to analysis markdown file)
?>
<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
    <h3>📚 참고 자료</h3>
    
    <?php if (isset($analysis_file) && !empty($analysis_file)): ?>
    <div style="background: #e8f4fd; padding: 15px; border-radius: 6px; margin-bottom: 15px; border-left: 4px solid #0066cc;">
        <h4 style="color: #0066cc; margin: 0 0 10px 0;">📋 상세 분석 문서</h4>
        <p style="margin: 0;">
            <a href="../../security_analysis/<?php echo htmlspecialchars($analysis_file); ?>" target="_blank" 
               style="color: #0066cc; text-decoration: none; font-weight: 500;">
                🔍 <?php echo htmlspecialchars(basename($analysis_file, '.md')); ?> 상세 분석 보기
            </a>
        </p>
        <small style="color: #666;">※ 이 문서에는 취약점의 원리, 공격 시나리오, 방어 방법이 자세히 설명되어 있습니다.</small>
    </div>
    <?php endif; ?>
    
    <ul>
        <?php foreach ($references as $title => $url): ?>
            <li><a href="<?php echo htmlspecialchars($url); ?>" target="_blank"><?php echo htmlspecialchars($title); ?></a></li>
        <?php endforeach; ?>
    </ul>
</div>
