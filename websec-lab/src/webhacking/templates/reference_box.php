
<?php
// $references (associative array 'Title' => 'URL')
// $analysis_file (optional - path to analysis markdown file)
?>
<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
    <h3>📚 참고 자료</h3>
    
    
    <div style="background: #e8f4fd; padding: 15px; border-radius: 6px; margin-bottom: 15px; border-left: 4px solid #0066cc;">
        <h4 style="color: #0066cc; margin: 0 0 10px 0;">📋 상세 분석 문서</h4>
        <?php if (isset($analysis_file) && !empty($analysis_file)): ?>
            <?php 
            $analysis_path = '/var/www/security_analysis/' . $analysis_file;
            if (file_exists($analysis_path)): 
            ?>
            <p style="margin: 0 0 10px 0;">
                <button onclick="toggleAnalysisContent()" 
                        style="background: #0066cc; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; font-weight: 500;">
                    🔍 <?php echo htmlspecialchars(basename($analysis_file, '.md')); ?> 상세 분석 보기
                </button>
                <a href="/security_analysis/<?php echo htmlspecialchars($analysis_file); ?>" target="_blank" 
                   style="color: #0066cc; text-decoration: none; font-weight: 500; margin-left: 10px; font-size: 14px;">
                    📄 원본 파일 보기
                </a>
            </p>
            <div id="analysis-content" style="display: none; background: white; padding: 20px; border-radius: 6px; border: 1px solid #ddd; margin-top: 10px; max-height: 600px; overflow-y: auto;">
                <!-- GitHub-style markdown CSS -->
                <style>
                #analysis-content .markdown-body {
                    font-family: -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji";
                    font-size: 16px;
                    line-height: 1.5;
                    word-wrap: break-word;
                }
                #analysis-content .markdown-body h1, #analysis-content .markdown-body h2, #analysis-content .markdown-body h3, #analysis-content .markdown-body h4, #analysis-content .markdown-body h5, #analysis-content .markdown-body h6 {
                    margin-top: 24px;
                    margin-bottom: 16px;
                    font-weight: 600;
                    line-height: 1.25;
                }
                #analysis-content .markdown-body h1 { font-size: 2em; border-bottom: 1px solid #d1d9e0; padding-bottom: 10px; }
                #analysis-content .markdown-body h2 { font-size: 1.5em; border-bottom: 1px solid #d1d9e0; padding-bottom: 8px; }
                #analysis-content .markdown-body h3 { font-size: 1.25em; }
                #analysis-content .markdown-body h4 { font-size: 1em; }
                #analysis-content .markdown-body h5 { font-size: 0.875em; }
                #analysis-content .markdown-body h6 { font-size: 0.85em; color: #656d76; }
                #analysis-content .markdown-body p { margin-bottom: 16px; }
                #analysis-content .markdown-body ul, #analysis-content .markdown-body ol { margin-bottom: 16px; padding-left: 2em; }
                #analysis-content .markdown-body li { margin-bottom: 4px; }
                #analysis-content .markdown-body blockquote { margin: 0 0 16px 0; padding: 0 1em; color: #656d76; border-left: 4px solid #d1d9e0; }
                #analysis-content .markdown-body code { padding: 2px 6px; font-size: 85%; background-color: rgba(175,184,193,0.2); border-radius: 6px; font-family: ui-monospace,SFMono-Regular,"SF Mono",Consolas,"Liberation Mono",Menlo,monospace; }
                #analysis-content .markdown-body pre { padding: 16px; overflow: auto; font-size: 85%; line-height: 1.45; background-color: #f6f8fa; border-radius: 6px; font-family: ui-monospace,SFMono-Regular,"SF Mono",Consolas,"Liberation Mono",Menlo,monospace; }
                #analysis-content .markdown-body pre code { padding: 0; background: transparent; border-radius: 0; }
                #analysis-content .markdown-body table { border-collapse: collapse; border-spacing: 0; width: 100%; margin-bottom: 16px; }
                #analysis-content .markdown-body table th, #analysis-content .markdown-body table td { padding: 6px 13px; border: 1px solid #d1d9e0; }
                #analysis-content .markdown-body table th { font-weight: 600; background-color: #f6f8fa; }
                #analysis-content .markdown-body a { color: #0969da; text-decoration: none; }
                #analysis-content .markdown-body a:hover { text-decoration: underline; }
                #analysis-content .markdown-body strong { font-weight: 600; }
                #analysis-content .markdown-body em { font-style: italic; }
                </style>
                
                <div id="markdown-content" class="markdown-body" data-file-path="<?php echo htmlspecialchars($analysis_file); ?>">
                    <div style="text-align: center; color: #666; padding: 20px;">
                        <div style="display: inline-block; width: 40px; height: 40px; border: 3px solid #f3f3f3; border-top: 3px solid #3498db; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                        <p>마크다운 파일을 로드하는 중...</p>
                    </div>
                </div>
                
                <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                </style>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
            <script>
            let markdownLoaded = false;
            
            async function toggleAnalysisContent() {
                const content = document.getElementById('analysis-content');
                const button = event.target;
                const markdownContainer = document.getElementById('markdown-content');
                
                if (content.style.display === 'none') {
                    content.style.display = 'block';
                    button.textContent = button.textContent.replace('보기', '숨기기');
                    
                    // 마크다운을 아직 로드하지 않았다면 로드
                    if (!markdownLoaded) {
                        try {
                            const fileName = markdownContainer.dataset.filePath;
                            const response = await fetch(`/security_analysis/${fileName}`);
                            
                            if (response.ok) {
                                const markdownText = await response.text();
                                
                                // marked.js 설정 (GitHub 스타일)
                                marked.setOptions({
                                    breaks: true,
                                    gfm: true,
                                    headerIds: true,
                                    langPrefix: 'language-',
                                    sanitize: false,
                                    smartypants: false
                                });
                                
                                const htmlContent = marked.parse(markdownText);
                                markdownContainer.innerHTML = htmlContent;
                                markdownLoaded = true;
                                
                                // 코드 하이라이팅을 위해 highlight.js 추가 (선택사항)
                                if (typeof hljs !== 'undefined') {
                                    markdownContainer.querySelectorAll('pre code').forEach((block) => {
                                        hljs.highlightBlock(block);
                                    });
                                }
                            } else {
                                markdownContainer.innerHTML = '<p style="color: #dc3545;">분석 파일을 로드하는데 실패했습니다.</p>';
                            }
                        } catch (error) {
                            markdownContainer.innerHTML = '<p style="color: #dc3545;">네트워크 오류로 분석 파일을 로드할 수 없습니다.</p>';
                        }
                    }
                } else {
                    content.style.display = 'none';
                    button.textContent = button.textContent.replace('숨기기', '보기');
                }
            }
            </script>
            
            <!-- 코드 하이라이팅을 위한 highlight.js (선택사항) -->
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css">
            <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
            <small style="color: #666;">※ 이 문서에는 취약점의 원리, 공격 시나리오, 방어 방법이 자세히 설명되어 있습니다.</small>
            <?php else: ?>
            <p style="margin: 0; color: #666;">분석 문서를 준비 중입니다.</p>
            <?php endif; ?>
        <?php else: ?>
        <p style="margin: 0; color: #666;">분석 문서가 설정되지 않았습니다.</p>
        <?php endif; ?>
    </div>
    
    <ul>
        <?php foreach ($references as $title => $url): ?>
            <li><a href="<?php echo htmlspecialchars($url); ?>" target="_blank"><?php echo htmlspecialchars($title); ?></a></li>
        <?php endforeach; ?>
    </ul>
</div>
