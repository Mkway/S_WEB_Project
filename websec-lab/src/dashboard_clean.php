<?php
session_start();
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/VulnerabilityDashboard.php';

// 메인 처리
global $pdo;
if (!isset($pdo) || !$pdo) {
    die("데이터베이스 연결에 실패했습니다. 설정을 확인해주세요.");
}
$dashboard = new VulnerabilityDashboard($pdo);
$result = '';

// 일반 POST 요청 처리 (AJAX가 아닌 경우)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['ajax_action'])) {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'generate_report') {
        $test_name = $_POST['test_name'] ?? '';
        $date_from = $_POST['date_from'] ?? '';
        $date_to = $_POST['date_to'] ?? '';
        
        $report_data = $dashboard->generateVulnerabilityReport($test_name, $date_from, $date_to);
        $result = $dashboard->formatReportHTML($report_data, $test_name, $date_from, $date_to);
    }
}

// HTML 출력을 위한 데이터 준비
$all_tests = $dashboard->getAllTests();
$test_categories = $dashboard->getTestsByCategory();
$stats = $dashboard->getDashboardStats();
$recent_results = $dashboard->getRecentResults(10);
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ WebSec-Lab 통합 대시보드</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --danger-color: #e74c3c;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --info-color: #17a2b8;
            --light-bg: #ecf0f1;
            --dark-bg: #34495e;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--light-bg);
            color: var(--primary-color);
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 30px;
            margin-top: 30px;
        }
        
        .sidebar {
            background: white;
            border-radius: 10px;
            padding: 25px;
            height: fit-content;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            position: sticky;
            top: 20px;
        }
        
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 30px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.basic {
            border-left: 5px solid var(--success-color);
        }
        
        .stat-card.intermediate {
            border-left: 5px solid var(--warning-color);
        }
        
        .stat-card.advanced {
            border-left: 5px solid var(--danger-color);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: #666;
            font-weight: 500;
        }
        
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        
        .test-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .test-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.15);
        }
        
        .test-card.basic::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--success-color);
        }
        
        .test-card.intermediate::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--warning-color);
        }
        
        .test-card.advanced::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--danger-color);
        }
        
        .test-card h3 {
            margin-bottom: 1rem;
            color: var(--primary-color);
            font-size: 1.3rem;
        }
        
        .test-card p {
            color: #666;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }
        
        .test-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            font-size: 0.85rem;
        }
        
        .difficulty-badge {
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.75rem;
        }
        
        .difficulty-badge.basic {
            background: var(--success-color);
        }
        
        .difficulty-badge.intermediate {
            background: var(--warning-color);
        }
        
        .difficulty-badge.advanced {
            background: var(--danger-color);
        }
        
        .test-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
            font-size: 0.9rem;
        }
        
        .btn-primary {
            background: var(--secondary-color);
            color: white;
        }
        
        .btn-primary:hover {
            background: #2980b9;
        }
        
        .btn-danger {
            background: var(--danger-color);
            color: white;
        }
        
        .btn-danger:hover {
            background: #c0392b;
        }
        
        .btn-success {
            background: var(--success-color);
            color: white;
        }
        
        .btn-success:hover {
            background: #219a52;
        }
        
        .sidebar h3 {
            margin-bottom: 1rem;
            color: var(--primary-color);
            font-size: 1.2rem;
        }
        
        .category-list {
            list-style: none;
            margin-bottom: 2rem;
        }
        
        .category-list li {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .category-count {
            background: var(--secondary-color);
            color: white;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .recent-results {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .result-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }
        
        .result-item:last-child {
            border-bottom: none;
        }
        
        .result-status {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .result-status.vulnerable {
            background: #ffebee;
            color: var(--danger-color);
        }
        
        .result-status.safe {
            background: #e8f5e8;
            color: var(--success-color);
        }
        
        .result-status.error {
            background: #fff3e0;
            color: var(--warning-color);
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            border-radius: 10px;
            padding: 30px;
            max-width: 800px;
            width: 90%;
            max-height: 90%;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #eee;
        }
        
        .close {
            font-size: 28px;
            cursor: pointer;
            color: #999;
        }
        
        .close:hover {
            color: #333;
        }
        
        .test-output {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 20px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid var(--secondary-color);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .filter-section {
            margin-bottom: 2rem;
        }
        
        .filter-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid var(--secondary-color);
            background: white;
            color: var(--secondary-color);
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .filter-btn.active {
            background: var(--secondary-color);
            color: white;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
            
            .test-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .container {
                padding: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WebSec-Lab 통합 대시보드</h1>
        <p>종합적인 웹 보안 취약점 테스트 플랫폼</p>
    </div>
    
    <div class="container">
        <!-- 통계 카드 -->
        <div class="stats-grid">
            <div class="stat-card basic">
                <div class="stat-number"><?php echo $stats['basic']; ?></div>
                <div class="stat-label">기본 취약점</div>
            </div>
            <div class="stat-card intermediate">
                <div class="stat-number"><?php echo $stats['intermediate']; ?></div>
                <div class="stat-label">중급 취약점</div>
            </div>
            <div class="stat-card advanced">
                <div class="stat-number"><?php echo $stats['advanced']; ?></div>
                <div class="stat-label">고급 취약점</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $stats['total_results'] ?? 0; ?></div>
                <div class="stat-label">총 테스트 실행</div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <!-- 사이드바 -->
            <div class="sidebar">
                <h3>📊 카테고리별 분류</h3>
                <ul class="category-list">
                    <?php foreach ($test_categories as $category): ?>
                    <li>
                        <span><?php echo htmlspecialchars($category['test_category']); ?></span>
                        <span class="category-count"><?php echo $category['count']; ?></span>
                    </li>
                    <?php endforeach; ?>
                </ul>
                
                <h3>🕒 최근 테스트 결과</h3>
                <div class="recent-results">
                    <?php foreach ($recent_results as $result): ?>
                    <div class="result-item">
                        <div>
                            <div style="font-weight: bold; font-size: 0.9rem;">
                                <?php echo htmlspecialchars($result['test_name']); ?>
                            </div>
                            <div style="font-size: 0.8rem; color: #666;">
                                <?php echo date('m/d H:i', strtotime($result['created_at'])); ?>
                            </div>
                        </div>
                        <span class="result-status <?php echo $result['result_type']; ?>">
                            <?php 
                            $status_text = [
                                'vulnerable' => '취약',
                                'safe' => '안전',
                                'error' => '오류'
                            ];
                            echo $status_text[$result['result_type']] ?? $result['result_type'];
                            ?>
                        </span>
                    </div>
                    <?php endforeach; ?>
                </div>
                
                <div style="margin-top: 2rem;">
                    <button class="btn btn-success" onclick="refreshStats()">
                        🔄 통계 새로고침
                    </button>
                </div>
            </div>
            
            <!-- 메인 콘텐츠 -->
            <div class="main-content">
                <!-- 필터 섹션 -->
                <div class="filter-section">
                    <h3>🔍 필터링</h3>
                    <div class="filter-buttons">
                        <button class="filter-btn active" data-filter="all">전체</button>
                        <button class="filter-btn" data-filter="basic">기본</button>
                        <button class="filter-btn" data-filter="intermediate">중급</button>
                        <button class="filter-btn" data-filter="advanced">고급</button>
                        <button class="filter-btn" data-filter="Web Application">웹 애플리케이션</button>
                        <button class="filter-btn" data-filter="Database">데이터베이스</button>
                        <button class="filter-btn" data-filter="System">시스템</button>
                    </div>
                </div>
                
                <!-- 취약점 테스트 카드 -->
                <div class="test-grid">
                    <?php foreach ($all_tests as $test): ?>
                    <div class="test-card <?php echo $test['difficulty']; ?>" 
                         data-difficulty="<?php echo $test['difficulty']; ?>" 
                         data-category="<?php echo $test['test_category']; ?>">
                        <h3><?php echo htmlspecialchars($test['test_name']); ?></h3>
                        <p><?php echo htmlspecialchars($test['description']); ?></p>
                        
                        <div class="test-meta">
                            <span class="difficulty-badge <?php echo $test['difficulty']; ?>">
                                <?php 
                                $difficulty_text = [
                                    'basic' => '기본',
                                    'intermediate' => '중급', 
                                    'advanced' => '고급'
                                ];
                                echo $difficulty_text[$test['difficulty']];
                                ?>
                            </span>
                            <span style="color: #666;">
                                📂 <?php echo htmlspecialchars($test['test_category']); ?>
                            </span>
                        </div>
                        
                        <div style="font-size: 0.85rem; color: #666; margin-bottom: 1rem;">
                            🧪 실행 횟수: <?php echo number_format($test['test_count']); ?>회
                        </div>
                        
                        <div class="test-actions">
                            <a href="<?php echo $test['test_file']; ?>" 
                               target="_blank" 
                               class="btn btn-primary">
                                🔗 직접 접속
                            </a>
                            <button class="btn btn-danger" 
                                    onclick="executeTest('<?php echo htmlspecialchars($test['test_name']); ?>', '<?php echo $test['test_file']; ?>')">
                                ⚡ 실행 테스트
                            </button>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 테스트 실행 모달 -->
    <div id="testModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">취약점 테스트 실행</h2>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <div id="modalBody">
                <div class="loading" id="loadingSpinner">
                    <div class="spinner"></div>
                    <p>테스트를 실행하고 있습니다...</p>
                </div>
                <div id="testResults" style="display: none;">
                    <h4>🎯 테스트 결과:</h4>
                    <div id="executionInfo" style="margin-bottom: 15px;"></div>
                    <div class="test-output" id="testOutput"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // 전역 변수
        let currentTests = <?php echo json_encode($all_tests); ?>;
        
        // 필터링 기능
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                // 활성 버튼 업데이트
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                
                const filter = this.getAttribute('data-filter');
                filterTests(filter);
            });
        });
        
        function filterTests(filter) {
            const testCards = document.querySelectorAll('.test-card');
            
            testCards.forEach(card => {
                const difficulty = card.getAttribute('data-difficulty');
                const category = card.getAttribute('data-category');
                
                if (filter === 'all') {
                    card.style.display = 'block';
                } else if (filter === difficulty || filter === category) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }
        
        // 테스트 실행 함수
        async function executeTest(testName, testFile) {
            const modal = document.getElementById('testModal');
            const modalTitle = document.getElementById('modalTitle');
            const loading = document.getElementById('loadingSpinner');
            const results = document.getElementById('testResults');
            
            modalTitle.textContent = `🧪 ${testName} 실행 중`;
            loading.style.display = 'block';
            results.style.display = 'none';
            modal.style.display = 'block';
            
            try {
                const formData = new FormData();
                formData.append('ajax_action', 'execute_test');
                formData.append('test_name', testName);
                formData.append('test_file', testFile);
                formData.append('payload', ''); // 기본 페이로드
                
                const response = await fetch('dashboard_ajax.php', {
                    method: 'POST',
                    body: formData
                });
                
                const responseText = await response.text();
                console.log('Raw response:', responseText); // 디버깅용
                
                let result;
                try {
                    result = JSON.parse(responseText);
                } catch (parseError) {
                    console.error('JSON 파싱 오류:', parseError);
                    console.error('응답 내용:', responseText);
                    throw new Error('서버 응답을 파싱할 수 없습니다: ' + responseText.substring(0, 100));
                }
                
                loading.style.display = 'none';
                
                if (result.success && result.redirect_url) {
                    // 새 탭에서 테스트 페이지 열기
                    window.open(result.redirect_url, '_blank');
                    closeModal();
                    
                    // 결과 로깅
                    const resultType = 'vulnerable'; // 기본값
                    logTestResult(testName, resultType, result.execution_time);
                    
                } else if (result.success) {
                    results.style.display = 'block';
                    modalTitle.textContent = `📊 ${testName} 실행 결과`;
                    
                    const executionInfo = document.getElementById('executionInfo');
                    const testOutput = document.getElementById('testOutput');
                    
                    executionInfo.innerHTML = `
                        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                            <span><strong>🎯 상태:</strong> ✅ 성공</span>
                            <span><strong>⏱️ 실행 시간:</strong> ${result.execution_time}ms</span>
                            <span><strong>📝 메시지:</strong> ${result.message}</span>
                        </div>
                    `;
                    
                    testOutput.innerHTML = result.output || '출력 데이터가 없습니다.';
                } else {
                    // 오류 표시
                    results.style.display = 'block';
                    modalTitle.textContent = `❌ ${testName} 실행 오류`;
                    
                    const executionInfo = document.getElementById('executionInfo');
                    const testOutput = document.getElementById('testOutput');
                    
                    executionInfo.innerHTML = `
                        <div style="color: #e74c3c;">
                            <span><strong>❌ 오류:</strong> ${result.message}</span>
                            <span><strong>⏱️ 실행 시간:</strong> ${result.execution_time}ms</span>
                        </div>
                    `;
                    
                    testOutput.innerHTML = '테스트 실행 중 오류가 발생했습니다.';
                }
                
                // 통계 새로고침
                refreshStats();
                
            } catch (error) {
                loading.style.display = 'none';
                results.style.display = 'block';
                
                modalTitle.textContent = `❌ ${testName} 실행 오류`;
                
                document.getElementById('executionInfo').innerHTML = `
                    <span style="color: #e74c3c;"><strong>오류:</strong> ${error.message}</span>
                `;
                document.getElementById('testOutput').innerHTML = '테스트 실행 중 오류가 발생했습니다.';
            }
        }
        
        // 모달 닫기
        function closeModal() {
            document.getElementById('testModal').style.display = 'none';
        }
        
        // 모달 외부 클릭 시 닫기
        window.onclick = function(event) {
            const modal = document.getElementById('testModal');
            if (event.target === modal) {
                closeModal();
            }
        }
        
        // 테스트 결과 로깅
        async function logTestResult(testName, resultType, executionTime) {
            try {
                const formData = new FormData();
                formData.append('ajax_action', 'log_result');
                formData.append('test_name', testName);
                formData.append('result_type', resultType);
                formData.append('execution_time', executionTime);
                
                await fetch('dashboard_ajax.php', {
                    method: 'POST',
                    body: formData
                });
            } catch (error) {
                console.error('결과 로깅 오류:', error);
            }
        }
        
        // 통계 새로고침
        async function refreshStats() {
            try {
                const formData = new FormData();
                formData.append('ajax_action', 'get_recent_results');
                
                const response = await fetch('dashboard_ajax.php', {
                    method: 'POST',
                    body: formData
                });
                
                const recentResults = await response.json();
                updateRecentResults(recentResults);
                
            } catch (error) {
                console.error('통계 새로고침 오류:', error);
            }
        }
        
        function updateRecentResults(results) {
            const container = document.querySelector('.recent-results');
            const statusText = {
                'vulnerable': '취약',
                'safe': '안전',
                'error': '오류'
            };
            
            container.innerHTML = results.map(result => `
                <div class="result-item">
                    <div>
                        <div style="font-weight: bold; font-size: 0.9rem;">
                            ${result.test_name}
                        </div>
                        <div style="font-size: 0.8rem; color: #666;">
                            ${new Date(result.created_at).toLocaleDateString('ko-KR', {
                                month: '2-digit', 
                                day: '2-digit', 
                                hour: '2-digit', 
                                minute: '2-digit'
                            })}
                        </div>
                    </div>
                    <span class="result-status ${result.result_type}">
                        ${statusText[result.result_type] || result.result_type}
                    </span>
                </div>
            `).join('');
        }
        
        // 키보드 이벤트
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeModal();
            }
        });
        
        // 페이지 로드 시 초기화
        document.addEventListener('DOMContentLoaded', function() {
            // 3분마다 통계 자동 새로고침
            setInterval(refreshStats, 180000);
        });
    </script>
</body>
</html>