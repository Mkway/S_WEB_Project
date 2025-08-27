<?php
/**
 * 로그 조회 페이지
 * 관리자만 접근 가능한 로그 조회 인터페이스
 */

session_start();
require_once 'db.php';
require_once 'utils.php';
require_once 'Logger.php';

// 관리자 권한 확인
require_admin();

$logger = get_logger();
$message = '';
$error = '';

// 로그 파일 목록 조회
$log_files = $logger->get_log_files();

// 선택된 로그 파일 내용 조회
$selected_file = $_GET['file'] ?? '';
$selected_lines = (int)($_GET['lines'] ?? 100);
$log_entries = [];

if ($selected_file && preg_match('/^app_[a-z]+_\d{4}-\d{2}-\d{2}\.log(\.\d+)?$/', $selected_file)) {
    $log_entries = $logger->read_log_file($selected_file, $selected_lines);
}

// 로그 정리 작업
if ($_POST['action'] ?? '' === 'cleanup') {
    $days = (int)($_POST['cleanup_days'] ?? 30);
    $deleted_count = $logger->cleanup_old_logs($days);
    $message = "{$deleted_count}개의 오래된 로그 파일이 삭제되었습니다.";
    log_user_activity($_SESSION['user_id'], 'log_cleanup', "Deleted {$deleted_count} files older than {$days} days");
}

// 로그 레벨별 필터링을 위한 함수
function filter_entries_by_level($entries, $level) {
    if (!$level || $level === 'all') {
        return $entries;  
    }
    
    return array_filter($entries, function($entry) use ($level) {
        return strtolower($entry['level']) === strtolower($level);
    });
}

$filter_level = $_GET['level'] ?? 'all';
if (!empty($log_entries)) {
    $log_entries = filter_entries_by_level($log_entries, $filter_level);
}

// 로그 레벨별 색상 매핑
$level_colors = [
    'debug' => '#6c757d',
    'info' => '#17a2b8', 
    'warning' => '#ffc107',
    'error' => '#dc3545',
    'critical' => '#6f42c1'
];
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그 조회 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="style.css">
    <style>
        .log-viewer {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .log-controls {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .log-controls .form-row {
            display: flex;
            gap: 15px;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .log-controls select, .log-controls input {
            padding: 8px 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
        }
        
        .log-files-list {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            background: white;
        }
        
        .log-file-item {
            padding: 10px 15px;
            border-bottom: 1px solid #f1f1f1;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .log-file-item:hover {
            background: #f8f9fa;
        }
        
        .log-file-item.selected {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
        }
        
        .log-file-info {
            font-size: 12px;
            color: #6c757d;
        }
        
        .log-entries {
            background: #1e1e1e;
            color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .log-entry {
            margin-bottom: 10px;
            padding: 8px;
            border-left: 3px solid #333;
            background: rgba(255, 255, 255, 0.05);
        }
        
        .log-entry.debug { border-left-color: #6c757d; }
        .log-entry.info { border-left-color: #17a2b8; }
        .log-entry.warning { border-left-color: #ffc107; }
        .log-entry.error { border-left-color: #dc3545; }
        .log-entry.critical { border-left-color: #6f42c1; }
        
        .log-timestamp {
            color: #28a745;
            font-weight: bold;
        }
        
        .log-level {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .log-level.debug { background: #6c757d; }
        .log-level.info { background: #17a2b8; }
        .log-level.warning { background: #ffc107; color: #000; }
        .log-level.error { background: #dc3545; }
        .log-level.critical { background: #6f42c1; }
        
        .log-message {
            margin: 5px 0;
            word-break: break-word;
        }
        
        .log-context {
            margin-top: 5px;
            padding: 5px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            font-size: 11px;
            color: #ccc;
        }
        
        .cleanup-section {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
        }
        
        .stats-row {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-box {
            flex: 1;
            background: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #dee2e6;
            text-align: center;
        }
        
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        
        .stat-label {
            font-size: 12px;
            color: #6c757d;
            text-transform: uppercase;
        }
        
        .no-logs {
            text-align: center;
            padding: 40px;
            color: #6c757d;
            background: #f8f9fa;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container log-viewer">
        <div class="nav">
            <h1>로그 조회</h1>
            <div>
                <a href="admin.php" class="btn">관리자 페이지</a>
                <a href="index.php" class="btn">메인으로</a>
            </div>
        </div>

        <?php if ($message): ?>
            <?php echo show_success_message($message); ?>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <?php echo show_error_message($error); ?>
        <?php endif; ?>

        <!-- 통계 정보 -->
        <div class="stats-row">
            <div class="stat-box">
                <div class="stat-number"><?php echo count($log_files); ?></div>
                <div class="stat-label">로그 파일</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">
                    <?php 
                    $total_size = array_sum(array_column($log_files, 'size'));
                    echo number_format($total_size / 1024, 1) . 'KB';
                    ?>
                </div>
                <div class="stat-label">총 용량</div>
            </div>
            <div class="stat-box">
                <div class="stat-number"><?php echo count($log_entries); ?></div>
                <div class="stat-label">표시된 로그</div>
            </div>
        </div>

        <!-- 로그 조회 컨트롤 -->
        <div class="log-controls">
            <h3>로그 파일 선택</h3>
            
            <form method="get" action="log_viewer.php">
                <div class="form-row">
                    <label for="level">레벨 필터:</label>
                    <select name="level" id="level">
                        <option value="all" <?php echo $filter_level === 'all' ? 'selected' : ''; ?>>모든 레벨</option>
                        <option value="debug" <?php echo $filter_level === 'debug' ? 'selected' : ''; ?>>DEBUG</option>
                        <option value="info" <?php echo $filter_level === 'info' ? 'selected' : ''; ?>>INFO</option>
                        <option value="warning" <?php echo $filter_level === 'warning' ? 'selected' : ''; ?>>WARNING</option>
                        <option value="error" <?php echo $filter_level === 'error' ? 'selected' : ''; ?>>ERROR</option>
                        <option value="critical" <?php echo $filter_level === 'critical' ? 'selected' : ''; ?>>CRITICAL</option>
                    </select>
                    
                    <label for="lines">표시할 라인:</label>
                    <select name="lines" id="lines">
                        <option value="50" <?php echo $selected_lines === 50 ? 'selected' : ''; ?>>50줄</option>
                        <option value="100" <?php echo $selected_lines === 100 ? 'selected' : ''; ?>>100줄</option>
                        <option value="500" <?php echo $selected_lines === 500 ? 'selected' : ''; ?>>500줄</option>
                        <option value="1000" <?php echo $selected_lines === 1000 ? 'selected' : ''; ?>>1000줄</option>
                    </select>
                    
                    <input type="hidden" name="file" value="<?php echo safe_output($selected_file); ?>">
                    <button type="submit" class="btn">필터 적용</button>
                </div>
            </form>
            
            <div class="log-files-list">
                <?php if (empty($log_files)): ?>
                    <div class="log-file-item">로그 파일이 없습니다.</div>
                <?php else: ?>
                    <?php foreach ($log_files as $file): ?>
                        <div class="log-file-item <?php echo $file['filename'] === $selected_file ? 'selected' : ''; ?>" 
                             onclick="selectLogFile('<?php echo $file['filename']; ?>')">
                            <div>
                                <strong><?php echo safe_output($file['filename']); ?></strong>
                                <div class="log-file-info">
                                    크기: <?php echo number_format($file['size'] / 1024, 1); ?>KB | 
                                    수정: <?php echo date('Y-m-d H:i:s', $file['modified']); ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- 로그 내용 표시 -->
        <?php if ($selected_file): ?>
            <h3><?php echo safe_output($selected_file); ?> 내용</h3>
            
            <?php if (empty($log_entries)): ?>
                <div class="no-logs">
                    선택한 필터 조건에 해당하는 로그가 없습니다.
                </div>
            <?php else: ?>
                <div class="log-entries">
                    <?php foreach ($log_entries as $entry): ?>
                        <div class="log-entry <?php echo strtolower($entry['level']); ?>">
                            <span class="log-timestamp">[<?php echo $entry['timestamp']; ?>]</span>
                            <span class="log-level <?php echo strtolower($entry['level']); ?>"><?php echo $entry['level']; ?></span>
                            <span class="session-id">[<?php echo $entry['session_id']; ?>]</span>
                            <div class="log-message"><?php echo safe_output($entry['message']); ?></div>
                            <?php if (!empty($entry['context'])): ?>
                                <div class="log-context">
                                    <strong>Context:</strong> <?php echo safe_output(json_encode($entry['context'], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT)); ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>

        <!-- 로그 정리 섹션 -->
        <div class="cleanup-section">
            <h3>로그 파일 정리</h3>
            <p>오래된 로그 파일을 삭제하여 디스크 공간을 확보할 수 있습니다.</p>
            
            <form method="post" action="log_viewer.php" onsubmit="return confirm('정말로 오래된 로그 파일을 삭제하시겠습니까?');">
                <input type="hidden" name="action" value="cleanup">
                <div class="form-row">
                    <label for="cleanup_days">보관 기간:</label>
                    <select name="cleanup_days" id="cleanup_days">
                        <option value="7">7일</option>
                        <option value="14">14일</option>
                        <option value="30" selected>30일</option>
                        <option value="60">60일</option>
                        <option value="90">90일</option>
                    </select>
                    <button type="submit" class="btn btn-danger">오래된 로그 삭제</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function selectLogFile(filename) {
            const urlParams = new URLSearchParams(window.location.search);
            urlParams.set('file', filename);
            window.location.search = urlParams.toString();
        }
        
        // 자동 새로고침 (선택사항)
        let autoRefresh = false;
        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            if (autoRefresh) {
                setInterval(() => {
                    if (document.querySelector('input[name="file"]').value) {
                        location.reload();
                    }
                }, 30000); // 30초마다 새로고침
            }
        }
        
        // 키보드 단축키
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'r') {
                e.preventDefault();
                location.reload();
            }
        });
    </script>
</body>
</html>