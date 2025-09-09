<?php
session_start();
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/VulnerabilityDashboard.php';

// JSON 헤더 설정
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');

// 출력 버퍼링 정리
while (ob_get_level()) {
    ob_end_clean();
}

// 데이터베이스 연결 확인
global $pdo;
if (!isset($pdo) || !$pdo) {
    echo json_encode(['success' => false, 'message' => '데이터베이스 연결에 실패했습니다.']);
    exit;
}

$dashboard = new VulnerabilityDashboard($pdo);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'POST 요청만 허용됩니다.']);
    exit;
}

$action = $_POST['ajax_action'] ?? '';

switch ($action) {
    case 'execute_test':
        $test_file = $_POST['test_file'] ?? '';
        $test_name = $_POST['test_name'] ?? '';
        $payload = $_POST['payload'] ?? '';
        
        $test_result = $dashboard->executeVulnerabilityTest($test_file, $payload);
        
        // 결과 로깅
        $result_type = $test_result['success'] ? 'vulnerable' : 'error';
        $dashboard->logTestResult($test_name, $result_type, $test_result['execution_time'], $payload, $test_result['output'] ?? '');
        
        echo json_encode($test_result);
        break;
        
    case 'get_stats':
        $stats = $dashboard->getDashboardStats();
        echo json_encode($stats);
        break;
        
    case 'get_recent_results':
        $recent = $dashboard->getRecentResults(20);
        echo json_encode($recent);
        break;
        
    case 'log_result':
        $test_name = $_POST['test_name'] ?? '';
        $result_type = $_POST['result_type'] ?? 'vulnerable';
        $execution_time = (float)($_POST['execution_time'] ?? 0);
        
        $dashboard->logTestResult($test_name, $result_type, $execution_time);
        echo json_encode(['success' => true]);
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => '알 수 없는 액션입니다.']);
        break;
}
exit;
?>