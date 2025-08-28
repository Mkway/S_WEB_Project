<?php
/**
 * 유틸리티 함수 모음
 * 프로젝트 전반에서 사용되는 공통 함수들을 정의합니다.
 */

/**
 * 사용자 입력값을 안전하게 출력하기 위해 HTML 엔티티로 변환
 * @param string $string 변환할 문자열
 * @return string HTML 엔티티로 변환된 문자열
 */
function safe_output($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/**
 * 사용자 입력값 검증 및 정리
 * @param string $input 입력값
 * @return string 정리된 입력값
 */
function clean_input($input) {
    return trim(stripslashes($input));
}

/**
 * 이메일 형식 검증
 * @param string $email 검증할 이메일
 * @return bool 유효한 이메일인지 여부
 */
function is_valid_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * 비밀번호 강도 검증
 * @param string $password 검증할 비밀번호
 * @return array 검증 결과 (is_valid, message)
 */
function validate_password($password) {
    $result = ['is_valid' => true, 'message' => ''];
    
    if (strlen($password) < 8) {
        $result['is_valid'] = false;
        $result['message'] = '비밀번호는 최소 8자 이상이어야 합니다.';
        return $result;
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $result['is_valid'] = false;
        $result['message'] = '비밀번호에는 최소 1개의 대문자가 포함되어야 합니다.';
        return $result;
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $result['is_valid'] = false;
        $result['message'] = '비밀번호에는 최소 1개의 소문자가 포함되어야 합니다.';
        return $result;
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $result['is_valid'] = false;
        $result['message'] = '비밀번호에는 최소 1개의 숫자가 포함되어야 합니다.';
        return $result;
    }
    
    return $result;
}

/**
 * 사용자가 로그인되어 있는지 확인
 * @return bool 로그인 상태
 */
function is_logged_in() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * 사용자가 관리자인지 확인
 * @return bool 관리자 여부
 */
function is_admin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}

/**
 * 로그인 페이지로 리다이렉트
 * @param string $message 표시할 메시지
 */
function redirect_to_login($message = '') {
    // 보안 이벤트 로깅
    if (function_exists('log_security')) {
        log_security('access_denied', 'Unauthorized access attempt', [
            'requested_url' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'message' => $message
        ]);
    }
    
    $redirect_url = 'login.php';
    if (!empty($message)) {
        $redirect_url .= '?message=' . urlencode($message);
    }
    header("Location: $redirect_url");
    exit;
}

/**
 * 관리자 권한 확인 및 리다이렉트
 */
function require_admin() {
    if (!is_logged_in()) {
        redirect_to_login('로그인이 필요합니다.');
    }
    
    if (!is_admin()) {
        header('Location: index.php');
        exit;
    }
}

/**
 * 로그인 상태 확인 및 리다이렉트
 */
function require_login() {
    if (!is_logged_in()) {
        redirect_to_login('로그인이 필요합니다.');
    }
}

/**
 * CSRF 토큰 생성
 * @return string CSRF 토큰
 */
function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * CSRF 토큰 검증
 * @param string $token 검증할 토큰
 * @return bool 토큰 유효성
 */
function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * 파일 확장자 검증
 * @param string $filename 파일명
 * @param array $allowed_extensions 허용된 확장자 배열
 * @return bool 허용된 확장자인지 여부
 */
function is_allowed_file_extension($filename, $allowed_extensions) {
    $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($file_extension, $allowed_extensions);
}

/**
 * 페이지네이션 계산
 * @param int $total_items 총 아이템 수
 * @param int $items_per_page 페이지당 아이템 수  
 * @param int $current_page 현재 페이지
 * @return array 페이지네이션 정보
 */
function calculate_pagination($total_items, $items_per_page, $current_page) {
    $total_pages = ceil($total_items / $items_per_page);
    $offset = ($current_page - 1) * $items_per_page;
    
    return [
        'total_pages' => $total_pages,
        'current_page' => $current_page,
        'offset' => $offset,
        'items_per_page' => $items_per_page,
        'has_previous' => $current_page > 1,
        'has_next' => $current_page < $total_pages
    ];
}

/**
 * 사용자의 읽지 않은 알림 수 조회
 * @param PDO $pdo 데이터베이스 연결
 * @param int $user_id 사용자 ID
 * @return int 읽지 않은 알림 수
 */
function get_unread_notifications_count($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
    $stmt->execute([$user_id]);
    return (int)$stmt->fetchColumn();
}

/**
 * 게시물의 첫 번째 이미지 첨부파일 경로 조회
 * @param PDO $pdo 데이터베이스 연결
 * @param int $post_id 게시물 ID
 * @return string|false 이미지 파일 경로 또는 false
 */
function get_first_image_attachment($pdo, $post_id) {
    $stmt = $pdo->prepare("
        SELECT filepath 
        FROM files 
        WHERE post_id = ? 
        AND (filename LIKE '%.jpg' OR filename LIKE '%.jpeg' OR filename LIKE '%.png' OR filename LIKE '%.gif' OR filename LIKE '%.webp') 
        LIMIT 1
    ");
    $stmt->execute([$post_id]);
    return $stmt->fetchColumn();
}

/**
 * 게시물의 카테고리 목록 조회
 * @param PDO $pdo 데이터베이스 연결
 * @param int $post_id 게시물 ID
 * @return array 카테고리 배열
 */
function get_post_categories($pdo, $post_id) {
    $stmt = $pdo->prepare("
        SELECT c.id, c.name 
        FROM categories c 
        JOIN post_categories pc ON c.id = pc.category_id 
        WHERE pc.post_id = ?
    ");
    $stmt->execute([$post_id]);
    return $stmt->fetchAll();
}

/**
 * 성공 메시지 표시용 HTML 생성
 * @param string $message 메시지
 * @return string HTML 문자열
 */
function show_success_message($message) {
    return '<div class="alert alert-success">' . safe_output($message) . '</div>';
}

/**
 * 에러 메시지 표시용 HTML 생성
 * @param string $message 메시지
 * @return string HTML 문자열
 */
function show_error_message($message) {
    return '<div class="alert alert-error">' . safe_output($message) . '</div>';
}

/**
 * 날짜 형식을 사용자 친화적으로 변환
 * @param string $date 날짜 문자열
 * @return string 형식화된 날짜
 */
function format_date($date) {
    return date('Y-m-d H:i', strtotime($date));
}

/**
 * 텍스트를 지정된 길이로 자르기
 * @param string $text 원본 텍스트
 * @param int $length 최대 길이
 * @param string $suffix 접미사 (기본값: '...')
 * @return string 잘린 텍스트
 */
function truncate_text($text, $length, $suffix = '...') {
    if (mb_strlen($text) <= $length) {
        return $text;
    }
    return mb_substr($text, 0, $length) . $suffix;
}

/**
 * 예외를 로그에 기록하고 사용자 친화적 메시지 반환
 * @param Exception $e 예외 객체
 * @param string $user_message 사용자에게 표시할 메시지
 * @return string 사용자 메시지
 */
function handle_exception($e, $user_message = '처리 중 오류가 발생했습니다.') {
    if (function_exists('log_error')) {
        log_error("Exception occurred: " . $e->getMessage(), [
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'trace' => $e->getTraceAsString()
        ]);
    }
    
    return DEBUG_MODE ? $e->getMessage() : $user_message;
}

/**
 * 사용자 로그인 시도 기록
 * @param string $username 사용자명
 * @param bool $success 로그인 성공 여부
 * @param string $reason 실패 사유 (실패시)
 */
function log_login_attempt($username, $success, $reason = '') {
    if (!function_exists('log_security')) {
        return;
    }
    
    $event = $success ? 'login_success' : 'login_failure';
    $message = $success ? "User '{$username}' logged in successfully" : "Failed login attempt for user '{$username}'";
    
    $context = [
        'username' => $username,
        'success' => $success
    ];
    
    if (!$success && $reason) {
        $context['failure_reason'] = $reason;
    }
    
    log_security($event, $message, $context);
}

/**
 * 파일 업로드 시도 기록
 * @param string $filename 파일명
 * @param bool $success 업로드 성공 여부
 * @param string $error 에러 메시지 (실패시)
 */
function log_file_upload($filename, $success, $error = '') {
    if (!function_exists('log_info') || !function_exists('log_warning')) {
        return;
    }
    
    if ($success) {
        log_info("File uploaded successfully", [
            'filename' => $filename,
            'user_id' => $_SESSION['user_id'] ?? 'anonymous'
        ]);
    } else {
        log_warning("File upload failed", [
            'filename' => $filename,
            'error' => $error,
            'user_id' => $_SESSION['user_id'] ?? 'anonymous'
        ]);
    }
}

/**
 * 데이터베이스 쿼리 실행 및 에러 로깅
 * @param PDO $pdo 데이터베이스 연결
 * @param string $query SQL 쿼리
 * @param array $params 쿼리 매개변수
 * @return PDOStatement|false 실행 결과
 */
function execute_query_with_logging($pdo, $query, $params = []) {
    try {
        $stmt = $pdo->prepare($query);
        $result = $stmt->execute($params);
        
        if (!$result) {
            if (function_exists('log_database_error')) {
                log_database_error($query, 'Query execution failed', [
                    'params' => $params,
                    'error_info' => $stmt->errorInfo()
                ]);
            }
            return false;
        }
        
        return $stmt;
        
    } catch (PDOException $e) {
        if (function_exists('log_database_error')) {
            log_database_error($query, $e->getMessage(), [
                'params' => $params
            ]);
        }
        return false;
    }
}

/**
 * 세션 시작 및 보안 설정
 */
function secure_session_start() {
    if (session_status() === PHP_SESSION_NONE) {
        // 세션 보안 설정
        ini_set('session.cookie_httponly', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_secure', 0); // HTTPS 환경에서는 1로 설정
        
        session_start();
        
        // 세션 고정 공격 방지
        if (!isset($_SESSION['initiated'])) {
            session_regenerate_id(true);
            $_SESSION['initiated'] = true;
            
            if (function_exists('log_info')) {
                log_info("New session initiated", [
                    'session_id' => session_id()
                ]);
            }
        }
        
        // 세션 타임아웃 체크
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
            session_destroy();
            if (function_exists('log_info')) {
                log_info("Session expired and destroyed");
            }
            redirect_to_login('세션이 만료되었습니다. 다시 로그인해주세요.');
        }
        
        $_SESSION['last_activity'] = time();
    }
}

/**
 * 안전한 리다이렉트 (오픈 리다이렉트 방지)
 * @param string $url 리다이렉트할 URL
 * @param string $default_url 기본 URL
 */
function safe_redirect($url, $default_url = 'index.php') {
    // 외부 URL 차단
    if (filter_var($url, FILTER_VALIDATE_URL) && !str_starts_with($url, $_SERVER['HTTP_HOST'])) {
        if (function_exists('log_security')) {
            log_security('open_redirect_attempt', 'Attempted redirect to external URL', [
                'attempted_url' => $url
            ]);
        }
        $url = $default_url;
    }
    
    // 상대 경로만 허용
    if (!str_starts_with($url, '/') && !preg_match('/^[a-zA-Z0-9_\-\.\/]+\.php(\?.*)?$/', $url)) {
        $url = $default_url;
    }
    
    header("Location: $url");
    exit;
}

/**
 * 간단한 마크다운을 HTML로 변환
 * @param string $markdown 마크다운 텍스트
 * @return string HTML로 변환된 텍스트
 */
function parse_markdown($markdown) {
    // HTML 인젝션 방지를 위해 기본 이스케이프
    $html = htmlspecialchars($markdown, ENT_QUOTES, 'UTF-8');
    
    // 제목 변환 (H1-H6)
    $html = preg_replace('/^# (.+)$/m', '<h1>$1</h1>', $html);
    $html = preg_replace('/^## (.+)$/m', '<h2>$1</h2>', $html);
    $html = preg_replace('/^### (.+)$/m', '<h3>$1</h3>', $html);
    $html = preg_replace('/^#### (.+)$/m', '<h4>$1</h4>', $html);
    $html = preg_replace('/^##### (.+)$/m', '<h5>$1</h5>', $html);
    $html = preg_replace('/^###### (.+)$/m', '<h6>$1</h6>', $html);
    
    // 굵은 글씨 변환
    $html = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $html);
    $html = preg_replace('/__(.+?)__/', '<strong>$1</strong>', $html);
    
    // 기울임 글씨 변환
    $html = preg_replace('/\*(.+?)\*/', '<em>$1</em>', $html);
    $html = preg_replace('/_(.+?)_/', '<em>$1</em>', $html);
    
    // 인라인 코드 변환
    $html = preg_replace('/`(.+?)`/', '<code>$1</code>', $html);
    
    // 링크 변환
    $html = preg_replace('/\[(.+?)\]\((.+?)\)/', '<a href="$2" target="_blank">$1</a>', $html);
    
    // 코드 블록 변환 (```로 감싸진 부분)
    $html = preg_replace('/```([a-zA-Z]*)\n(.*?)\n```/s', '<pre><code class="language-$1">$2</code></pre>', $html);
    
    // 목록 변환
    $lines = explode("\n", $html);
    $in_list = false;
    $result = [];
    
    foreach ($lines as $line) {
        $line = trim($line);
        
        // 순서 없는 목록
        if (preg_match('/^[-\*\+] (.+)$/', $line, $matches)) {
            if (!$in_list) {
                $result[] = '<ul>';
                $in_list = 'ul';
            } elseif ($in_list === 'ol') {
                $result[] = '</ol><ul>';
                $in_list = 'ul';
            }
            $result[] = '<li>' . $matches[1] . '</li>';
        }
        // 순서 있는 목록
        elseif (preg_match('/^\d+\. (.+)$/', $line, $matches)) {
            if (!$in_list) {
                $result[] = '<ol>';
                $in_list = 'ol';
            } elseif ($in_list === 'ul') {
                $result[] = '</ul><ol>';
                $in_list = 'ol';
            }
            $result[] = '<li>' . $matches[1] . '</li>';
        }
        // 일반 텍스트
        else {
            if ($in_list) {
                $result[] = '</' . $in_list . '>';
                $in_list = false;
            }
            
            if (!empty($line)) {
                // 단락 처리
                if (!preg_match('/^<[h1-6|pre|ul|ol]/', $line)) {
                    $line = '<p>' . $line . '</p>';
                }
            }
            $result[] = $line;
        }
    }
    
    // 목록이 끝나지 않은 경우 닫기
    if ($in_list) {
        $result[] = '</' . $in_list . '>';
    }
    
    return implode("\n", $result);
}

/**
 * 마크다운 파일을 읽고 HTML로 변환하여 반환
 * @param string $file_path 마크다운 파일 경로
 * @return string|null HTML로 변환된 내용 또는 null (파일이 없는 경우)
 */
function load_and_parse_markdown($file_path) {
    if (!file_exists($file_path)) {
        return null;
    }
    
    $markdown_content = file_get_contents($file_path);
    if ($markdown_content === false) {
        return null;
    }
    
    return parse_markdown($markdown_content);
}
?>