<?php
/**
 * 로깅 시스템 클래스
 * 애플리케이션의 모든 로그를 체계적으로 관리합니다.
 */

class Logger {
    // 로그 레벨 상수
    const LEVEL_DEBUG = 1;
    const LEVEL_INFO = 2;
    const LEVEL_WARNING = 3;
    const LEVEL_ERROR = 4;
    const LEVEL_CRITICAL = 5;
    
    // 로그 레벨 이름 매핑
    private static $level_names = [
        self::LEVEL_DEBUG => 'DEBUG',
        self::LEVEL_INFO => 'INFO',
        self::LEVEL_WARNING => 'WARNING',
        self::LEVEL_ERROR => 'ERROR',
        self::LEVEL_CRITICAL => 'CRITICAL'
    ];
    
    private $log_dir;
    private $max_file_size;
    private $max_files;
    private $current_level;
    
    /**
     * Logger 생성자
     * @param string $log_dir 로그 디렉토리 경로
     * @param int $max_file_size 최대 파일 크기 (바이트)
     * @param int $max_files 보관할 최대 파일 수
     * @param int $current_level 현재 로그 레벨
     */
    public function __construct($log_dir = 'logs/', $max_file_size = 10485760, $max_files = 5, $current_level = self::LEVEL_INFO) {
        $this->log_dir = rtrim($log_dir, '/') . '/';
        $this->max_file_size = $max_file_size;
        $this->max_files = $max_files;
        $this->current_level = $current_level;
        
        // 로그 디렉토리 생성 (에러 무시)
        if (!is_dir($this->log_dir)) {
            @mkdir($this->log_dir, 0755, true);
        }
        
        // .htaccess 파일 생성 (웹 접근 차단)
        $this->create_htaccess();
    }
    
    /**
     * 웹 접근을 차단하는 .htaccess 파일 생성
     */
    private function create_htaccess() {
        $htaccess_path = $this->log_dir . '.htaccess';
        if (!file_exists($htaccess_path) && is_dir($this->log_dir)) {
            $content = "Order Deny,Allow\nDeny from all\n";
            @file_put_contents($htaccess_path, $content);
        }
    }
    
    /**
     * 디버그 로그 기록
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    public function debug($message, $context = []) {
        $this->log(self::LEVEL_DEBUG, $message, $context);
    }
    
    /**
     * 정보 로그 기록
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    public function info($message, $context = []) {
        $this->log(self::LEVEL_INFO, $message, $context);
    }
    
    /**
     * 경고 로그 기록
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    public function warning($message, $context = []) {
        $this->log(self::LEVEL_WARNING, $message, $context);
    }
    
    /**
     * 에러 로그 기록
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    public function error($message, $context = []) {
        $this->log(self::LEVEL_ERROR, $message, $context);
    }
    
    /**
     * 치명적 에러 로그 기록
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    public function critical($message, $context = []) {
        $this->log(self::LEVEL_CRITICAL, $message, $context);
    }
    
    /**
     * 보안 관련 이벤트 로그 기록
     * @param string $event 보안 이벤트 종류
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    public function security($event, $message, $context = []) {
        $context['security_event'] = $event;
        $context['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $context['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $context['request_uri'] = $_SERVER['REQUEST_URI'] ?? 'unknown';
        
        $this->log(self::LEVEL_WARNING, "[SECURITY] {$event}: {$message}", $context);
    }
    
    /**
     * 사용자 활동 로그 기록
     * @param int $user_id 사용자 ID
     * @param string $action 수행한 작업
     * @param string $details 작업 세부사항
     * @param array $context 추가 컨텍스트 정보
     */
    public function user_activity($user_id, $action, $details = '', $context = []) {
        $context['user_id'] = $user_id;
        $context['action'] = $action;
        $context['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $message = "User {$user_id} performed action: {$action}";
        if ($details) {
            $message .= " - {$details}";
        }
        
        $this->log(self::LEVEL_INFO, $message, $context);
    }
    
    /**
     * 데이터베이스 관련 로그 기록
     * @param string $query SQL 쿼리 (민감한 정보 제거됨)
     * @param string $error 에러 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    public function database_error($query, $error, $context = []) {
        // 민감한 정보 제거 (비밀번호, 개인정보 등)
        $safe_query = $this->sanitize_query($query);
        
        $context['query'] = $safe_query;
        $context['db_error'] = $error;
        
        $this->log(self::LEVEL_ERROR, "Database error: {$error}", $context);
    }
    
    /**
     * 메인 로깅 메서드
     * @param int $level 로그 레벨
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     */
    private function log($level, $message, $context = []) {
        // 현재 설정된 레벨보다 낮은 레벨은 기록하지 않음
        if ($level < $this->current_level) {
            return;
        }
        
        $log_entry = $this->format_log_entry($level, $message, $context);
        $log_file = $this->get_log_file_path($level);
        
        // 로그 파일 크기 확인 및 로테이션
        $this->rotate_log_if_needed($log_file);
        
        // 로그 기록 (에러 무시)
        @file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
        
        // 권한 설정 (처음 생성시에만, 에러 무시)
        if (@filesize($log_file) === strlen($log_entry)) {
            @chmod($log_file, 0640);
        }
    }
    
    /**
     * 로그 엔트리 포맷팅
     * @param int $level 로그 레벨
     * @param string $message 로그 메시지
     * @param array $context 추가 컨텍스트 정보
     * @return string 포맷된 로그 엔트리
     */
    private function format_log_entry($level, $message, $context = []) {
        $timestamp = date('Y-m-d H:i:s');
        $level_name = self::$level_names[$level];
        $session_id = session_id() ?: 'no-session';
        
        // 기본 로그 정보
        $log_data = [
            'timestamp' => $timestamp,
            'level' => $level_name,
            'session_id' => substr($session_id, 0, 8),
            'message' => $message
        ];
        
        // 컨텍스트 정보 추가
        if (!empty($context)) {
            $log_data['context'] = $context;
        }
        
        // JSON 형태로 로그 저장 (구조화된 로그)
        return json_encode($log_data, JSON_UNESCAPED_UNICODE) . "\n";
    }
    
    /**
     * 로그 파일 경로 생성
     * @param int $level 로그 레벨
     * @return string 로그 파일 경로
     */
    private function get_log_file_path($level) {
        $date = date('Y-m-d');
        $level_name = strtolower(self::$level_names[$level]);
        
        // 레벨별, 날짜별 로그 파일 분리
        return $this->log_dir . "app_{$level_name}_{$date}.log";
    }
    
    /**
     * 로그 파일 로테이션 (크기 제한)
     * @param string $log_file 로그 파일 경로
     */
    private function rotate_log_if_needed($log_file) {
        if (!file_exists($log_file) || filesize($log_file) < $this->max_file_size) {
            return;
        }
        
        // 기존 로테이션 파일들 이동
        for ($i = $this->max_files - 1; $i >= 1; $i--) {
            $old_file = $log_file . '.' . $i;
            $new_file = $log_file . '.' . ($i + 1);
            
            if (file_exists($old_file)) {
                if ($i === $this->max_files - 1) {
                    unlink($old_file); // 가장 오래된 파일 삭제
                } else {
                    rename($old_file, $new_file);
                }
            }
        }
        
        // 현재 파일을 .1로 이동
        if (file_exists($log_file)) {
            rename($log_file, $log_file . '.1');
        }
    }
    
    /**
     * SQL 쿼리에서 민감한 정보 제거
     * @param string $query SQL 쿼리
     * @return string 정리된 쿼리
     */
    private function sanitize_query($query) {
        // 비밀번호 필드 값 숨기기
        $query = preg_replace('/password\s*=\s*[\'"][^\']*[\'"]/', "password='***'", $query);
        $query = preg_replace('/pwd\s*=\s*[\'"][^\']*[\'"]/', "pwd='***'", $query);
        
        // 이메일 일부 숨기기
        $query = preg_replace('/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/', '$1***@$2', $query);
        
        return $query;
    }
    
    /**
     * 로그 파일 목록 조회
     * @param string $level 로그 레벨 (선택사항)
     * @return array 로그 파일 목록
     */
    public function get_log_files($level = null) {
        $pattern = $this->log_dir . 'app_';
        if ($level) {
            $pattern .= strtolower($level) . '_';
        }
        $pattern .= '*.log*';
        
        $files = glob($pattern);
        
        // 파일 정보와 함께 반환
        $log_files = [];
        foreach ($files as $file) {
            $log_files[] = [
                'filename' => basename($file),
                'filepath' => $file,
                'size' => filesize($file),
                'modified' => filemtime($file)
            ];
        }
        
        // 수정일 기준 내림차순 정렬
        usort($log_files, function($a, $b) {
            return $b['modified'] - $a['modified'];
        });
        
        return $log_files;
    }
    
    /**
     * 로그 파일 내용 읽기
     * @param string $filename 로그 파일명
     * @param int $lines 읽을 라인 수 (기본: 100)
     * @return array 로그 엔트리 배열
     */
    public function read_log_file($filename, $lines = 100) {
        $filepath = $this->log_dir . $filename;
        
        if (!file_exists($filepath)) {
            return [];
        }
        
        $file_lines = file($filepath, FILE_IGNORE_NEW_LINES);
        $file_lines = array_slice($file_lines, -$lines); // 마지막 N줄만
        
        $entries = [];
        foreach ($file_lines as $line) {
            $decoded = json_decode($line, true);
            if ($decoded) {
                $entries[] = $decoded;
            }
        }
        
        return array_reverse($entries); // 최신 순으로 정렬
    }
    
    /**
     * 오래된 로그 파일 정리
     * @param int $days 보관할 일수
     */
    public function cleanup_old_logs($days = 30) {
        $cutoff_time = time() - ($days * 24 * 60 * 60);
        $files = glob($this->log_dir . '*.log*');
        
        $deleted_count = 0;
        foreach ($files as $file) {
            if (filemtime($file) < $cutoff_time) {
                unlink($file);
                $deleted_count++;
            }
        }
        
        $this->info("Log cleanup completed", [
            'deleted_files' => $deleted_count,
            'cutoff_days' => $days
        ]);
        
        return $deleted_count;
    }
}

/**
 * 전역 Logger 인스턴스 생성
 */
function get_logger() {
    static $logger = null;
    if ($logger === null) {
        $logger = new Logger(
            LOG_DIR ?? 'logs/',
            LOG_MAX_SIZE ?? 10485760,
            LOG_MAX_FILES ?? 5,
            DEBUG_MODE ? Logger::LEVEL_DEBUG : Logger::LEVEL_INFO
        );
    }
    return $logger;
}

/**
 * 빠른 로깅을 위한 헬퍼 함수들
 */
function log_debug($message, $context = []) {
    get_logger()->debug($message, $context);
}

function log_info($message, $context = []) {
    get_logger()->info($message, $context);
}

function log_warning($message, $context = []) {  
    get_logger()->warning($message, $context);
}

function log_error($message, $context = []) {
    get_logger()->error($message, $context);
}

function log_critical($message, $context = []) {
    get_logger()->critical($message, $context);
}

function log_security($event, $message, $context = []) {
    get_logger()->security($event, $message, $context);
}

function log_user_activity($user_id, $action, $details = '', $context = []) {
    get_logger()->user_activity($user_id, $action, $details, $context);
}

function log_database_error($query, $error, $context = []) {
    get_logger()->database_error($query, $error, $context);
}
?>