<?php
/**
 * 로컬 개발 환경용 설정 파일
 * Docker 없이 테스트할 때 사용
 */

// 로컬 데이터베이스 설정 (Docker 대신 localhost 사용)
define('DB_HOST', 'localhost');
define('DB_NAME', 'my_database');
define('DB_USER', 'root');
define('DB_PASS', ''); // 로컬 MySQL root 비밀번호
define('DB_CHARSET', 'utf8mb4');

// 페이지네이션 설정
define('POSTS_PER_PAGE', 10);
define('COMMENTS_PER_PAGE', 20);

// 파일 업로드 설정
define('UPLOAD_DIR', 'uploads/');
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('ALLOWED_IMAGE_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp']);
define('ALLOWED_DOCUMENT_EXTENSIONS', ['pdf', 'doc', 'docx', 'txt']);

// 보안 설정
define('MIN_PASSWORD_LENGTH', 8);
define('SESSION_TIMEOUT', 3600); // 1시간
define('CSRF_TOKEN_NAME', 'csrf_token');

// 알림 설정
define('MAX_NOTIFICATIONS', 50);
define('NOTIFICATION_CLEANUP_DAYS', 30);

// 사이트 설정
define('SITE_NAME', 'My Board (Local)');
define('SITE_DESCRIPTION', '게시판 사이트 - 로컬 개발환경');
define('DEFAULT_TIMEZONE', 'Asia/Seoul');

// 로그 설정
define('LOG_DIR', 'logs/');
define('LOG_MAX_SIZE', 10 * 1024 * 1024); // 10MB
define('LOG_MAX_FILES', 5);

// 개발 모드
define('DEBUG_MODE', true);
define('SHOW_ERRORS', DEBUG_MODE);

// 취약점 테스트 모드 (로컬에서는 안전하게 false)
define('VULNERABILITY_MODE', false);

// 타임존 설정
date_default_timezone_set(DEFAULT_TIMEZONE);

// 에러 표시 설정
if (SHOW_ERRORS) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

// 세션 보안 설정
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 0);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
}
?>