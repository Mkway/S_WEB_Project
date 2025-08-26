<?php
/**
 * 로컬 환경 테스트 스크립트
 * Docker 없이 PHP 기능을 테스트합니다.
 */

echo "=== S_WEB_Project 로컬 환경 테스트 ===\n\n";

// 1. PHP 버전 확인
echo "1. PHP 버전: " . PHP_VERSION . "\n";

// 2. 필요한 확장 모듈 확인
$required_extensions = ['pdo', 'pdo_mysql', 'session', 'json', 'mbstring'];
echo "2. PHP 확장 모듈 확인:\n";

foreach ($required_extensions as $ext) {
    $status = extension_loaded($ext) ? "✅ 설치됨" : "❌ 미설치";
    echo "   - $ext: $status\n";
}

echo "\n3. 설정 파일 테스트:\n";

// 로컬 설정 파일 사용
if (file_exists('config.local.php')) {
    require_once 'config.local.php';
    echo "   ✅ config.local.php 로드됨\n";
    echo "   - DB_HOST: " . DB_HOST . "\n";
    echo "   - DB_NAME: " . DB_NAME . "\n";
    echo "   - SITE_NAME: " . SITE_NAME . "\n";
} else {
    echo "   ❌ config.local.php 파일이 없습니다.\n";
}

// 4. 데이터베이스 연결 테스트 (로컬 MySQL이 있는 경우)
echo "\n4. 데이터베이스 연결 테스트:\n";

try {
    $dsn = sprintf(
        "mysql:host=%s;charset=%s",
        DB_HOST,
        DB_CHARSET
    );
    
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    
    echo "   ✅ MySQL 서버 연결 성공\n";
    
    // 데이터베이스 존재 확인
    $stmt = $pdo->query("SHOW DATABASES LIKE '" . DB_NAME . "'");
    if ($stmt->rowCount() > 0) {
        echo "   ✅ 데이터베이스 '" . DB_NAME . "' 존재함\n";
    } else {
        echo "   ⚠️ 데이터베이스 '" . DB_NAME . "' 없음 (install.php 실행 필요)\n";
    }
    
} catch (PDOException $e) {
    echo "   ❌ 데이터베이스 연결 실패: " . $e->getMessage() . "\n";
    echo "   💡 해결방법:\n";
    echo "      1. MySQL 서버 시작: sudo service mysql start\n";
    echo "      2. 또는 Docker 환경 사용: docker-compose up -d\n";
}

// 5. 유틸리티 함수 테스트
echo "\n5. 유틸리티 함수 테스트:\n";

if (file_exists('utils.php')) {
    require_once 'utils.php';
    
    // safe_output 테스트
    $test_string = '<script>alert("xss")</script>';
    $safe_string = safe_output($test_string);
    echo "   ✅ safe_output() 작동: $safe_string\n";
    
    // clean_input 테스트
    $dirty_input = "  Hello World  \n";
    $clean_input = clean_input($dirty_input);
    echo "   ✅ clean_input() 작동: '$clean_input'\n";
    
    // CSRF 토큰 생성 테스트
    session_start();
    $csrf_token = generate_csrf_token();
    echo "   ✅ CSRF 토큰 생성: " . substr($csrf_token, 0, 16) . "...\n";
    
} else {
    echo "   ❌ utils.php 파일이 없습니다.\n";
}

// 6. 웹해킹 모듈 확인
echo "\n6. 웹해킹 모듈 확인:\n";

if (is_dir('webhacking')) {
    $php_files = glob('webhacking/*.php');
    $module_count = count($php_files);
    echo "   ✅ 웹해킹 모듈 디렉토리 존재\n";
    echo "   ✅ 보안 테스트 모듈 수: {$module_count}개\n";
    
    // TestPage.php 확인
    if (file_exists('webhacking/TestPage.php')) {
        echo "   ✅ TestPage.php 표준화 클래스 존재\n";
    } else {
        echo "   ❌ TestPage.php 없음\n";
    }
} else {
    echo "   ❌ webhacking 디렉토리가 없습니다.\n";
}

echo "\n=== 테스트 완료 ===\n";
echo "💡 Docker 환경 사용 시: cd .. && docker-compose up -d\n";
echo "💡 로컬 환경 사용 시: php -S localhost:8000\n";
?>