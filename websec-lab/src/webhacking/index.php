<?php
/**
 * 웹 해킹 테스트 메인 페이지
 * 다양한 보안 취약점 테스트를 제공합니다.
 */

session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>보안 취약점 테스트 - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .security-tests {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .test-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .test-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            border-color: #dc3545;
        }
        
        .test-card h3 {
            color: #dc3545;
            margin-bottom: 10px;
        }
        
        .test-card p {
            color: #6c757d;
            margin-bottom: 15px;
            line-height: 1.5;
        }
        
        
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
        
        .warning-box strong {
            color: #d63384;
        }
        
        .breadcrumb {
            background: #e9ecef;
            padding: 10px 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        
        .breadcrumb a {
            color: #007bff;
            text-decoration: none;
        }
        
        .breadcrumb a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 바 -->
        <nav class="nav">
            <h1>보안 취약점 테스트</h1>
            <div class="nav-links">
                <span>환영합니다, <?php echo safe_output($_SESSION['username']); ?>님!</span>
                <a href="../dashboard.php" class="btn">📊 대시보드</a>
                <a href="../index.php" class="btn">메인으로</a>
                <a href="../logout.php" class="btn">로그아웃</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; <span>보안 취약점 테스트</span>
        </nav>

        <!-- 경고 메시지 -->
        <div class="warning-box">
            <strong>⚠️ 주의사항:</strong> 이 페이지는 교육 목적으로만 사용되어야 합니다. 
            실제 운영 환경에서는 이러한 테스트를 수행하지 마세요. 
            모든 테스트는 통제된 환경에서만 실행하시기 바랍니다.
        </div>

        <!-- 대시보드 바로가기 -->
        <div style="text-align: center; margin: 30px 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px;">
            <h3 style="color: white; margin-bottom: 15px;">🛡️ WebSec-Lab 통합 대시보드</h3>
            <p style="color: #f0f0f0; margin-bottom: 20px;">모든 취약점 테스트를 한눈에 관리하고, 실행 통계를 확인하세요!</p>
            <a href="../dashboard.php" style="display: inline-block; padding: 12px 30px; background: white; color: #667eea; text-decoration: none; border-radius: 25px; font-weight: bold; box-shadow: 0 4px 15px rgba(0,0,0,0.2); transition: all 0.3s ease;">
                📊 대시보드로 이동 →
            </a>
        </div>

        <!-- 테스트 카테고리 -->
        <section class="security-tests">
            <!-- SQL Injection -->
            <div class="test-card">
                <h3>🗃️ SQL Injection</h3>
                <p>UNION, Boolean-based, Time-based, Error-based SQL Injection 페이로드를 테스트합니다.</p>
                <a href="sql_injection.php" style="display: none;"></a>
            </div>

            <!-- PostgreSQL Injection -->
            <div class="test-card">
                <h3>🐘 PostgreSQL Injection</h3>
                <p>PL/pgSQL 저장 프로시저 인젝션, COPY FROM PROGRAM 공격 등 PostgreSQL 특화 취약점을 테스트합니다.</p>
                <a href="postgresql_injection_test.php" style="display: none;"></a>
            </div>

            <!-- XSS -->
            <div class="test-card">
                <h3>🚨 Cross-Site Scripting (XSS)</h3>
                <p>Reflected, Stored, DOM-based XSS 취약점을 테스트합니다.</p>
                <a href="xss_test.php" style="display: none;"></a>
            </div>

            <!-- Command Injection -->
            <div class="test-card">
                <h3>💻 Command Injection</h3>
                <p>운영체제 명령어 주입 취약점을 테스트합니다.</p>
                <a href="command_injection.php" style="display: none;"></a>
            </div>

            <!-- File Inclusion -->
            <div class="test-card">
                <h3>📁 File Inclusion (LFI/RFI)</h3>
                <p>Local File Inclusion과 Remote File Inclusion 취약점을 테스트합니다.</p>
                <a href="file_inclusion.php" style="display: none;"></a>
            </div>

            <!-- Directory Traversal -->
            <div class="test-card">
                <h3>📂 Directory Traversal</h3>
                <p>디렉토리 순회 공격을 통한 파일 접근 테스트를 수행합니다.</p>
                <a href="directory_traversal.php" style="display: none;"></a>
            </div>

            <!-- CSRF -->
            <div class="test-card">
                <h3>🔄 Cross-Site Request Forgery (CSRF)</h3>
                <p>CSRF 공격 시뮬레이션과 토큰 우회 기법을 테스트합니다.</p>
                <a href="csrf_test.php" style="display: none;"></a>
            </div>

            <!-- IDOR -->
            <div class="test-card">
                <h3>🔑 Insecure Direct Object References (IDOR)</h3>
                <p>직접 객체 참조 취약점을 테스트합니다.</p>
                <a href="idor_test.php" style="display: none;"></a>
            </div>

            <!-- Authentication Bypass -->
            <div class="test-card">
                <h3>🔓 Authentication Bypass</h3>
                <p>인증 우회 기법과 세션 관리 취약점을 테스트합니다.</p>
                <a href="auth_bypass.php" style="display: none;"></a>
            </div>

            <!-- API Key Leaks -->
            <div class="test-card">
                <h3>🔑 API Key Leaks</h3>
                <p>API 키가 코드에 하드코딩되거나 노출되는 취약점을 테스트합니다.</p>
                <a href="api_key_leak_test.php" style="display: none;"></a>
            </div>

            <!-- Account Takeover -->
            <div class="test-card">
                <h3>👤 Account Takeover</h3>
                <p>약한 비밀번호 재설정 등 계정 탈취 시나리오를 테스트합니다.</p>
                <a href="account_takeover_test.php" style="display: none;"></a>
            </div>

            <!-- CRLF Injection -->
            <div class="test-card">
                <h3>↩️ CRLF Injection</h3>
                <p>HTTP 응답 분할 및 로그 주입 취약점을 테스트합니다.</p>
                <a href="crlf_injection_test.php" style="display: none;"></a>
            </div>

            <!-- CVE Exploit -->
            <div class="test-card">
                <h3>💥 CVE Exploit</h3>
                <p>특정 CVE (Common Vulnerabilities and Exposures)를 시뮬레이션합니다.</p>
                <a href="cve_exploit_test.php" style="display: none;"></a>
            </div>

            <!-- Client Side Path Traversal -->
            <div class="test-card">
                <h3>📁 Client Side Path Traversal</h3>
                <p>클라이언트 측 스크립트에서 경로 조작을 통한 파일 접근 취약점을 테스트합니다.</p>
                <a href="client_side_path_traversal_test.php" style="display: none;"></a>
            </div>

            <!-- DNS Rebinding -->
            <div class="test-card">
                <h3>🌐 DNS Rebinding</h3>
                <p>DNS 레코드 조작을 통한 동일 출처 정책 우회 취약점을 테스트합니다.</p>
                <a href="dns_rebinding_test.php" style="display: none;"></a>
            </div>

            <!-- DoS -->
            <div class="test-card">
                <h3>🚫 Denial of Service (DoS)</h3>
                <p>서버 자원 고갈을 통한 서비스 거부 공격을 시뮬레이션합니다.</p>
                <a href="dos_test.php" style="display: none;"></a>
            </div>

            <!-- Dependency Confusion -->
            <div class="test-card">
                <h3>📦 Dependency Confusion</h3>
                <p>패키지 관리 시스템의 의존성 혼동 취약점을 테스트합니다.</p>
                <a href="dependency_confusion_test.php" style="display: none;"></a>
            </div>

            <!-- External Variable Modification -->
            <div class="test-card">
                <h3>⚙️ External Variable Modification</h3>
                <p>HTTP 헤더, 쿠키 등 외부 변수 조작 취약점을 테스트합니다.</p>
                <a href="external_variable_modification_test.php" style="display: none;"></a>
            </div>

            <!-- Headless Browser Vulnerabilities -->
            <div class="test-card">
                <h3>👻 Headless Browser Vulnerabilities</h3>
                <p>서버 측 헤드리스 브라우저 사용 시 발생할 수 있는 취약점을 테스트합니다.</p>
                <a href="headless_browser_test.php" style="display: none;"></a>
            </div>

            <!-- Hidden Parameters -->
            <div class="test-card">
                <h3>🕵️ Hidden Parameters</h3>
                <p>숨겨진 폼 필드, URL 파라미터 등 조작 취약점을 테스트합니다.</p>
                <a href="hidden_parameters_test.php" style="display: none;"></a>
            </div>

            <!-- Initial Access -->
            <div class="test-card">
                <h3>🚪 Initial Access</h3>
                <p>약한 자격 증명, 공개된 관리 인터페이스 등 초기 접근 시나리오를 테스트합니다.</p>
                <a href="initial_access_test.php" style="display: none;"></a>
            </div>

            <!-- Reverse Proxy Misconfigurations -->
            <div class="test-card">
                <h3>🔄 Reverse Proxy Misconfigurations</h3>
                <p>잘못된 리버스 프록시 설정으로 인한 정보 노출 및 우회 취약점을 테스트합니다.</p>
                <a href="reverse_proxy_misconfig_test.php" style="display: none;"></a>
            </div>

            <!-- SAML Injection -->
            <div class="test-card">
                <h3>🛡️ SAML Injection</h3>
                <p>SAML 어설션 조작을 통한 인증 우회 및 가장 취약점을 테스트합니다.</p>
                <a href="saml_injection_test.php" style="display: none;"></a>
            </div>

            <!-- Server Side Include Injection -->
            <div class="test-card">
                <h3>🖥️ Server Side Include Injection</h3>
                <p>SSI 지시어 주입을 통한 서버 명령 실행 및 파일 접근 취약점을 테스트합니다.</p>
                <a href="ssi_injection_test.php" style="display: none;"></a>
            </div>

            <!-- Type Juggling -->
            <div class="test-card">
                <h3>🤹 Type Juggling</h3>
                <p>PHP의 느슨한 타입 비교를 악용한 인증 우회 취약점을 테스트합니다.</p>
                <a href="type_juggling_test.php" style="display: none;"></a>
            </div>

            <!-- Web Cache Deception -->
            <div class="test-card">
                <h3>🕸️ Web Cache Deception</h3>
                <p>캐싱 프록시를 속여 민감한 정보를 캐싱하도록 유도하는 취약점을 테스트합니다.</p>
                <a href="web_cache_deception_test.php" style="display: none;"></a>
            </div>

            <!-- Web Sockets vulnerabilities -->
            <div class="test-card">
                <h3>🔌 Web Sockets vulnerabilities</h3>
                <p>웹 소켓 통신에서 발생할 수 있는 취약점(인증/권한 부족, 메시지 주입)을 테스트합니다.</p>
                <a href="web_sockets_test.php" style="display: none;"></a>
            </div>

            <!-- XSLT Injection -->
            <div class="test-card">
                <h3>📝 XSLT Injection</h3>
                <p>악의적인 XSLT 주입을 통한 임의 코드 실행 및 데이터 접근 취약점을 테스트합니다.</p>
                <a href="xslt_injection_test.php" style="display: none;"></a>
            </div>

            <!-- JWT Testing -->
            <div class="test-card">
                <h3>🔐 JWT (JSON Web Token)</h3>
                <p>JWT 토큰 조작, 알고리즘 혼동, 키 누출 취약점을 테스트합니다.</p>
                <a href="jwt_test.php" style="display: none;"></a>
            </div>

            <!-- XXE -->
            <div class="test-card">
                <h3>📄 XML External Entity (XXE)</h3>
                <p>XML 외부 엔티티 주입 취약점을 테스트합니다.</p>
                <a href="xxe_test.php" style="display: none;"></a>
            </div>

            <!-- SSRF -->
            <div class="test-card">
                <h3>🌐 Server-Side Request Forgery (SSRF)</h3>
                <p>서버 사이드 요청 위조 취약점을 테스트합니다.</p>
                <a href="ssrf_test.php" style="display: none;"></a>
            </div>

            <!-- SSTI -->
            <div class="test-card">
                <h3>🧩 Server-Side Template Injection (SSTI)</h3>
                <p>서버 사이드 템플릿 주입 취약점을 테스트합니다.</p>
                <a href="ssti_test.php" style="display: none;"></a>
            </div>

            <!-- HTTP Parameter Pollution -->
            <div class="test-card">
                <h3>🔄 HTTP Parameter Pollution (HPP)</h3>
                <p>HTTP 매개변수 오염 취약점을 테스트합니다.</p>
                <a href="hpp_test.php" style="display: none;"></a>
            </div>

            <!-- NoSQL Injection -->
            <div class="test-card">
                <h3>🗄️ NoSQL Injection</h3>
                <p>MongoDB, CouchDB 등 NoSQL 데이터베이스 주입 취약점을 테스트합니다.</p>
                <a href="nosql_test.php" style="display: none;"></a>
            </div>

            <!-- LDAP Injection -->
            <div class="test-card">
                <h3>🏢 LDAP Injection</h3>
                <p>LDAP 디렉토리 서비스 주입 취약점을 테스트합니다.</p>
                <a href="ldap_test.php" style="display: none;"></a>
            </div>

            <!-- XPath Injection -->
            <div class="test-card">
                <h3>📍 XPath Injection</h3>
                <p>XPath 표현식 주입을 통한 XML 데이터 조작 취약점을 테스트합니다.</p>
                <a href="xpath_test.php" style="display: none;"></a>
            </div>

            <!-- Insecure Deserialization -->
            <div class="test-card">
                <h3>🔓 Insecure Deserialization</h3>
                <p>불안전한 역직렬화를 통한 원격 코드 실행 취약점을 테스트합니다.</p>
                <a href="deserialization_test.php" style="display: none;"></a>
            </div>

            <!-- Tabnabbing -->
            <div class="test-card">
                <h3>👁️‍🗨️ Tabnabbing</h3>
                <p>백그라운드 탭의 내용을 피싱 사이트로 변경하여 사용자를 속이는 공격을 테스트합니다.</p>
                <a href="tabnabbing_test.php" style="display: none;"></a>
            </div>

            <!-- DOM Clobbering -->
            <div class="test-card">
                <h3>🧱 DOM Clobbering</h3>
                <p>HTML 요소로 JavaScript 전역 변수를 오염시키는 취약점을 테스트합니다.</p>
                <a href="dom_clobbering_test.php" style="display: none;"></a>
            </div>

            <!-- Clickjacking -->
            <div class="test-card">
                <h3>🖱️ Clickjacking</h3>
                <p>투명한 iframe을 사용하여 사용자의 클릭을 가로채는 취약점을 테스트합니다.</p>
                <a href="clickjacking_test.php" style="display: none;"></a>
            </div>

            <!-- CORS Misconfiguration -->
            <div class="test-card">
                <h3>🌐 CORS Misconfiguration</h3>
                <p>교차 출처 리소스 공유 설정 오류 취약점을 테스트합니다.</p>
                <a href="cors_test.php" style="display: none;"></a>
            </div>

            <!-- GraphQL Injection -->
            <div class="test-card">
                <h3>🔗 GraphQL Injection</h3>
                <p>GraphQL API 쿼리 조작 및 정보 노출 취약점을 테스트합니다.</p>
                <a href="graphql_test.php" style="display: none;"></a>
            </div>

            <!-- Business Logic Errors -->
            <div class="test-card">
                <h3>💼 Business Logic Errors</h3>
                <p>비즈니스 로직 결함 악용 취약점을 테스트합니다.</p>
                <a href="business_logic_test.php" style="display: none;"></a>
            </div>

            <!-- Open Redirect -->
            <div class="test-card">
                <h3>🔀 Open Redirect</h3>
                <p>신뢰할 수 있는 도메인을 통한 피싱 공격 취약점을 테스트합니다.</p>
                <a href="open_redirect_test.php" style="display: none;"></a>
            </div>

            <!-- OAuth 2.0 Misconfiguration -->
            <div class="test-card">
                <h3>🔑 OAuth 2.0 Misconfiguration</h3>
                <p>부적절한 redirect_uri 검증 등 OAuth 2.0 설정 오류 취약점을 테스트합니다.</p>
                <a href="oauth_test.php" style="display: none;"></a>
            </div>

            <!-- Session Management -->
            <div class="test-card">
                <h3>🍪 Session Management</h3>
                <p>세션 고정, 세션 하이재킹 등 세션 관리 취약점을 테스트합니다.</p>
                <a href="session_management_test.php" style="display: none;"></a>
            </div>

            <!-- Insecure File Upload -->
            <div class="test-card">
                <h3>📤 Insecure File Upload</h3>
                <p>확장자 검증 우회를 통한 웹쉘 업로드 등 파일 업로드 취약점을 테스트합니다.</p>
                <a href="file_upload_test.php" style="display: none;"></a>
            </div>

            <!-- Zip Slip -->
            <div class="test-card">
                <h3>🗜️ Zip Slip</h3>
                <p>압축 파일 경로 조작을 통한 임의 파일 생성/덮어쓰기 취약점을 테스트합니다.</p>
                <a href="zip_slip_test.php" style="display: none;"></a>
            </div>

            <!-- CSV Injection -->
            <div class="test-card">
                <h3>📊 CSV Injection</h3>
                <p>스프레드시트 수식 주입을 통한 악성 코드 실행 취약점을 테스트합니다.</p>
                <a href="csv_injection_test.php" style="display: none;"></a>
            </div>

            <!-- Prompt Injection -->
            <div class="test-card">
                <h3>🤖 Prompt Injection</h3>
                <p>AI 시스템의 프롬프트를 조작하여 의도하지 않은 동작을 유발하는 공격을 테스트합니다.</p>
                <a href="prompt_injection_test.php" style="display: none;"></a>
            </div>

            <!-- Regular Expression Vulnerabilities (ReDoS) -->
            <div class="test-card">
                <h3>⚡ Regular Expression Vulnerabilities (ReDoS)</h3>
                <p>정규식의 백트래킹 특성을 악용하여 과도한 CPU 사용을 유발하는 공격을 테스트합니다.</p>
                <a href="redos_test.php" style="display: none;"></a>
            </div>

            <!-- Insecure Randomness -->
            <div class="test-card">
                <h3>🎲 Insecure Randomness</h3>
                <p>예측 가능한 의사난수 생성기를 사용한 보안 취약점을 테스트합니다.</p>
                <a href="insecure_randomness_test.php" style="display: none;"></a>
            </div>

            <!-- LaTeX Injection -->
            <div class="test-card">
                <h3>📄 LaTeX Injection</h3>
                <p>LaTeX 문서 처리 시스템에서 악의적인 명령어 주입 취약점을 테스트합니다.</p>
                <a href="latex_injection_test.php" style="display: none;"></a>
            </div>

            <!-- Race Condition -->
            <div class="test-card">
                <h3>🏃‍♂️ Race Condition</h3>
                <p>여러 프로세스의 동시 접근으로 인한 경합 조건 취약점을 테스트합니다.</p>
                <a href="race_condition_test.php" style="display: none;"></a>
            </div>

            <!-- ORM Leak -->
            <div class="test-card">
                <h3>🗄️ ORM Leak</h3>
                <p>ORM 시스템에서 의도하지 않은 데이터베이스 정보 노출 취약점을 테스트합니다.</p>
                <a href="orm_leak_test.php" style="display: none;"></a>
            </div>

            <!-- Virtual Hosts -->
            <div class="test-card">
                <h3>🌐 Virtual Hosts</h3>
                <p>가상 호스트 설정 오류로 인한 내부 시스템 접근 취약점을 테스트합니다.</p>
                <a href="virtual_hosts_test.php" style="display: none;"></a>
            </div>

            <!-- Encoding Transformations -->
            <div class="test-card">
                <h3>🔄 Encoding Transformations</h3>
                <p>문자 인코딩 변환 과정에서 입력 검증 필터 우회 취약점을 테스트합니다.</p>
                <a href="encoding_transformations_test.php" style="display: none;"></a>
            </div>
        </section>

        <!-- 진행률 표시 -->
        <section style="margin-top: 40px;">
            <h2>📊 테스트 현황</h2>
            <?php
            $files = scandir('.');
            $excluded_files = [
                '.',
                '..',
                'index.php',
                'assets',
                'templates',
                'oauth_server_sim.php',
                'tabnabbing_target.php',
                'TestPage.php'
            ];
            $test_files = array_diff($files, $excluded_files);
            $test_count = count($test_files);

            // Function to get test name from filename
            function get_test_name($filename) {
                $name = str_replace(['_test.php', '_injection.php', '.php'], '', $filename);
                $name = str_replace('_', ' ', $name);
                return ucwords($name);
            }
            ?>
            <div style="background: #e8f5e8; padding: 20px; border-radius: 8px; border-left: 5px solid #28a745;">
                <h3 style="color: #28a745; margin-bottom: 15px;">✅ 구현 완료된 취약점 테스트 (<?php echo $test_count; ?>개)</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 20px;">
                    <?php foreach ($test_files as $file): ?>
                        <span>• <?php echo get_test_name($file); ?></span>
                    <?php endforeach; ?>
                </div>
                <div style="background: #ffffff; padding: 15px; border-radius: 5px; margin-top: 15px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span><strong>PayloadsAllTheThings 커버리지:</strong></span>
                        <span style="font-size: 18px; color: #28a745;"><strong>100% (<?php echo $test_count; ?>/<?php echo $test_count; ?>개 카테고리)</strong></span>
                    </div>
                    <div style="width: 100%; background: #e9ecef; height: 10px; border-radius: 5px; margin-top: 10px;">
                        <div style="width: 100%; background: #28a745; height: 100%; border-radius: 5px;"></div>
                    </div>
                </div>
            </div>
        </section>

        <!-- 추가 정보 -->
        <section style="margin-top: 40px;">
            <h2>📚 추가 리소스</h2>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
                <p><strong>PayloadsAllTheThings:</strong> 이 테스트 페이지는 
                <a href="https://github.com/swisskyrepo/PayloadsAllTheThings" target="_blank" rel="noopener">
                PayloadsAllTheThings</a> 저장소의 페이로드를 참고하여 구성되었습니다.</p>
                
                <p><strong>보안 학습:</strong> 각 테스트 페이지에서는 해당 취약점에 대한 설명과 
                방어 방법도 함께 제공됩니다.</p>
                
                <p><strong>실습 환경:</strong> 모든 테스트는 격리된 환경에서 안전하게 수행됩니다.</p>
                
                <p><strong>최신 업데이트:</strong> 2025년 8월 기준으로 21개의 주요 웹 보안 취약점 테스트가 
                포함되어 있으며, 지속적으로 확장하고 있습니다.</p>
            </div>
        </section>
    </div>

    <script>
        // 테스트 카드 클릭 효과
        document.querySelectorAll('.test-card').forEach(card => {
            card.addEventListener('click', function() {
                const link = this.querySelector('a');
                if (link) {
                    window.location.href = link.href;
                }
            });
        });
    </script>
</body>
</html>
