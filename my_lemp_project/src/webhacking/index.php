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
        }
        
        .test-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
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
        
        .test-card .btn {
            width: 100%;
            background: #dc3545;
            color: white;
            text-decoration: none;
            padding: 10px;
            border-radius: 4px;
            display: inline-block;
            text-align: center;
            transition: background 0.3s ease;
        }
        
        .test-card .btn:hover {
            background: #c82333;
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

        <!-- 테스트 카테고리 -->
        <section class="security-tests">
            <!-- SQL Injection -->
            <div class="test-card">
                <h3>🗃️ SQL Injection</h3>
                <p>UNION, Boolean-based, Time-based, Error-based SQL Injection 페이로드를 테스트합니다.</p>
                <a href="sql_injection.php" class="btn">테스트 시작</a>
            </div>

            <!-- XSS -->
            <div class="test-card">
                <h3>🚨 Cross-Site Scripting (XSS)</h3>
                <p>Reflected, Stored, DOM-based XSS 취약점을 테스트합니다.</p>
                <a href="xss_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- Command Injection -->
            <div class="test-card">
                <h3>💻 Command Injection</h3>
                <p>운영체제 명령어 주입 취약점을 테스트합니다.</p>
                <a href="command_injection.php" class="btn">테스트 시작</a>
            </div>

            <!-- File Inclusion -->
            <div class="test-card">
                <h3>📁 File Inclusion (LFI/RFI)</h3>
                <p>Local File Inclusion과 Remote File Inclusion 취약점을 테스트합니다.</p>
                <a href="file_inclusion.php" class="btn">테스트 시작</a>
            </div>

            <!-- Directory Traversal -->
            <div class="test-card">
                <h3>📂 Directory Traversal</h3>
                <p>디렉토리 순회 공격을 통한 파일 접근 테스트를 수행합니다.</p>
                <a href="directory_traversal.php" class="btn">테스트 시작</a>
            </div>

            <!-- CSRF -->
            <div class="test-card">
                <h3>🔄 Cross-Site Request Forgery (CSRF)</h3>
                <p>CSRF 공격 시뮬레이션과 토큰 우회 기법을 테스트합니다.</p>
                <a href="csrf_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- IDOR -->
            <div class="test-card">
                <h3>🔑 Insecure Direct Object References (IDOR)</h3>
                <p>직접 객체 참조 취약점을 테스트합니다.</p>
                <a href="idor_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- Authentication Bypass -->
            <div class="test-card">
                <h3>🔓 Authentication Bypass</h3>
                <p>인증 우회 기법과 세션 관리 취약점을 테스트합니다.</p>
                <a href="auth_bypass.php" class="btn">테스트 시작</a>
            </div>

            <!-- JWT Testing -->
            <div class="test-card">
                <h3>🔐 JWT (JSON Web Token)</h3>
                <p>JWT 토큰 조작, 알고리즘 혼동, 키 누출 취약점을 테스트합니다.</p>
                <a href="jwt_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- XXE -->
            <div class="test-card">
                <h3>📄 XML External Entity (XXE)</h3>
                <p>XML 외부 엔티티 주입 취약점을 테스트합니다.</p>
                <a href="xxe_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- SSRF -->
            <div class="test-card">
                <h3>🌐 Server-Side Request Forgery (SSRF)</h3>
                <p>서버 사이드 요청 위조 취약점을 테스트합니다.</p>
                <a href="ssrf_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- SSTI -->
            <div class="test-card">
                <h3>🧩 Server-Side Template Injection (SSTI)</h3>
                <p>서버 사이드 템플릿 주입 취약점을 테스트합니다.</p>
                <a href="ssti_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- HTTP Parameter Pollution -->
            <div class="test-card">
                <h3>🔄 HTTP Parameter Pollution (HPP)</h3>
                <p>HTTP 매개변수 오염 취약점을 테스트합니다.</p>
                <a href="hpp_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- NoSQL Injection -->
            <div class="test-card">
                <h3>🗄️ NoSQL Injection</h3>
                <p>MongoDB, CouchDB 등 NoSQL 데이터베이스 주입 취약점을 테스트합니다.</p>
                <a href="nosql_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- LDAP Injection -->
            <div class="test-card">
                <h3>🏢 LDAP Injection</h3>
                <p>LDAP 디렉토리 서비스 주입 취약점을 테스트합니다.</p>
                <a href="ldap_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- XPath Injection -->
            <div class="test-card">
                <h3>📍 XPath Injection</h3>
                <p>XPath 표현식 주입을 통한 XML 데이터 조작 취약점을 테스트합니다.</p>
                <a href="xpath_test.php" class="btn">테스트 시작</a>
            </div>

            <!-- Insecure Deserialization -->
            <div class="test-card">
                <h3>🔓 Insecure Deserialization</h3>
                <p>불안전한 역직렬화를 통한 원격 코드 실행 취약점을 테스트합니다.</p>
                <a href="deserialization_test.php" class="btn">테스트 시작</a>
            </div>
        </section>

        <!-- 진행률 표시 -->
        <section style="margin-top: 40px;">
            <h2>📊 테스트 현황</h2>
            <div style="background: #e8f5e8; padding: 20px; border-radius: 8px; border-left: 5px solid #28a745;">
                <h3 style="color: #28a745; margin-bottom: 15px;">✅ 구현 완료된 취약점 테스트 (17개)</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 20px;">
                    <span>• SQL Injection</span>
                    <span>• XSS (Cross-Site Scripting)</span>
                    <span>• Command Injection</span>
                    <span>• File Inclusion (LFI/RFI)</span>
                    <span>• Directory Traversal</span>
                    <span>• CSRF</span>
                    <span>• IDOR</span>
                    <span>• Authentication Bypass</span>
                    <span>• JWT (JSON Web Token)</span>
                    <span>• XXE (XML External Entity)</span>
                    <span>• SSRF (Server-Side Request Forgery)</span>
                    <span>• SSTI (Server-Side Template Injection)</span>
                    <span>• HPP (HTTP Parameter Pollution)</span>
                    <span>• NoSQL Injection</span>
                    <span>• LDAP Injection</span>
                    <span>• XPath Injection</span>
                    <span>• Insecure Deserialization</span>
                </div>
                <div style="background: #ffffff; padding: 15px; border-radius: 5px; margin-top: 15px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span><strong>PayloadsAllTheThings 커버리지:</strong></span>
                        <span style="font-size: 18px; color: #28a745;"><strong>~30% (17/57개 카테고리)</strong></span>
                    </div>
                    <div style="width: 100%; background: #e9ecef; height: 10px; border-radius: 5px; margin-top: 10px;">
                        <div style="width: 30%; background: #28a745; height: 100%; border-radius: 5px;"></div>
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
                
                <p><strong>최신 업데이트:</strong> 2025년 8월 기준으로 17개의 주요 웹 보안 취약점 테스트가 
                포함되어 있으며, 지속적으로 확장하고 있습니다.</p>
            </div>
        </section>
    </div>

    <script>
        // 테스트 카드 클릭 효과
        document.querySelectorAll('.test-card').forEach(card => {
            card.addEventListener('click', function(e) {
                if (e.target.tagName !== 'A') {
                    const link = this.querySelector('.btn');
                    if (link) {
                        window.location.href = link.href;
                    }
                }
            });
        });

        // 경고 메시지 확인
        document.querySelectorAll('.test-card .btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                const confirmed = confirm(
                    '이 테스트는 교육 목적으로만 사용되어야 합니다.\n' +
                    '실제 운영 환경에서는 절대 사용하지 마세요.\n\n' +
                    '계속하시겠습니까?'
                );
                
                if (!confirmed) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>