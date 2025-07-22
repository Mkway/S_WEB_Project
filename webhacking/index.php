<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Web Hacking Test Site</title>
    <link rel="stylesheet" href="../my_lemp_project/src/style.css">
    <style>
        .container { max-width: 800px; }
        h1 { text-align: center; }
        .challenge-list { list-style: none; padding: 0; }
        .challenge-list li {
            background: #f9f9f9;
            border: 1px solid #ddd;
            margin-bottom: 10px;
            padding: 15px;
            border-radius: 5px;
        }
        .challenge-list a {
            text-decoration: none;
            color: #333;
            font-weight: bold;
            font-size: 1.2em;
        }
        .challenge-list .description {
            margin-top: 5px;
            color: #666;
        }
        .challenge-list .status {
            font-style: italic;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Web Hacking Challenges</h1>
        <ul class="challenge-list">
            <li>
                <a href="sqli.php">1. SQL Injection</a>
                <p class="description">사용자 이름으로 정보를 검색하는 페이지에서 발생하는 SQL Injection 취약점을 테스트합니다.</p>
            </li>
            <li>
                <a href="xss.php">2. XSS (Cross-Site Scripting)</a>
                <p class="description">게시판이나 댓글에서 스크립트가 필터링 없이 실행되는 취약점을 테스트합니다.</p>
            </li>
            <li>
                <a href="csrf.php">3. CSRF (Cross-Site Request Forgery)</a>
                <p class="description">사용자 정보 변경 시 CSRF 토큰이 없어 발생하는 취약점을 테스트합니다.</p>
            </li>
            <li>
                <a href="file_upload.php">4. File Upload Vulnerability</a>
                <p class="description">악의적인 스크립트 파일(웹쉘)이 업로드되는 취약점을 테스트합니다.</p>
            </li>
            <li>
                <a href="auth_bypass.php">5. Authentication Bypass</a>
                <p class="description">특정 HTTP 헤더나 쿠키 값만으로 관리자 권한을 우회할 수 있는 취약점을 테스트합니다.</p>
            </li>
            <li>
                <a href="directory_traversal.php">6. Directory Traversal</a>
                <p class="description">파일 경로 조작을 통해 웹 루트 외부의 파일에 접근하는 취약점을 테스트합니다.</p>
            </li>
        </ul>
    </div>
</body>
</html>
