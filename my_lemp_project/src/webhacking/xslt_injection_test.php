<?php
/**
 * XSLT Injection 테스트 페이지
 * 공격자가 악의적인 XSLT (Extensible Stylesheet Language Transformations)를 주입하여
 * 임의 코드 실행 또는 민감한 데이터 접근을 시뮬레이션합니다.
 */

session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$result = '';
$error = '';
$xml_input = $_POST['xml_input'] ?? '';
$xslt_input = $_POST['xslt_input'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_xslt_injection') {
        // XSLT Injection 공격 시뮬레이션
        // 실제 환경에서는 PHP의 XSLTProcessor 등을 사용하여 XML과 XSLT를 처리합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "XSLT Injection 시뮬레이션이 시작되었습니다.<br>";
        $result .= "제출된 XML: <code>" . htmlspecialchars($xml_input) . "</code><br>";
        $result .= "제출된 XSLT: <code>" . htmlspecialchars($xslt_input) . "</code><br>";
        $result .= "<br>만약 애플리케이션이 사용자 입력으로 받은 XSLT를 검증 없이 XML 문서에 적용한다면, 공격자는 다음과 같은 공격을 수행할 수 있습니다:";
        $result .= "<ul>";
        $result .= "<li>임의 파일 읽기: <code>&lt;xsl:value-of select=\"document('file:///etc/passwd')\"/&gt;</code></li>";
        $result .= "<li>임의 코드 실행: XSLT 프로세서의 확장 함수를 통해 시스템 명령 실행 (PHP의 <code>php:function</code> 등)</li>";
        $result .= "<li>SSRF: <code>document('http://internal-service/admin')</code></li>";
        $result .= "</ul>";
        $result .= "<br><strong>참고:</strong> 이 시뮬레이션은 실제 XSLT 변환을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
    } else {
        $error = "알 수 없는 요청입니다.";
    }
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSLT Injection 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .payload-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .test-form {
            background: white;
            border: 2px solid #dc3545;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .result-box {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #155724;
        }
        .error-box {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #721c24;
        }
        .info-box {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #0c5460;
        }
        code {
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: monospace;
        }
        textarea {
            width: 100%;
            min-height: 100px;
            font-family: monospace;
            border: 1px solid #ced4da;
            border-radius: 4px;
            padding: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>XSLT Injection 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>XSLT Injection</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>📝 XSLT Injection 테스트</h3>
            <p><strong>XSLT (Extensible Stylesheet Language Transformations) Injection</strong>은 웹 애플리케이션이 사용자 입력으로 받은 XSLT 스타일시트를 XML 문서에 적용할 때 발생하는 취약점입니다.</p>
            <p>공격자는 악의적인 XSLT를 주입하여 임의의 파일을 읽거나, 임의 코드를 실행하거나, SSRF 공격을 수행하는 등 다양한 공격을 수행할 수 있습니다.</p>
            <p>이 페이지에서는 XSLT Injection 공격의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 XSLT Injection 시뮬레이션</h3>
            <p>아래 입력 필드에 XML 문서와 조작된 XSLT를 입력하여 시뮬레이션을 시작하세요.</p>
            <label for="xml_input">XML 문서 (가상):</label>
            <textarea id="xml_input" name="xml_input" placeholder="예: &lt;data&gt;&lt;user&gt;test&lt;/user&gt;&lt;/data&gt;" required><?php echo htmlspecialchars($xml_input); ?></textarea>
            <br>
            <label for="xslt_input">XSLT 스타일시트 (가상):</label>
            <textarea id="xslt_input" name="xslt_input" placeholder="예: &lt;xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"&gt;&lt;xsl:template match=\"//\"&gt;&lt;xsl:value-of select=\"document('file:///etc/passwd')\"/&gt;&lt;/xsl:template&gt;&lt;/xsl:stylesheet&gt;" required><?php echo htmlspecialchars($xslt_input); ?></textarea>
            <br><br>
            <button type="submit" name="action" value="simulate_xslt_injection" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
        </form>

        <!-- 결과 표시 -->
        <?php if ($result): ?>
            <div class="result-box">
                <h3>📊 테스트 결과</h3>
                <?php echo $result; ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error-box">
                <h3>❌ 오류</h3>
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <!-- 방어 방법 -->
        <div class="info-box">
            <h3>🛡️ XSLT Injection 방어 방법</h3>
            <ul>
                <li><strong>사용자 입력 검증:</strong> 사용자로부터 XSLT를 직접 받지 않거나, 받는 경우 엄격한 화이트리스트 기반의 검증을 수행합니다.</li>
                <li><strong>외부 엔티티 및 확장 함수 비활성화:</strong> XSLT 프로세서에서 외부 엔티티(<code>document()</code> 함수 등) 및 임의 코드 실행을 허용하는 확장 함수를 비활성화합니다.</li>
                <li><strong>최소 권한 원칙:</strong> XSLT 프로세서가 실행되는 환경의 권한을 최소화하여 공격의 영향을 줄입니다.</li>
                <li><strong>웹 애플리케이션 방화벽 (WAF):</strong> XSLT Injection 패턴을 탐지하고 차단하는 WAF를 사용합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/XSLT_Injection" target="_blank">OWASP - XSLT Injection</a></li>
                <li><a href="https://portswigger.net/web-security/xxe/xslt-injection" target="_blank">PortSwigger - XSLT injection</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
