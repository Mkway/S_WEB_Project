<?php
/**
 * SAML Injection 테스트 페이지
 * SAML (Security Assertion Markup Language) 어설션을 조작하여 인증을 우회하거나 사용자를 가장하는 공격을 시뮬레이션합니다.
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
$saml_assertion = $_POST['saml_assertion'] ?? '';

// 시뮬레이션: SAML 어설션 파싱 및 검증 (취약한 방식)
// 실제 환경에서는 XML 파싱 및 디지털 서명 검증이 필요합니다.
function parse_saml_assertion($assertion) {
    // 매우 단순화된 파싱 (실제 SAML 파서는 훨씬 복잡합니다)
    if (strpos($assertion, '<saml:NameID') !== false) {
        preg_match('/<saml:NameID[^>]*>(.*?)<\/saml:NameID>/s', $assertion, $matches);
        $username = $matches[1] ?? 'unknown';
    } else {
        $username = 'unknown';
    }

    if (strpos($assertion, '<saml:Attribute Name="Role">') !== false) {
        preg_match('/<saml:Attribute Name="Role">\s*<saml:AttributeValue[^>]*>(.*?)<\/saml:AttributeValue>/s', $assertion, $matches);
        $role = $matches[1] ?? 'user';
    } else {
        $role = 'user';
    }

    return ['username' => $username, 'role' => $role];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_saml_injection') {
        // SAML Injection 공격 시뮬레이션
        // 실제 공격은 SAML 응답을 가로채거나 조작하여 재전송할 때 발생합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $parsed_data = parse_saml_assertion($saml_assertion);
        $simulated_username = $parsed_data['username'];
        $simulated_role = $parsed_data['role'];

        $result = "SAML Injection 시뮬레이션이 실행되었습니다.<br>";
        $result .= "제출된 SAML 어설션에서 추출된 정보:<br>";
        $result .= "사용자 이름: <strong>" . htmlspecialchars($simulated_username) . "</strong><br>";
        $result .= "역할: <strong>" . htmlspecialchars($simulated_role) . "</strong><br>";
        $result .= "<br>만약 애플리케이션이 SAML 어설션의 디지털 서명을 제대로 검증하지 않거나, NameID/Attribute 값을 신뢰한다면, 공격자는 임의의 사용자 계정으로 로그인하거나 권한을 상승시킬 수 있습니다.";
        $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 SAML 인증을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
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
    <title>SAML Injection 테스트 - 보안 테스트</title>
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
            min-height: 150px;
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
            <h1>SAML Injection 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>SAML Injection</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🛡️ SAML Injection 테스트</h3>
            <p><strong>SAML (Security Assertion Markup Language) Injection</strong>은 SAML 기반의 싱글 사인온(SSO) 시스템에서 공격자가 SAML 어설션(Assertion)을 조작하여 인증을 우회하거나, 다른 사용자를 가장하거나, 권한을 상승시키는 취약점입니다.</p>
            <p>이는 SAML 응답의 디지털 서명 검증이 미흡하거나, 어설션 내의 사용자 식별 정보(NameID)나 속성(Attribute)을 제대로 검증하지 않을 때 발생합니다.</p>
            <p>이 페이지에서는 SAML 어설션 조작을 통한 인증 우회 개념을 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 SAML Injection 시뮬레이션</h3>
            <p>아래 입력 필드에 조작된 SAML 어설션을 입력하여 시뮬레이션을 시작하세요.</p>
            <p><strong>예시 페이로드:</strong></p>
            <pre><code>&lt;saml:Assertion ...&gt;
  &lt;saml:Subject&gt;
    &lt;saml:NameID&gt;admin&lt;/saml:NameID&gt;
    ...
  &lt;/saml:Subject&gt;
  &lt;saml:AttributeStatement&gt;
    &lt;saml:Attribute Name="Role"&gt;
      &lt;saml:AttributeValue&gt;admin&lt;/saml:AttributeValue&gt;
    &lt;/saml:Attribute&gt;
  &lt;/saml:AttributeStatement&gt;
  ...
&lt;/saml:Assertion&gt;</code></pre>
            <label for="saml_assertion">조작된 SAML 어설션:</label>
            <textarea id="saml_assertion" name="saml_assertion" required><?php echo htmlspecialchars($saml_assertion); ?></textarea>
            <br><br>
            <button type="submit" name="action" value="simulate_saml_injection" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
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
            <h3>🛡️ SAML Injection 방어 방법</h3>
            <ul>
                <li><strong>디지털 서명 검증:</strong> SAML 응답의 디지털 서명을 항상 철저히 검증하여 어설션의 무결성과 신뢰성을 확인합니다.</li>
                <li><strong>NameID 및 속성 검증:</strong> SAML 어설션 내의 사용자 식별 정보(NameID) 및 속성(Attribute) 값을 신뢰하기 전에 적절히 검증하고, 예상된 형식과 값만 허용합니다.</li>
                <li><strong>재전송 공격 방지:</strong> <code>NotOnOrAfter</code>, <code>IssueInstant</code> 등 시간 관련 속성을 검증하여 오래된 어설션의 재사용을 방지합니다.</li>
                <li><strong>대상 검증:</strong> <code>AudienceRestriction</code>을 통해 SAML 어설션이 올바른 서비스 제공자(SP)를 대상으로 하는지 확인합니다.</li>
                <li><strong>최소 권한 원칙:</strong> SAML 어설션에서 제공되는 권한을 최소화하고, 애플리케이션 내부에서 추가적인 권한 검증을 수행합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/SAML_Injection" target="_blank">OWASP - SAML Injection</a></li>
                <li><a href="https://portswigger.net/web-security/saml" target="_blank">PortSwigger - SAML vulnerabilities</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
