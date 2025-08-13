<?php
/**
 * Dependency Confusion 테스트 페이지
 * 패키지 관리자가 비공개 패키지보다 공개 패키지를 우선시하는 취약점을 시뮬레이션합니다.
 * 이 페이지는 공격의 개념을 설명하며, 실제 공격은 패키지 저장소 제어가 필요합니다.
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
$package_name = $_POST['package_name'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'simulate_confusion') {
        // Dependency Confusion 공격 시뮬레이션
        // 실제 공격은 빌드 시스템이나 개발 환경에서 발생하며, 패키지 저장소 조작이 필요합니다.
        // 여기서는 개념적인 설명을 제공합니다.
        $result = "Dependency Confusion 공격 시뮬레이션이 시작되었습니다.";
        $result .= "<br>공격자는 <code>{$package_name}</code>과 같은 이름의 악성 패키지를 공개 저장소에 업로드합니다.";
        $result .= "<br>개발 환경에서 이 패키지를 설치할 때, 패키지 관리자는 비공개 저장소보다 공개 저장소의 패키지를 우선적으로 선택할 수 있습니다.";
        $result .= "<br>이로 인해 개발 시스템에 악성 코드가 실행될 수 있습니다.";
        $result .= "<br><br><strong>참고:</strong> 이 시뮬레이션은 실제 Dependency Confusion 공격을 수행하지 않습니다. 공격의 원리를 설명하기 위한 것입니다.";
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
    <title>Dependency Confusion 테스트 - 보안 테스트</title>
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
        input[type="text"] {
            width: calc(100% - 22px);
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ced4da;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 네비게이션 -->
        <nav class="nav">
            <h1>Dependency Confusion 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Dependency Confusion</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>📦 Dependency Confusion 테스트</h3>
            <p><strong>Dependency Confusion</strong>은 패키지 관리 시스템(npm, pip, Composer 등)이 비공개(private) 패키지보다 공개(public) 패키지를 우선적으로 선택하는 취약점을 악용하는 공격입니다.</p>
            <p>공격자는 내부에서 사용되는 비공개 패키지와 동일한 이름의 악성 패키지를 공개 저장소에 업로드하여, 개발 시스템에 악성 코드를 주입할 수 있습니다.</p>
            <p>이 페이지에서는 Dependency Confusion 공격의 개념과 원리를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 Dependency Confusion 시뮬레이션</h3>
            <p>아래 입력 필드에 공격자가 사용할 가상의 패키지 이름을 입력하여 시뮬레이션을 시작하세요.</p>
            <label for="package_name">가상의 패키지 이름:</label>
            <input type="text" id="package_name" name="package_name" value="<?php echo htmlspecialchars($package_name); ?>" placeholder="예: internal-lib" required>
            <br><br>
            <button type="submit" name="action" value="simulate_confusion" class="btn" style="background: #dc3545;">시뮬레이션 실행</button>
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
            <h3>🛡️ Dependency Confusion 방어 방법</h3>
            <ul>
                <li><strong>스코프(Scope) 사용:</strong> 비공개 패키지에 스코프(예: <code>@mycompany/package</code>)를 사용하여 공개 패키지와 이름 충돌을 방지합니다.</li>
                <li><strong>내부 저장소 우선 설정:</strong> 패키지 관리자가 항상 내부 저장소를 먼저 확인하도록 설정합니다.</li>
                <li><strong>패키지 서명 및 무결성 검증:</strong> 패키지 설치 시 서명을 확인하고, 해시 값을 통해 무결성을 검증합니다.</li>
                <li><strong>빌드 시스템 보안 강화:</strong> 빌드 환경에서 외부 네트워크 접근을 제한하고, 신뢰할 수 있는 소스에서만 패키지를 다운로드하도록 합니다.</li>
                <li><strong>정기적인 의존성 감사:</strong> 사용 중인 모든 의존성에 대해 정기적으로 보안 감사를 수행합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://snyk.io/blog/what-is-dependency-confusion/" target="_blank">Snyk - What is Dependency Confusion?</a></li>
                <li><a href="https://www.trendmicro.com/en_us/research/21/a/dependency-confusion-supply-chain-attack.html" target="_blank">Trend Micro - Dependency Confusion Supply Chain Attack</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
