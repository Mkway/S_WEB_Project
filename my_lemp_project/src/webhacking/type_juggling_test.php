<?php
/**
 * Type Juggling 테스트 페이지
 * PHP의 느슨한 타입 비교(loose type comparison)를 악용하여 인증 우회 등을 시뮬레이션합니다.
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
$input_password = $_POST['password'] ?? '';

// 시뮬레이션: 취약한 비밀번호 비교 로직
$expected_password = '0e123456789'; // 숫자형 문자열로 시작하는 해시 값 (MD5 등)

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'check_password') {
        // === (strict comparison) 대신 == (loose comparison) 사용 시 취약
        if ($input_password == $expected_password) {
            $result = "<span style=\"color: red; font-weight: bold;\">비밀번호 비교 성공!</span><br>";
            $result .= "입력된 값: <code>" . htmlspecialchars($input_password) . "</code><br>";
            $result .= "예상된 값: <code>" . htmlspecialchars($expected_password) . "</code><br>";
            $result .= "PHP의 느슨한 타입 비교(==)로 인해 <code>0e</code>로 시작하는 문자열이 <code>0</code>으로 평가되어 비교가 성공했습니다.";
        } else {
            $error = "비밀번호 비교 실패: 입력된 값이 일치하지 않습니다.";
        }
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
    <title>Type Juggling 테스트 - 보안 테스트</title>
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
            <h1>Type Juggling 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Type Juggling</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🤹 Type Juggling 테스트</h3>
            <p><strong>Type Juggling</strong>은 PHP와 같은 일부 프로그래밍 언어에서 발생하는 취약점으로, 느슨한 타입 비교(loose type comparison, <code>==</code>)를 사용할 때 서로 다른 타입의 값이 예상치 못하게 <code>true</code>로 평가되어 인증 우회 등의 문제가 발생할 수 있습니다.</p>
            <p>특히 <code>0e</code>로 시작하는 문자열이 숫자형으로 변환될 때 <code>0</code>으로 평가되는 특성을 악용할 수 있습니다.</p>
            <p>이 페이지에서는 <code>0e</code> 문자열을 이용한 비밀번호 비교 우회 시나리오를 시뮬레이션합니다.</p>
            <p><strong>예상 비밀번호 (내부):</strong> <code>0e123456789</code></p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 비밀번호 비교 시뮬레이션</h3>
            <p>아래 입력 필드에 <code>0e</code>로 시작하는 문자열을 입력하여 비밀번호 비교를 우회해보세요.</p>
            <label for="password">비밀번호 입력:</label>
            <input type="text" id="password" name="password" value="<?php echo htmlspecialchars($input_password); ?>" placeholder="예: 0e123" required>
            <br><br>
            <button type="submit" name="action" value="check_password" class="btn" style="background: #dc3545;">비밀번호 확인</button>
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
            <h3>🛡️ Type Juggling 방어 방법</h3>
            <ul>
                <li><strong>엄격한 타입 비교 사용:</strong> PHP에서 값을 비교할 때는 항상 <code>===</code> (strict comparison)를 사용하여 값과 타입 모두를 비교합니다.</li>
                <li><strong>입력 값 검증:</strong> 사용자 입력에 대해 예상되는 타입과 형식에 맞는지 철저히 검증합니다.</li>
                <li><strong>해시 함수 사용:</strong> 비밀번호와 같은 민감한 정보는 비교 전에 항상 강력한 해시 함수(예: <code>password_hash()</code>)를 사용하여 해시 값을 비교합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://www.php.net/manual/en/language.types.type-juggling.php" target="_blank">PHP Manual - Type Juggling</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Type_Juggling" target="_blank">OWASP - Type Juggling</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
