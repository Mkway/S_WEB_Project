<?php
/**
 * Hidden Parameters 테스트 페이지
 * 공격자가 숨겨진 매개변수(폼 필드, URL 파라미터, 쿠키 등)를 조작하여 애플리케이션의 동작을 변경하는 취약점을 시뮬레이션합니다.
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
$item_price = 100; // 기본 상품 가격
$is_admin = false; // 기본 관리자 권한

// 시뮬레이션: 숨겨진 폼 필드나 URL 파라미터를 통해 가격 조작
// 실제 환경에서는 서버 측에서 가격을 검증해야 합니다.
if (isset($_POST['price'])) {
    $submitted_price = (int)$_POST['price'];
    if ($submitted_price < $item_price) {
        $result .= "<span style=\"color: red; font-weight: bold;\">가격 조작 시도 감지!</span><br>";
        $result .= "제출된 가격: " . htmlspecialchars($submitted_price) . "원 (원래 가격: " . $item_price . "원)<br>";
        $result .= "만약 서버에서 검증하지 않았다면, 공격자는 더 낮은 가격으로 상품을 구매할 수 있었을 것입니다.";
    } else {
        $result .= "제출된 가격: " . htmlspecialchars($submitted_price) . "원 (정상 처리)<br>";
    }
}

// 시뮬레이션: 숨겨진 폼 필드나 쿠키를 통해 관리자 권한 조작
// 실제 환경에서는 세션이나 DB에서 권한을 가져와야 합니다.
if (isset($_POST['user_type']) && $_POST['user_type'] === 'admin') {
    $is_admin = true;
    $result .= "<br><span style=\"color: red; font-weight: bold;\">관리자 권한 획득 시도 감지!</span><br>";
    $result .= "만약 서버에서 검증하지 않았다면, 공격자는 관리자 페이지에 접근할 수 있었을 것입니다.";
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hidden Parameters 테스트 - 보안 테스트</title>
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
        input[type="number"] {
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
            <h1>Hidden Parameters 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <!-- 브레드크럼 -->
        <nav class="breadcrumb">
            <a href="../index.php">홈</a> &gt; 
            <a href="index.php">보안 테스트</a> &gt; 
            <span>Hidden Parameters</span>
        </nav>

        <!-- 설명 -->
        <div class="info-box">
            <h3>🕵️ Hidden Parameters 테스트</h3>
            <p><strong>Hidden Parameters</strong>는 웹 애플리케이션에서 사용자에게 보이지 않지만, 애플리케이션 로직에 영향을 미치는 매개변수(예: 숨겨진 폼 필드, URL 파라미터, 쿠키)를 의미합니다.</p>
            <p>공격자는 이러한 숨겨진 매개변수를 조작하여 가격 변경, 권한 상승, 데이터 변조 등 다양한 공격을 수행할 수 있습니다.</p>
            <p>이 페이지에서는 숨겨진 가격 필드와 사용자 유형 필드를 조작하는 시나리오를 시뮬레이션합니다.</p>
        </div>

        <!-- 테스트 폼 -->
        <form method="post" class="test-form">
            <h3>🧪 숨겨진 매개변수 조작 시뮬레이션</h3>
            <p>아래는 상품 구매 폼을 시뮬레이션합니다. 개발자 도구(F12)를 열어 숨겨진 <code>price</code> 필드와 <code>user_type</code> 필드를 찾아 값을 조작해보세요.</p>
            <p><strong>원래 상품 가격:</strong> <code><?php echo $item_price; ?></code>원</p>
            <p><strong>현재 사용자 유형:</strong> <code><?php echo $is_admin ? 'admin' : 'guest'; ?></code></p>
            
            <!-- 숨겨진 필드 (공격자가 조작할 수 있는 대상) -->
            <input type="hidden" name="price" value="<?php echo $item_price; ?>">
            <input type="hidden" name="user_type" value="guest">

            <br>
            <button type="submit" name="action" value="check_role" class="btn" style="background: #dc3545;">구매 시도 / 역할 확인</button>
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
            <h3>🛡️ Hidden Parameters 방어 방법</h3>
            <ul>
                <li><strong>서버 측 검증:</strong> 클라이언트 측에서 전송되는 모든 매개변수는 신뢰할 수 없으므로, 서버 측에서 가격, 권한 등 중요한 값들을 반드시 재검증해야 합니다.</li>
                <li><strong>중요 정보는 서버에서 관리:</strong> 가격, 재고, 사용자 권한 등 민감한 정보는 클라이언트 측에 숨겨진 필드로 전송하지 않고, 서버 측 세션이나 데이터베이스에서 관리합니다.</li>
                <li><strong>토큰 사용:</strong> 중요한 폼 제출 시 CSRF 토큰과 유사하게, 일회성 토큰을 사용하여 폼의 무결성을 검증합니다.</li>
                <li><strong>최소 권한 원칙:</strong> 애플리케이션이 외부 변수를 통해 접근할 수 있는 권한을 최소화합니다.</li>
            </ul>
        </div>

        <!-- 참고 자료 -->
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>📚 참고 자료</h3>
            <ul>
                <li><a href="https://owasp.org/www-community/attacks/Mass_Assignment" target="_blank">OWASP - Mass Assignment (관련)</a></li>
                <li><a href="https://portswigger.net/web-security/logic-flaws" target="_blank">PortSwigger - Logic flaws (관련)</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
