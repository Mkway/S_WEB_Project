<?php
/**
 * Mass Assignment 취약점 테스트 페이지
 */
session_start();
require_once '../db.php';
require_once '../utils.php';

// 로그인 확인
if (!is_logged_in()) {
    header('Location: ../login.php');
    exit();
}

$message = '';
$user_data = [
    'username' => $_SESSION['username'] ?? 'guest',
    'email' => 'user@example.com',
    'is_admin' => false // 이 필드를 조작하는 것이 목표
];

// 사용자 프로필 업데이트 시뮬레이션
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // --- 취약점 발생 지점 ---
    // 사용자 입력 데이터를 검증 없이 모델에 직접 할당
    // (실제 프레임워크에서는 fillable/guarded 속성으로 방어)
    
    // 취약한 로직: 모든 POST 데이터를 $user_data에 병합
    foreach ($_POST as $key => $value) {
        if (array_key_exists($key, $user_data)) {
            $user_data[$key] = $value;
        }
    }

    // 안전한 로직 예시: 허용된 필드만 명시적으로 할당
    /*
    $user_data['username'] = $_POST['username'] ?? $user_data['username'];
    $user_data['email'] = $_POST['email'] ?? $user_data['email'];
    // $user_data['is_admin'] = $_POST['is_admin'] ?? $user_data['is_admin']; // 이 줄은 없어야 함
    */

    $message = "프로필 업데이트 시도됨. 결과 확인:\n";
    $message .= "Username: " . htmlspecialchars($user_data['username']) . "\n";
    $message .= "Email: " . htmlspecialchars($user_data['email']) . "\n";
    $message .= "Is Admin: " . ($user_data['is_admin'] ? 'true' : 'false') . "\n";
    $message .= "\n(실제 DB 업데이트는 시뮬레이션되지 않습니다.)";
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mass Assignment 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container {
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .info-box {
            background-color: #f9f9f9;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .test-form {
            background: #e0f7fa;
            border: 1px solid #b2ebf2;
            padding: 20px;
            border-radius: 8px;
        }
        .test-form input[type="text"], .test-form input[type="email"] {
            width: calc(100% - 22px);
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        .result-box pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
            white-space: pre-wrap;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>Mass Assignment 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 Mass Assignment 취약점</h3>
            <p><strong>설명:</strong> 사용자로부터 입력받은 데이터를 검증 없이 데이터베이스 모델에 대량으로 할당할 때 발생하는 취약점입니다.</p>
            <p>공격자는 사용자가 수정해서는 안 되는 필드(예: <code>is_admin</code>, <code>balance</code>)를 조작하여 권한 상승이나 데이터 변조를 시도할 수 있습니다.</p>
        </div>

        <div class="test-form">
            <h3>🧪 프로필 업데이트 시뮬레이션</h3>
            <p>아래 폼은 사용자 프로필을 업데이트하는 기능을 시뮬레이션합니다. 개발자 도구를 사용하여 숨겨진 필드를 추가하여 <code>is_admin</code> 값을 <code>true</code>로 변경해 보세요.</p>
            <form method="post">
                <label for="username">사용자 이름:</label>
                <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($user_data['username']); ?>" required><br>
                
                <label for="email">이메일:</label>
                <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($user_data['email']); ?>" required><br>
                
                <!-- 공격자는 개발자 도구를 사용하여 아래와 같은 숨겨진 필드를 추가할 수 있습니다. -->
                <!-- <input type="hidden" name="is_admin" value="true"> -->
                
                <button type="submit" class="btn">프로필 업데이트</button>
            </form>
        </div>

        <?php if ($message): ?>
            <div class="result-box">
                <h3>📊 업데이트 결과 (시뮬레이션)</h3>
                <pre><code><?php echo htmlspecialchars($message); ?></code></pre>
            </div>
        <?php endif; ?>

        <div class="payload-section">
            <h3>🎯 공격 시나리오</h3>
            <ol>
                <li>브라우저 개발자 도구(F12)를 엽니다.</li>
                <li>위 폼의 <code>&lt;form&gt;</code> 태그 내부에 다음 숨겨진 필드를 추가합니다.<br>
                    <code>&lt;input type="hidden" name="is_admin" value="true"&gt;</code></li>
                <li>'프로필 업데이트' 버튼을 클릭합니다.</li>
                <li>결과에서 <code>Is Admin: true</code>로 변경되었는지 확인합니다. (실제 DB는 변경되지 않음)</li>
            </ol>
        </div>

        <div class="info-box">
            <h3>🛡️ Mass Assignment 방어 방법</h3>
            <ul>
                <li><strong>화이트리스트(Whitelist) 기반 할당:</strong> 모델에 할당할 수 있는 필드를 명시적으로 지정합니다. (예: Laravel의 <code>$fillable</code> 속성)</li>
                <li><strong>블랙리스트(Blacklist) 기반 할당:</strong> 할당을 금지할 필드를 명시적으로 지정합니다. (화이트리스트가 더 안전)</li>
                <li><strong>사용자 입력 검증:</strong> 모든 사용자 입력에 대해 엄격한 유효성 검증을 수행합니다.</li>
                <li><strong>민감한 필드 분리:</strong> <code>is_admin</code>과 같은 민감한 필드는 별도의 로직으로 처리하고, 사용자 입력으로 직접 변경되지 않도록 합니다.</li>
            </ul>
        </div>
    </div>
</body>
</html>
