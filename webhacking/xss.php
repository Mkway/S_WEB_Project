<?php
session_start(); // 페이지를 새로고침해도 방명록 내용이 유지되도록 세션 사용

// 방명록 데이터 초기화
if (!isset($_SESSION['guestbook'])) {
    $_SESSION['guestbook'] = [];
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $message = $_POST['message'];

    if (!empty($name) && !empty($message)) {
        $_SESSION['guestbook'][] = ['name' => $name, 'message' => $message, 'time' => date('Y-m-d H:i:s')];
    } else {
        $error = "이름과 메시지를 모두 입력해주세요.";
    }
}

// 방명록 초기화 기능
if (isset($_GET['action']) && $_GET['action'] === 'reset') {
    $_SESSION['guestbook'] = [];
    header('Location: xss.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>XSS Test</title>
    <link rel="stylesheet" href="../style.css">
    <style>
        .container { max-width: 800px; }
        .guestbook-entry {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
            background: #f9f9f9;
        }
        .guestbook-entry .meta {
            font-size: 0.9em;
            color: #666;
        }
        .guestbook-entry .message {
            margin-top: 10px;
        }
        /* 경고: 이 부분에서 사용자의 입력이 필터링 없이 그대로 출력됩니다. */
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS (Cross-Site Scripting) Challenge</h1>
        <p>방명록에 글을 남겨보세요. 메시지에 HTML 태그나 JavaScript 코드를 포함하여 다른 사용자에게 경고창(alert)을 띄울 수 있는지 테스트해보세요.</p>

        <form action="xss.php" method="POST">
            <label for="name">이름:</label>
            <input type="text" id="name" name="name" required>
            <label for="message">메시지:</label>
            <textarea id="message" name="message" rows="4" required></textarea>
            <button type="submit">글 남기기</button>
        </form>

        <?php if ($error): ?>
            <p style="color:red;"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>

        <h3 style="margin-top: 30px;">방명록</h3>
        <div id="guestbook-entries">
            <?php if (empty($_SESSION['guestbook'])): ?>
                <p>아직 등록된 글이 없습니다.</p>
            <?php else: ?>
                <?php foreach (array_reverse($_SESSION['guestbook']) as $entry): ?>
                    <div class="guestbook-entry">
                        <div class="meta">
                            <strong><?php echo htmlspecialchars($entry['name']); ?></strong>
                            (<?php echo $entry['time']; ?>)
                        </div>
                        <div class="message">
                            <?php 
                                // !!! 경고: 이 부분에서 XSS 취약점이 발생합니다. !!!
                                // htmlspecialchars() 함수를 사용하지 않아 스크립트가 그대로 출력됩니다.
                                echo $entry['message']; 
                            ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
        
        <hr style="margin-top: 30px;">

        <div>
            <h3>테스트 아이디어</h3>
            <ul>
                <li>간단한 스크립트 실행: `&lt;script&gt;alert('XSS');&lt;/script&gt;`</li>
                <li>이미지 태그를 이용한 스크립트 실행: `&lt;img src=x onerror="alert('XSS')"&gt;`</li>
                <li>다른 사람의 쿠키 정보를 훔쳐보는 스크립트를 작성할 수 있을까요?</li>
            </ul>
            <a href="xss.php?action=reset" style="font-size: 0.9em;">방명록 초기화</a>
        </div>
        <a href="index.php" style="display: block; margin-top: 20px;"> &laquo; 뒤로 가기</a>
    </div>
</body>
</html>
