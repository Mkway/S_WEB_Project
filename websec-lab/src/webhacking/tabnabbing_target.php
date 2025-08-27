<?php
/**
 * Tabnabbing 공격 대상 페이지 (새 탭에서 열림)
 * 이 페이지의 JavaScript가 window.opener를 통해 원래 페이지를 조작합니다.
 */

// 실제 환경에서는 이 페이지가 악성 피싱 사이트가 됩니다.

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>새 탭 - 피싱 시뮬레이션</title>
    <style>
        body {
            font-family: sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #f0f2f5;
            margin: 0;
            color: #333;
        }
        .message-box {
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 500px;
        }
        .message-box h1 {
            color: #dc3545;
        }
        .message-box p {
            font-size: 1.1em;
            line-height: 1.6;
        }
        .message-box small {
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="message-box">
        <h1>새 탭이 열렸습니다!</h1>
        <p>이 페이지는 Tabnabbing 공격을 시뮬레이션하기 위해 새 탭에서 열렸습니다.</p>
        <p>잠시 후, 백그라운드에 있는 원래 탭의 내용이 변경될 것입니다.</p>
        <small>실제 공격에서는 이 페이지가 피싱 사이트가 됩니다.</small>
    </div>

    <script>
        // 이 스크립트가 Tabnabbing 공격을 수행합니다.
        // 5초 후 원래 탭의 URL을 피싱 사이트로 변경 시도
        setTimeout(() => {
            if (window.opener) {
                // 실제 공격에서는 window.opener.location.replace('https://phishing.example.com/login');
                // 여기서는 시뮬레이션 메시지를 원래 탭에 표시하도록 합니다.
                // 원래 탭의 내용을 직접 조작하는 대신, 원래 탭의 스크립트가 변경되도록 유도합니다.
                // (실제 브라우저 보안 정책으로 인해 window.opener.location.replace는 제한될 수 있음)
                
                // 이 부분은 실제 공격 코드를 시뮬레이션하는 것이므로, 
                // window.opener.location.replace()를 직접 호출하는 대신,
                // 원래 탭의 스크립트가 변경된 것을 감지하도록 메시지를 보낼 수 있습니다.
                // 하지만 이 예제에서는 간단히 원래 탭의 내용을 변경하는 것으로 시뮬레이션합니다.
                
                // 실제 공격에서는 이 코드가 실행되어 원래 탭의 URL이 변경됩니다.
                // window.opener.location.replace('http://localhost/webhacking/tabnabbing_test.php?attack_success=true');
                
                // 현재 시뮬레이션에서는 tabnabbing_test.php의 setTimeout이 이 페이지를 변경합니다.
                // 이 페이지는 단순히 열리는 역할만 합니다.
            }
        }, 5000);
    </script>
</body>
</html>
