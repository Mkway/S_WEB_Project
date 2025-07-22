<?php
require_once '../my_lemp_project/src/db.php'; // 기존 DB 연결 사용

$results = [];
$error = null;
$query_string = "";

if (isset($_GET['username']) && $_GET['username'] !== '') {
    $username = $_GET['username'];

    // !!! 경고: 이 코드는 SQL Injection에 매우 취약합니다. !!!
    // 사용자의 입력을 전혀 검증하지 않고 쿼리에 직접 삽입합니다.
    $query_string = "SELECT id, username, email, created_at FROM users WHERE username = '" . $username . "'";

    try {
        $stmt = $pdo->query($query_string);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $error = "오류가 발생했습니다: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>SQL Injection Test</title>
    <link rel="stylesheet" href="../my_lemp_project/src/style.css">
    <style>
        .container { max-width: 800px; }
        .query-display { 
            background-color: #2d2d2d;
            color: #f1f1f1;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            font-family: monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .result-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .result-table th, .result-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .result-table th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SQL Injection Challenge</h1>
        <p>사용자 이름을 입력하여 정보를 검색하세요. 데이터베이스에 저장된 모든 사용자의 정보를 알아낼 수 있는지 테스트해보세요.</p>
        
        <form action="sqli.php" method="GET">
            <label for="username">사용자 이름:</label>
            <input type="text" id="username" name="username" placeholder="예: admin" required>
            <button type="submit">검색</button>
        </form>

        <?php if ($query_string): ?>
            <h3>실행된 SQL 쿼리:</h3>
            <div class="query-display"><?php echo htmlspecialchars($query_string); ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <p style="color:red; margin-top: 20px;"><?php echo htmlspecialchars($error); ?></p>
        <?php elseif (!empty($results)): ?>
            <h3 style="margin-top: 20px;">검색 결과:</h3>
            <table class="result-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Created At</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($results as $row): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($row['id']); ?></td>
                            <td><?php echo htmlspecialchars($row['username']); ?></td>
                            <td><?php echo htmlspecialchars($row['email']); ?></td>
                            <td><?php echo htmlspecialchars($row['created_at']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php elseif (isset($_GET['username'])): ?>
            <p style="margin-top: 20px;">검색 결과가 없습니다.</p>
        <?php endif; ?>

        <hr style="margin-top: 30px;">

        <div>
            <h3>테스트 아이디어</h3>
            <ul>
                <li>모든 사용자의 정보를 보려면 어떻게 입력해야 할까요? (Hint: `' OR '1'='1`)</li>
                <li>주석을 사용하여 쿼리의 뒷부분을 무시할 수 있을까요? (Hint: `--` 또는 `#`)</li>
                <li>`UNION` 구문을 사용하여 다른 테이블의 정보를 가져올 수 있을까요?</li>
            </ul>
        </div>
        <a href="index.php" style="display: block; margin-top: 20px;"> &laquo; 뒤로 가기</a>
    </div>
</body>
</html>
