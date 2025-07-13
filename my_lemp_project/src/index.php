<!DOCTYPE html>
<html>
<head>
    <title>LEMP Stack Test</title>
</head>
<body>
    <h1>Hello from LEMP Stack!</h1>

    <h2>PHP Info</h2>
    <?php
        // PHP 정보 출력 (보안을 위해 실제 운영 환경에서는 이 부분을 제거하세요)
        // phpinfo(); 
        echo "<p>PHP version: " . phpversion() . "</p>";
    ?>

    <h2>MySQL (MariaDB) Connection Test</h2>
    <?php
    $host = 'db'; // docker-compose에 정의된 DB 서비스 이름
    $dbname = getenv('MYSQL_DATABASE');
    $user = getenv('MYSQL_USER');
    $pass = getenv('MYSQL_PASSWORD');

    try {
        $dbh = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass);
        echo "<p style='color:green;'>Successfully connected to the database '{$dbname}'!</p>";
    } catch (PDOException $e) {
        echo "<p style='color:red;'>Database connection failed: " . $e->getMessage() . "</p>";
    }
    ?>
</body>
</html>
