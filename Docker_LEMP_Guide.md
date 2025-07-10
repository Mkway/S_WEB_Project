### **Docker와 Docker Compose를 이용한 LEMP 스택 구축 가이드**

이 가이드는 Docker와 Docker Compose를 사용하여 Nginx, PHP, MariaDB(MySQL)로 구성된 웹 개발 환경을 구축하는 방법을 안내합니다. 아래 단계를 따라 프로젝트 디렉토리를 구성하고 파일을 생성하세요.

#### **1. 프로젝트 디렉토리 구조**

먼저, 다음과 같은 구조로 디렉토리와 파일을 생성합니다.

```
my_lemp_project/
├── docker-compose.yml
├── nginx/
│   └── default.conf
└── src/
    └── index.php
```

*   `my_lemp_project/`: 프로젝트의 최상위 디렉토리입니다.
*   `docker-compose.yml`: Docker 서비스들을 정의하고 관리하는 파일입니다.
*   `nginx/default.conf`: Nginx 웹 서버의 설정 파일입니다.
*   `src/index.php`: 실제 웹 애플리케이션 코드가 위치할 디렉토리 및 테스트 파일입니다.

---

#### **2. 파일 내용 작성**

각 파일에 아래 내용을 작성합니다.

**1) `docker-compose.yml`**

이 파일은 `nginx`, `php`, `db` 세 개의 컨테이너를 정의합니다.

```yaml
version: '3.8'

services:
  # Nginx 웹 서버 서비스
  nginx:
    image: nginx:stable-alpine
    container_name: my_nginx
    ports:
      - "8080:80" # 호스트의 8080 포트를 컨테이너의 80 포트로 연결
    volumes:
      - ./src:/var/www/html
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - php

  # PHP-FPM 서비스
  php:
    image: php:8.2-fpm-alpine
    container_name: my_php
    volumes:
      - ./src:/var/www/html
    depends_on:
      - db

  # MariaDB 데이터베이스 서비스
  db:
    image: mariadb:10.6
    container_name: my_db
    restart: always
    environment:
      MYSQL_DATABASE: 'my_database'      # 생성할 데이터베이스 이름
      MYSQL_USER: 'my_user'              # 데이터베이스 사용자
      MYSQL_PASSWORD: 'my_password'      # 사용자 비밀번호
      MYSQL_ROOT_PASSWORD: 'my_root_password' # root 계정 비밀번호
    volumes:
      - db_data:/var/lib/mysql

volumes:
  db_data: # 데이터베이스 데이터를 영구적으로 저장하기 위한 볼륨

```

**2) `nginx/default.conf`**

Nginx가 PHP 요청을 `php` 컨테이너로 전달하도록 설정합니다.

```nginx
server {
    listen 80;
    index index.php index.html;
    server_name localhost;
    root /var/www/html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass php:9000; # 'php'는 docker-compose에 정의된 PHP 서비스 이름
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
    }
}
```

**3) `src/index.php`**

PHP와 데이터베이스 연결이 잘 되었는지 확인하기 위한 테스트 파일입니다.

```php
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
```

---

#### **3. Docker 컨테이너 실행**

모든 파일 작성이 완료되면, `my_lemp_project` 디렉토리에서 아래 명령어를 실행하여 Docker 컨테이너들을 빌드하고 실행합니다.

```bash
# -d 옵션은 컨테이너를 백그라운드에서 실행합니다.
docker-compose up -d
```

#### **4. 확인**

웹 브라우저를 열고 주소창에 `http://localhost:8080` 을 입력합니다. "Hello from LEMP Stack!" 메시지와 함께 데이터베이스 연결 성공 메시지가 보이면 모든 설정이 성공적으로 완료된 것입니다.

#### **5. 종료**

프로젝트를 중단하고 싶을 때는 아래 명령어를 실행하여 컨테이너를 정지하고 삭제합니다.

```bash
# -v 옵션은 docker-compose.yml에 정의된 볼륨(db_data)까지 삭제합니다.
docker-compose down -v
```
