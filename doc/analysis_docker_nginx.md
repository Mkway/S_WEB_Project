# docker-compose.yml 파일 분석

`docker-compose.yml` 파일은 여러 개의 Docker 컨테이너를 정의하고 실행하기 위한 설정 파일입니다. 이 파일을 통해 Nginx, PHP, MariaDB 서비스를 한 번에 관리할 수 있습니다.

```yaml
# Docker Compose 파일 형식의 버전을 지정합니다. '''3.3'''은 특정 기능 세트를 지원합니다.
version: '''3.3'''

# 서비스(컨테이너)들의 집합을 정의합니다.
services:
  # Nginx 웹 서버 서비스 정의
  nginx:
    # '''nginx:stable-alpine''' 이미지를 사용하여 컨테이너를 생성합니다.
    # '''stable-alpine'''은 안정적이고 가벼운 버전의 Nginx입니다.
    image: nginx:stable-alpine
    # 컨테이너의 이름을 '''my_nginx'''로 지정합니다.
    container_name: my_nginx
    # 호스트와 컨테이너 간의 포트를 매핑합니다.
    ports:
      - "80:80"      # 호스트의 80번 포트를 컨테이너의 80번 포트(HTTP)에 연결합니다.
      - "443:443"    # 호스트의 443번 포트를 컨테이너의 443번 포트(HTTPS)에 연결합니다.
    # 볼륨을 마운트하여 호스트의 파일/디렉토리를 컨테이너 내부에서 사용할 수 있게 합니다.
    volumes:
      # 현재 docker-compose.yml이 위치한 디렉토리의 부모 디렉토리(S_WEB_Project)를
      # 컨테이너 내부의 /app 디렉토리에 마운트합니다.
      - ../:/app
      # 호스트의 '''./nginx/default.conf''' 파일을 컨테이너의 '''/etc/nginx/conf.d/default.conf'''에 마운트합니다.
      # 이를 통해 Nginx 설정을 관리합니다.
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf
      # 호스트의 '''./nginx/ssl''' 디렉토리를 컨테이너의 '''/etc/nginx/ssl'''에 마운트합니다.
      # SSL 인증서와 키를 저장하기 위함입니다.
      - ./nginx/ssl:/etc/nginx/ssl
    # 이 서비스가 의존하는 다른 서비스를 지정합니다.
    depends_on:
      - php # '''php''' 서비스가 시작된 후에 '''nginx''' 서비스가 시작됩니다.

  # PHP-FPM 서비스 정의
  php:
    # 이미지를 직접 빌드하여 사용합니다.
    # php.Dockerfile은 멀티스테이지 빌드를 사용하여 최종 이미지 크기를 최적화합니다.
    build:
      # 빌드 컨텍스트(빌드에 필요한 파일들이 있는 위치)를 현재 디렉토리로 지정합니다.
      context: .
      # 사용할 Dockerfile의 이름을 '''php.Dockerfile'''로 지정합니다.
      dockerfile: php.Dockerfile
    # 컨테이너의 이름을 '''my_php'''로 지정합니다.
    container_name: my_php
    # 컨테이너 내에서 사용할 환경 변수를 설정합니다.
    environment:
      MYSQL_DATABASE: '''my_database''' # PHP 애플리케이션이 연결할 DB 이름
      MYSQL_USER: '''my_user'''         # DB 사용자 이름
      MYSQL_PASSWORD: '''my_password''' # DB 사용자 비밀번호
    # 볼륨을 마운트합니다.
    volumes:
      # 호스트의 '''./src''' 디렉토리(PHP 소스 코드)를 컨테이너의 '''/var/www/html'''에 마운트합니다.
      - ./src:/var/www/html
      # '''uploads_data'''라는 이름의 볼륨을 컨테이너의 '''/var/www/html/uploads'''에 마운트합니다.
      # 파일 업로드를 영구적으로 저장하기 위함입니다.
      - uploads_data:/var/www/html/uploads
    # '''db''' 서비스가 시작된 후에 '''php''' 서비스가 시작됩니다.
    depends_on:
      - db

  # MariaDB 데이터베이스 서비스 정의
  db:
    # '''mariadb:10.6''' 이미지를 사용하여 컨테이너를 생성합니다.
    image: mariadb:10.6
    # 컨테이너의 이름을 '''my_db'''로 지정합니다.
    container_name: my_db
    # 컨테이너가 중지될 경우 항상 다시 시작하도록 설정합니다.
    restart: always
    # 데이터베이스 설정을 위한 환경 변수입니다.
    environment:
      MYSQL_DATABASE: '''my_database'''      # 생성할 데이터베이스의 이름
      MYSQL_USER: '''my_user'''              # 생성할 데이터베이스 사용자의 이름
      MYSQL_PASSWORD: '''my_password'''      # 사용자의 비밀번호
      MYSQL_ROOT_PASSWORD: '''my_root_password''' # root 계정의 비밀번호
    # 볼륨을 마운트합니다.
    volumes:
      # '''db_data'''라는 이름의 볼륨을 컨테이너의 '''/var/lib/mysql'''에 마운트합니다.
      # 데이터베이스 파일을 영구적으로 저장하여 컨테이너가 삭제되어도 데이터가 보존되게 합니다.
      - db_data:/var/lib/mysql
    # 컨테이너의 상태를 확인하는 방법을 정의합니다.
    healthcheck:
      # '''mysqladmin ping''' 명령어를 사용하여 DB가 응답하는지 확인합니다.
      test: ["CMD", "mysqladmin" ,"ping", "-h", "localhost"]
      # 타임아웃 시간을 20초로 설정합니다.
      timeout: 20s
      # 실패 시 10번 재시도합니다.
      retries: 10

# 서비스들 간에 공유하고 데이터를 영구적으로 저장하기 위한 볼륨을 정의합니다.
volumes:
  db_data: # '''db''' 서비스가 사용할 볼륨
  uploads_data: # '''php''' 서비스가 파일 업로드를 위해 사용할 볼륨
```

# nginx/default.conf 파일 분석

이 파일은 Nginx 웹 서버의 동작을 정의하는 기본 설정 파일입니다. HTTP(80)와 HTTPS(443) 두 개의 서버 블록으로 구성되어 있습니다.

## HTTP 서버 블록 (Port 80)

```nginx
# '''server''' 블록은 하나의 가상 서버에 대한 설정을 정의합니다.
server {
    # 80번 포트에서 들어오는 HTTP 요청을 수신합니다.
    listen 80;
    # 이 서버가 처리할 도메인 이름을 지정합니다. '''localhost'''로 오는 요청을 처리합니다.
    server_name localhost;
    # 웹 서버의 루트 디렉토리를 지정합니다.
    # docker-compose.yml에서 마운트한 '''/app''' 내의 '''my_lemp_project/src''' 디렉토리입니다.
    root /app/my_lemp_project/src;

    # 디렉토리 요청 시 기본으로 보여줄 파일의 순서를 지정합니다.
    # index.php가 있으면 그것을, 없으면 index.html을 보여줍니다.
    index index.php index.html;

    # 특정 URL 경로에 대한 처리를 정의하는 '''location''' 블록입니다.
    # '''/'''는 모든 요청에 대한 기본 처리입니다.
    location / {
        # 요청된 URI($uri)에 해당하는 파일이나 디렉토리($uri/)가 있는지 확인합니다.
        # 만약 없다면, 요청을 /index.php로 전달하여 PHP가 처리하도록 합니다.
        # $query_string은 원래 요청의 쿼리 파라미터를 그대로 넘겨줍니다.
        try_files $uri $uri/ /index.php?$query_string;
    }

    # '''/webhacking/'''으로 시작하는 경로의 요청을 처리합니다.
    location /webhacking/ {
        # 이 경로의 요청은 파일 시스템의 다른 경로에 매핑됩니다.
        # '''/app/webhacking/''' 디렉토리의 파일을 찾습니다.
        alias /app/webhacking/;
        # 요청된 파일이나 디렉토리가 있는지 확인하고, 없으면 404 에러를 반환합니다.
        try_files $uri $uri/ =404;
        # 이 경로의 인덱스 파일은 '''index.php''' 입니다.
        index index.php;
    }

    # 정규 표현식을 사용하여 '''.php'''로 끝나는 모든 요청을 처리합니다.
    location ~ \.php$ {
        # 요청된 PHP 파일이 없으면 404 에러를 반환합니다.
        try_files $uri =404;
        # 요청 경로를 스크립트 파일 이름과 경로 정보로 분리합니다.
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        # 요청을 PHP-FPM 서비스로 전달합니다.
        # '''php:9000'''은 docker-compose.yml에 정의된 '''php''' 서비스의 9000번 포트를 의미합니다.
        fastcgi_pass php:9000;
        # FastCGI의 인덱스 파일을 지정합니다.
        fastcgi_index index.php;
        # 표준 FastCGI 파라미터 설정을 포함합니다.
        include fastcgi_params;
        # PHP가 실행할 스크립트의 전체 경로를 설정합니다.
        # PHP 컨테이너의 웹 루트인 '''/var/www/html'''를 기준으로 경로를 만듭니다.
        fastcgi_param SCRIPT_FILENAME /var/www/html$fastcgi_script_name;
        # PATH_INFO 환경 변수를 설정합니다.
        fastcgi_param PATH_INFO $fastcgi_path_info;
    }
}
```

## HTTPS 서버 블록 (Port 443)

이 블록은 HTTP 블록과 거의 동일하지만, SSL/TLS 암호화를 사용하여 HTTPS 통신을 처리하는 점이 다릅니다.

```nginx
# 443번 포트에서 SSL을 사용하여 들어오는 HTTPS 요청을 수신합니다.
server {
    listen 443 ssl;
    server_name localhost;
    root /app/my_lemp_project/src;

    # SSL 인증서 파일의 경로를 지정합니다.
    ssl_certificate /etc/nginx/ssl/nginx.crt;
    # SSL 개인 키 파일의 경로를 지정합니다.
    ssl_certificate_key /etc/nginx/ssl/nginx.key;

    # 사용할 SSL/TLS 프로토콜 버전을 지정합니다. (TLS 1.2와 1.3)
    ssl_protocols TLSv1.2 TLSv1.3;
    # 클라이언트보다 서버의 암호화 스위트(cipher suite)를 우선적으로 사용하도록 설정합니다.
    ssl_prefer_server_ciphers on;
    # 사용할 암호화 스위트 목록을 지정합니다. 보안 강도가 높은 최신 스위트들입니다.
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256;

    # --- 이하 설정은 HTTP 블록과 동일합니다 ---
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location /webhacking/ {
        alias /app/webhacking/;
        try_files $uri $uri/ =404;
        index index.php;
    }

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/html$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
    }
}
```
