### **Nginx, PHP, MySQL(MariaDB) 웹 서버 구축 가이드**

이 가이드는 사용자가 `sudo` 권한을 가지고 있다고 가정합니다. 각 명령어는 터미널에 복사하여 실행할 수 있습니다.

#### **1단계: 필수 패키지 설치**

가장 먼저 웹 서버 운영에 필요한 핵심 소프트웨어들을 설치합니다.

1.  **패키지 목록 업데이트**
    최신 버전의 패키지를 설치하기 위해 로컬 패키지 목록을 업데이트합니다.
    ```bash
    sudo apt-get update
    ```

2.  **Nginx 설치**
    웹 서버 소프트웨어인 Nginx를 설치합니다.
    ```bash
    sudo apt-get install -y nginx
    ```

3.  **MariaDB (MySQL 호환) 설치**
    데이터베이스 서버를 설치합니다. `mariadb-server`는 `mysql-server`를 대체하는 일반적인 패키지입니다.
    ```bash
    sudo apt-get install -y mariadb-server
    ```

4.  **PHP 및 관련 모듈 설치**
    PHP와 Nginx 연동을 위한 `php-fpm`, MySQL 연동을 위한 `php-mysql` 등 필수 모듈들을 설치합니다. (PHP 8.2 버전 기준)
    ```bash
    sudo apt-get install -y php8.2-fpm php8.2-mysql php8.2-cli php8.2-mbstring php8.2-xml php8.2-curl
    ```

#### **2단계: 데이터베이스 초기 설정**

설치된 MariaDB의 보안을 강화하고 `root` 비밀번호를 설정합니다.

1.  **MariaDB 보안 설정 스크립트 실행**
    아래 명령어를 실행하고 화면의 지시에 따라 설정을 진행합니다.
    ```bash
    sudo mariadb-secure-installation
    ```
    *   **Enter current password for root (enter for none):** 처음에는 그냥 **Enter**를 누릅니다.
    *   **Set root password? [Y/n]:** **Y**를 누르고 새 `root` 비밀번호(예: `1234qwer`)를 입력합니다.
    *   **Remove anonymous users? [Y/n]:** **Y**를 누릅니다.
    *   **Disallow root login remotely? [Y/n]:** **Y**를 누릅니다.
    *   **Remove test database and access to it? [Y/n]:** **Y**를 누릅니다.
    *   **Reload privilege tables now? [Y/n]:** **Y**를 누릅니다.

#### **3단계: Nginx 설정**

Nginx가 PHP 요청을 처리할 수 있도록 설정을 변경합니다.

1.  **새로운 Nginx 설정 파일 생성**
    웹사이트를 위한 새로운 Nginx 설정 파일을 생성합니다. `my_project` 부분은 원하시는 이름으로 변경해도 됩니다.
    ```bash
    sudo nano /etc/nginx/sites-available/my_project
    ```

2.  **설정 파일 내용 작성**
    열린 편집기에 아래 내용을 복사하여 붙여넣습니다.
    *   `root`: 웹사이트 파일이 위치할 최상위 디렉토리입니다.
    *   `server_name`: 도메인 주소나 서버의 IP 주소를 입력합니다.
    *   `fastcgi_pass`: 설치한 PHP-FPM의 버전에 맞게 소켓 경로를 지정합니다. (이 예제에서는 `php8.2-fpm.sock`)

    ```nginx
    server {
        listen 80;
        server_name your_domain_or_ip; # 여기에 도메인 또는 IP 주소 입력

        root /var/www/my_project; # 웹 루트 디렉토리
        index index.php index.html index.htm;

        location / {
            try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php8.2-fpm.sock; # PHP-FPM 소켓 경로
        }

        location ~ /\.ht {
            deny all;
        }
    }
    ```
    작성 후 `Ctrl+X`, `Y`, `Enter`를 눌러 저장하고 나옵니다.

3.  **웹 루트 디렉토리 생성 및 권한 설정**
    위 설정 파일에서 `root`로 지정한 디렉토리를 만들고, Nginx가 접근할 수 있도록 권한을 부여합니다.
    ```bash
    sudo mkdir /var/www/my_project
    sudo chown -R www-data:www-data /var/www/my_project
    ```

4.  **새로운 설정을 Nginx에 활성화**
    `sites-available`에 만든 설정 파일을 `sites-enabled`에 링크하여 활성화합니다.
    ```bash
    sudo ln -s /etc/nginx/sites-available/my_project /etc/nginx/sites-enabled/
    ```
    **중요:** 기본 설정과의 충돌을 막기 위해 기본값 링크는 제거하는 것이 좋습니다.
    ```bash
    sudo rm /etc/nginx/sites-enabled/default
    ```

5.  **Nginx 설정 테스트 및 재시작**
    문법에 오류가 없는지 확인하고, Nginx 서비스를 재시작하여 설정을 적용합니다.
    ```bash
    sudo nginx -t
    sudo systemctl reload nginx
    ```

#### **4단계: PHP 연동 테스트**

모든 설정이 올바르게 되었는지 확인하기 위해 간단한 PHP 파일을 만들어 테스트합니다.

1.  **테스트용 PHP 파일 생성**
    웹 루트 디렉토리에 `info.php` 파일을 생성합니다.
    ```bash
    sudo nano /var/www/my_project/info.php
    ```

2.  **PHP 정보 출력 코드 작성**
    열린 편집기에 아래 내용을 입력합니다.
    ```php
    <?php
    phpinfo();
    ?>
    ```
    `Ctrl+X`, `Y`, `Enter`로 저장하고 나옵니다.

3.  **웹 브라우저에서 확인**
    웹 브라우저를 열고 주소창에 `http://your_domain_or_ip/info.php` 를 입력합니다.
    PHP 정보가 상세하게 표시된 페이지가 나타나면 Nginx와 PHP 연동이 성공적으로 완료된 것입니다.

4.  **(중요) 테스트 파일 삭제**
    보안을 위해 확인이 끝난 후에는 반드시 `info.php` 파일을 삭제하세요.
    ```bash
    sudo rm /var/www/my_project/info.php
    ```
