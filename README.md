# 웹 보안 취약점 학습을 위한 PHP 기반 웹 애플리케이션 (S_WEB_Project)

이 프로젝트는 웹 개발 및 웹 보안의 다양한 측면을 학습하고 실험하기 위해 만들어진 PHP 기반 웹 애플리케이션입니다. 사용자 인증, 게시판, 관리자 기능 등을 포함하고 있으며, Docker를 사용하여 간편하게 로컬 개발 환경을 구축할 수 있습니다.

## ✨ 주요 기능

*   **사용자 인증:** 회원가입, 로그인, 로그아웃 기능
*   **게시판:** 게시글 작성, 조회, 수정, 삭제 (CRUD)
*   **댓글:** 게시글에 대한 댓글 작성 및 삭제 기능
*   **파일 업로드:** 게시글 작성 시 이미지 등 파일 첨부 기능
*   **관리자 페이지:** 사용자 관리 및 게시글 관리 기능
*   **알림:** 새 댓글 등 사용자 활동에 대한 알림 기능

## 🛠️ 기술 스택

*   **Back-end:** PHP 8.2
*   **Web Server:** Nginx
*   **Database:** MariaDB 10.6
*   **Containerization:** Docker, Docker Compose
*   **Testing:** PHPUnit

## 🚀 시작하기

### 1. Docker를 이용한 간편 실행 (권장)

프로젝트를 가장 쉽게 시작하는 방법은 Docker를 사용하는 것입니다. Docker와 Docker Compose가 설치되어 있어야 합니다.

1.  **프로젝트 클론**
    ```bash
    git clone https://github.com/your-username/S_WEB_Project.git
    cd S_WEB_Project/my_lemp_project
    ```

2.  **Docker 컨테이너 실행**
    `my_lemp_project` 디렉토리에서 아래 명령어를 실행하여 웹 서버와 데이터베이스를 실행합니다.
    ```bash
    docker-compose up -d
    ```

3.  **웹 애플리케이션 접속**
    웹 브라우저를 열고 `http://localhost:8080`으로 접속합니다. 초기 설치 화면이 나타나면 안내에 따라 데이터베이스 테이블을 생성하세요.

### 2. 수동 설치

직접 LEMP 스택(Linux, Nginx, MariaDB, PHP)을 구축하려면 아래 가이드를 참고하세요.

*   [LEMP 스택 설치 가이드](./LEMP_setup_guide.md)

## 📂 디렉토리 구조

```
S_WEB_Project/
├── my_lemp_project/
│   ├── docker-compose.yml   # Docker 서비스 정의
│   ├── nginx/               # Nginx 설정
│   │   └── default.conf
│   ├── src/                 # PHP 소스 코드
│   │   ├── index.php        # 메인 페이지
│   │   ├── login.php        # 로그인
│   │   ├── register.php     # 회원가입
│   │   ├── create_post.php  # 글쓰기
│   │   ├── view_post.php    # 글보기
│   │   ├── test/            # PHPUnit 테스트 코드
│   │   └── vendor/          # Composer 패키지
│   └── php.Dockerfile       # PHP Docker 이미지 설정
├── log/                     # 개발 로그
└── ...
```

## ✅ 테스트

이 프로젝트는 PHPUnit을 사용하여 코드의 안정성을 검증합니다. 테스트를 실행하려면 `my_lemp_project` 디렉토리에서 다음 명령어를 실행하세요.

```bash
# Docker 컨테이너 내에서 테스트 실행
docker-compose exec php ./vendor/bin/phpunit --testdox test/
```

## 🤝 기여하기

이 프로젝트는 학습 목적으로 만들어졌지만, 개선을 위한 기여는 언제나 환영합니다. 버그를 발견하거나 새로운 아이디어가 있다면 자유롭게 이슈를 등록하거나 Pull Request를 보내주세요.

## 📝 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.
