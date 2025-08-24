# 🔄 Docker LEMP 환경 구축 가이드

**시작일**: 2025-08-24  
**상태**: IN-PROGRESS  

## 🎯 목표
프로젝트를 쉽게 배포하고 실행할 수 있는 Docker 기반 LEMP 스택 환경 구축

## 📋 현재 구성 확인

### ✅ 이미 구성된 것들
- `docker-compose.yml` - LEMP 스택 정의 완료
- `nginx/default.conf` - Nginx 설정
- `php.Dockerfile` - PHP-FPM 커스텀 이미지
- SSL 자동 생성 스크립트 내장

### 🔍 Docker 환경 분석

#### 1. **서비스 구성**
```yaml
services:
  nginx:    # Nginx 웹서버 (포트 80, 443)
  php:      # PHP-FPM 8.x
  db:       # MariaDB 10.6
  my_node_app: # Node.js 앱 (포트 3000)
```

#### 2. **볼륨 설정**
```yaml
volumes:
  - mysql_data:/var/lib/mysql    # DB 영속성 ✅
  - uploads_data                 # 파일 업로드 ✅  
  - ./src:/var/www/html         # 소스코드 마운트 ✅
```

#### 3. **보안 기능**
- SSL 인증서 자동 생성 ✅
- 환경변수 기반 DB 설정 ✅
- Health Check 구현 ✅

## 🚀 Docker 설치 가이드

### Ubuntu/Debian 환경
```bash
# Docker 설치
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose 설치  
sudo curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### Windows (WSL2)
```bash
# WSL2에서 Docker Desktop 사용 권장
# 또는 Docker CE 직접 설치
sudo apt update
sudo apt install docker.io docker-compose
sudo service docker start
```

## 🏃 실행 방법

### 1. 프로젝트 실행
```bash
cd /home/wsl/S_WEB_Project/my_lemp_project
docker-compose up -d
```

### 2. 서비스 확인
```bash
docker-compose ps
docker-compose logs nginx
docker-compose logs php
docker-compose logs db
```

### 3. 웹사이트 접속
- **HTTP**: http://localhost
- **HTTPS**: https://localhost (자체 서명 인증서)
- **웹해킹 테스트**: http://localhost/webhacking/

## 🔧 환경 설정

### MySQL 초기 설정
```bash
# 컨테이너에 접속하여 DB 초기화
docker-compose exec php php install.php
```

### 개발 모드 설정
```bash
# 취약점 테스트 모드 활성화
# config.php에서 VULNERABILITY_MODE = true 설정
```

## 📊 현재 진행 상황

### ✅ 완료
- Docker Compose 파일 분석
- 서비스 구성 확인
- 설치 가이드 작성

### 🔄 진행중  
- Docker 실제 테스트 (현재 환경에 Docker 미설치)
- 성능 최적화 가이드
- 트러블슈팅 가이드

### ⏳ 대기
- 프로덕션 환경 설정
- CI/CD 연동
- 모니터링 설정

## 🎯 다음 단계
1. 현재 환경에 Docker 설치 테스트
2. 실제 구동 테스트 및 오류 수정
3. 성능 최적화 및 보안 강화