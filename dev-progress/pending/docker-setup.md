# ⏳ Docker LEMP 환경 설정

**상태**: PENDING  
**우선순위**: HIGH

## 🎯 목표
Docker를 이용한 LEMP 스택 배포 환경 구축

## 📋 작업 계획

### 1. Docker 환경 설정
- [ ] Docker & Docker Compose 설치 가이드 작성
- [ ] docker-compose.yml 최적화
- [ ] MySQL 데이터 영속성 확보

### 2. 서비스 설정  
- [ ] Nginx 설정 최적화
- [ ] PHP-FPM 설정 개선
- [ ] MariaDB 설정 튜닝

### 3. SSL/HTTPS 설정
- [ ] 자체 서명 인증서 자동 생성
- [ ] HTTPS 리다이렉션 설정

### 4. 개발환경 최적화
- [ ] 볼륨 마운트 최적화  
- [ ] 로그 관리 설정
- [ ] 개발용 PHP 설정

## 📁 관련 파일들
- `/my_lemp_project/docker-compose.yml`
- `/my_lemp_project/nginx/`
- `/my_lemp_project/php.Dockerfile`

## 💡 참고사항
현재 환경에는 Docker가 설치되어 있지 않음