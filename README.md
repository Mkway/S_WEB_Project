# 포괄적인 웹 보안 테스트 환경 (S_WEB_Project)

[![PHP](https://img.shields.io/badge/PHP-8.2-777BB4?style=flat-square&logo=php)](https://php.net)
[![Nginx](https://img.shields.io/badge/Nginx-1.20-009639?style=flat-square&logo=nginx)](https://nginx.org)
[![MariaDB](https://img.shields.io/badge/MariaDB-10.6-003545?style=flat-square&logo=mariadb)](https://mariadb.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

**웹 보안 취약점 학습과 방어 기법 실습을 위한 종합적인 PHP 기반 웹 애플리케이션**

이 프로젝트는 웹 개발자와 보안 연구자들이 실제 웹 취약점을 안전한 환경에서 학습하고 테스트할 수 있도록 설계된 교육용 플랫폼입니다. PayloadsAllTheThings 기반의 실제 공격 페이로드와 방어 메커니즘을 모두 제공합니다.

## 🎯 프로젝트 목적

- **교육적 목적**: 웹 보안 취약점의 원리와 방어 방법 학습
- **실무 적용**: 실제 공격 시나리오와 방어 코드 예제 제공
- **안전한 실습**: 격리된 Docker 환경에서 안전한 테스트 수행
- **포괄적 커버리지**: OWASP Top 10 기반의 주요 취약점 포함

## ✨ 주요 기능

### 🏠 **핵심 웹 애플리케이션**
- **사용자 인증 시스템**: 회원가입, 로그인, 세션 관리
- **게시판 시스템**: CRUD 기능과 파일 업로드
- **댓글 시스템**: 실시간 댓글 작성 및 관리
- **관리자 패널**: 사용자 및 콘텐츠 관리
- **알림 시스템**: 사용자 활동 추적 및 알림

### 🔐 **포괄적인 보안 테스트 환경 (21개 완료)**
- **SQL Injection**: UNION, Boolean-based, Time-based, Error-based 공격
- **XSS (Cross-Site Scripting)**: Reflected, Stored, DOM-based, Polyglot 페이로드
- **Command Injection**: OS 명령어 실행 및 우회 기법
- **File Inclusion (LFI/RFI)**: 로컬/원격 파일 포함 취약점
- **Directory Traversal**: 디렉토리 순회 및 시스템 파일 접근
- **CSRF**: Cross-Site Request Forgery 공격 및 토큰 우회
- **IDOR**: Insecure Direct Object References 테스트
- **Authentication Bypass**: 다양한 인증 우회 기법
- **JWT (JSON Web Token)**: 토큰 조작, 알고리즘 혼동, 키 누출 공격
- **XXE (XML External Entity)**: XML 외부 엔티티 주입 공격
- **SSRF (Server-Side Request Forgery)**: 서버측 요청 위조 공격
- **SSTI (Server-Side Template Injection)**: 서버측 템플릿 주입 공격
- **HPP (HTTP Parameter Pollution)**: HTTP 매개변수 오염 공격
- **NoSQL Injection**: MongoDB, CouchDB 등 NoSQL 데이터베이스 주입
- **LDAP Injection**: LDAP 디렉토리 서비스 주입 공격
- **XPath Injection**: XPath 표현식 주입을 통한 XML 데이터 조작
- **Insecure Deserialization**: 불안전한 역직렬화를 통한 코드 실행
- **CORS Misconfiguration**: 교차 출처 리소스 공유 설정 오류
- **GraphQL Injection**: GraphQL API 쿼리 조작 및 정보 노출
- **Business Logic Errors**: 비즈니스 로직 결함 악용
- **Open Redirect**: 신뢰할 수 있는 도메인을 통한 피싱 공격
- **현대적 Bootstrap 5 UI**: 반응형 디자인과 직관적 인터페이스

### 📚 웹 취약점 분석 문서
이 프로젝트에서 구현된 주요 웹 취약점들에 대한 상세 분석 문서입니다. 각 문서는 취약점의 원리, 공격 시나리오, 취약한 코드 예시, 그리고 안전한 방어 방법을 포함하고 있습니다. 스터디 발표 자료나 학습 자료로 활용하기에 적합합니다.

- [**분석 문서 디렉토리 바로가기**](security_analysis/)

### 🛡️ **고급 보안 기능**
- **실시간 공격 탐지**: 위험한 패턴 실시간 감지 및 경고
- **교육적 피드백**: 각 테스트별 상세한 설명과 방어 방법
- **안전한 시뮬레이션**: 실제 시스템 손상 없는 테스트 환경
- **코드 예제**: 취약한 코드와 안전한 코드 비교 제공

## 🛠️ 기술 스택

### Backend
- **PHP 8.2**: 최신 PHP 기능 활용
- **MariaDB 10.6**: 안정적인 데이터베이스
- **Nginx 1.28**: 고성능 웹 서버

### Frontend
- **Bootstrap 5.3**: 현대적이고 반응형 UI 프레임워크
- **Bootstrap Icons**: 아이콘 시스템
- **반응형 디자인**: 모바일/태블릿/데스크톱 최적화

### DevOps & Testing
- **Docker & Docker Compose**: 컨테이너화된 개발 환경
- **PHPUnit**: 포괄적인 단위 테스트
- **SSL/TLS**: 보안 통신 지원

### Security Features
- **CSRF Protection**: 토큰 기반 요청 보호
- **Session Security**: 안전한 세션 관리
- **Input Validation**: 포괄적인 입력값 검증
- **XSS Protection**: 출력 인코딩 및 CSP

## 🚀 시작하기

### 1. 빠른 시작 (Docker 사용 - 권장)

```bash
# 프로젝트 클론
git clone https://github.com/Mkway/S_WEB_Project.git
cd S_WEB_Project/my_lemp_project

# Docker 컨테이너 실행
docker-compose up -d

# 애플리케이션 접속
# 메인 애플리케이션: http://localhost
# 보안 테스트 환경: http://localhost/webhacking
```

### 2. 초기 설정

1. **데이터베이스 초기화**: `http://localhost/install.php` 접속
2. **테스트 사용자 생성**: 회원가입 또는 기본 계정 사용
3. **보안 테스트 접근**: 로그인 후 "보안 테스트" 메뉴 클릭

### 3. 테스트 실행

```bash
# PHPUnit 테스트 실행
docker-compose exec php ./vendor/bin/phpunit --testdox test/

# 특정 보안 테스트 실행
docker-compose exec php ./vendor/bin/phpunit test/SecurityTest.php
```

## 📂 프로젝트 구조

```
S_WEB_Project/
├── security_analysis/              # 웹 취약점 분석 문서
├── my_lemp_project/
│   ├── docker-compose.yml          # Docker 서비스 정의
│   ├── nginx/                      # Nginx 설정 및 SSL
│   │   ├── default.conf
│   │   ├── ssl/
│   │   └── docker-entrypoint.sh
│   ├── src/                        # PHP 애플리케이션
│   │   ├── webhacking/             # 🔥 보안 테스트 환경
│   │   │   ├── index.php           # 테스트 메인 페이지 (Bootstrap 5)
│   │   │   ├── sql_injection.php   # SQL Injection 테스트
│   │   │   ├── xss_test.php        # XSS 테스트
│   │   │   ├── command_injection.php
│   │   │   ├── file_inclusion.php
│   │   │   ├── directory_traversal.php
│   │   │   ├── csrf_test.php
│   │   │   ├── idor_test.php
│   │   │   ├── auth_bypass.php
│   │   │   └── jwt_test.php        # 🆕 JWT 취약점 테스트
│   │   ├── test/                   # PHPUnit 테스트
│   │   ├── config.php              # 애플리케이션 설정
│   │   ├── utils.php               # 보안 유틸리티
│   │   └── ...                     # 기타 PHP 파일들
│   └── php.Dockerfile              # PHP Docker 설정
└── README.md
```

## 🧪 보안 테스트 가이드

### 접근 방법
1. 메인 애플리케이션에 로그인
2. "보안 테스트" 메뉴 클릭
3. 원하는 취약점 테스트 선택
4. 제공된 페이로드 버튼 클릭 또는 직접 입력
5. 테스트 결과 및 방어 방법 확인

### 주요 테스트 시나리오

#### 🗃️ SQL Injection
```sql
-- UNION 기반 공격
' UNION SELECT null,username,password FROM users--

-- Boolean 기반 블라인드 공격
' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>64--
```

#### 🚨 XSS (Cross-Site Scripting)
```html
<!-- Reflected XSS -->
<script>alert('XSS')</script>

<!-- DOM-based XSS -->
<img src="x" onerror="alert(1)">
```

#### 💻 Command Injection
```bash
# 기본 명령어 연결
; ls -la

# 블라인드 공격
; ping -c 4 127.0.0.1
```

#### 🔐 JWT (JSON Web Token)
```javascript
// None Algorithm Attack
{"typ":"JWT","alg":"none"}

// Algorithm Confusion (RS256 → HS256)
// 공개키를 HMAC 시크릿으로 사용

// Weak Secret Attack
secret, 123456, password, key, jwt
```

### 안전 수칙
⚠️ **중요**: 모든 테스트는 교육 목적으로만 사용하세요
- 실제 운영 환경에서 절대 사용 금지
- 격리된 Docker 환경에서만 테스트
- 타인의 시스템에 대한 무단 테스트 금지

## 📊 테스트 커버리지

### 포함된 보안 테스트
- ✅ **OWASP Top 10** 주요 취약점 커버
- ✅ **PayloadsAllTheThings** 기반 실제 페이로드
- ✅ **실시간 공격 탐지** 시스템
- ✅ **방어 코드 예제** 및 설명
- ✅ **참고 자료** 링크 (OWASP, PortSwigger 등)

### 지원하는 공격 벡터
| 카테고리 | 테스트 항목 | 상태 |
|---------|------------|------|
| **Injection** | SQL, NoSQL, LDAP, XPath, Command | ✅ |
| **XSS** | Reflected, Stored, DOM-based | ✅ |
| **Access Control** | IDOR, Auth Bypass | ✅ |
| **CSRF** | Token Bypass, Method Override | ✅ |
| **File Security** | LFI, RFI, Directory Traversal | ✅ |
| **Session** | Fixation, Hijacking | ✅ |
| **JWT Security** | None Algorithm, Algorithm Confusion, Weak Secret | ✅ |
| **UI/UX** | Bootstrap 5, 반응형 디자인, 아이콘 시스템 | ✅ |

## 🔧 개발자 가이드

### 환경 설정
```bash
# 개발 모드로 실행
docker-compose -f docker-compose.dev.yml up -d

# 로그 확인
docker-compose logs -f php nginx db

# 컨테이너 접속
docker-compose exec php bash
```

### 새로운 테스트 추가
1. `src/webhacking/` 디렉토리에 새 PHP 파일 생성
2. 기존 테스트 페이지를 템플릿으로 활용
3. `src/webhacking/index.php`에 새 테스트 링크 추가
4. 관련 PHPUnit 테스트 작성

### 보안 고려사항
- 모든 사용자 입력은 적절히 검증
- 출력값은 컨텍스트에 맞게 인코딩
- CSRF 토큰을 모든 상태 변경 요청에 포함
- 최소 권한 원칙 적용

## 🤝 기여하기

이 프로젝트는 교육 및 연구 목적으로 지속적으로 발전하고 있습니다.

### 기여 방법
1. **이슈 리포트**: 버그나 개선사항 제안
2. **Pull Request**: 새로운 테스트나 기능 추가
3. **문서화**: 사용법이나 보안 가이드 개선
4. **피드백**: 교육적 효과 향상을 위한 의견

### 개발 가이드라인
- 모든 코드는 교육적 목적에 적합해야 함
- 보안 테스트는 안전한 환경에서만 작동해야 함
- 명확한 주석과 설명 포함
- PHPUnit 테스트 커버리지 유지

## 🆕 최신 업데이트 (2025년 8월)

### 새롭게 추가된 기능
- **JWT 취약점 테스트**: PayloadsAllTheThings 기반 JWT 보안 테스트
  - None Algorithm Attack (서명 검증 우회)
  - Algorithm Confusion (RS256 ↔ HS256)
  - Weak Secret Brute Force
  - Token Manipulation (페이로드 조작)
  - JWT Information Disclosure
- **Bootstrap 5 UI 전면 개편**: 현대적이고 반응형 인터페이스
- **카드 기반 레이아웃**: 직관적인 테스트 선택 인터페이스
- **실시간 공격 시뮬레이션**: 교육적 피드백과 CVSS 스코어링
- **향상된 보안 로깅**: 상세한 공격 패턴 분석

### 기술적 개선사항
- **Docker 컨테이너 최적화**: 더 빠른 시작과 안정성
- **Nginx 설정 개선**: 웹해킹 경로 접근성 향상
- **PHP 8.2 호환성**: 최신 보안 기능 활용
- **SSL/TLS 지원**: HTTPS 기본 지원

## 📚 학습 자료

### 참고 문서
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### 추천 학습 순서
1. **기본 웹 애플리케이션 이해**
2. **SQL Injection 테스트부터 시작**
3. **XSS 공격 패턴 학습**
4. **JWT 보안 테스트** (새로 추가됨)
5. **고급 공격 기법 순차 학습**
6. **방어 메커니즘 구현 실습**

### 프로젝트 통계
- **총 보안 테스트**: 21개 완료 (PayloadsAllTheThings 커버리지 37%)
- **코드 라인 수**: 16,000+ 라인
- **테스트 케이스**: 80+ 시나리오
- **지원 언어**: PHP 8.2, JavaScript ES6+
- **Docker 이미지**: 3개 (Nginx, PHP-FPM, MariaDB)

## 📄 라이선스

이 프로젝트는 [MIT 라이선스](LICENSE)를 따릅니다.

---

## ⚠️ 면책 조항

이 프로젝트는 **교육 목적으로만** 제작되었습니다. 실제 운영 환경이나 타인의 시스템에 대한 무단 보안 테스트는 법적 문제를 야기할 수 있습니다. 사용자는 관련 법률을 준수하고 윤리적으로 이 도구를 사용할 책임이 있습니다.

**🎓 Happy Ethical Hacking & Secure Coding!**