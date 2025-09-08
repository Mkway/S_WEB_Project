# MongoDB NoSQL Injection 테스트 환경 구축

## 📋 구현 현황 (2025-09-08)

### ✅ 완료된 작업

1. **Docker Compose 설정**
   - MongoDB 7 서비스 추가 (`docker-compose.yml`)
   - 포트 27017 매핑
   - 초기화 스크립트 볼륨 마운트

2. **MongoDB 초기 데이터 설정**
   - `nosql-challenges/mongo/init/01-init-security-test.js` 생성
   - 4개 테스트용 컬렉션 구성:
     - `users`: 인증 우회 테스트용
     - `products`: 검색 인젝션 테스트용  
     - `posts`: 복합 쿼리 테스트용
     - `logs`: 정보 수집 테스트용

3. **PHP MongoDB 연결 클래스**
   - `src/database/MongoDBConnection.php` 완성
   - 취약한 메서드와 안전한 메서드 구현
   - NoSQL Operator Injection, JavaScript Expression Injection 지원

4. **NoSQL Injection 테스트 페이지**
   - `src/webhacking/nosql_injection_test.php` 완성
   - 3가지 테스트 유형 지원:
     - 로그인 우회 (Operator Injection)
     - 제품 검색 (JavaScript Injection)
     - JSON 페이로드 (Direct Query)
   - 취약한 실행과 안전한 구현 비교 표시

5. **MongoDB 연결 테스트 스크립트**
   - `src/test_mongodb.php` 작성
   - 연결 상태 확인 및 간단한 NoSQL Injection 테스트

### 🔄 진행중인 작업

1. **PHP Dockerfile 수정**
   - MongoDB PHP 확장 설치 완료
   - Composer 의존성 버전 호환성 문제 해결중
   - MongoDB PHP 확장 v2.1.1과 mongodb/mongodb 패키지 버전 매칭 필요

### ❌ 해결해야 할 문제

1. **Composer 의존성 충돌**
   ```
   mongodb/mongodb ^2.0 requires ext-mongodb ^2.0
   현재 설치된 ext-mongodb 2.1.1과 버전 호환성 문제
   ```

2. **Docker 빌드 최적화**
   - 현재 MongoDB 확장 컴파일에 시간이 오래 걸림 (880개 소스 파일)
   - 캐시 활용 최적화 필요

### 📁 파일 구조

```
websec-lab/
├── docker-compose.yml              # MongoDB 서비스 추가
├── php.Dockerfile                  # MongoDB PHP 확장 설치
├── src/
│   ├── composer.json               # MongoDB 패키지 의존성 추가
│   ├── database/
│   │   └── MongoDBConnection.php   # MongoDB 연결 및 쿼리 클래스
│   ├── webhacking/
│   │   └── nosql_injection_test.php # NoSQL Injection 테스트 페이지
│   └── test_mongodb.php            # MongoDB 연결 테스트
└── nosql-challenges/
    └── mongo/
        └── init/
            └── 01-init-security-test.js # MongoDB 초기 데이터
```

## 🚀 다음 단계

### 즉시 해결 필요
1. **Composer 버전 호환성 해결**
   - MongoDB PHP 확장과 패키지 버전 매칭
   - 또는 `--ignore-platform-reqs` 옵션 사용 검토

2. **Docker 환경 완성**
   - PHP + MongoDB 컨테이너 빌드 완료
   - 전체 스택 (nginx, php, mysql, postgres, mongodb) 동시 실행 테스트

### 기능 테스트
3. **NoSQL Injection 테스트 검증**
   - 웹 인터페이스를 통한 실제 공격 시뮬레이션
   - 각 취약점 유형별 결과 확인

4. **보안 권장사항 보완**
   - 추가 방어 기법 문서화
   - 실무 적용 가이드라인 작성

## 🔧 기술적 세부사항

### MongoDB 연결 설정
- **호스트**: mongodb (Docker 내부 네트워크)
- **포트**: 27017
- **인증**: admin/admin123
- **데이터베이스**: security_test

### 지원하는 NoSQL Injection 유형
1. **MongoDB Operator Injection**
   - `$ne`, `$gt`, `$or` 등 연산자 악용
   - 인증 우회 시나리오

2. **JavaScript Expression Injection**  
   - `$where` 절 JavaScript 코드 실행
   - 타이밍 공격, 데이터 추출

3. **정규식 인젝션**
   - `$regex` 연산자를 통한 데이터 추출
   - 브루트포스 공격

### 방어 메커니즘
- 입력 타입 검증 (`is_string()`)
- 화이트리스트 기반 필드 검증
- `$where` 절 사용 금지
- 입력 길이 제한
- MongoDB ODM/ORM 사용 권장

---

*다음 세션에서는 Docker 빌드 완료 후 실제 NoSQL Injection 테스트를 진행할 예정입니다.*