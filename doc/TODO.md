# S_WEB_Project: 보안 테스트 확장 로드맵

PayloadsAllTheThings 기반의 보안 테스트 커버리지를 100%로 확장하기 위한 구체적인 구현 계획입니다.

**📈 현재 상황**: 53개 테스트 완료 (커버리지 ~90%)

---

### Phase 1: 인증 및 네트워크 보안
- [x] **SSRF 공격 시뮬레이션**: 내부 IP 스캔, 메타데이터 서비스 접근
- [x] **XXE Injection 테스트**: 외부 엔티티를 통한 파일 읽기
- [x] **CORS 설정 오류 테스트**: 악의적 도메인에서의 리소스 접근
- [x] **SAML Injection**: SAML 인증 우회 및 조작
- [x] **Request Smuggling**: HTTP 요청 밀수, 프록시 우회
- [x] **Prototype Pollution**: JavaScript 프로토타입 오염
- [x] **OAuth Misconfiguration**: OAuth 2.0/OpenID Connect 취약점 테스트 구현
- [x] **Session Management**: 세션 고정, 하이재킹 등 세션 관리 취약점 테스트 구현
- [x] **Insecure File Upload**: 확장자 검증 우회를 통한 웹쉘 업로드 등 파일 업로드 취약점 테스트 구현

### Phase 2: 고급 주입 공격
- [x] **SSTI 템플릿 인젝션**: Twig, Jinja2 등 템플릿 엔진 공격
- [x] **GraphQL 취약점**: 쿼리 깊이, 정보 노출, 권한 우회
- [x] **Insecure Deserialization**: 직렬화 객체 조작
- [x] **NoSQL Injection**: MongoDB, CouchDB 등 NoSQL 주입
- [x] **LDAP Injection**: LDAP 쿼리 조작
- [x] **XPath Injection**: XPath 표현식 조작
- [x] **XSLT Injection**: XSLT 스타일시트 조작

### Phase 3: 파일 및 업로드 보안
- [x] **Zip Slip**: 압축 파일 경로 조작
- [x] **CSV Injection**: 스프레드시트 수식 주입

### Phase 4: 클라이언트 사이드 공격
- [x] **Tabnabbing**: 새 탭에서 원본 페이지 조작
- [x] **DOM Clobbering**: HTML 요소를 통한 JavaScript 변수 오염
- [x] **Clickjacking**: 투명한 iframe을 통한 클릭 도용
- [x] **Open Redirect**: 리다이렉션 취약점
- [x] **Client Side Path Traversal**: 클라이언트 측 경로 순회

### Phase 5: 비즈니스 로직 및 데이터 조작
- [x] **Business Logic Errors**: 업무 로직 결함 악용
- [x] **Mass Assignment**: 대량 할당 취약점
- [x] **Type Juggling**: PHP 타입 저글링
- [x] **Race Condition**: 동시성 접근으로 인한 경합 조건 취약점

### Phase 6: 정보 수집 및 누출
- [x] **API Key Leaks**: API 키 노출 및 악용
- [x] **Hidden Parameters**: 숨겨진 매개변수 발견
- [x] **ORM Leak**: Object-Relational Mapping 시스템 정보 누출

### Phase 7: 네트워크 및 인프라
- [x] **DNS Rebinding**: DNS 리바인딩 공격
- [x] **Web Cache Deception**: 웹 캐시 기만
- [x] **Reverse Proxy Misconfigurations**: 리버스 프록시 설정 오류
- [x] **Web Sockets**: WebSocket 프로토콜 취약점

### Phase 8: 기타 공격 벡터
- [x] **CRLF Injection**: 캐리지 리턴/라인 피드 주입
- [x] **External Variable Modification**: 외부 변수 조작
- [x] **Insecure Randomness**: 예측 가능한 난수 생성기 취약점
- [x] **Regular Expression Vulnerabilities (ReDoS)**: 정규식 백트래킹 악용 DoS 공격
- [x] **Dependency Confusion**: 의존성 혼동 공격
- [x] **DoS**: 서비스 거부 공격
- [x] **CVE Exploits**: 알려진 CVE 취약점 모음
- [x] **Initial Access**: 초기 접근
- [x] **Authentication Bypass**: 인증 우회
- [x] **Virtual Hosts**: 가상 호스트 설정 오류
- [x] **Encoding Transformations**: 문자 인코딩 변환 과정에서 필터 우회
- [x] **LaTeX Injection**: LaTeX 문서 처리 시스템 명령어 주입

---

## 🗂️ Backlog: 일반 개선 과제

### 플랫폼 안정화 및 품질 개선
- [x] **보안 테스트 모듈 리팩토링**: 새로운 취약점 추가가 용이하도록 구조 개선
- [x] **의존성 보안 감사**: Composer 및 NPM 의존성 정기 검토

### 개발 환경 및 문서 관리
- [x] **`install.php` 기능 개선**: 샘플 데이터 자동 생성 기능 추가
- [x] **Dockerfile 최적화**: 이미지 사이즈 축소 및 빌드 시간 단축
- [x] **문서 최신화**: `doc/` 폴더 내 모든 문서 내용 검토
- [x] **기여 가이드 작성**: `CONTRIBUTING.md` 작성

## 🏁 최종 단계
- [x] **코어 애플리케이션 테스트 커버리지 확대**: PHPUnit 테스트 보강 ✅ **완료** (2025-08-26)
