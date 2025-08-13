# S_WEB_Project TODO List

프로젝트의 다음 단계를 위한 작업 목록입니다.

### 1. 보안 강화 (Security Enhancement)
- [ ] `index.php`의 `VULNERABILITY_MODE` 로직 제거 및 안전한 코드로 통일
- [ ] 파일 업로드 기능 상세 분석 및 확장자/MIME 타입 검증 강화
- [ ] 모든 사용자 입력값에 대한 추가적인 검증 로직 검토 (예: `admin_actions.php`)
- [ ] 세션 관리 강화 (타임아웃, 고정 공격 방어 등) 검토

### 2. 코드 리팩토링 및 품질 개선 (Code Refactoring & Quality Improvement)
- [ ] `utils.php`의 기능 분리 및 클래스화 검토
- [ ] PHPUnit 테스트 커버리지 확대 (특히, 보안 관련 기능)
- [ ] 중복 코드(HTML, PHP) 제거 및 공통 템플릿 또는 함수로 분리
- [ ] `webhacking` 디렉터리 내 테스트 코드 가독성 및 UI 개선

### 3. 문서 및 환경 개선 (Documentation & Environment Improvement)
- [ ] `doc/` 폴더 내 모든 문서 내용 검토 및 최신화
- [ ] `install.php`에 초기 데이터(샘플 게시물, 사용자 등) 추가 기능 구현
- [ ] Composer 및 NPM 의존성 검토 및 보안 업데이트
- [ ] Dockerfile 최적화 (이미지 사이즈 축소, 빌드 시간 단축)

### 4. PayloadsAllTheThings 기반 테스트 확장
- [ ] **OAuth Misconfiguration**: OAuth 2.0/OpenID Connect 취약점 테스트 구현
- [ ] **SAML Injection**: SAML 인증 우회 및 조작 테스트 구현
- [ ] **Session Management**: 세션 고정, 하이재킹 등 세션 관련 취약점 테스트 구현
- [ ] **Request Smuggling**: HTTP 요청 밀수 테스트 환경 구현 (리서치 필요)
- [ ] **Prototype Pollution**: JavaScript 프로토타입 오염 테스트 구현