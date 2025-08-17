# S_WEB_Project: 보안 테스트 확장 로드맵

PayloadsAllTheThings 기반의 보안 테스트 커버리지를 100%로 확장하기 위한 구체적인 구현 계획입니다.

**📈 현재 상황**: 43개 테스트 완료 (커버리지 ~75%)

---

### Phase 1: 인증 및 네트워크 보안 (Next Steps)
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

### Phase 3: 파일 및 업로드 보안
- [x] **Insecure Deserialization**: 직렬화 객체 조작

### Phase 4: 클라이언트 사이드 공격
- [x] **Tabnabbing**: 새 탭에서 원본 페이지 조작

### Phase 5: 신기술 및 최신 보안 이슈 (NEW - 2025년 8월 추가)
- [x] **Prompt Injection**: AI 시스템 프롬프트 조작 공격
- [x] **Regular Expression Vulnerabilities (ReDoS)**: 정규식 백트래킹 악용 DoS 공격
- [x] **Insecure Randomness**: 예측 가능한 난수 생성기 취약점
- [x] **LaTeX Injection**: LaTeX 문서 처리 시스템 명령어 주입

---

## 🗂️ Backlog: 일반 개선 과제

### 플랫폼 안정화 및 품질 개선
- [ ] **보안 테스트 모듈 리팩토링**: 새로운 취약점 추가가 용이하도록 구조 개선
- [ ] **의존성 보안 감사**: Composer 및 NPM 의존성 정기 검토

### 개발 환경 및 문서 관리
- [ ] **`install.php` 기능 개선**: 샘플 데이터 자동 생성 기능 추가
- [ ] **Dockerfile 최적화**: 이미지 사이즈 축소 및 빌드 시간 단축
- [ ] **문서 최신화**: `doc/` 폴더 내 모든 문서 내용 검토
- [ ] **기여 가이드 작성**: `CONTRIBUTING.md` 작성

### 🧪 테스트 (최종 단계)
- [ ] **코어 애플리케이션 테스트 커버리지 확대**: PHPUnit 테스트 보강
