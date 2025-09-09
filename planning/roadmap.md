# 🚀 S_WEB_Project 로드맵

## 🔄 Current Priority (현재 작업중)
### Advanced Vulnerability Modules
**목표**: 고급 취약점 시나리오 구현

#### 1. Business Logic Vulnerability 테스트
- [ ] **가격 조작 공격** - 할인/쿠폰 로직 우회
- [ ] **권한 우회 공격** - 관리자 기능 접근
- [ ] **워크플로우 우회** - 결제/승인 프로세스 건너뛰기
- [ ] **수량 제한 우회** - 재고/한도 제한 무시

#### 2. Race Condition 공격
- [ ] **TOCTOU (Time-of-Check-Time-of-Use)** 공격
- [ ] **동시 요청을 통한 잔액 조작**
- [ ] **파일 업로드 레이스 컨디션**
- [ ] **세션/쿠키 레이스 컨디션**

#### 3. 추가 Deserialization 취약점
- [ ] **Python Pickle** 직렬화 취약점
- [ ] **.NET BinaryFormatter** 취약점
- [ ] **PHP unserialize()** 객체 인젝션
- [ ] **Ruby Marshal** 취약점

## 🚀 Next Priority Options (다음 우선순위)

### Option A: Web Interface Enhancement
- [ ] **통합 대시보드** - 모든 취약점 테스트 중앙 관리
- [ ] **결과 비교 시각화** - 취약한 vs 안전한 구현 그래프
- [ ] **취약점 리포트** - PDF/HTML 리포트 생성
- [ ] **사용자 가이드** - 각 테스트별 상세 설명

### Option B: API Security Testing  
- [ ] **REST API 취약점** - API 인증/인가 우회
- [ ] **GraphQL Injection** - GraphQL 쿼리 조작
- [ ] **JWT 취약점** - 토큰 변조/우회
- [ ] **Rate Limiting 우회** - API 남용 공격

### Option C: Container Security
- [ ] **Docker Escape** - 컨테이너 탈출 공격
- [ ] **Kubernetes 취약점** - 클러스터 보안 테스트
- [ ] **이미지 스캔** - 취약한 베이스 이미지 탐지
- [ ] **Secret 관리** - 민감 정보 노출 테스트

## 📅 타임라인 예상

### Phase 1: Advanced Vulnerabilities (2주)
- Week 1: Business Logic + Race Condition
- Week 2: Additional Deserialization

### Phase 2: Enhancement (1주)
- Web Interface 통합 및 개선

### Phase 3: Expansion (2주)  
- API Security 또는 Container Security 선택

## 🎯 성공 지표
- [ ] **25개 이상** 취약점 테스트 모듈 완성
- [ ] **실제 공격 실행** 가능한 교육 환경
- [ ] **취약한 vs 안전한** 구현 비교 완성
- [ ] **Docker 기반** 완전 자동화 환경