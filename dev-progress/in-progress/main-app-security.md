# 🔄 메인 애플리케이션 보안 강화

**시작일**: 2025-08-24  
**상태**: IN-PROGRESS  

## 🎯 목표
메인 게시판 애플리케이션의 보안 취약점을 식별하고 수정

## 📋 작업 항목

### ✅ 완료된 작업
- [x] 보안 함수 확인 (utils.php의 safe_output, clean_input)
- [x] 입력값 처리 현황 스캔

### 🔄 진행중인 작업  
- [ ] XSS 방어 강화 (htmlspecialchars → safe_output 통일)
- [ ] 입력값 검증 개선 (clean_input 함수 적용)
- [ ] SQL Injection 방어 점검

### ⏳ 대기중인 작업
- [ ] CSRF 토큰 구현
- [ ] 파일 업로드 보안 강화  
- [ ] 세션 보안 개선
- [ ] 에러 핸들링 개선

## 🔍 발견된 이슈
1. **view_post.php**: htmlspecialchars 대신 safe_output 사용 필요
2. **add_comment.php**: 입력값에 clean_input 미적용
3. **전역적**: CSRF 보호 부족

## 📁 관련 파일들
- `/src/utils.php` - 보안 함수들
- `/src/view_post.php` - 게시물 조회
- `/src/add_comment.php` - 댓글 추가
- `/src/*.php` - 기타 메인 앱 파일들