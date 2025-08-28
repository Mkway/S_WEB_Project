# Claude Code Development Workflow

## Git Commit Guidelines

### 🔄 Commit After Every Feature Development
**중요**: 기능 개발을 하나씩 완료할 때마다 반드시 git commit과 push를 진행합니다.

```bash
# 1. 변경사항 확인
git status
git diff

# 2. 파일 스테이징
git add <modified_files>

# 3. 커밋 (상세한 메시지와 함께)
git commit -m "feat: [기능 설명]

- 구체적인 변경 내용 1
- 구체적인 변경 내용 2  
- 구체적인 변경 내용 3

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# 4. 원격 저장소에 푸시
git push
```

### 📋 Commit Message Format
```
<type>: <subject>

<body>

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

**Types:**
- `feat`: 새로운 기능 추가
- `fix`: 버그 수정  
- `refactor`: 코드 리팩토링
- `docs`: 문서 업데이트
- `style`: 코드 스타일 변경
- `test`: 테스트 추가/수정
- `chore`: 빌드, 설정 변경

### 🎯 Development Process

1. **기능 계획 수립**
   - TodoWrite tool로 작업 항목 정리
   - 우선순위 설정

2. **개발 진행**  
   - 기능별로 단계적 개발
   - 각 단계마다 테스트

3. **커밋 & 푸시**
   - 기능 하나 완성 시마다 커밋
   - 상세한 커밋 메시지 작성
   - 즉시 푸시로 백업

4. **다음 기능으로 이동**
   - TodoWrite로 진행 상황 업데이트
   - 다음 우선순위 작업 시작

### 🚨 Important Rules

- **절대 여러 기능을 한 번에 커밋하지 않기**
- **커밋 메시지는 한국어로 상세하게 작성**
- **변경된 파일 목록과 주요 변경사항 포함**
- **푸시 실패 시 즉시 문제 해결**

### 📖 Example Commits

```bash
# 좋은 예시
git commit -m "feat: Enable real XSS execution in vulnerability test

- Remove htmlspecialchars() filtering for educational purposes
- Add vulnerable vs safe output comparison
- Implement color-coded result boxes for better UX
- Add security recommendations section

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# 나쁜 예시  
git commit -m "update files"
```

---

## Development Environment Setup

### Required Tools
- Git (version control)
- PHP 7.4+ (웹 서버)
- MySQL/MariaDB (데이터베이스)
- Node.js 18+ (프론트엔드 도구)

### Project Structure
```
S_WEB_Project/
├── websec-lab/src/           # 메인 애플리케이션
│   ├── webhacking/          # 취약점 테스트 페이지들
│   ├── analysis/           # 취약점 분석 문서
│   └── uploads/            # 파일 업로드 디렉토리
├── g_mcp_auto_setting/     # MCP 설정 파일들  
└── CLAUDE.md              # 이 파일
```

### Testing Guidelines
- 각 취약점 테스트는 실제 공격이 실행되도록 구현
- 교육 목적으로 안전한 환경에서만 사용
- 보안 권장사항을 함께 제공

---

*이 파일은 Claude Code 개발 시 참고용으로 작성되었습니다.*