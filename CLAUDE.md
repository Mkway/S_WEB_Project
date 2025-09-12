# Claude Code Development Workflow

## 🤖 Claude Development System Prompt

**Use this prompt to ensure efficient development workflow:**

```
You are working on the S_WEB_Project websec-lab vulnerability testing platform. 

MANDATORY DEVELOPMENT RULES:
1. 🔄 ALWAYS use TodoWrite tool for every multi-step task
2. 🔄 ALWAYS commit & push after completing each individual feature  
3. 🔄 NEVER batch multiple features into one commit
4. 🔄 Use Korean for commit messages with detailed descriptions

WORKFLOW FOR EACH TASK:
1. TodoWrite: Plan the task with specific steps
2. Execute: Complete one feature at a time  
3. Commit: Detailed Korean commit message following format below
4. Push: Immediately push to backup progress
5. Update TodoWrite: Mark completed and move to next

COMMIT MESSAGE FORMAT:
feat/fix/refactor: [한국어 제목]

- 구체적 변경사항 1
- 구체적 변경사항 2
- 실행 가능한 새로운 기능 설명

🤖 Generated with [Claude Code](https://claude.ai/code)
Co-Authored-By: Claude <noreply@anthropic.com>

CURRENT PROJECT CONTEXT:
- Main goal: Make vulnerability tests execute real attacks (not simulations)
- Show vulnerable vs safe output comparisons
- Include security recommendations
- Priority: SQL injection, XSS, Command injection, File upload, CSRF, LFI, Directory traversal, Auth bypass completed
- Next priority: XXE, SSRF, SSTI, Open redirect, XPath injection

Always ask which specific vulnerability test to work on next and follow the workflow above.
```

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

## 📊 Project Overview

**현재 상태**: Advanced Vulnerability Modules 구현 중

**프로젝트 세부 계획**: 
- 📋 **진행 상황**: `/planning/project-status.md`
- 🚀 **로드맵**: `/planning/roadmap.md`  
- 🎯 **취약점 스펙**: `/planning/vulnerability-specs.md`

**주요 완료 모듈**: 16개 (기본 8개 + 중간 5개 + 고급 3개)

### 📋 Development Environment Setup

**Required Tools:**
- Git (version control)
- PHP 7.4+ (웹 서버) 
- MySQL/MariaDB (데이터베이스)
- Node.js 18+ (프론트엔드 도구)

**Project Structure:**
```
S_WEB_Project/
├── websec-lab/src/           # 메인 애플리케이션
│   ├── webhacking/          # 취약점 테스트 페이지들  
│   ├── analysis/           # 취약점 분석 문서
│   └── uploads/            # 파일 업로드 디렉토리
├── g_mcp_auto_setting/     # MCP 설정 파일들
└── CLAUDE.md              # 개발 가이드 (이 파일)
```

**Testing Implementation Pattern:**
```php
// 1. 취약한 실행부
$result .= "<div class='vulnerable-output'>실제 공격 실행 결과</div>";

// 2. 안전한 구현 비교  
$result .= "<div class='safe-comparison'>안전한 구현이었다면</div>";

// 3. 보안 권장사항
$result .= "<div class='security-recommendations'>보안 권장사항</div>";
```

---

## 🚀 Quick Start for Next Development

**Copy this prompt when starting new session:**

```
Following CLAUDE.md workflow: Work on S_WEB_Project websec-lab. Use TodoWrite for planning, complete one vulnerability test modification at a time, commit & push immediately after each feature. Focus on making tests execute real attacks with vulnerable vs safe comparisons. Which vulnerability test should I work on next from the middle priority list: XXE, SSRF, SSTI, Open Redirect, or XPath?
```

*이 파일은 효율적인 Claude Code 개발을 위한 시스템 가이드입니다.*

---

## 🛡️ PayloadsAllTheThings 취약점 구현 프롬프트

### 📝 구현 시 사용할 프롬프트
```
다음 취약점을 PayloadsAllTheThings 기반으로 구현해주세요:

취약점: [취약점명]
언어: [PHP/Node.js/Python/Java/Go]

요구사항:
✅ 실제 동작하는 취약점 (Docker 환경, 시뮬레이션 아님)
✅ 간단하고 명확한 코드 (10-20줄 이내)
✅ 교육적 문서 출력 (백엔드 동작, 원리, 테스트, 구현)
✅ PayloadsAllTheThings 페이로드 활용
✅ 취약한 버전 vs 안전한 버전 비교

구현 패턴: 실제 실행 → 결과 확인 → 보안 권장사항
```

### 🎯 목표
PayloadsAllTheThings 58개 취약점 완전 구현 (상세 계획은 /planning/ 참고)