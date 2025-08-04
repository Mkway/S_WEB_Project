## Gemini Added Memories
- Do not use the `rm` command without explicit user confirmation.
- 앞으로의 진행 상황은 log/** 폴더에 log 형식으로 작성합니다.

## Vibe Kanban 자동 연동 규칙
- TodoWrite 도구로 작업을 추적할 때, 중요한 작업은 자동으로 vibe kanban에도 기록합니다.
- 작업 상태가 변경될 때마다 vibe kanban의 해당 task도 업데이트합니다.
- 프로젝트 ID: `918df41f-28a6-43db-92fd-7f3e19a29e11` (S WEB Project)

### 자동 연동 프로세스:
1. **새 작업 시작**: TodoWrite에서 "in_progress"로 변경 시 → vibe kanban에 새 task 생성 (status: "inprogress")
2. **작업 완료**: TodoWrite에서 "completed"로 변경 시 → vibe kanban task를 "done"으로 업데이트
3. **작업 취소**: TodoWrite에서 제거 시 → vibe kanban task를 "cancelled"로 업데이트

### 매핑 규칙:
- TodoWrite "pending" → vibe kanban "todo"
- TodoWrite "in_progress" → vibe kanban "inprogress" 
- TodoWrite "completed" → vibe kanban "done"

## Custom Commands
- `update_log_commit_push <commit_message>`: `log/2025_07_16.md` 파일을 업데이트하고, 모든 변경 사항을 스테이징하며, 제공된 커밋 메시지로 커밋하고 `main` 브랜치에 푸시합니다.
  - Usage: `update_log_commit_push "feat: 새로운 기능 추가"`
  - Implementation:
    ```bash
    # 1. Update log file (manual step before calling this command)
    # 2. Stage all changes
    git add .
    # 3. Commit with provided message from stdin
    echo "$1" | git commit -F -
    # 4. Push to main branch
    git push origin main
    ```