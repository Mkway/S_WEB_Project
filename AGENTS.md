## Gemini Added Memories
- Do not use the `rm` command without explicit user confirmation.
- 앞으로의 진행 상황은 log/** 폴더에 log 형식으로 작성합니다.

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