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

## Lessons Learned from Recent Interactions

This section summarizes key challenges encountered and lessons learned during recent interactions, aiming to improve future performance and efficiency.

### 1. `run_shell_command` Input Handling

-   **Issue:** Attempting to pass multi-line strings directly as `stdin` to shell commands (e.g., `git commit -F -`) via the `command` argument resulted in errors (`Aborting commit due to empty commit message.` or `Command substitution not allowed`).
-   **Lesson:** The `input` argument of `run_shell_command` does not directly pipe to `stdin` of the command. For multi-line input, write the content to a temporary file and then pass the file path to the command (e.g., `git commit -F <temp_file>`).
-   **Best Practice:** For `git commit` messages, always write to a temporary file and use `git commit -F <temp_file>`.

### 2. Absolute Path Requirement for File Operations

-   **Issue:** Repeatedly encountered `Error: Invalid parameters provided. Reason: File path must be absolute:` when using `write_file` or other file system tools with relative paths.
-   **Lesson:** All file system tools (`read_file`, `write_file`, `replace`, `list_directory`, `glob`, `search_file_content`) strictly require **absolute paths**. Always construct the full absolute path by combining the project root with the relative path.
-   **Best Practice:** Before any file system operation, ensure the `file_path` argument is an absolute path.

### 3. `docker-compose` Usage in Subdirectories

-   **Issue:** Attempting to use `directory="my_lemp_project"` with `docker-compose` commands resulted in "Directory 'my_lemp_project' is not a registered workspace directory."
-   **Lesson:** The `directory` argument for `run_shell_command` expects a registered workspace directory (typically the project root). When `docker-compose.yml` is in a subdirectory, execute `docker-compose` from the project root and use the `-f` flag to specify the path to the YAML file.
-   **Example:** Instead of `run_shell_command(command="docker-compose up", directory="my_lemp_project")`, use `run_shell_command(command="docker-compose -f my_lemp_project/docker-compose.yml up")`.

### 4. Handling Permission Denied Errors

-   **Issue:** Encountered "Permission denied" when attempting to delete files/directories (`rm -rf`).
-   **Lesson:** The agent operates without `sudo` privileges. If a permission error occurs for file system modifications, the agent cannot directly resolve it.
-   **Best Practice:** Inform the user about the permission issue and advise them to perform the action manually or provide necessary permissions. Do not attempt to bypass permission errors.

### 5. Precision in `replace` `old_string`

-   **Issue:** `replace` operations failed because the `old_string` did not *exactly* match the content in the file (due to subtle differences in whitespace, newlines, or comments).
-   **Lesson:** The `old_string` parameter for the `replace` tool requires an **exact literal match**, including all whitespace, indentation, and newlines.
-   **Best Practice:** When replacing a significant block of code or text, first use `read_file` to fetch the exact content of the `old_string` directly from the target file to ensure a precise match.

### 6. Handling Nested String Literals and Escaping (PHP/JS Example)

-   **Issue:** A PHP parse error occurred due to complex escaping of backslashes in a JavaScript string embedded within a PHP string literal. The PHP interpreter misread the backslashes.
-   **Lesson:** Be extremely cautious when dealing with nested string literals, especially across different languages (e.g., PHP string containing JavaScript string). Backslashes (``) are escape characters in many languages, and their interpretation can lead to unexpected parse errors if not handled meticulously.
-   **Best Practice:**
    *   Minimize nesting of string literals.
    *   Use language-specific escaping functions (e.g., `addslashes` in PHP, `JSON.stringify` for JavaScript).
    *   Consider alternative data representations (e.g., JSON encoding/decoding) to avoid complex string manipulation.
    *   When debugging parse errors, simplify the problematic line/string to isolate the issue.

```