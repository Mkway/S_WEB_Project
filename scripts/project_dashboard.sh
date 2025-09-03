#!/bin/bash

# ==============================================
# S_WEB_Project 프로젝트 대시보드 스크립트
# ==============================================

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# 프로젝트 설정
PROJECT_ROOT="/home/wsl/S_WEB_Project"
WEBSEC_LAB_DIR="$PROJECT_ROOT/websec-lab/src/webhacking"

# 취약점 상태 추적
declare -A VULN_STATUS=()
declare -A VULN_NAMES=(
    ["sql_injection"]="SQL Injection"
    ["xss_test"]="XSS (Cross-Site Scripting)"
    ["command_injection"]="Command Injection"
    ["file_upload_test"]="File Upload"
    ["csrf_test"]="CSRF"
    ["file_inclusion"]="File Inclusion (LFI/RFI)"
    ["directory_traversal"]="Directory Traversal"
    ["auth_bypass"]="Authentication Bypass"
    ["xxe_test"]="XXE (XML External Entity)"
    ["ssrf_test"]="SSRF (Server-Side Request Forgery)"
    ["ssti_test"]="SSTI (Server-Side Template Injection)"
    ["open_redirect_test"]="Open Redirect"
    ["xpath_test"]="XPath Injection"
)

# 메시지 출력 함수들
print_header() {
    echo -e "${PURPLE}"
    echo "============================================================"
    echo "🚀 S_WEB_Project - 웹보안 취약점 테스트 플랫폼 대시보드"
    echo "============================================================"
    echo -e "${NC}"
}

print_section() {
    echo -e "${CYAN}$1${NC}"
    echo "------------------------------------------------------------"
}

print_status() {
    local status="$1"
    local message="$2"
    
    case $status in
        "completed")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "in_progress")
            echo -e "${YELLOW}🔄 $message${NC}"
            ;;
        "pending")
            echo -e "${BLUE}📋 $message${NC}"
            ;;
        "error")
            echo -e "${RED}❌ $message${NC}"
            ;;
        *)
            echo -e "${WHITE}⭕ $message${NC}"
            ;;
    esac
}

# 프로젝트 상태 분석 함수
analyze_project_status() {
    print_section "📊 프로젝트 현재 상태 분석"
    
    # Git 상태 확인
    cd "$PROJECT_ROOT"
    if git status &>/dev/null; then
        local git_status=$(git status --porcelain)
        if [[ -z "$git_status" ]]; then
            print_status "completed" "Git 작업 디렉토리 clean"
        else
            local changed_files=$(echo "$git_status" | wc -l)
            print_status "in_progress" "$changed_files 개 파일에 변경사항 있음"
        fi
        
        local current_branch=$(git branch --show-current)
        echo -e "   현재 브랜치: ${YELLOW}$current_branch${NC}"
        
        local last_commit=$(git log -1 --oneline 2>/dev/null || echo "커밋 없음")
        echo -e "   최근 커밋: ${BLUE}$last_commit${NC}"
    else
        print_status "error" "Git 저장소 아님"
    fi
    
    echo ""
}

# 취약점 테스트 상태 분석
analyze_vulnerability_status() {
    print_section "🔍 취약점 테스트 구현 상태"
    
    local completed_count=0
    local real_execution_count=0
    local total_vulns=${#VULN_NAMES[@]}
    
    for vuln_file in "${!VULN_NAMES[@]}"; do
        local full_path="$WEBSEC_LAB_DIR/${vuln_file}.php"
        local vuln_name="${VULN_NAMES[$vuln_file]}"
        
        if [[ -f "$full_path" ]]; then
            ((completed_count++))
            
            # 실제 실행 구현 여부 확인
            local implementation_status="시뮬레이션"
            
            # 파일 내용 분석
            if ! grep -q "시뮬레이션\|simulation" "$full_path" 2>/dev/null; then
                if grep -q "실제\|real.*execution\|file_get_contents\|curl\|exec\|system" "$full_path" 2>/dev/null; then
                    implementation_status="실제실행"
                    ((real_execution_count++))
                fi
            fi
            
            if [[ "$implementation_status" == "실제실행" ]]; then
                print_status "completed" "$vuln_name - $implementation_status"
            else
                print_status "in_progress" "$vuln_name - $implementation_status"
            fi
            
            VULN_STATUS[$vuln_file]="$implementation_status"
        else
            print_status "pending" "$vuln_name - 파일 없음"
            VULN_STATUS[$vuln_file]="미구현"
        fi
    done
    
    echo ""
    print_section "📈 구현 통계"
    echo -e "전체 취약점:     ${WHITE}$total_vulns${NC}개"
    echo -e "파일 생성됨:     ${GREEN}$completed_count${NC}개 ($(( completed_count * 100 / total_vulns ))%)"
    echo -e "실제 실행 구현:  ${YELLOW}$real_execution_count${NC}개 ($(( real_execution_count * 100 / total_vulns ))%)"
    echo -e "시뮬레이션만:    ${BLUE}$(( completed_count - real_execution_count ))${NC}개"
    echo -e "미구현:         ${RED}$(( total_vulns - completed_count ))${NC}개"
    echo ""
}

# 다음 우선순위 작업 추천
recommend_next_tasks() {
    print_section "🎯 다음 우선순위 작업 추천"
    
    # CLAUDE.md에서 정의한 중간 우선순위 취약점들
    local priority_vulns=("xxe_test" "ssrf_test" "ssti_test" "open_redirect_test" "xpath_test")
    local recommendations=()
    
    for vuln in "${priority_vulns[@]}"; do
        local status="${VULN_STATUS[$vuln]:-미구현}"
        local name="${VULN_NAMES[$vuln]}"
        
        case $status in
            "미구현")
                recommendations+=("🔴 HIGH: $name 파일 생성 및 기본 구현")
                ;;
            "시뮬레이션")
                recommendations+=("🟡 MEDIUM: $name 실제 실행으로 업그레이드")
                ;;
            "실제실행")
                recommendations+=("🟢 LOW: $name 이미 완료, 테스트 및 개선")
                ;;
        esac
    done
    
    if [[ ${#recommendations[@]} -eq 0 ]]; then
        print_status "completed" "모든 우선순위 작업 완료!"
    else
        echo -e "${YELLOW}추천 작업 순서:${NC}"
        local i=1
        for rec in "${recommendations[@]}"; do
            echo -e "  $i. $rec"
            ((i++))
        done
    fi
    echo ""
}

# 프로젝트 도구 상태 확인
check_project_tools() {
    print_section "🛠️  프로젝트 도구 상태"
    
    # 자동화 스크립트들 확인
    local scripts=(
        "vulnerability_dev_workflow.sh"
        "vulnerability_test.sh"
        "vulnerability_commit.sh"
        "project_dashboard.sh"
    )
    
    for script in "${scripts[@]}"; do
        local script_path="$PROJECT_ROOT/scripts/$script"
        if [[ -x "$script_path" ]]; then
            print_status "completed" "$script 실행 가능"
        elif [[ -f "$script_path" ]]; then
            print_status "in_progress" "$script 존재하지만 실행 권한 없음"
        else
            print_status "error" "$script 파일 없음"
        fi
    done
    
    # PHP 환경 확인
    if command -v php &> /dev/null; then
        local php_version=$(php -v | head -n1 | cut -d' ' -f2)
        print_status "completed" "PHP $php_version 사용 가능"
    else
        print_status "error" "PHP 설치되지 않음"
    fi
    
    # Docker 환경 확인
    if command -v docker &> /dev/null; then
        print_status "completed" "Docker 사용 가능"
    else
        print_status "in_progress" "Docker 미설치 (선택사항)"
    fi
    
    echo ""
}

# 개발 가이드 표시
show_development_guide() {
    print_section "📚 개발 워크플로우 가이드"
    
    echo -e "${YELLOW}1. 새 취약점 개발 시작:${NC}"
    echo "   ./scripts/vulnerability_dev_workflow.sh"
    echo ""
    
    echo -e "${YELLOW}2. 구현 완료 후 테스트:${NC}"
    echo "   ./scripts/vulnerability_test.sh [vulnerability_type]"
    echo ""
    
    echo -e "${YELLOW}3. 커밋 및 푸시:${NC}"
    echo "   ./scripts/vulnerability_commit.sh [vulnerability_type]"
    echo ""
    
    echo -e "${YELLOW}4. 프로젝트 상태 확인:${NC}"
    echo "   ./scripts/project_dashboard.sh"
    echo ""
    
    echo -e "${CYAN}품질 체크리스트: ${WHITE}docs/QUALITY_CHECKLIST.md${NC}"
    echo -e "${CYAN}개발 가이드: ${WHITE}CLAUDE.md${NC}"
    echo ""
}

# 빠른 액션 메뉴
show_quick_actions() {
    print_section "⚡ 빠른 액션"
    
    echo "다음 중 하나를 선택하세요:"
    echo ""
    echo "1) 🚀 새 취약점 개발 시작"
    echo "2) 🧪 특정 취약점 테스트"
    echo "3) 📦 변경사항 커밋"
    echo "4) 📊 상세 상태 보고서"
    echo "5) 📝 체크리스트 보기"
    echo "6) ❌ 종료"
    echo ""
    
    read -p "선택 (1-6): " choice
    
    case $choice in
        1)
            echo -e "${GREEN}새 취약점 개발을 시작합니다...${NC}"
            exec "$PROJECT_ROOT/scripts/vulnerability_dev_workflow.sh"
            ;;
        2)
            echo "테스트할 취약점 타입을 입력하세요 (예: xxe_test):"
            read -p "> " vuln_type
            exec "$PROJECT_ROOT/scripts/vulnerability_test.sh" "$vuln_type"
            ;;
        3)
            echo -e "${GREEN}커밋 프로세스를 시작합니다...${NC}"
            exec "$PROJECT_ROOT/scripts/vulnerability_commit.sh"
            ;;
        4)
            echo -e "${GREEN}상세 보고서를 생성합니다...${NC}"
            generate_detailed_report
            ;;
        5)
            echo -e "${GREEN}체크리스트를 표시합니다...${NC}"
            if command -v less &> /dev/null; then
                less "$PROJECT_ROOT/docs/QUALITY_CHECKLIST.md"
            else
                cat "$PROJECT_ROOT/docs/QUALITY_CHECKLIST.md"
            fi
            ;;
        6)
            echo -e "${YELLOW}대시보드를 종료합니다.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}잘못된 선택입니다.${NC}"
            ;;
    esac
}

# 상세 보고서 생성
generate_detailed_report() {
    local report_file="$PROJECT_ROOT/log/project_status_$(date +%Y%m%d_%H%M%S).md"
    
    {
        echo "# S_WEB_Project 상태 보고서"
        echo ""
        echo "생성일: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        
        echo "## Git 상태"
        git status
        echo ""
        
        echo "## 취약점 구현 현황"
        for vuln in "${!VULN_STATUS[@]}"; do
            echo "- ${VULN_NAMES[$vuln]}: ${VULN_STATUS[$vuln]}"
        done
        echo ""
        
        echo "## 파일 통계"
        echo "- 총 PHP 파일: $(find "$WEBSEC_LAB_DIR" -name "*.php" | wc -l)개"
        echo "- 총 라인 수: $(find "$WEBSEC_LAB_DIR" -name "*.php" -exec wc -l {} + | tail -1)"
        echo ""
        
    } > "$report_file"
    
    echo -e "${GREEN}상세 보고서 생성 완료: $report_file${NC}"
}

# 메인 함수
main() {
    clear
    print_header
    
    # 프로젝트 루트로 이동
    if [[ ! -d "$PROJECT_ROOT" ]]; then
        echo -e "${RED}프로젝트 루트 디렉토리를 찾을 수 없습니다: $PROJECT_ROOT${NC}"
        exit 1
    fi
    
    analyze_project_status
    analyze_vulnerability_status
    recommend_next_tasks
    check_project_tools
    show_development_guide
    
    # 인터랙티브 모드인지 확인
    if [[ $# -eq 0 ]]; then
        show_quick_actions
    fi
}

# 스크립트 실행
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi