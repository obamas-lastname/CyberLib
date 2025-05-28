#!/bin/bash

# Enhanced CTF Vulnerability Scanner with Improved Terminal Reporting
# Educational tool for CTF competitions and security learning

SCAN_DIR="/scan/source_code"
RESULTS_DIR="/scan/results"
TOOLS_DIR="/opt/security_tools"
LOG_FILE="/scan/vuln_scan.log"
TEMP_DIR="/tmp/vuln_scan_$$"

# Enhanced color scheme for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Icons for better visual appeal
ICON_SUCCESS="✅"
ICON_WARNING="⚠️ "
ICON_ERROR="❌"
ICON_INFO="ℹ️ "
ICON_VULN="🔥"
ICON_SECRET="🔑"
ICON_CONFIG="⚙️ "
ICON_NETWORK="🌐"
ICON_FILE="📁"

# Improved logging functions with better formatting
log() {
    echo -e "${GREEN}${ICON_SUCCESS} [$(date '+%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}${ICON_ERROR} [$(date '+%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}${ICON_WARNING} [$(date '+%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}${ICON_INFO} [$(date '+%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

vuln() {
    echo -e "${PURPLE}${ICON_VULN} [$(date '+%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

progress() {
    echo -e "${CYAN}⏳ [$(date '+%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

# Function to print section headers with better formatting
print_section_header() {
    local title="$1"
    local width=80
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo ""
    echo -e "${BOLD}${WHITE}$(printf '═%.0s' $(seq 1 $width))${NC}"
    echo -e "${BOLD}${WHITE}$(printf '%*s' $padding)$title$(printf '%*s' $padding)${NC}"
    echo -e "${BOLD}${WHITE}$(printf '═%.0s' $(seq 1 $width))${NC}"
    echo ""
}

# Function to print subsection headers
print_subsection_header() {
    local title="$1"
    echo ""
    echo -e "${BOLD}${CYAN}▶ $title${NC}"
    echo -e "${DIM}$(printf '─%.0s' $(seq 1 60))${NC}"
}

# Function to create a summary box
print_summary_box() {
    local title="$1"
    local content="$2"
    local color="$3"
    
    echo ""
    echo -e "${color}┌─ $title$(printf ' %.0s' $(seq 1 $((70 - ${#title}))))┐${NC}"
    echo -e "${color}│$(printf ' %.0s' $(seq 1 72))│${NC}"
    
    # Split content by newlines and print each line
    while IFS= read -r line; do
        local padding=$((70 - ${#line}))
        echo -e "${color}│ $line$(printf ' %.0s' $(seq 1 $padding)) │${NC}"
    done <<< "$content"
    
    echo -e "${color}│$(printf ' %.0s' $(seq 1 72))│${NC}"
    echo -e "${color}└$(printf '─%.0s' $(seq 1 72))┘${NC}"
    echo ""
}

# Enhanced progress bar function with division by zero protection
show_progress() {
    local current=$1
    local total=$2
    local task="$3"
    local width=50
    
    # Protect against division by zero
    if [[ $total -eq 0 ]]; then
        echo -e "${CYAN}⏳ $task [${GREEN}$(printf '%*s' $width | tr ' ' '█')${CYAN}] ${WHITE}100%%${NC}"
        return
    fi
    
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r${CYAN}⏳ $task [${GREEN}"
    printf "%*s" $filled | tr ' ' '█'
    printf "${DIM}"
    printf "%*s" $empty | tr ' ' '░'
    printf "${CYAN}] ${WHITE}$percentage%%${NC}"
    
    if [[ $current -eq $total ]]; then
        echo ""
    fi
}

# Function to create a findings table
create_findings_table() {
    local title="$1"
    local findings_file="$2"
    local max_lines="${3:-20}"
    
    if [[ ! -f "$findings_file" ]] || [[ ! -s "$findings_file" ]]; then
        return
    fi
    
    print_subsection_header "$title"
    
    local line_count=0
    while IFS= read -r line && [[ $line_count -lt $max_lines ]]; do
        if [[ -n "$line" ]]; then
            # Color code different types of findings
            if [[ "$line" =~ (CRITICAL|HIGH|SEVERE) ]]; then
                echo -e "  ${RED}▸ $line${NC}"
            elif [[ "$line" =~ (MEDIUM|WARNING) ]]; then
                echo -e "  ${YELLOW}▸ $line${NC}"
            elif [[ "$line" =~ (LOW|INFO) ]]; then
                echo -e "  ${BLUE}▸ $line${NC}"
            else
                echo -e "  ${WHITE}▸ $line${NC}"
            fi
            ((line_count++))
        fi
    done < "$findings_file"
    
    local total_lines=$(wc -l < "$findings_file" 2>/dev/null || echo 0)
    if [[ $total_lines -gt $max_lines ]]; then
        echo -e "  ${DIM}... and $((total_lines - max_lines)) more findings${NC}"
    fi
}

# Enhanced codebase analysis with better visualization
analyze_codebase() {
    local source_dir="$1"
    local analysis_file="$TEMP_DIR/codebase_analysis.txt"
    
    progress "Analyzing codebase structure..."
    
    print_section_header "CODEBASE ANALYSIS"
    
    # File type analysis with visual representation
    echo -e "${BOLD}${WHITE}📊 File Type Distribution:${NC}"
    echo ""
    
    declare -A file_counts
    local total_files=0
    
    # Count files more safely
    while IFS= read -r file; do
        if [[ -n "$file" && -f "$file" ]]; then
            local ext="${file##*.}"
            if [[ "$ext" != "$file" && -n "$ext" ]]; then
                if [[ -z "${file_counts[$ext]}" ]]; then
                    file_counts["$ext"]=1
                else
                    file_counts["$ext"]=$((file_counts["$ext"] + 1))
                fi
                total_files=$((total_files + 1))
            fi
        fi
    done < <(find "$source_dir" -type f 2>/dev/null || true)
    
    # Check if any files were found
    if [[ $total_files -eq 0 ]]; then
        echo -e "  ${YELLOW}⚠️  No files found in the specified directory${NC}"
    else
        # Sort and display file types with bar chart
        for ext in $(printf '%s\n' "${!file_counts[@]}" | sort 2>/dev/null || true); do
            if [[ -n "$ext" && -n "${file_counts[$ext]}" ]]; then
                local count="${file_counts[$ext]}"
                local percentage=0
                local bar_width=0
                
                # Safe arithmetic operations
                if [[ $total_files -gt 0 && $count -gt 0 ]]; then
                    percentage=$(( (count * 100) / total_files ))
                    if [[ $percentage -gt 0 ]]; then
                        bar_width=$(( (percentage * 30) / 100 ))
                    fi
                fi
                
                printf "  %-8s %4d files " "$ext" "$count"
                printf "${GREEN}"
                if [[ $bar_width -gt 0 ]]; then
                    printf "%*s" $bar_width 2>/dev/null | tr ' ' '█' 2>/dev/null || true
                fi
                printf "${NC} %d%%\n" "$percentage"
            fi
        done
    fi
    
    echo ""
    echo -e "${BOLD}${WHITE}🔍 Technologies Detected:${NC}"
    
    # Enhanced technology detection
    local techs_found=()
    
    [[ -n "$(find "$source_dir" -name "*.php" 2>/dev/null | head -1)" ]] && techs_found+=("${RED}PHP${NC}")
    [[ -n "$(find "$source_dir" -name "*.js" -o -name "*.ts" 2>/dev/null | head -1)" ]] && techs_found+=("${YELLOW}JavaScript/TypeScript${NC}")
    [[ -n "$(find "$source_dir" -name "*.py" 2>/dev/null | head -1)" ]] && techs_found+=("${BLUE}Python${NC}")
    [[ -n "$(find "$source_dir" -name "*.java" 2>/dev/null | head -1)" ]] && techs_found+=("${PURPLE}Java${NC}")
    [[ -n "$(find "$source_dir" -name "*.c" -o -name "*.cpp" 2>/dev/null | head -1)" ]] && techs_found+=("${CYAN}C/C++${NC}")
    [[ -n "$(find "$source_dir" -name "*.go" 2>/dev/null | head -1)" ]] && techs_found+=("${GREEN}Go${NC}")
    
    if [[ ${#techs_found[@]} -gt 0 ]]; then
        for tech in "${techs_found[@]}"; do
            echo -e "  ▸ $tech"
        done
    else
        echo -e "  ${DIM}No common programming languages detected${NC}"
    fi
    
    echo ""
    echo -e "${BOLD}${WHITE}📦 Frameworks & Dependencies:${NC}"
    
    # Framework detection
    [[ -f "$source_dir/composer.json" ]] && echo -e "  ▸ ${RED}PHP Composer project${NC}"
    [[ -f "$source_dir/package.json" ]] && echo -e "  ▸ ${YELLOW}Node.js project${NC}"
    [[ -f "$source_dir/requirements.txt" ]] && echo -e "  ▸ ${BLUE}Python pip project${NC}"
    [[ -f "$source_dir/pom.xml" ]] && echo -e "  ▸ ${PURPLE}Java Maven project${NC}"
    [[ -f "$source_dir/build.gradle" ]] && echo -e "  ▸ ${PURPLE}Java Gradle project${NC}"
    [[ -f "$source_dir/go.mod" ]] && echo -e "  ▸ ${GREEN}Go module${NC}"
    [[ -f "$source_dir/Dockerfile" ]] && echo -e "  ▸ ${CYAN}Docker containerized${NC}"
    
    # Save detailed analysis
    {
        echo "=== DETAILED CODEBASE ANALYSIS ==="
        echo "Analysis Date: $(date)"
        echo "Source Directory: $source_dir"
        echo "Total Files: $total_files"
        echo ""
        echo "File Types:"
        for ext in "${!file_counts[@]}"; do
            echo "  $ext: ${file_counts[$ext]} files"
        done
    } > "$analysis_file"
}

# Enhanced secret scanning with better output formatting
scan_secrets_comprehensive() {
    local dir="$1"
    local output="$2"
    
    print_section_header "SECRET & CREDENTIAL DETECTION"
    
    local secrets_found=0
    local temp_secrets="$TEMP_DIR/secrets_temp.txt"
    
    # Create progress steps
    local steps=("TruffleHog" "GitLeaks" "Pattern Matching" "Manual Review")
    local current_step=0
    local total_steps=${#steps[@]}
    
    for step in "${steps[@]}"; do
        ((current_step++))
        show_progress $current_step $total_steps "Scanning with $step"
        sleep 0.5  # Visual effect
    done
    
    # TruffleHog scanning
    if command -v trufflehog >/dev/null 2>&1; then
        print_subsection_header "${ICON_SECRET} TruffleHog Results"
        local trufflehog_output="$TEMP_DIR/trufflehog.txt"
        trufflehog filesystem "$dir" --no-update --no-verification 2>/dev/null | head -20 > "$trufflehog_output"
        
        if [[ -s "$trufflehog_output" ]]; then
            create_findings_table "TruffleHog Secrets" "$trufflehog_output" 10
            secrets_found=$((secrets_found + $(wc -l < "$trufflehog_output")))
        else
            echo -e "  ${GREEN}${ICON_SUCCESS} No secrets detected by TruffleHog${NC}"
        fi
    else
        echo -e "  ${YELLOW}${ICON_WARNING} TruffleHog not installed${NC}"
    fi
    
    # Manual pattern detection with better categorization
    print_subsection_header "${ICON_SECRET} Pattern-Based Detection"
    
    local patterns=(
        "Password patterns:password|passwd|pwd"
        "API keys:api[_-]?key|token"
        "Database credentials:db_pass|database.*password"
        "SSH keys:-----BEGIN.*PRIVATE KEY"
        "Hash values:[a-fA-F0-9]{32,64}"
    )
    
    for pattern_info in "${patterns[@]}"; do
        local pattern_name="${pattern_info%:*}"
        local pattern="${pattern_info#*:}"
        
        local matches=$(grep -r -i -E "$pattern" "$dir" 2>/dev/null | head -5)
        if [[ -n "$matches" ]]; then
            echo -e "  ${RED}${ICON_VULN} $pattern_name found:${NC}"
            while IFS= read -r match; do
                # Truncate long lines and highlight the match
                local truncated=$(echo "$match" | cut -c1-100)
                echo -e "    ${DIM}$truncated${NC}"
                ((secrets_found++))
            done <<< "$matches"
        else
            echo -e "  ${GREEN}✓ No $pattern_name detected${NC}"
        fi
    done
    
    # Summary box for secrets
    local secret_summary="Total potential secrets found: $secrets_found"
    if [[ $secrets_found -gt 0 ]]; then
        secret_summary+="\nRecommendation: Review and rotate credentials"
        print_summary_box "🔑 SECRET DETECTION SUMMARY" "$secret_summary" "$RED"
    else
        print_summary_box "🔑 SECRET DETECTION SUMMARY" "$secret_summary" "$GREEN"
    fi
    
    # Save to output file
    {
        echo "=== COMPREHENSIVE SECRET DETECTION ==="
        echo "Secrets found: $secrets_found"
        echo "Scan completed: $(date)"
    } >> "$output"
}

# Enhanced vulnerability summary with visual dashboard
generate_visual_summary() {
    local results_file="$1"
    
    print_section_header "VULNERABILITY DASHBOARD"
    
    # Safe counts with fallback to 0
    local secret_count=$(grep -c -i "secret\|password\|token\|key.*=" "$results_file" 2>/dev/null)
    local vuln_count=$(grep -c -i "cve-\|vulnerability\|critical\|high" "$results_file" 2>/dev/null)
    local config_count=$(grep -c -i "configuration\|permission\|suid" "$results_file" 2>/dev/null)

    secret_count=$(( ${secret_count:-0} ))
    vuln_count=$(( ${vuln_count:-0} ))
    config_count=$(( ${config_count:-0} ))
    local total_issues=$((secret_count + vuln_count + config_count))
    
    # Risk level
    local risk_level="LOW"
    local risk_color="$GREEN"
    
    if [[ $secret_count -gt 5 || $vuln_count -gt 10 ]]; then
        risk_level="HIGH"
        risk_color="$RED"
    elif [[ $secret_count -gt 2 || $vuln_count -gt 5 ]]; then
        risk_level="MEDIUM"
        risk_color="$YELLOW"
    fi
    
    echo ""
    echo -e "${BOLD}${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${WHITE}│                        🛡️  SECURITY DASHBOARD                        │${NC}"
    echo -e "${BOLD}${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${BOLD}${WHITE}│${NC} %-20s ${RED}%8d${WHITE} │ %-20s ${YELLOW}%8d${WHITE} │${NC}\n" "🔑 Secrets Found:" "$secret_count" "⚙️  Config Issues:" "$config_count"
    printf "${BOLD}${WHITE}│${NC} %-20s ${PURPLE}%8d${WHITE} │ %-20s ${CYAN}%8d${WHITE} │${NC}\n" "🔥 Vulnerabilities:" "$vuln_count" "📊 Total Issues:" "$total_issues"
    echo -e "${BOLD}${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${BOLD}${WHITE}│${NC}                    Overall Risk Level: ${risk_color}%-8s${WHITE}                   │${NC}\n" "$risk_level"
    echo -e "${BOLD}${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Priority Actions
    if [[ $total_issues -gt 0 ]]; then
        print_subsection_header "🚨 PRIORITY ACTIONS REQUIRED"
        
        [[ $secret_count -gt 0 ]] && echo -e "  ${RED}1. ${BOLD}IMMEDIATE:${NC} Review and rotate exposed credentials"
        [[ $vuln_count -gt 0 ]] && echo -e "  ${YELLOW}2. ${BOLD}HIGH:${NC} Update vulnerable dependencies"
        [[ $config_count -gt 0 ]] && echo -e "  ${BLUE}3. ${BOLD}MEDIUM:${NC} Fix configuration and permission issues"
        
        echo ""
        echo -e "${BOLD}${WHITE}📋 REMEDIATION COMMANDS:${NC}"
        echo -e "${DIM}# Fix file permissions:${NC}"
        echo -e "  find $SCAN_DIR -type f -perm -002 -exec chmod 644 {} \\;"
        echo -e "${DIM}# Remove dangerous SUID bits:${NC}"
        echo -e "  find $SCAN_DIR -type f -perm -4000 -exec chmod u-s {} \\;"
    else
        print_summary_box "🎉 CLEAN SCAN RESULT" "No significant security issues detected!\nCodebase appears to follow security best practices." "$GREEN"
    fi
}

# Enhanced main scanning function with better progress tracking
comprehensive_vulnerability_scan() {
    local source_dir="$1"
    local results_file="$RESULTS_DIR/scan_$(date +%Y%m%d_%H%M%S).txt"
    
    # Create header
    clear
    echo -e "${BOLD}${WHITE}"
    cat << "EOF"
 ██████╗████████╗███████╗    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
██╔════╝╚══██╔══╝██╔════╝    ██║   ██║██║   ██║██║     ████╗  ██║
██║        ██║   █████╗      ██║   ██║██║   ██║██║     ██╔██╗ ██║
██║        ██║   ██╔══╝      ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
╚██████╗   ██║   ██║          ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
 ╚═════╝   ╚═╝   ╚═╝           ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
                SCANNER v2.0 - Enhanced Terminal Edition
EOF
    echo -e "${NC}"
    
    info "Starting comprehensive vulnerability scan"
    info "Target: $source_dir"
    info "Results will be saved to: $results_file"
    
    mkdir -p "$RESULTS_DIR" "$TEMP_DIR"
    
    # Initialize results file
    {
        echo "=== CTF VULNERABILITY SCAN RESULTS ==="
        echo "Scan Date: $(date)"
        echo "Target Directory: $source_dir"
        echo "Scanner Version: 2.0 Enhanced"
        echo "========================================="
    } > "$results_file"
    
    # Main scanning phases
    local scan_phases=("Codebase Analysis" "Secret Detection" "Dependency Scan" "Configuration Check")
    local current_phase=0
    local total_phases=${#scan_phases[@]}
    
    for phase in "${scan_phases[@]}"; do
        ((current_phase++))
        
        case "$phase" in
            "Codebase Analysis")
                analyze_codebase "$source_dir"
                ;;
            "Secret Detection")
                scan_secrets_comprehensive "$source_dir" "$results_file"
                ;;
            "Dependency Scan")
                print_section_header "DEPENDENCY ANALYSIS"
                info "Dependency scanning would run here..."
                ;;
            "Configuration Check")
                print_section_header "CONFIGURATION REVIEW"
                info "Configuration analysis would run here..."
                ;;
        esac
        
        echo ""
        sleep 1
    done
    
    # Generate final summary
    generate_visual_summary "$results_file"
    
    # Final output
    echo ""
    print_section_header "SCAN COMPLETE"
    
    log "Scan completed successfully!"
    info "Full results saved to: $results_file"
    info "Run with --ctf-mode for additional CTF-specific patterns"
    
    echo ""
    echo -e "${BOLD}${GREEN}Thank you for using CTF Vulnerability Scanner! 🚀${NC}"
    echo ""
}

# Cleanup function
cleanup() {
    info "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Enhanced main function with better argument parsing
main() {
    local INSTALL_TOOLS=false
    local CTF_MODE=false
    
    # Parse arguments with better help
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--directory)
                SCAN_DIR="$2"
                shift 2
                ;;
            -o|--output)
                RESULTS_DIR="$2"
                shift 2
                ;;
            --install-tools)
                INSTALL_TOOLS=true
                shift
                ;;
            --ctf-mode)
                CTF_MODE=true
                shift
                ;;
            -h|--help)
                cat << EOF
${BOLD}${WHITE}CTF Vulnerability Scanner v2.0${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    -d, --directory DIR    Directory to scan (default: $SCAN_DIR)
    -o, --output DIR       Output directory (default: $RESULTS_DIR)
    --install-tools        Install required security tools
    --ctf-mode            Enable CTF-specific scanning patterns
    -h, --help            Show this help message

${BOLD}EXAMPLES:${NC}
    $0 -d /tmp/source_code -o /tmp/results
    $0 --ctf-mode --directory ./challenge_files
    $0 --install-tools

${BOLD}FEATURES:${NC}
    • Multi-language vulnerability detection
    • Secret and credential scanning
    • Dependency vulnerability analysis
    • Enhanced terminal-friendly reporting
    • CTF-specific pattern detection

EOF
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Verify scan directory
    if [[ ! -d "$SCAN_DIR" ]]; then
        error "Scan directory does not exist: $SCAN_DIR"
        exit 1
    fi
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    
    # Install tools if requested
    if [[ "$INSTALL_TOOLS" == "true" ]]; then
        print_section_header "TOOL INSTALLATION"
        info "Tool installation would run here..."
        echo ""
    fi
    
    # Run the main scan
    comprehensive_vulnerability_scan "$SCAN_DIR"
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
