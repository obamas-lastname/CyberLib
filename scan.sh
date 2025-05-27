#!/bin/bash

# Comprehensive vulnerability scanner for competition environments
# Supports: PHP, JavaScript, Python, Java, C/C++, Go, binaries, and more
# Uses multiple open-source security tools for maximum coverage

SCAN_DIR="/scan/source_code"
RESULTS_DIR="/scan/results"
TOOLS_DIR="/opt/security_tools"
LOG_FILE="/scan/vuln_scan.log"
TEMP_DIR="/tmp/vuln_scan_$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

vuln() {
    echo -e "${PURPLE}[$(date '+%Y-%m-%d %H:%M:%S')] VULNERABILITY: $1${NC}" | tee -a "$LOG_FILE"
}

progress() {
    echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')] PROGRESS: $1${NC}" | tee -a "$LOG_FILE"
}

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Function to detect system architecture and OS
detect_system() {
    ARCH=$(uname -m)
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get >/dev/null; then
            DISTRO="debian"
        elif command -v yum >/dev/null; then
            DISTRO="rhel"
        elif command -v pacman >/dev/null; then
            DISTRO="arch"
        else
            DISTRO="unknown"
        fi
    fi
    
    log "Detected system: $OS/$DISTRO on $ARCH"
}

# Function to install system dependencies
install_system_deps() {
    progress "Installing system dependencies..."
    
    case $DISTRO in
        debian)
            apt-get update -qq
            apt-get install -y curl wget git unzip tar gzip python3 python3-pip \
                nodejs npm golang-go openjdk-11-jdk maven gradle \
                php php-cli php-xml clang gcc g++ make cmake \
                binutils file strings objdump hexdump \
                ruby gem libxml2-utils jq yq parallel \
                git-core build-essential libssl-dev libffi-dev \
                sqlite3 libsqlite3-dev ripgrep fd-find 2>/dev/null
            ;;
        rhel)
            yum check-update -q
            yum install -y curl wget git unzip tar gzip python3 python3-pip \
                nodejs npm golang java-11-openjdk-devel maven \
                php php-cli php-xml clang gcc gcc-c++ make cmake \
                binutils file strings \
                ruby rubygems libxml2 jq parallel \
                git-core openssl-devel libffi-devel \
                sqlite sqlite-devel 2>/dev/null
            ;;
        arch)
            pacman -Sy --noconfirm curl wget git unzip tar gzip python python-pip \
                nodejs npm go jdk11-openjdk maven gradle \
                php clang gcc make cmake \
                binutils file strings \
                ruby rubygems libxml2 jq parallel \
                openssl libffi sqlite ripgrep fd 2>/dev/null
            ;;
    esac
}

# Function to install Python security tools
install_python_tools() {
    progress "Installing Python security tools..."
    
    pip3 install --upgrade pip setuptools wheel 2>/dev/null
    
    # Core security tools
    pip3 install bandit safety semgrep pysafe dlint \
                 detect-secrets pypinfo vulndb \
                 cyclonedx-bom py-find-injection \
                 audit-python-package 2>/dev/null
    
    # Web security tools
    pip3 install xsscrapy sqlparse html5lib beautifulsoup4 \
                 requests urllib3 2>/dev/null
}

# Function to install Node.js security tools
install_nodejs_tools() {
    progress "Installing Node.js security tools..."
    
    # Global npm security tools
    npm install -g eslint eslint-plugin-security \
                   retire jshint jslint \
                   npm-audit nsp snyk \
                   yarn-audit-fix audit-ci \
                   better-npm-audit 2>/dev/null
    
    # Additional security scanners
    npm install -g @0xsecurity/dumpster \
                   nodejs-scan njsscan 2>/dev/null
}

# Function to install specialized security tools
install_security_tools() {
    progress "Installing specialized security tools..."
    mkdir -p "$TOOLS_DIR"
    cd "$TOOLS_DIR"
    
    # TruffleHog v3 (secrets detection)
    if ! command -v trufflehog >/dev/null; then
        log "Installing TruffleHog v3..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
    fi
    
    # GitLeaks (secret scanner)
    if ! command -v gitleaks >/dev/null; then
        log "Installing GitLeaks..."
        latest=$(curl -s https://api.github.com/repos/zricethezav/gitleaks/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
        wget -q "https://github.com/zricethezav/gitleaks/releases/download/${latest}/gitleaks_linux_${ARCH}.tar.gz" -O gitleaks.tar.gz
        tar -xzf gitleaks.tar.gz && mv gitleaks /usr/local/bin/ && rm gitleaks.tar.gz
    fi
    
    # CodeQL CLI (GitHub's code analysis)
    if ! command -v codeql >/dev/null; then
        log "Installing CodeQL CLI..."
        latest=$(curl -s https://api.github.com/repos/github/codeql-cli-binaries/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
        wget -q "https://github.com/github/codeql-cli-binaries/releases/download/${latest}/codeql-linux64.zip" -O codeql.zip
        unzip -q codeql.zip && mv codeql /opt/ && ln -sf /opt/codeql/codeql /usr/local/bin/
        rm codeql.zip
        
        # Download CodeQL standard libraries
        git clone --depth 1 https://github.com/github/codeql /opt/codeql-repo 2>/dev/null
    fi
    
    # Semgrep (already in pip, but ensure latest)
    pip3 install --upgrade semgrep 2>/dev/null
    
    # Bearer (security scanner)
    if ! command -v bearer >/dev/null; then
        log "Installing Bearer..."
        curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
    fi
    
    # Grype (vulnerability scanner for containers/packages)
    if ! command -v grype >/dev/null; then
        log "Installing Grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
    fi
    
    # Syft (SBOM generator)
    if ! command -v syft >/dev/null; then
        log "Installing Syft..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
    fi
    
    # Safety CLI (Python dependency vulnerabilities)
    if ! command -v safety >/dev/null; then
        pip3 install safety 2>/dev/null
    fi
    
    # OSV Scanner (comprehensive vulnerability scanner)
    if ! command -v osv-scanner >/dev/null; then
        log "Installing OSV Scanner..."
        go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null
        cp "$(go env GOPATH)/bin/osv-scanner" /usr/local/bin/ 2>/dev/null
    fi
    
    # PHPStan (PHP static analysis)
    if ! command -v phpstan >/dev/null && command -v php >/dev/null; then
        log "Installing PHPStan..."
        wget -q https://github.com/phpstan/phpstan/releases/latest/download/phpstan.phar -O /usr/local/bin/phpstan
        chmod +x /usr/local/bin/phpstan
    fi
    
    # PHPCS Security Audit (PHP security)
    if command -v composer >/dev/null; then
        composer global require --dev squizlabs/php_codesniffer 2>/dev/null
        composer global require --dev securecodewarrior/sensei-security-for-php 2>/dev/null
    fi
    
    # Binwalk (binary analysis)
    if ! command -v binwalk >/dev/null; then
        log "Installing Binwalk..."
        git clone --depth 1 https://github.com/ReFirmLabs/binwalk.git
        cd binwalk && python3 setup.py install && cd .. && rm -rf binwalk
    fi
    
    cd - >/dev/null
}

# Function to detect file types in source code
analyze_codebase() {
    local source_dir="$1"
    local analysis_file="$TEMP_DIR/codebase_analysis.txt"
    
    progress "Analyzing codebase structure..."
    
    # Count files by extension
    echo "=== CODEBASE ANALYSIS ===" > "$analysis_file"
    echo "Analysis Date: $(date)" >> "$analysis_file"
    echo "Source Directory: $source_dir" >> "$analysis_file"
    echo "" >> "$analysis_file"
    
    # File type analysis
    echo "File Types Found:" >> "$analysis_file"
    find "$source_dir" -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn >> "$analysis_file"
    echo "" >> "$analysis_file"
    
    # Language detection
    echo "Programming Languages Detected:" >> "$analysis_file"
    
    local has_php=$(find "$source_dir" -name "*.php" | head -1)
    local has_js=$(find "$source_dir" -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" | head -1)
    local has_python=$(find "$source_dir" -name "*.py" | head -1)
    local has_java=$(find "$source_dir" -name "*.java" -o -name "*.class" | head -1)
    local has_c=$(find "$source_dir" -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" | head -1)
    local has_go=$(find "$source_dir" -name "*.go" | head -1)
    local has_ruby=$(find "$source_dir" -name "*.rb" | head -1)
    local has_binaries=$(find "$source_dir" -type f -executable | head -1)
    
    [[ -n "$has_php" ]] && echo "- PHP" >> "$analysis_file"
    [[ -n "$has_js" ]] && echo "- JavaScript/TypeScript" >> "$analysis_file"
    [[ -n "$has_python" ]] && echo "- Python" >> "$analysis_file"
    [[ -n "$has_java" ]] && echo "- Java" >> "$analysis_file"
    [[ -n "$has_c" ]] && echo "- C/C++" >> "$analysis_file"
    [[ -n "$has_go" ]] && echo "- Go" >> "$analysis_file"
    [[ -n "$has_ruby" ]] && echo "- Ruby" >> "$analysis_file"
    [[ -n "$has_binaries" ]] && echo "- Binaries/Executables" >> "$analysis_file"
    
    echo "" >> "$analysis_file"
    
    # Framework detection
    echo "Frameworks/Technologies Detected:" >> "$analysis_file"
    
    # Web frameworks
    if find "$source_dir" -name "composer.json" | head -1 | grep -q .; then
        echo "- PHP Composer project" >> "$analysis_file"
    fi
    if find "$source_dir" -name "package.json" | head -1 | grep -q .; then
        echo "- Node.js project" >> "$analysis_file"
    fi
    if find "$source_dir" -name "requirements.txt" -o -name "setup.py" -o -name "pyproject.toml" | head -1 | grep -q .; then
        echo "- Python project" >> "$analysis_file"
    fi
    if find "$source_dir" -name "pom.xml" -o -name "build.gradle" | head -1 | grep -q .; then
        echo "- Java Maven/Gradle project" >> "$analysis_file"
    fi
    if find "$source_dir" -name "go.mod" | head -1 | grep -q .; then
        echo "- Go module" >> "$analysis_file"
    fi
    
    log "Codebase analysis completed"
    cat "$analysis_file" | tee -a "$LOG_FILE"
}

# Enhanced secret scanning with multiple tools
scan_secrets_comprehensive() {
    local dir="$1"
    local output="$2"
    
    progress "Running comprehensive secret detection..."
    echo "=== COMPREHENSIVE SECRET DETECTION ===" >> "$output"
    
    # TruffleHog v3 (filesystem scan)
    if command -v trufflehog >/dev/null; then
        echo "--- TruffleHog Results ---" >> "$output"
        trufflehog filesystem "$dir" --no-update --no-verification 2>/dev/null | head -50 >> "$output"
        echo "" >> "$output"
    fi
    
    # GitLeaks
    if command -v gitleaks >/dev/null; then
        echo "--- GitLeaks Results ---" >> "$output"
        gitleaks detect --source "$dir" --no-git --report-format json --report-path "$TEMP_DIR/gitleaks.json" 2>/dev/null
        if [[ -f "$TEMP_DIR/gitleaks.json" ]]; then
            jq -r '.[] | "File: \(.File) | Secret: \(.Description) | Line: \(.StartLine)"' "$TEMP_DIR/gitleaks.json" 2>/dev/null >> "$output"
        fi
        echo "" >> "$output"
    fi
    
    # detect-secrets
    if command -v detect-secrets >/dev/null; then
        echo "--- detect-secrets Results ---" >> "$output"
        detect-secrets scan "$dir" 2>/dev/null | jq -r '.results | to_entries[] | "\(.key): \(.value | length) potential secrets"' >> "$output"
        echo "" >> "$output"
    fi
    
    # Manual patterns for competition-specific secrets
    echo "--- Manual Pattern Detection ---" >> "$output"
    grep -r -n -i -E "(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}" "$dir" 2>/dev/null | head -20 >> "$output"
    grep -r -n -E "(['\"]|^)[A-Za-z0-9+/]{40,}['\"]?" "$dir" 2>/dev/null | head -10 >> "$output"
    grep -r -n -E "(api[_-]?key|token|secret)['\"]?\s*[:=]\s*['\"][^'\"]{10,}" "$dir" 2>/dev/null | head -15 >> "$output"
    
    echo "" >> "$output"
}

# Advanced static analysis with multiple tools
run_static_analysis() {
    local dir="$1"
    local output="$2"
    
    progress "Running static analysis tools..."
    echo "=== STATIC ANALYSIS RESULTS ===" >> "$output"
    
    # Semgrep with security rules
    if command -v semgrep >/dev/null; then
        echo "--- Semgrep Security Analysis ---" >> "$output"
        semgrep --config=auto --severity=ERROR --severity=WARNING "$dir" 2>/dev/null | head -100 >> "$output"
        echo "" >> "$output"
        
        # Specific ruleset scans
        semgrep --config=p/security-audit --config=p/secrets --config=p/owasp-top-ten "$dir" 2>/dev/null | head -50 >> "$output"
        echo "" >> "$output"
    fi
    
    # Bearer security scanner
    if command -v bearer >/dev/null; then
        echo "--- Bearer Security Scan ---" >> "$output"
        bearer scan "$dir" --format json --output "$TEMP_DIR/bearer.json" 2>/dev/null
        if [[ -f "$TEMP_DIR/bearer.json" ]]; then
            jq -r '.findings[] | "Rule: \(.rule_id) | File: \(.filename) | Severity: \(.severity)"' "$TEMP_DIR/bearer.json" 2>/dev/null >> "$output"
        fi
        echo "" >> "$output"
    fi
    
    # CodeQL analysis (if database can be created)
    if command -v codeql >/dev/null; then
        echo "--- CodeQL Analysis ---" >> "$output"
        run_codeql_analysis "$dir" "$output"
        echo "" >> "$output"
    fi
}

# CodeQL specific analysis
run_codeql_analysis() {
    local dir="$1"
    local output="$2"
    
    # Detect languages for CodeQL
    local codeql_langs=""
    [[ -n "$(find "$dir" -name "*.java" | head -1)" ]] && codeql_langs="$codeql_langs,java"
    [[ -n "$(find "$dir" -name "*.js" -o -name "*.ts" | head -1)" ]] && codeql_langs="$codeql_langs,javascript"
    [[ -n "$(find "$dir" -name "*.py" | head -1)" ]] && codeql_langs="$codeql_langs,python"
    [[ -n "$(find "$dir" -name "*.cpp" -o -name "*.c" | head -1)" ]] && codeql_langs="$codeql_langs,cpp"
    [[ -n "$(find "$dir" -name "*.go" | head -1)" ]] && codeql_langs="$codeql_langs,go"
    
    codeql_langs=${codeql_langs#,}  # Remove leading comma
    
    if [[ -n "$codeql_langs" ]]; then
        local db_path="$TEMP_DIR/codeql_db"
        
        # Create CodeQL database
        codeql database create "$db_path" \
            --language="$codeql_langs" \
            --source-root="$dir" \
            --overwrite 2>/dev/null
        
        if [[ -d "$db_path" ]]; then
            # Run security queries
            codeql database analyze "$db_path" \
                --format=json \
                --output="$TEMP_DIR/codeql_results.json" \
                "/opt/codeql-repo/*/ql/src/Security/**/*.ql" 2>/dev/null
            
            if [[ -f "$TEMP_DIR/codeql_results.json" ]]; then
                echo "CodeQL found $(jq '.runs[0].results | length' "$TEMP_DIR/codeql_results.json" 2>/dev/null || echo "0") potential issues" >> "$output"
                jq -r '.runs[0].results[] | "Rule: \(.ruleId) | Message: \(.message.text) | File: \(.locations[0].physicalLocation.artifactLocation.uri)"' "$TEMP_DIR/codeql_results.json" 2>/dev/null | head -20 >> "$output"
            fi
        fi
    fi
}

# Language-specific vulnerability scanning
scan_language_specific() {
    local dir="$1"
    local output="$2"
    
    progress "Running language-specific vulnerability scans..."
    echo "=== LANGUAGE-SPECIFIC VULNERABILITY SCANS ===" >> "$output"
    
    # PHP Security Analysis
    if find "$dir" -name "*.php" | head -1 | grep -q .; then
        echo "--- PHP Security Analysis ---" >> "$output"
        scan_php_vulnerabilities "$dir" "$output"
        echo "" >> "$output"
    fi
    
    # JavaScript/Node.js Security
    if find "$dir" -name "*.js" -o -name "package.json" | head -1 | grep -q .; then
        echo "--- JavaScript/Node.js Security ---" >> "$output"
        scan_javascript_vulnerabilities "$dir" "$output"
        echo "" >> "$output"
    fi
    
    # Python Security
    if find "$dir" -name "*.py" -o -name "requirements.txt" | head -1 | grep -q .; then
        echo "--- Python Security Analysis ---" >> "$output"
        scan_python_vulnerabilities "$dir" "$output"
        echo "" >> "$output"
    fi
    
    # Java Security
    if find "$dir" -name "*.java" -o -name "pom.xml" | head -1 | grep -q .; then
        echo "--- Java Security Analysis ---" >> "$output"
        scan_java_vulnerabilities "$dir" "$output"
        echo "" >> "$output"
    fi
    
    # Binary Analysis
    if find "$dir" -type f -executable | head -1 | grep -q .; then
        echo "--- Binary Security Analysis ---" >> "$output"
        scan_binary_vulnerabilities "$dir" "$output"
        echo "" >> "$output"
    fi
}

# PHP-specific vulnerability scanning
scan_php_vulnerabilities() {
    local dir="$1"
    local output="$2"
    
    # PHPStan analysis
    if command -v phpstan >/dev/null; then
        echo "PHPStan static analysis:" >> "$output"
        phpstan analyze "$dir" --level=5 --no-progress 2>/dev/null | head -30 >> "$output"
    fi
    
    # Manual PHP vulnerability patterns
    echo "Manual PHP vulnerability scan:" >> "$output"
    
    # SQL Injection patterns
    grep -rn "mysql_query.*\$_\|mysqli_query.*\$_" "$dir" 2>/dev/null | head -10 >> "$output"
    
    # XSS patterns
    grep -rn "echo.*\$_GET\|echo.*\$_POST\|print.*\$_" "$dir" 2>/dev/null | head -10 >> "$output"
    
    # File inclusion
    grep -rn "include.*\$_\|require.*\$_" "$dir" 2>/dev/null | head -10 >> "$output"
    
    # Command injection
    grep -rn "system.*\$_\|exec.*\$_\|shell_exec.*\$_" "$dir" 2>/dev/null | head -10 >> "$output"
    
    # Deserialization
    grep -rn "unserialize.*\$_\|eval.*\$_" "$dir" 2>/dev/null | head -10 >> "$output"
}

# JavaScript-specific vulnerability scanning
scan_javascript_vulnerabilities() {
    local dir="$1"
    local output="$2"
    
    # ESLint security plugin
    if command -v eslint >/dev/null; then
        echo "ESLint security analysis:" >> "$output"
        cd "$dir" && eslint --ext .js,.ts . --format compact --no-eslintrc --config '{"plugins":["security"],"extends":["plugin:security/recommended"]}' 2>/dev/null | head -20 >> "$output"
        cd - >/dev/null
    fi
    
    # npm audit for dependencies
    if [[ -f "$dir/package.json" ]] && command -v npm >/dev/null; then
        echo "npm audit results:" >> "$output"
        cd "$dir" && npm audit --audit-level moderate 2>/dev/null | head -30 >> "$output"
        cd - >/dev/null
    fi
    
    # Manual JS patterns
    echo "Manual JavaScript vulnerability patterns:" >> "$output"
    grep -rn "eval(\|innerHTML.*+\|document.write(" "$dir" --include="*.js" 2>/dev/null | head -15 >> "$output"
}

# Python-specific vulnerability scanning
scan_python_vulnerabilities() {
    local dir="$1"
    local output="$2"
    
    # Bandit security analysis
    if command -v bandit >/dev/null; then
        echo "Bandit security analysis:" >> "$output"
        bandit -r "$dir" -f txt --severity-level medium 2>/dev/null | head -50 >> "$output"
    fi
    
    # Safety check for known vulnerabilities
    if [[ -f "$dir/requirements.txt" ]] && command -v safety >/dev/null; then
        echo "Safety vulnerability check:" >> "$output"
        cd "$dir" && safety check -r requirements.txt 2>/dev/null | head -20 >> "$output"
        cd - >/dev/null
    fi
    
    # Manual Python patterns
    echo "Manual Python vulnerability patterns:" >> "$output"
    grep -rn "eval(\|exec(\|pickle.loads\|__import__" "$dir" --include="*.py" 2>/dev/null | head -15 >> "$output"
}

# Java-specific vulnerability scanning
scan_java_vulnerabilities() {
    local dir="$1"
    local output="$2"
    
    # Look for Maven/Gradle dependencies
    if [[ -f "$dir/pom.xml" ]]; then
        echo "Maven project detected - checking for known vulnerable dependencies" >> "$output"
        grep -A2 -B2 "version>" "$dir/pom.xml" | head -20 >> "$output"
    fi
    
    # Manual Java patterns
    echo "Manual Java vulnerability patterns:" >> "$output"
    grep -rn "Runtime.getRuntime\|ProcessBuilder\|ScriptEngine" "$dir" --include="*.java" 2>/dev/null | head -15 >> "$output"
}

# Binary analysis for executables
scan_binary_vulnerabilities() {
    local dir="$1"
    local output="$2"
    
    echo "Binary security analysis:" >> "$output"
    
    find "$dir" -type f -executable | head -10 | while read binary; do
        echo "Analyzing binary: $binary" >> "$output"
        
        # File information
        file "$binary" 2>/dev/null >> "$output"
        
        # Check for security features
        if command -v checksec >/dev/null; then
            checksec --file="$binary" 2>/dev/null >> "$output"
        fi
        
        # Strings analysis (look for potential issues)
        strings "$binary" 2>/dev/null | grep -i -E "(password|admin|root|key|token)" | head -5 >> "$output"
        
        # Binwalk analysis if available
        if command -v binwalk >/dev/null; then
            binwalk "$binary" 2>/dev/null | head -10 >> "$output"
        fi
        
        echo "---" >> "$output"
    done
}

# Dependency and package vulnerability scanning
scan_dependencies() {
    local dir="$1"
    local output="$2"
    
    progress "Scanning dependencies for known vulnerabilities..."
    echo "=== DEPENDENCY VULNERABILITY SCAN ===" >> "$output"
    
    # Generate Software Bill of Materials (SBOM)
    if command -v syft >/dev/null; then
        echo "--- Software Bill of Materials ---" >> "$output"
        syft "$dir" -o json > "$TEMP_DIR/sbom.json" 2>/dev/null
        if [[ -f "$TEMP_DIR/sbom.json" ]]; then
            echo "Generated SBOM with $(jq '.artifacts | length' "$TEMP_DIR/sbom.json" 2>/dev/null) components" >> "$output"
        fi
    fi
    
    # Grype vulnerability scanning
    if command -v grype >/dev/null; then
        echo "--- Grype Vulnerability Scan ---" >> "$output"
        grype "$dir" -o json > "$TEMP_DIR/grype.json" 2>/dev/null
        if [[ -f "$TEMP_DIR/grype.json" ]]; then
            local vuln_count=$(jq '.matches | length' "$TEMP_DIR/grype.json" 2>/dev/null)
            echo "Found $vuln_count potential vulnerabilities in dependencies" >> "$output"
            jq -r '.matches[] | "CVE: \(.vulnerability.id) | Package: \(.artifact.name) | Severity: \(.vulnerability.severity)"' "$TEMP_DIR/grype.json" 2>/dev/null | head -20 >> "$output"
        fi
    fi
    
    # OSV Scanner
    if command -v osv-scanner >/dev/null; then
        echo "--- OSV Scanner Results ---" >> "$output"
        osv-scanner -r "$dir" --format json --output "$TEMP_DIR/osv.json" 2>/dev/null
        if [[ -f "$TEMP_DIR/osv.json" ]]; then
            jq -r '.results[]?.packages[]?.vulnerabilities[]? | "ID: \(.id) | Package: \(.package.name) | Summary: \(.summary)"' "$TEMP_DIR/osv.json" 2>/dev/null | head -15 >> "$output"
        fi
    fi
    
    echo "" >> "$output"
}

# Main comprehensive vulnerability scan
comprehensive_vulnerability_scan() {
    local source_dir="$1"
    local results_file="$RESULTS_DIR/comprehensive_scan_$(date +%Y%m%d_%H%M%S).txt"
    
    log "Starting comprehensive vulnerability scan of $source_dir"
    mkdir -p "$RESULTS_DIR" "$TEMP_DIR"
    
    echo "=== COMPREHENSIVE VULNERABILITY SCAN RESULTS ===" > "$results_file"
    echo "Scan Date: $(date)" >> "$results_file"
    echo "Source Directory: $source_dir" >> "$results_file"
    echo "=========================================" >> "$results_file"
    echo "" >> "$results_file"
    
    # Analyze codebase structure first
    analyze_codebase "$source_dir"
    cat "$TEMP_DIR/codebase_analysis.txt" >> "$results_file"
    
    # Run comprehensive secret scanning
    scan_secrets_comprehensive "$source_dir" "$results_file"
    
    # Run static analysis
    run_static_analysis "$source_dir" "$results_file"
    
    # Run language-specific scans
    scan_language_specific "$source_dir" "$results_file"
    
    # Scan dependencies
    scan_dependencies "$source_dir" "$results_file"
    
    # Network and service analysis
    scan_network_services "$results_file"
    
    # File permission analysis
    scan_file_permissions "$source_dir" "$results_file"
    
    # Configuration analysis
    scan_configurations "$source_dir" "$results_file"
    
    log "Comprehensive scan completed. Results saved to: $results_file"
    
    # Generate summary report
    generate_summary_report "$results_file"
}

# Network and service vulnerability scanning
scan_network_services() {
    local output="$1"
    
    progress "Scanning network services and open ports..."
    echo "=== NETWORK SERVICE ANALYSIS ===" >> "$output"
    
    # Check for running services
    echo "--- Active Network Services ---" >> "$output"
    if command -v netstat >/dev/null; then
        netstat -tlnp 2>/dev/null | grep LISTEN >> "$output"
    elif command -v ss >/dev/null; then
        ss -tlnp 2>/dev/null | grep LISTEN >> "$output"
    fi
    echo "" >> "$output"
    
    # Check for weak service configurations
    echo "--- Service Configuration Issues ---" >> "$output"
    
    # Apache/Nginx configs
    for config in /etc/apache2/apache2.conf /etc/nginx/nginx.conf /etc/httpd/conf/httpd.conf; do
        if [[ -f "$config" ]]; then
            echo "Analyzing $config:" >> "$output"
            grep -i "ServerTokens\|ServerSignature\|expose_php" "$config" 2>/dev/null >> "$output"
        fi
    done
    
    # SSH configuration
    if [[ -f /etc/ssh/sshd_config ]]; then
        echo "SSH configuration issues:" >> "$output"
        grep -E "^PermitRootLogin|^PasswordAuthentication|^Port" /etc/ssh/sshd_config 2>/dev/null >> "$output"
    fi
    
    echo "" >> "$output"
}

# File permission vulnerability analysis
scan_file_permissions() {
    local dir="$1"
    local output="$2"
    
    progress "Analyzing file permissions and ownership..."
    echo "=== FILE PERMISSION ANALYSIS ===" >> "$output"
    
    # World-writable files
    echo "--- World-Writable Files ---" >> "$output"
    find "$dir" -type f -perm -002 2>/dev/null | head -20 >> "$output"
    echo "" >> "$output"
    
    # SUID/SGID files
    echo "--- SUID/SGID Files ---" >> "$output"
    find "$dir" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20 >> "$output"
    echo "" >> "$output"
    
    # Files with no owner
    echo "--- Files with No Owner ---" >> "$output"
    find "$dir" -nouser -o -nogroup 2>/dev/null | head -10 >> "$output"
    echo "" >> "$output"
    
    # Sensitive files with weak permissions
    echo "--- Sensitive Files with Weak Permissions ---" >> "$output"
    find "$dir" -name "*.key" -o -name "*.pem" -o -name "*password*" -o -name "*secret*" | while read file; do
        if [[ -f "$file" ]]; then
            ls -la "$file" 2>/dev/null >> "$output"
        fi
    done
    echo "" >> "$output"
}

# Configuration file analysis
scan_configurations() {
    local dir="$1"
    local output="$2"
    
    progress "Scanning configuration files for security issues..."
    echo "=== CONFIGURATION ANALYSIS ===" >> "$output"
    
    # Database configuration files
    echo "--- Database Configuration Issues ---" >> "$output"
    find "$dir" -name "*.conf" -o -name "config.php" -o -name "database.yml" -o -name ".env" | while read config_file; do
        if [[ -f "$config_file" ]]; then
            echo "Analyzing $config_file:" >> "$output"
            grep -i -n "password\|username\|host\|port" "$config_file" 2>/dev/null | head -5 >> "$output"
            echo "---" >> "$output"
        fi
    done
    
    # Web server configurations
    echo "--- Web Server Configuration Issues ---" >> "$output"
    find "$dir" -name ".htaccess" -o -name "web.config" | while read web_config; do
        if [[ -f "$web_config" ]]; then
            echo "Analyzing $web_config:" >> "$output"
            cat "$web_config" 2>/dev/null >> "$output"
            echo "---" >> "$output"
        fi
    done
    
    # Docker configurations
    echo "--- Container Configuration Issues ---" >> "$output"
    find "$dir" -name "Dockerfile" -o -name "docker-compose.yml" | while read docker_file; do
        if [[ -f "$docker_file" ]]; then
            echo "Analyzing $docker_file:" >> "$output"
            grep -n "USER\|EXPOSE\|ENV.*PASSWORD" "$docker_file" 2>/dev/null >> "$output"
            echo "---" >> "$output"
        fi
    done
    
    echo "" >> "$output"
}

# Generate executive summary report
generate_summary_report() {
    local results_file="$1"
    local summary_file="${results_file%.txt}_summary.txt"
    
    progress "Generating executive summary report..."
    
    echo "=== EXECUTIVE SECURITY SUMMARY ===" > "$summary_file"
    echo "Generated: $(date)" >> "$summary_file"
    echo "=========================================" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Count different types of issues
    local secret_count=$(grep -c "VULNERABILITY\|Secret\|Password\|Token" "$results_file" 2>/dev/null || echo "0")
    local vuln_count=$(grep -c "CVE-\|vulnerability\|CRITICAL\|HIGH" "$results_file" 2>/dev/null || echo "0")
    local config_count=$(grep -c "configuration\|permission\|SUID" "$results_file" 2>/dev/null || echo "0")
    
    echo "SECURITY FINDINGS SUMMARY:" >> "$summary_file"
    echo "- Potential secrets/credentials: $secret_count" >> "$summary_file"
    echo "- Known vulnerabilities: $vuln_count" >> "$summary_file"
    echo "- Configuration issues: $config_count" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # High-priority findings
    echo "HIGH-PRIORITY FINDINGS:" >> "$summary_file"
    grep -i -A2 -B1 "critical\|high\|password.*=\|secret.*=" "$results_file" 2>/dev/null | head -20 >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Recommendations
    echo "IMMEDIATE ACTION ITEMS:" >> "$summary_file"
    echo "1. Review and rotate any exposed credentials" >> "$summary_file"
    echo "2. Update dependencies with known vulnerabilities" >> "$summary_file"
    echo "3. Fix file permission issues" >> "$summary_file"
    echo "4. Secure configuration files" >> "$summary_file"
    echo "5. Implement input validation and output encoding" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Generate quick remediation commands
    echo "QUICK REMEDIATION COMMANDS:" >> "$summary_file"
    echo "# Fix world-writable files:" >> "$summary_file"
    echo "find $SCAN_DIR -type f -perm -002 -exec chmod 644 {} \\;" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "# Remove SUID from non-essential files:" >> "$summary_file"
    echo "find $SCAN_DIR -type f -perm -4000 -exec chmod u-s {} \\;" >> "$summary_file"
    echo "" >> "$summary_file"
    
    log "Summary report generated: $summary_file"
    
    # Display summary to console
    echo ""
    echo "=== SCAN COMPLETE ==="
    echo "Full results: $results_file"
    echo "Summary: $summary_file"
    echo ""
    cat "$summary_file"
}

# CTF-specific vulnerability patterns
scan_ctf_patterns() {
    local dir="$1"
    local output="$2"
    
    progress "Scanning for common CTF vulnerability patterns..."
    echo "=== CTF-SPECIFIC VULNERABILITY PATTERNS ===" >> "$output"
    
    # Common CTF flags
    echo "--- Potential CTF Flags ---" >> "$output"
    grep -r -i -E "flag\{.*\}|ctf\{.*\}|[a-f0-9]{32}" "$dir" 2>/dev/null | head -10 >> "$output"
    echo "" >> "$output"
    
    # Command injection patterns
    echo "--- Command Injection Patterns ---" >> "$output"
    grep -r -n -E "system\(.*\$_|exec\(.*\$_|shell_exec\(.*\$_" "$dir" 2>/dev/null >> "$output"
    grep -r -n -E "os\.system\(|subprocess\.|eval\(" "$dir" --include="*.py" 2>/dev/null >> "$output"
    echo "" >> "$output"
    
    # SQL injection patterns
    echo "--- SQL Injection Patterns ---" >> "$output"
    grep -r -n -E "SELECT.*\$_|INSERT.*\$_|UPDATE.*\$_|DELETE.*\$_" "$dir" 2>/dev/null >> "$output"
    echo "" >> "$output"
    
    # File inclusion patterns
    echo "--- File Inclusion Patterns ---" >> "$output"
    grep -r -n -E "include.*\$_|require.*\$_|fopen.*\$_" "$dir" 2>/dev/null >> "$output"
    echo "" >> "$output"
    
    # Deserialization patterns
    echo "--- Unsafe Deserialization ---" >> "$output"
    grep -r -n -E "unserialize\(|pickle\.loads\(|yaml\.load\(" "$dir" 2>/dev/null >> "$output"
    echo "" >> "$output"
}

# Main function
main() {
    log "Starting CTF Defensive Vulnerability Scanner"
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root - this is recommended for full system scanning"
    fi
    
    # Parse command line arguments
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
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  -d, --directory DIR    Directory to scan (default: $SCAN_DIR)"
                echo "  -o, --output DIR       Output directory (default: $RESULTS_DIR)"
                echo "  --install-tools        Install security tools first"
                echo "  --ctf-mode            Enable CTF-specific scanning patterns"
                echo "  -h, --help            Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Detect system
    detect_system
    
    # Install tools if requested
    if [[ "$INSTALL_TOOLS" == "true" ]]; then
        install_system_deps
        install_python_tools
        install_nodejs_tools
        install_security_tools
    fi
    
    # Verify scan directory exists
    if [[ ! -d "$SCAN_DIR" ]]; then
        error "Scan directory does not exist: $SCAN_DIR"
        exit 1
    fi
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    
    # Run comprehensive scan
    comprehensive_vulnerability_scan "$SCAN_DIR"
    
    # Run CTF-specific patterns if enabled
    if [[ "$CTF_MODE" == "true" ]]; then
        local results_file="$RESULTS_DIR/comprehensive_scan_$(date +%Y%m%d_%H%M%S).txt"
        scan_ctf_patterns "$SCAN_DIR" "$results_file"
    fi
    
    log "Vulnerability scanning completed successfully!"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi