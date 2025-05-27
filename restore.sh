#!/bin/bash

# Configuration - MODIFY THESE VALUES
BLUE_USER="backup_user"
BLUE_IP="10.0.0.100"
BLUE_PATH="/backup/vulnerable_vm"
RESTORE_DIRS="/etc /var/www /home /opt /usr/local"

# Critical files to check for corruption
CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/apache2/apache2.conf"
    "/etc/nginx/nginx.conf"
    "/var/www/html/index.html"
    "/etc/fstab"
    "/etc/hosts"
)

# Critical directories
CRITICAL_DIRS=(
    "/etc"
    "/var/www"
    "/home"
    "/usr/local/bin"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

# Function to check file integrity
check_file_integrity() {
    local corruption_score=0
    local total_checks=0
    
    info "Checking critical files for corruption..."
    
    for file in "${CRITICAL_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            total_checks=$((total_checks + 1))
            
            # Check if file is readable
            if ! cat "$file" >/dev/null 2>&1; then
                warn "Cannot read $file - possibly corrupted"
                corruption_score=$((corruption_score + 3))
                continue
            fi
            
            # Check for null bytes (common corruption indicator)
            if grep -q $'\0' "$file" 2>/dev/null; then
                warn "Null bytes found in $file - likely corrupted"
                corruption_score=$((corruption_score + 2))
            fi
            
            # Check file size (if suspiciously small)
            size=$(wc -c < "$file" 2>/dev/null || echo 0)
            if [[ $size -lt 10 ]]; then
                warn "$file is suspiciously small ($size bytes)"
                corruption_score=$((corruption_score + 1))
            fi
            
            # Specific checks based on file type
            case "$file" in
                */passwd)
                    if ! grep -q "root:" "$file"; then
                        error "/etc/passwd missing root entry - corrupted!"
                        corruption_score=$((corruption_score + 5))
                    fi
                    ;;
                */sshd_config)
                    if ! grep -q "Port\|#Port" "$file"; then
                        warn "SSH config may be corrupted"
                        corruption_score=$((corruption_score + 2))
                    fi
                    ;;
                */apache2.conf|*/nginx.conf)
                    if [[ $(wc -l < "$file") -lt 5 ]]; then
                        warn "Web server config seems too short"
                        corruption_score=$((corruption_score + 2))
                    fi
                    ;;
            esac
        else
            warn "$file is missing!"
            corruption_score=$((corruption_score + 3))
        fi
    done
    
    echo $corruption_score
}

# Function to check directory integrity
check_directory_integrity() {
    local corruption_score=0
    
    info "Checking critical directories..."
    
    for dir in "${CRITICAL_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            # Check if directory is accessible
            if ! ls "$dir" >/dev/null 2>&1; then
                error "Cannot access $dir"
                corruption_score=$((corruption_score + 5))
                continue
            fi
            
            # Check for unusual file counts
            file_count=$(find "$dir" -type f 2>/dev/null | wc -l)
            
            case "$dir" in
                "/etc")
                    # /etc should have many files
                    if [[ $file_count -lt 50 ]]; then
                        warn "/etc has unusually few files ($file_count)"
                        corruption_score=$((corruption_score + 3))
                    fi
                    ;;
                "/var/www")
                    # Check if web root exists
                    if [[ ! -d "$dir/html" && ! -d "$dir/public" ]]; then
                        warn "Web document root missing"
                        corruption_score=$((corruption_score + 2))
                    fi
                    ;;
            esac
        else
            error "$dir directory is missing!"
            corruption_score=$((corruption_score + 5))
        fi
    done
    
    echo $corruption_score
}

# Function to check service status
check_service_status() {
    local corruption_score=0
    local critical_services=("ssh" "sshd" "apache2" "nginx" "mysql" "postgresql")
    
    info "Checking critical services..."
    
    for service in "${critical_services[@]}"; do
        # Skip if service doesn't exist
        if ! systemctl list-unit-files | grep -q "^$service"; then
            continue
        fi
        
        # Check if service should be running but isn't
        if systemctl is-enabled "$service" &>/dev/null; then
            if ! systemctl is-active "$service" &>/dev/null; then
                warn "$service is enabled but not running"
                corruption_score=$((corruption_score + 1))
            fi
        fi
    done
    
    echo $corruption_score
}

# Function to check system logs for corruption indicators
check_system_logs() {
    local corruption_score=0
    
    info "Checking system logs for corruption indicators..."
    
    # Check recent kernel messages for filesystem errors
    if dmesg | tail -n 100 | grep -i "error\|corruption\|fault" >/dev/null 2>&1; then
        warn "Found error messages in kernel log"
        corruption_score=$((corruption_score + 2))
    fi
    
    # Check system logs for critical errors
    if journalctl --since "1 hour ago" --priority=err --no-pager -q 2>/dev/null | head -n 10 | grep -q .; then
        warn "Found recent critical errors in system log"
        corruption_score=$((corruption_score + 1))
    fi
    
    echo $corruption_score
}

# Main corruption detection function
detect_corruption() {
    local total_score=0
    
    log "Starting corruption detection..."
    
    # Run all checks
    file_score=$(check_file_integrity)
    dir_score=$(check_directory_integrity)
    service_score=$(check_service_status)
    log_score=$(check_system_logs)
    
    total_score=$((file_score + dir_score + service_score + log_score))
    
    info "Corruption scores:"
    info "  File integrity: $file_score"
    info "  Directory integrity: $dir_score"
    info "  Service status: $service_score"
    info "  System logs: $log_score"
    info "  Total corruption score: $total_score"
    
    # Determine corruption level
    if [[ $total_score -ge 10 ]]; then
        error "SEVERE corruption detected (score: $total_score)"
        return 3
    elif [[ $total_score -ge 5 ]]; then
        warn "MODERATE corruption detected (score: $total_score)"
        return 2
    elif [[ $total_score -ge 2 ]]; then
        warn "MINOR corruption detected (score: $total_score)"
        return 1
    else
        log "System appears healthy (score: $total_score)"
        return 0
    fi
}

# Function to restore from backup
restore_from_backup() {
    local backup_file="$1"
    
    log "Starting restoration from backup: $backup_file"
    
    # Create temporary directory
    TEMP_DIR="/tmp/restore_$$"
    mkdir -p "$TEMP_DIR"
    
    # Cleanup function
    cleanup() {
        log "Cleaning up temporary files..."
        rm -rf "$TEMP_DIR"
    }
    trap cleanup EXIT
    
    # Download backup from blue VM
    log "Downloading backup from blue VM..."
    scp -o ConnectTimeout=10 "${BLUE_USER}@${BLUE_IP}:${BLUE_PATH}/${backup_file}" "$TEMP_DIR/"
    
    if [[ $? -ne 0 ]]; then
        error "Failed to download backup from blue VM"
        return 1
    fi
    
    # Verify backup file
    if [[ ! -f "$TEMP_DIR/$backup_file" ]]; then
        error "Backup file not found after download"
        return 1
    fi
    
    # Test backup integrity
    log "Testing backup integrity..."
    if ! tar -tzf "$TEMP_DIR/$backup_file" >/dev/null 2>&1; then
        error "Backup file appears to be corrupted"
        return 1
    fi
    
    # Create pre-restore backup of current state
    log "Creating pre-restore backup..."
    tar -czf "$TEMP_DIR/pre_restore_backup.tar.gz" $RESTORE_DIRS 2>/dev/null
    
    # Stop critical services before restore
    log "Stopping services for restoration..."
    systemctl stop apache2 nginx mysql postgresql 2>/dev/null
    
    # Restore files
    log "Restoring files from backup..."
    cd /
    tar -xzf "$TEMP_DIR/$backup_file" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        log "Files restored successfully"
        
        # Restart services
        log "Restarting services..."
        systemctl start apache2 nginx mysql postgresql ssh 2>/dev/null
        
        # Fix permissions
        log "Fixing critical file permissions..."
        chmod 644 /etc/passwd /etc/group /etc/hosts
        chmod 600 /etc/shadow /etc/sudoers
        chmod 644 /etc/ssh/sshd_config
        chown -R www-data:www-data /var/www 2>/dev/null
        
        log "Restoration completed successfully!"
        return 0
    else
        error "Restoration failed"
        
        # Attempt to restore pre-restore backup
        warn "Attempting to restore previous state..."
        tar -xzf "$TEMP_DIR/pre_restore_backup.tar.gz" 2>/dev/null
        
        return 1
    fi
}

# Main script logic
case "${1:-detect}" in
    detect)
        detect_corruption
        exit_code=$?
        
        case $exit_code in
            0) log "No significant corruption detected" ;;
            1) warn "Minor corruption detected - consider monitoring closely" ;;
            2) warn "Moderate corruption detected - restoration recommended" ;;
            3) error "Severe corruption detected - immediate restoration required" ;;
        esac
        
        exit $exit_code
        ;;
    
    restore)
        # Get latest backup name
        backup_file="latest_backup.tar.gz"
        if [[ -n "$2" ]]; then
            backup_file="$2"
        fi
        
        restore_from_backup "$backup_file"
        ;;
    
    auto)
        detect_corruption
        corruption_level=$?
        
        if [[ $corruption_level -ge 2 ]]; then
            warn "Corruption level $corruption_level detected - starting automatic restoration"
            restore_from_backup "latest_backup.tar.gz"
        else
            log "Corruption level $corruption_level - no restoration needed"
        fi
        ;;
    
    list-backups)
        log "Available backups on blue VM:"
        ssh "${BLUE_USER}@${BLUE_IP}" "ls -la ${BLUE_PATH}/*.tar.gz" 2>/dev/null || error "Could not list backups"
        ;;
    
    *)
        echo "Usage: $0 {detect|restore [backup_file]|auto|list-backups}"
        echo ""
        echo "  detect       - Check for corruption and report level"
        echo "  restore      - Restore from backup (latest or specified file)"
        echo "  auto         - Detect corruption and auto-restore if severe"
        echo "  list-backups - Show available backups on blue VM"
        exit 1
        ;;
esac