#!/bin/bash

# Configuration
CHECK_INTERVAL=30  # seconds between checks
LOG_FILE="/var/log/service_monitor.log"
PID_FILE="/var/run/service_monitor.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        error "Service monitor already running with PID $OLD_PID"
        exit 1
    else
        warn "Removing stale PID file"
        rm -f "$PID_FILE"
    fi
fi

# Function to detect critical services
detect_services() {
    declare -A SERVICES
    
    # Web servers
    if systemctl is-enabled apache2 &>/dev/null || pgrep apache2 &>/dev/null; then
        SERVICES["apache2"]="Apache Web Server"
    fi
    if systemctl is-enabled nginx &>/dev/null || pgrep nginx &>/dev/null; then
        SERVICES["nginx"]="Nginx Web Server"
    fi
    
    # SSH
    if systemctl is-enabled ssh &>/dev/null || systemctl is-enabled sshd &>/dev/null || pgrep sshd &>/dev/null; then
        if systemctl is-enabled ssh &>/dev/null; then
            SERVICES["ssh"]="SSH Server"
        else
            SERVICES["sshd"]="SSH Server"
        fi
    fi
    
    # Database servers
    if systemctl is-enabled mysql &>/dev/null || pgrep mysqld &>/dev/null; then
        SERVICES["mysql"]="MySQL Database"
    fi
    if systemctl is-enabled postgresql &>/dev/null || pgrep postgres &>/dev/null; then
        SERVICES["postgresql"]="PostgreSQL Database"
    fi
    
    # FTP servers
    if systemctl is-enabled vsftpd &>/dev/null || pgrep vsftpd &>/dev/null; then
        SERVICES["vsftpd"]="FTP Server"
    fi
    if systemctl is-enabled proftpd &>/dev/null || pgrep proftpd &>/dev/null; then
        SERVICES["proftpd"]="ProFTPD Server"
    fi
    
    # DNS
    if systemctl is-enabled bind9 &>/dev/null || pgrep named &>/dev/null; then
        SERVICES["bind9"]="DNS Server"
    fi
    
    # Mail servers
    if systemctl is-enabled postfix &>/dev/null || pgrep master &>/dev/null; then
        SERVICES["postfix"]="Mail Server"
    fi
    
    # Docker
    if systemctl is-enabled docker &>/dev/null || pgrep dockerd &>/dev/null; then
        SERVICES["docker"]="Docker Service"
    fi
    
    # Custom services (add your competition-specific services here)
    # Example: SERVICES["custom-app"]="Custom Application"
    
    echo "${!SERVICES[@]}"
}

# Function to check if service is running
is_service_running() {
    local service="$1"
    
    # First check systemctl
    if systemctl is-active "$service" &>/dev/null; then
        return 0
    fi
    
    # If systemctl fails, check processes
    if pgrep "$service" &>/dev/null; then
        return 0
    fi
    
    return 1
}

# Function to restart service
restart_service() {
    local service="$1"
    local description="$2"
    
    warn "Attempting to restart $description ($service)"
    
    # Try systemctl first
    if systemctl restart "$service" 2>/dev/null; then
        log "Successfully restarted $description using systemctl"
        return 0
    fi
    
    # If systemctl fails, try service command
    if service "$service" restart 2>/dev/null; then
        log "Successfully restarted $description using service command"
        return 0
    fi
    
    error "Failed to restart $description ($service)"
    return 1
}

# Function to handle signals
cleanup() {
    info "Service monitor shutting down..."
    rm -f "$PID_FILE"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Main monitoring function
monitor_services() {
    local services=($(detect_services))
    
    if [ ${#services[@]} -eq 0 ]; then
        warn "No services detected to monitor"
        return
    fi
    
    log "Monitoring ${#services[@]} services: ${services[*]}"
    
    while true; do
        for service in "${services[@]}"; do
            if ! is_service_running "$service"; then
                error "$service is not running!"
                restart_service "$service" "$service"
                
                # Wait a bit and check again
                sleep 5
                if is_service_running "$service"; then
                    log "$service is now running"
                else
                    error "$service failed to start - manual intervention may be required"
                fi
            fi
        done
        
        sleep "$CHECK_INTERVAL"
    done
}

# Function to show status
show_status() {
    local services=($(detect_services))
    
    echo "Service Monitor Status"
    echo "====================="
    echo "Monitored Services: ${#services[@]}"
    echo "Check Interval: ${CHECK_INTERVAL} seconds"
    echo ""
    
    for service in "${services[@]}"; do
        if is_service_running "$service"; then
            echo -e "$service: ${GREEN}RUNNING${NC}"
        else
            echo -e "$service: ${RED}STOPPED${NC}"
        fi
    done
}

# Main script logic
case "${1:-start}" in
    start)
        if [[ $EUID -ne 0 ]]; then
            error "This script must be run as root"
            exit 1
        fi
        
        echo $$ > "$PID_FILE"
        log "Starting service monitor (PID: $$)"
        log "Log file: $LOG_FILE"
        
        # Initial service detection
        services=($(detect_services))
        log "Detected services: ${services[*]}"
        
        # Start monitoring
        monitor_services
        ;;
    
    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                kill "$PID"
                log "Service monitor stopped (PID: $PID)"
            else
                warn "Service monitor not running"
            fi
            rm -f "$PID_FILE"
        else
            warn "Service monitor not running"
        fi
        ;;
    
    status)
        show_status
        ;;
    
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        exit 1
        ;;
esac