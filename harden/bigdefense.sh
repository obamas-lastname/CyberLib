#!/bin/bash

# CTF VM Security Hardening Script
# For CyberEDU Competition Environment
# WARNING: Test this script in a safe environment first!

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/ctf_hardening.log"
BACKUP_DIR="/root/ctf_backup_$(date +%Y%m%d_%H%M%S)"
CYBEREDU_USER="cyberedu"
SSH_PORT="2222"  # Change from default 22
MAX_AUTH_TRIES="3"
LOGIN_GRACE_TIME="60"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

# Print colored output
print_status() {
    local color="$1"
    shift
    echo -e "${color}$@${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Create backup directory
create_backup_dir() {
    log_info "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
}

# Backup critical files
backup_files() {
    log_info "Backing up critical configuration files..."
    
    local files_to_backup=(
        "/etc/ssh/sshd_config"
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/sudoers"
        "/etc/hosts"
        "/etc/iptables/rules.v4"
        "/etc/iptables/rules.v6"
        "/etc/fail2ban/jail.local"
        "/etc/sysctl.conf"
        "/etc/login.defs"
        "/etc/security/limits.conf"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [[ -f "$file" ]]; then
            cp "$file" "$BACKUP_DIR/$(basename $file).bak" 2>/dev/null || true
            log_info "Backed up: $file"
        fi
    done
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    
    if command -v apt-get &> /dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get upgrade -y -qq
        apt-get autoremove -y -qq
        apt-get autoclean -qq
    elif command -v yum &> /dev/null; then
        yum update -y -q
        yum clean all -q
    elif command -v dnf &> /dev/null; then
        dnf update -y -q
        dnf clean all -q
    fi
    
    log_success "System updated successfully"
}

# Install essential security tools
install_security_tools() {
    log_info "Installing essential security tools..."
    
    local tools=(
        "fail2ban"
        "ufw"
        "aide"
        "rkhunter"
        "chkrootkit"
        "lynis"
        "htop"
        "iotop"
        "netstat-nat"
        "tcpdump"
        "nmap"
        "auditd"
        "acct"
    )
    
    if command -v apt-get &> /dev/null; then
        for tool in "${tools[@]}"; do
            apt-get install -y -qq "$tool" 2>/dev/null || log_warn "Failed to install $tool"
        done
    elif command -v yum &> /dev/null; then
        for tool in "${tools[@]}"; do
            yum install -y -q "$tool" 2>/dev/null || log_warn "Failed to install $tool"
        done
    elif command -v dnf &> /dev/null; then
        for tool in "${tools[@]}"; do
            dnf install -y -q "$tool" 2>/dev/null || log_warn "Failed to install $tool"
        done
    fi
    
    log_success "Security tools installation completed"
}

# Secure SSH configuration
secure_ssh() {
    log_info "Securing SSH configuration..."
    
    local ssh_config="/etc/ssh/sshd_config"
    
    # Backup original config
    cp "$ssh_config" "$BACKUP_DIR/sshd_config.original"
    
    # Create new SSH config
    cat > "$ssh_config" << EOF
# CTF Hardened SSH Configuration
Port $SSH_PORT
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Connection settings
MaxAuthTries $MAX_AUTH_TRIES
LoginGraceTime $LOGIN_GRACE_TIME
MaxStartups 10:30:100
MaxSessions 4

# Security settings
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
AllowAgentForwarding no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Ciphers and algorithms (secure ones only)
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256

# Allow specific users
AllowUsers $CYBEREDU_USER
EOF
    
    # Test SSH config
    if sshd -t; then
        log_success "SSH configuration is valid"
        systemctl restart sshd || service ssh restart
        log_info "SSH service restarted on port $SSH_PORT"
    else
        log_error "SSH configuration is invalid, restoring backup"
        cp "$BACKUP_DIR/sshd_config.original" "$ssh_config"
        systemctl restart sshd || service ssh restart
    fi
}

# Configure firewall with UFW
configure_firewall() {
    log_info "Configuring UFW firewall..."
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH on new port
    ufw allow $SSH_PORT/tcp comment 'SSH'
    
    # Allow common web services (adjust based on your needs)
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow from your blue team network
    ufw allow from 10.11.158.0/24 comment 'Blue team network'
    
    # Rate limiting for SSH
    ufw limit $SSH_PORT/tcp
    
    # Enable UFW
    ufw --force enable
    
    log_success "UFW firewall configured and enabled"
}

# Configure fail2ban
configure_fail2ban() {
    log_info "Configuring fail2ban..."
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban time (seconds)
bantime = 3600
# Find time window
findtime = 600
# Max retry attempts
maxretry = 3
# Backend
backend = auto

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = true
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 6

[apache-badbots]
enabled = true
filter = apache-badbots
logpath = /var/log/apache2/access.log
maxretry = 2

[apache-noscript]
enabled = true
filter = apache-noscript
logpath = /var/log/apache2/access.log
maxretry = 6

[apache-overflows]
enabled = true
filter = apache-overflows
logpath = /var/log/apache2/access.log
maxretry = 2
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "Fail2ban configured and started"
}

# Kernel hardening
kernel_hardening() {
    log_info "Applying kernel hardening settings..."
    
    cat >> /etc/sysctl.conf << EOF

# CTF Security Hardening
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# File system security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    sysctl -p
    log_success "Kernel hardening applied"
}

# Secure file permissions
secure_file_permissions() {
    log_info "Securing file permissions..."
    
    # Critical system files
    chmod 644 /etc/passwd
    chmod 640 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    chmod 600 /etc/ssh/sshd_config
    chmod 644 /etc/hosts
    chmod 600 /etc/crontab
    chmod 700 /root
    chmod 755 /home
    
    # Remove world-readable permissions from sensitive directories
    find /etc -type f -perm -o+r -exec chmod o-r {} \; 2>/dev/null || true
    
    # Secure log files
    chmod 640 /var/log/auth.log 2>/dev/null || true
    chmod 640 /var/log/syslog 2>/dev/null || true
    
    log_success "File permissions secured"
}

# User account security
secure_user_accounts() {
    log_info "Securing user accounts..."
    
    # Set password policy
    cat >> /etc/login.defs << EOF

# CTF Password Policy
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
PASS_MIN_LEN 12
EOF
    
    # Lock unnecessary accounts (but preserve cyberedu)
    local system_users=("daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody")
    
    for user in "${system_users[@]}"; do
        if id "$user" &>/dev/null; then
            usermod -L "$user" 2>/dev/null || true
            usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        fi
    done
    
    # Ensure cyberedu user is not locked
    usermod -U "$CYBEREDU_USER" 2>/dev/null || true
    
    log_success "User accounts secured"
}

# Configure auditd for monitoring
configure_auditd() {
    log_info "Configuring system auditing..."
    
    if command -v auditctl &> /dev/null; then
        cat > /etc/audit/rules.d/ctf-audit.rules << EOF
# CTF Audit Rules
# Monitor authentication events
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor system configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes
-w /etc/hosts -p wa -k hosts_changes
-w /etc/crontab -p wa -k cron_changes

# Monitor network configuration
-w /etc/network/interfaces -p wa -k network_changes
-w /etc/iptables/ -p wa -k iptables_changes

# Monitor privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -k privilege_escalation
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid!=0 -k privilege_escalation

# Monitor file access
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -k access_denied
EOF
        
        systemctl restart auditd
        log_success "Auditd configured and restarted"
    else
        log_warn "Auditd not available"
    fi
}

# Setup file integrity monitoring with AIDE
setup_aide() {
    log_info "Setting up AIDE file integrity monitoring..."
    
    if command -v aide &> /dev/null; then
        # Initialize AIDE database
        aide --init
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        
        # Create cron job for daily checks
        cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
aide --check > /var/log/aide-check.log 2>&1
if [ $? -ne 0 ]; then
    echo "AIDE detected changes!" | mail -s "AIDE Alert" root
fi
EOF
        chmod +x /etc/cron.daily/aide-check
        
        log_success "AIDE initialized and scheduled"
    else
        log_warn "AIDE not available"
    fi
}

# Configure log rotation and retention
configure_logging() {
    log_info "Configuring logging and retention..."
    
    # Ensure rsyslog is configured properly
    cat >> /etc/rsyslog.conf << EOF

# CTF Enhanced logging
auth,authpriv.*          /var/log/auth.log
*.*;auth,authpriv.none   -/var/log/syslog
kern.*                   -/var/log/kern.log
mail.*                   -/var/log/mail.log
user.*                   -/var/log/user.log
EOF
    
    systemctl restart rsyslog
    
    # Configure logrotate for security logs
    cat > /etc/logrotate.d/ctf-security << EOF
/var/log/auth.log
/var/log/fail2ban.log
/var/log/ufw.log
{
    daily
    missingok
    rotate 30
    compress
    notifempty
    create 640 root adm
}
EOF
    
    log_success "Logging configured"
}

# Remove unnecessary packages and services
remove_unnecessary() {
    log_info "Removing unnecessary packages and services..."
    
    # Potentially unnecessary packages (be careful!)
    local packages_to_remove=(
        "telnet"
        "rsh-client"
        "rsh-redone-client"
        "talk"
        "finger"
    )
    
    if command -v apt-get &> /dev/null; then
        for package in "${packages_to_remove[@]}"; do
            apt-get remove -y -qq "$package" 2>/dev/null || true
        done
    fi
    
    # Disable unnecessary services
    local services_to_disable=(
        "avahi-daemon"
        "cups"
        "bluetooth"
    )
    
    for service in "${services_to_disable[@]}"; do
        systemctl disable "$service" 2>/dev/null || true
        systemctl stop "$service" 2>/dev/null || true
    done
    
    log_success "Unnecessary packages and services removed/disabled"
}

# Setup monitoring scripts
setup_monitoring() {
    log_info "Setting up monitoring scripts..."
    
    # Create monitoring directory
    mkdir -p /opt/ctf-monitoring
    
    # Network monitoring script
    cat > /opt/ctf-monitoring/network-monitor.sh << 'EOF'
#!/bin/bash
# Network monitoring script
LOG_FILE="/var/log/network-monitor.log"
THRESHOLD=100  # Max connections per IP

netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | while read count ip; do
    if [[ $count -gt $THRESHOLD ]] && [[ $ip != "127.0.0.1" ]] && [[ $ip != "" ]]; then
        echo "$(date): Suspicious activity from $ip: $count connections" >> $LOG_FILE
        # Optionally block IP
        # ufw deny from $ip
    fi
done
EOF
    
    # System resource monitoring
    cat > /opt/ctf-monitoring/resource-monitor.sh << 'EOF'
#!/bin/bash
# Resource monitoring script
LOG_FILE="/var/log/resource-monitor.log"

# Check CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
    echo "$(date): High CPU usage: $CPU_USAGE%" >> $LOG_FILE
fi

# Check memory usage
MEM_USAGE=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')
if (( $(echo "$MEM_USAGE > 80" | bc -l) )); then
    echo "$(date): High memory usage: $MEM_USAGE%" >> $LOG_FILE
fi

# Check disk usage
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
if [[ $DISK_USAGE -gt 80 ]]; then
    echo "$(date): High disk usage: $DISK_USAGE%" >> $LOG_FILE
fi
EOF
    
    chmod +x /opt/ctf-monitoring/*.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/5 * * * * /opt/ctf-monitoring/network-monitor.sh") | crontab -
    (crontab -l 2>/dev/null; echo "*/10 * * * * /opt/ctf-monitoring/resource-monitor.sh") | crontab -
    
    log_success "Monitoring scripts setup completed"
}

# Create incident response script
create_incident_response() {
    log_info "Creating incident response script..."
    
    cat > /opt/ctf-monitoring/incident-response.sh << EOF
#!/bin/bash
# Incident Response Script

BACKUP_DIR="$BACKUP_DIR"
LOG_FILE="/var/log/incident-response.log"

log() {
    echo "\$(date): \$1" | tee -a \$LOG_FILE
}

# Function to restore from backup
restore_config() {
    local file="\$1"
    local backup_file="\$BACKUP_DIR/\$(basename \$file).bak"
    
    if [[ -f "\$backup_file" ]]; then
        cp "\$backup_file" "\$file"
        log "Restored \$file from backup"
    else
        log "ERROR: Backup file \$backup_file not found"
    fi
}

# Function to block suspicious IPs
block_ip() {
    local ip="\$1"
    ufw deny from "\$ip"
    log "Blocked IP: \$ip"
}

# Function to restart critical services
restart_services() {
    local services=("sshd" "fail2ban" "ufw")
    
    for service in "\${services[@]}"; do
        systemctl restart "\$service"
        log "Restarted service: \$service"
    done
}

case "\$1" in
    restore-ssh)
        restore_config "/etc/ssh/sshd_config"
        systemctl restart sshd
        ;;
    block-ip)
        block_ip "\$2"
        ;;
    restart-all)
        restart_services
        ;;
    *)
        echo "Usage: \$0 {restore-ssh|block-ip <ip>|restart-all}"
        exit 1
        ;;
esac
EOF
    
    chmod +x /opt/ctf-monitoring/incident-response.sh
    log_success "Incident response script created"
}

# Generate security report
generate_report() {
    log_info "Generating security report..."
    
    local report_file="/root/ctf_security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
CTF VM Security Hardening Report
Generated: $(date)
Hostname: $(hostname)
IP Address: $(hostname -I | awk '{print $1}')

=== APPLIED SECURITY MEASURES ===

1. SSH Security:
   - Changed SSH port to: $SSH_PORT
   - Disabled password authentication
   - Disabled root login
   - Enabled key-based authentication only
   - Applied connection limits

2. Firewall Configuration:
   - UFW enabled with restrictive rules
   - SSH rate limiting enabled
   - Only necessary ports opened

3. Fail2ban:
   - Configured for SSH protection
   - Web service protection enabled
   - Custom ban times and retry limits

4. System Hardening:
   - Kernel security parameters applied
   - File permissions secured
   - Unnecessary services disabled
   - User accounts secured

5. Monitoring:
   - Auditd configured for system monitoring
   - AIDE file integrity monitoring
   - Custom network and resource monitoring
   - Enhanced logging configured

6. Backup:
   - Configuration files backed up to: $BACKUP_DIR
   - Incident response procedures documented

=== IMPORTANT NOTES ===

- The 'cyberedu' user has been preserved as required
- SSH is now available on port $SSH_PORT
- All changes are logged in: $LOG_FILE
- Backups are stored in: $BACKUP_DIR
- Monitoring scripts located in: /opt/ctf-monitoring

=== NEXT STEPS ===

1. Test all services to ensure they work correctly
2. Monitor logs for any issues: tail -f $LOG_FILE
3. Review firewall rules: ufw status verbose
4. Check fail2ban status: fail2ban-client status
5. Monitor system: /opt/ctf-monitoring/resource-monitor.sh

EOF
    
    log_success "Security report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    print_status "$BLUE" "=== CTF VM Security Hardening Script ==="
    print_status "$YELLOW" "WARNING: This script will make significant changes to your system!"
    print_status "$YELLOW" "Make sure you have console access in case SSH becomes unavailable."
    
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Script cancelled by user"
        exit 0
    fi
    
    log_info "Starting CTF VM security hardening..."
    
    # Execute hardening steps
    check_root
    create_backup_dir
    backup_files
    update_system
    install_security_tools
    secure_ssh
    configure_firewall
    configure_fail2ban
    kernel_hardening
    secure_file_permissions
    secure_user_accounts
    configure_auditd
    setup_aide
    configure_logging
    remove_unnecessary
    setup_monitoring
    create_incident_response
    generate_report
    
    print_status "$GREEN" "=== Security hardening completed successfully! ==="
    print_status "$YELLOW" "IMPORTANT: SSH is now on port $SSH_PORT"
    print_status "$YELLOW" "IMPORTANT: Password authentication is disabled"
    print_status "$YELLOW" "IMPORTANT: Make sure you have SSH keys configured!"
    
    log_success "CTF VM security hardening completed"
}

# Execute main function
main "$@"
