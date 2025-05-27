#!/bin/bash

# Configuration - MODIFY THESE VALUES
BLUE_USER="backup_user"
BLUE_IP="10.0.0.100"
BLUE_PATH="/backup/vulnerable_vm"

# Second server for vulnerability scanning
SCAN_USER="scan_user"
SCAN_IP="10.0.0.200"
SCAN_PATH="/scan/source_code"

BACKUP_DIRS="/etc /var/www /home /opt /usr/local"
BACKUP_NAME="vm_backup_$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

log "Starting backup process..."

# Create temporary directory
TEMP_DIR="/tmp/backup_$$"
mkdir -p "$TEMP_DIR"

# Function to cleanup on exit
cleanup() {
    log "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Create backup archive
log "Creating backup archive..."
cd /
tar -czf "$TEMP_DIR/${BACKUP_NAME}.tar.gz" \
    --exclude='*.log' \
    --exclude='/tmp/*' \
    --exclude='/var/tmp/*' \
    --exclude='/proc/*' \
    --exclude='/sys/*' \
    --exclude='/dev/*' \
    --exclude='/run/*' \
    --exclude='/mnt/*' \
    --exclude='/media/*' \
    $BACKUP_DIRS 2>/dev/null

if [ $? -eq 0 ]; then
    log "Backup archive created successfully"
else
    error "Failed to create backup archive"
    exit 1
fi

# Get file size for progress
FILE_SIZE=$(du -h "$TEMP_DIR/${BACKUP_NAME}.tar.gz" | cut -f1)
log "Backup size: $FILE_SIZE"

# Test SSH connection first
log "Testing SSH connection to blue VM..."
ssh -o ConnectTimeout=5 -o BatchMode=yes "${BLUE_USER}@${BLUE_IP}" "echo 'Connection test successful'" 2>/dev/null
if [ $? -ne 0 ]; then
    error "Cannot connect to blue VM. Check SSH keys and network connectivity."
    exit 1
fi

# Create backup directory on blue VM
log "Creating backup directory on blue VM..."
ssh "${BLUE_USER}@${BLUE_IP}" "mkdir -p ${BLUE_PATH}" 2>/dev/null

# Transfer backup using SCP with progress
log "Transferring backup to blue VM..."
scp -o ConnectTimeout=10 -o ServerAliveInterval=5 \
    "$TEMP_DIR/${BACKUP_NAME}.tar.gz" \
    "${BLUE_USER}@${BLUE_IP}:${BLUE_PATH}/"

if [ $? -eq 0 ]; then
    log "Backup transferred successfully to ${BLUE_USER}@${BLUE_IP}:${BLUE_PATH}/${BACKUP_NAME}.tar.gz"
    
    # Create a "latest" symlink on blue VM
    ssh "${BLUE_USER}@${BLUE_IP}" "cd ${BLUE_PATH} && rm -f latest_backup.tar.gz && ln -s ${BACKUP_NAME}.tar.gz latest_backup.tar.gz"
    
    # Save backup info locally
    echo "${BACKUP_NAME}.tar.gz" > /tmp/last_backup_name
    echo "$(date)" > /tmp/last_backup_time
    
    log "Backup process completed successfully!"
else
    error "Failed to transfer backup to blue VM"
    exit 1
fi

# Optional: Keep only last 5 backups on blue VM
log "Cleaning old backups on blue VM (keeping last 5)..."
ssh "${BLUE_USER}@${BLUE_IP}" "cd ${BLUE_PATH} && ls -1t vm_backup_*.tar.gz | tail -n +6 | xargs -r rm -f"

# Send to second server for vulnerability scanning
log "Sending backup to scanning server..."
ssh "${SCAN_USER}@${SCAN_IP}" "mkdir -p ${SCAN_PATH}" 2>/dev/null

scp -o ConnectTimeout=10 "$TEMP_DIR/${BACKUP_NAME}.tar.gz" \
    "${SCAN_USER}@${SCAN_IP}:${SCAN_PATH}/"

if [ $? -eq 0 ]; then
    log "Backup also sent to scanning server"
    
    # Trigger vulnerability scan on remote server
    ssh "${SCAN_USER}@${SCAN_IP}" "cd ${SCAN_PATH} && ./vuln_scanner.sh ${BACKUP_NAME}.tar.gz" &
    log "Vulnerability scan initiated on scanning server"
else
    warn "Failed to send backup to scanning server (continuing anyway)"
fi

log "Backup script finished!"