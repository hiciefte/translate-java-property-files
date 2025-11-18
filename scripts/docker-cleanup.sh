#!/bin/bash
# Automated Docker cleanup for translation projects
# Purpose: Prevent disk space accumulation from Docker images and build cache
#
# This script safely removes:
# - Stopped containers older than 24 hours
# - Dangling images (untagged from builds)
# - Unused images older than 7 days (keeps recent builds for rollback)
# - Unused Docker volumes
# - Build cache older than 7 days
#
# Safety features:
# - Preserves running containers and their images
# - Keeps recent builds (7 days) for rollback capability
# - Logs all actions with before/after disk metrics
#
# Usage:
#   ./docker-cleanup.sh
#
# Recommended schedule: Weekly (e.g., cron job every Sunday 2 AM)
#
# Installation:
#   1. Copy this script to your project directory
#   2. Make executable: chmod +x docker-cleanup.sh
#   3. Test manually: ./docker-cleanup.sh
#   4. Add to cron: see docs/maintenance/disk-space-management.md

set -e
set -o pipefail  # Ensure pipe failures are detected

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${PROJECT_ROOT}/logs/docker-cleanup.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

echo "[$DATE] Starting Docker cleanup..." | tee -a "$LOG_FILE"

# Get disk usage before cleanup (in KB for robustness across systems)
BEFORE_AVAIL=$(df --block-size=1K / 2>/dev/null | awk 'NR==2 {print $4}')
if ! [[ "$BEFORE_AVAIL" =~ ^[0-9]+$ ]]; then
    # Fallback for systems without --block-size support (e.g., macOS)
    BEFORE_AVAIL=$(df -k / | awk 'NR==2 {print $4}')
    if ! [[ "$BEFORE_AVAIL" =~ ^[0-9]+$ ]]; then
        echo "[$DATE] Warning: Could not parse disk usage reliably" | tee -a "$LOG_FILE"
        BEFORE_AVAIL=0
    fi
fi
BEFORE_GB=$((BEFORE_AVAIL / 1024 / 1024))
# Extract percentage with robust parsing
BEFORE_PERCENT=$(df --output=pcent / 2>/dev/null | tail -1 | sed 's/[^0-9]//g')
if ! [[ "$BEFORE_PERCENT" =~ ^[0-9]+$ ]]; then
    # Fallback: find the column with % sign
    BEFORE_PERCENT=$(df / | awk 'NR==2 {for(i=1;i<=NF;i++) if($i ~ /%$/) {gsub(/%/, "", $i); print $i; exit}}')
    if ! [[ "$BEFORE_PERCENT" =~ ^[0-9]+$ ]]; then
        echo "[$DATE] Warning: Could not parse disk percentage reliably" | tee -a "$LOG_FILE"
        BEFORE_PERCENT=0
    fi
fi
echo "[$DATE] Disk before cleanup: ${BEFORE_GB} GB available (${BEFORE_PERCENT}% used)" | tee -a "$LOG_FILE"

# Remove stopped containers older than 24 hours
echo "[$DATE] Removing old containers..." | tee -a "$LOG_FILE"
docker container prune -f --filter "until=24h" 2>&1 | tee -a "$LOG_FILE"

# Remove dangling images (untagged images from builds)
echo "[$DATE] Removing dangling images..." | tee -a "$LOG_FILE"
docker image prune -f 2>&1 | tee -a "$LOG_FILE"

# Remove unused images older than 7 days (keeps recent builds)
echo "[$DATE] Removing unused images older than 7 days..." | tee -a "$LOG_FILE"
docker image prune -a -f --filter "until=168h" 2>&1 | tee -a "$LOG_FILE"

# Remove unused volumes
echo "[$DATE] Removing unused volumes..." | tee -a "$LOG_FILE"
docker volume prune -f 2>&1 | tee -a "$LOG_FILE"

# Remove build cache older than 7 days
echo "[$DATE] Removing old build cache..." | tee -a "$LOG_FILE"
docker builder prune -f --filter "until=168h" 2>&1 | tee -a "$LOG_FILE"

# Get disk usage after cleanup (in KB for robustness across systems)
AFTER_AVAIL=$(df --block-size=1K / 2>/dev/null | awk 'NR==2 {print $4}')
if ! [[ "$AFTER_AVAIL" =~ ^[0-9]+$ ]]; then
    # Fallback for systems without --block-size support (e.g., macOS)
    AFTER_AVAIL=$(df -k / | awk 'NR==2 {print $4}')
    if ! [[ "$AFTER_AVAIL" =~ ^[0-9]+$ ]]; then
        echo "[$DATE] Warning: Could not parse disk usage reliably" | tee -a "$LOG_FILE"
        AFTER_AVAIL=0
    fi
fi
AFTER_GB=$((AFTER_AVAIL / 1024 / 1024))
# Extract percentage with robust parsing
AFTER_PERCENT=$(df --output=pcent / 2>/dev/null | tail -1 | sed 's/[^0-9]//g')
if ! [[ "$AFTER_PERCENT" =~ ^[0-9]+$ ]]; then
    # Fallback: find the column with % sign
    AFTER_PERCENT=$(df / | awk 'NR==2 {for(i=1;i<=NF;i++) if($i ~ /%$/) {gsub(/%/, "", $i); print $i; exit}}')
    if ! [[ "$AFTER_PERCENT" =~ ^[0-9]+$ ]]; then
        echo "[$DATE] Warning: Could not parse disk percentage reliably" | tee -a "$LOG_FILE"
        AFTER_PERCENT=0
    fi
fi
FREED_KB=$((AFTER_AVAIL - BEFORE_AVAIL))
FREED_GB=$((FREED_KB / 1024 / 1024))
PERCENT_CHANGE=$((BEFORE_PERCENT - AFTER_PERCENT))

echo "[$DATE] Disk after cleanup: ${AFTER_GB} GB available (${AFTER_PERCENT}% used)" | tee -a "$LOG_FILE"
if [ "$FREED_GB" -gt 0 ]; then
    echo "[$DATE] Space freed: ${FREED_GB} GB (disk usage reduced by ${PERCENT_CHANGE} percentage points)" | tee -a "$LOG_FILE"
else
    echo "[$DATE] Space freed: ${FREED_KB} KB (disk usage reduced by ${PERCENT_CHANGE} percentage points)" | tee -a "$LOG_FILE"
fi

echo "[$DATE] Docker cleanup completed successfully" | tee -a "$LOG_FILE"
echo "---" | tee -a "$LOG_FILE"
