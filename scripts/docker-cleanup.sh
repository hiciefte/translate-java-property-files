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

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${PROJECT_ROOT}/logs/docker-cleanup.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

echo "[$DATE] Starting Docker cleanup..." | tee -a "$LOG_FILE"

# Get disk usage before cleanup
BEFORE=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//g')
echo "[$DATE] Disk usage before: ${BEFORE}%" | tee -a "$LOG_FILE"

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

# Get disk usage after cleanup
AFTER=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//g')
FREED=$((BEFORE - AFTER))
echo "[$DATE] Disk usage after: ${AFTER}%" | tee -a "$LOG_FILE"
echo "[$DATE] Space freed: ${FREED}%" | tee -a "$LOG_FILE"

echo "[$DATE] Docker cleanup completed successfully" | tee -a "$LOG_FILE"
echo "---" | tee -a "$LOG_FILE"
