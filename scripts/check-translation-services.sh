#!/bin/bash
# Translation Service Health Check Script
# Created: 2025-11-27
# Purpose: Monitor for abnormal translation service behavior

set -euo pipefail

ALERT_FILE="/var/log/translation-service-alerts.log"
GITHUB_TOKEN=$(grep '^GITHUB_TOKEN=' /opt/translate-java-property-files/docker/.env | cut -d= -f2)

log_alert() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ALERT: $1" | tee -a "$ALERT_FILE"
}

log_ok() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] OK: $1"
}

count_open_translation_prs() {
    local repo="$1"
    curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/repos/${repo}/pulls?state=open&per_page=100" \
        | jq '[.[] | select(.head.ref | startswith("translation-updates-"))] | length'
}

check_cron_log() {
    local label="$1"
    local log_file="$2"

    if [ ! -f "$log_file" ]; then
        log_alert "$label cron log not found: $log_file"
        return
    fi

    local start_line
    start_line=$(grep -nE "Starting Git and Transifex validation" "$log_file" | tail -n1 | cut -d: -f1 || true)

    if [ -z "$start_line" ]; then
        log_alert "$label cron job has no run markers - check $log_file"
        return
    fi

    local start_ts
    start_ts=$(sed -n "${start_line}p" "$log_file" | sed -n 's/^\[\([^]]*\)\].*/\1/p')

    local status_segment
    status_segment=$(tail -n +"$start_line" "$log_file" | grep -E "Translation update script finished successfully|No further processing needed|BLOCKING CONDITION DETECTED" | tail -n1 || true)

    if [ -n "$status_segment" ]; then
        log_ok "$label cron job completed successfully or blocked appropriately"
        return
    fi

    local now_epoch start_epoch age_sec
    now_epoch=$(date +%s)
    start_epoch=$(date -d "$start_ts" +%s 2>/dev/null || echo 0)
    age_sec=$((now_epoch - start_epoch))

    if [ "$start_epoch" -gt 0 ] && [ "$age_sec" -lt 10800 ]; then
        log_ok "$label cron job appears to be still running (started ${age_sec}s ago)"
    else
        log_alert "$label cron job may have failed or stalled - check $log_file"
    fi
}

# Check 1: Ensure systemd service is NOT running
if systemctl is-active --quiet translator.service 2>/dev/null; then
    log_alert "translator.service is running - it should be disabled!"
    systemctl stop translator.service
    systemctl disable translator.service
else
    log_ok "translator.service is not running"
fi

# Check 2: Count open translation PRs (translation branches only)
bisq2_pr_count=$(count_open_translation_prs "bisq-network/bisq2")
mobile_pr_count=$(count_open_translation_prs "bisq-network/bisq-mobile")
total_pr_count=$((bisq2_pr_count + mobile_pr_count))

if [ "$total_pr_count" -gt 2 ]; then
    log_alert "Too many open translation PRs: total=${total_pr_count} (bisq2=${bisq2_pr_count}, mobile=${mobile_pr_count}, expected total <= 2)"
else
    log_ok "Open translation PRs: total=${total_pr_count} (bisq2=${bisq2_pr_count}, mobile=${mobile_pr_count})"
fi

# Check 3: Check latest cron run result robustly
main_log="/opt/translate-java-property-files/logs/cron_job.log"
mobile_log="/opt/translate-java-property-files-mobile-app/logs/cron_job.log"
check_cron_log "Main service" "$main_log"
check_cron_log "Mobile app service" "$mobile_log"

# Check 4: Disk space for Docker volumes
disk_usage=$(df -h /var/lib/docker | tail -1 | awk '{print $5}' | sed 's/%//' )
if [ "$disk_usage" -gt 85 ]; then
    log_alert "Docker volume disk usage high: ${disk_usage}%"
else
    log_ok "Docker volume disk usage: ${disk_usage}%"
fi

echo "Health check completed at $(date)"
