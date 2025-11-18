# Maintenance Scripts

This directory contains maintenance and utility scripts for the translation project.

## Docker Cleanup Scripts

### docker-cleanup.sh

Automated Docker cleanup script that prevents disk space accumulation from Docker images and build cache.

**What it does:**
- Removes stopped containers older than 24 hours
- Removes dangling images (untagged from builds)
- Removes unused images older than 7 days (keeps recent builds)
- Removes unused Docker volumes
- Removes build cache older than 7 days
- Logs all actions with before/after disk metrics

**Safety features:**
- Preserves running containers and their images
- Keeps recent builds (7 days) for rollback capability
- Provides detailed logging of all cleanup operations

**Usage:**
```bash
# Manual execution
cd /path/to/project
./docker-cleanup.sh

# View cleanup logs
tail -50 logs/docker-cleanup.log
```

**Recommended schedule:** Weekly (e.g., every Sunday 2 AM)

### setup-cron-cleanup.sh

Automated installation script for setting up the Docker cleanup as a weekly cron job.

**What it does:**
- Copies docker-cleanup.sh to your project directory
- Makes the script executable
- Creates a weekly cron job in `/etc/cron.weekly/`
- Tests the cleanup script

**Usage:**
```bash
# Install for specific project
sudo ./setup-cron-cleanup.sh /path/to/project

# Install for current directory
cd /path/to/project
sudo ./scripts/setup-cron-cleanup.sh
```

**Requirements:**
- Must be run as root (use `sudo`)
- Docker must be installed
- Project directory must exist

**What gets installed:**
- Cleanup script in project directory
- Cron job in `/etc/cron.weekly/docker-cleanup-{project-name}`
- Logs directory for cleanup output

## Additional Configuration

For complete disk space management including log rotation and systemd journal limits, see:
- [Disk Space Management Guide](../docs/maintenance/disk-space-management.md)

## Customization

You can adjust the cleanup retention periods by editing `docker-cleanup.sh`:

```bash
# Keep containers for 48 hours instead of 24
docker container prune -f --filter "until=48h"

# Keep images for 14 days instead of 7
docker image prune -a -f --filter "until=336h"
```

See the [maintenance documentation](../docs/maintenance/disk-space-management.md#customization) for more options.
