#!/bin/bash
#
# Entrypoint script for the Translate Java Property Files service.
# This script handles initial setup, privilege dropping, and Git repository management.
#

# --- Strict Mode ---
set -euo pipefail

# --- Log Function ---
# Moved to the top to be available for all parts of the script, including error paths.
log() {
    # Use "$*" to log all arguments as a single string, preserving quotes and spaces.
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint] $*"
}

# --- Root-Level Execution ---
# This block runs only if the container is started as root (UID 0).
# Its primary jobs are to fix permissions and then drop to the non-root 'appuser'.
if [ "$(id -u)" -eq 0 ]; then
    log "Running as root. Ensuring /target_repo exists and has correct permissions..."

    # The TARGET_REPO_DIR can be overridden by an environment variable.
    # Default to /target_repo if not set.
    TARGET_REPO_DIR="${TARGET_REPO_DIR:-/target_repo}"

    # Ensure the target repo directory exists and is owned by appuser.
    # This is crucial because the volume might be mounted from the host with root ownership.
    mkdir -p "$TARGET_REPO_DIR"
    if [ "$(stat -c '%u:%g' "$TARGET_REPO_DIR")" != "$(id -u appuser):$(id -g appuser)" ]; then
      chown appuser:appuser "$TARGET_REPO_DIR"
    fi

    # Also ensure the application's log directory exists, is a directory, and is owned by appuser
    if [ -e /app/logs ] && [ ! -d /app/logs ]; then
        log "Error: /app/logs exists but is not a directory" >&2; exit 1
    fi
    # Allow overriding via LOG_DIR_MODE (default 0755)
    LOG_DIR_MODE="${LOG_DIR_MODE:-0755}"
    # Accept common numeric modes like 755/0755 or symbolic (u=rwx,go=rx); otherwise fallback.
    if ! chmod --reference=/dev/null "$LOG_DIR_MODE" /dev/null 2>/dev/null; then
      log "Warning: invalid LOG_DIR_MODE provided; defaulting to 0755"
      LOG_DIR_MODE="0755"
    fi
    mkdir -p /app/logs
    # Avoid expensive chown -R unless ownership is wrong.
    if [ "$(stat -c '%u:%g' /app/logs)" != "$(id -u appuser):$(id -g appuser)" ]; then
      chown -R appuser:appuser /app/logs
    fi
    chmod "$LOG_DIR_MODE" /app/logs

    log "Permissions fixed. Re-executing as appuser..."
    # Drop privileges and re-run this script as 'appuser'
    if command -v gosu >/dev/null 2>&1; then
        exec gosu appuser "$0" "$@"
    elif command -v su-exec >/dev/null 2>&1; then
        exec su-exec appuser "$0" "$@"
    else
        log "Error: neither 'gosu' nor 'su-exec' found in PATH."
        exit 1
    fi
fi

# --- Appuser-Level Execution ---
# This part of the script runs as the non-root 'appuser'

# Ensure logs directory exists when not started as root
[ -d /app/logs ] || mkdir -p /app/logs
# Align permissions if we can modify the directory. Degrade gracefully on failure.
if [ -w /app/logs ]; then
  LOG_DIR_MODE="${LOG_DIR_MODE:-0755}"
  # Validate mode to prevent script exit
  if ! chmod --reference=/dev/null "$LOG_DIR_MODE" /dev/null 2>/dev/null; then
    log "Warning: invalid LOG_DIR_MODE provided; defaulting to 0755"
    LOG_DIR_MODE="0755"
  fi
  chmod "$LOG_DIR_MODE" /app/logs || log "Warning: Could not set permissions on /app/logs. Continuing..."
fi

log "Starting entrypoint script as user: $(whoami)"

# The TARGET_REPO_DIR can be overridden by an environment variable.
# Default to /target_repo if not set.
TARGET_REPO_DIR="${TARGET_REPO_DIR:-/target_repo}"

# --- Git Configuration ---
log "Configuring git user..."
# Configure git user with GPG signing key if available
# This relies on the GPG key being imported during the Docker build process for 'appuser'
GIT_USER_NAME=$(git config --global --get user.name || echo "bisq-bot")
GIT_USER_EMAIL=$(git config --global --get user.email || echo "bisq-bot@users.noreply.github.com")
GPG_SIGNING_KEY=$(gpg --list-secret-keys --with-colons | grep '^sec' | cut -d: -f5 | head -n1 || true)

git config --global user.name "$GIT_USER_NAME"
git config --global user.email "$GIT_USER_EMAIL"

if [ -n "$GPG_SIGNING_KEY" ]; then
    git config --global user.signingkey "$GPG_SIGNING_KEY"
    git config --global commit.gpgsign true
    log "Git user configured with GPG signing key."
else
    log "Git user configured without a GPG signing key."
fi

# --- Repository Initialization/Update ---
# If the repo exists, update it. Otherwise, clone it.
if [ -d "$TARGET_REPO_DIR/.git" ]; then
    if [ ! -w "$TARGET_REPO_DIR" ]; then
      log "Error: $TARGET_REPO_DIR is not writable by $(whoami). Ensure correct ownership/permissions."
      exit 1
    fi
    log "Repository already exists in $TARGET_REPO_DIR. Updating..."
    cd "$TARGET_REPO_DIR"

    # Fetch the latest changes
    log "Fetching latest changes from upstream..."
    git fetch --prune --tags upstream

    # Determine default branch dynamically
    DEFAULT_BRANCH="${TARGET_BRANCH_FOR_PR:-}"
    if [ -z "$DEFAULT_BRANCH" ]; then
      DEFAULT_BRANCH="$(git remote show upstream 2>/dev/null | awk -F': ' '/HEAD branch/ {print $2}')"
      DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}" # Fallback to main
    fi
    log "Using default branch: ${DEFAULT_BRANCH}"

    # Checkout the branch, creating it if it doesn't exist locally,
    # and reset it to match the upstream state. This is a robust way
    # to ensure the local branch is a clean copy of the remote.
    log "Checking out '${DEFAULT_BRANCH}' and resetting to match 'upstream/${DEFAULT_BRANCH}'..."
    git checkout -B "$DEFAULT_BRANCH" "upstream/${DEFAULT_BRANCH}"

else
    if [ -e "$TARGET_REPO_DIR" ] && [ ! -w "$TARGET_REPO_DIR" ]; then
      log "Error: $TARGET_REPO_DIR exists but is not writable by $(whoami)."
      exit 1
    fi
    log "No repository found in $TARGET_REPO_DIR. Cloning from fork..."
    # Derive fork and upstream URLs from environment variables
    FORK_REPO_URL="https://github.com/${FORK_REPO_NAME}.git"
    ACTUAL_UPSTREAM_REPO_URL="https://github.com/${UPSTREAM_REPO_NAME}.git"

    git clone "$FORK_REPO_URL" "$TARGET_REPO_DIR"
    cd "$TARGET_REPO_DIR"
    git remote add upstream "$ACTUAL_UPSTREAM_REPO_URL"
fi

# --- Final Steps ---
log "Repository is up to date."

# Hand off to the main command passed to the container (e.g., from docker-compose CMD)
log "Handing off to the main container command."
exec "$@" 