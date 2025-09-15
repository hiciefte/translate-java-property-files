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
    chown -R appuser:appuser "$TARGET_REPO_DIR"

    # Also ensure the application's log directory exists, is a directory, and is owned by appuser
    if [ -e /app/logs ] && [ ! -d /app/logs ]; then
        echo "[Entrypoint] Error: /app/logs exists but is not a directory" >&2; exit 1
    fi
    # Allow overriding via LOG_DIR_MODE (default 0755)
    LOG_DIR_MODE="${LOG_DIR_MODE:-0755}"
    mkdir -p /app/logs
    chown -R appuser:appuser /app/logs
    chmod "$LOG_DIR_MODE" /app/logs

    echo "[Entrypoint] Permissions fixed. Re-executing as appuser..."
    # Drop privileges and re-run this script as 'appuser'
    if command -v gosu >/dev/null 2>&1; then
        exec gosu appuser "$0" "$@"
    elif command -v su-exec >/dev/null 2>&1; then
        exec su-exec appuser "$0" "$@"
    else
        # Use echo directly as log() may not be available if this block is moved
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint] Error: neither 'gosu' nor 'su-exec' found in PATH." >&2
        exit 1
    fi
fi

# --- Appuser-Level Execution ---
# This part of the script runs as the non-root 'appuser'

# Ensure logs directory exists when not started as root
[ -d /app/logs ] || mkdir -p /app/logs
# Align permissions if we can modify the directory
if [ -w /app/logs ]; then
  chmod "${LOG_DIR_MODE:-0755}" /app/logs
fi

# Log function for this script
log() {
    # Use "$*" to log all arguments as a single string, preserving quotes and spaces.
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint] $*"
}

log "Starting entrypoint script as user: $(whoami)"

# --- Environment Variable Validation ---
# Ensure required Git-related environment variables are set.
if [ -z "${FORK_REPO_URL:-}" ] || [ -z "${GIT_AUTHOR_NAME:-}" ] || [ -z "${GIT_AUTHOR_EMAIL:-}" ]; then
    log "Error: One or more required environment variables are missing."
    log "Please set: FORK_REPO_URL, GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL (optional: UPSTREAM_REPO_URL)"
    exit 1
fi

# Derive upstream if not provided (fallback to fork).
ACTUAL_UPSTREAM_REPO_URL="${UPSTREAM_REPO_URL:-$FORK_REPO_URL}"
# Use the same logic as the root block to ensure consistency
TARGET_REPO_DIR="${TARGET_REPO_DIR:-/target_repo}"

# --- Git User Configuration ---
log "Configuring git user..."
        git config --global user.name "$GIT_AUTHOR_NAME"
        git config --global user.email "$GIT_AUTHOR_EMAIL"
if [ -n "${GIT_SIGNING_KEY:-}" ]; then
        git config --global user.signingkey "$GIT_SIGNING_KEY"
        git config --global commit.gpgsign true 
    log "Git user configured with GPG signing key."
else
    git config --global commit.gpgsign false
    log "Git user configured without a GPG signing key."
fi

# --- Repository Setup ---
# The target directory is a mounted volume, so its contents persist.
# This logic handles both the initial setup and subsequent runs.
    if [ -d "$TARGET_REPO_DIR/.git" ]; then
    log "Repository already exists in $TARGET_REPO_DIR. Updating..."
        cd "$TARGET_REPO_DIR"

    # Verify and set remote URLs to ensure they are correct
    git remote set-url origin "$FORK_REPO_URL"
    git remote set-url upstream "$ACTUAL_UPSTREAM_REPO_URL" 2>/dev/null || git remote add upstream "$ACTUAL_UPSTREAM_REPO_URL"

    log "Fetching latest changes from upstream..."
    git fetch --prune --tags upstream

    # Determine the default branch to reset against
    DEFAULT_BRANCH="${TARGET_BRANCH_FOR_PR:-}"
    if [ -z "$DEFAULT_BRANCH" ]; then
      DEFAULT_BRANCH="$(git remote show upstream 2>/dev/null | awk -F': ' '/HEAD branch/ {print $2}')"
      DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
    fi
    log "Using default branch: ${DEFAULT_BRANCH}"

    log "Checking out '${DEFAULT_BRANCH}' and resetting to match 'upstream/${DEFAULT_BRANCH}'..."
    git checkout "$DEFAULT_BRANCH"
    git reset --hard "upstream/${DEFAULT_BRANCH}"
else
    log "No repository found in $TARGET_REPO_DIR. Cloning from fork..."
    git clone "$FORK_REPO_URL" "$TARGET_REPO_DIR"
        cd "$TARGET_REPO_DIR"

    log "Adding 'upstream' remote..."
    git remote add upstream "$ACTUAL_UPSTREAM_REPO_URL"

    log "Fetching latest changes from upstream..."
    git fetch --prune --tags upstream

    # Determine the default branch for the initial checkout
    DEFAULT_BRANCH="${TARGET_BRANCH_FOR_PR:-}"
    if [ -z "$DEFAULT_BRANCH" ]; then
      DEFAULT_BRANCH="$(git remote show upstream 2>/dev/null | awk -F': ' '/HEAD branch/ {print $2}')"
      DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
    fi
    log "Using default branch: ${DEFAULT_BRANCH}"

    log "Checking out '${DEFAULT_BRANCH}' and resetting to match 'upstream/${DEFAULT_BRANCH}'..."
    git checkout "$DEFAULT_BRANCH"
    git reset --hard "upstream/${DEFAULT_BRANCH}"
fi

log "Repository is up to date."
cd /app # Return to the application's working directory

# --- Execute Main Command ---
# The entrypoint has finished its setup. The container's main command can now be executed.
# The update-translations.sh script is responsible for managing its own working directory.
log "Handing off to the main container command:" "$@"
exec "$@" 