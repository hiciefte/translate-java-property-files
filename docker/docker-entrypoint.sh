#!/usr/bin/env bash
set -euo pipefail

# If this script is run as root, fix permissions for the target repository
# and then re-execute this script as the non-root 'appuser'.
if [ "$(id -u)" = '0' ]; then
    echo "[Entrypoint] Running as root. Fixing /target_repo permissions..."
    # Ensure the target directory exists and is owned by appuser.
    # This makes the container resilient to the volume's initial state.
    mkdir -p /target_repo
    chown -R appuser:appuser /target_repo
    echo "[Entrypoint] Permissions fixed. Re-executing as appuser..."
    # Use gosu to drop privileges and run the rest of the script as appuser.
    # "$@" passes along any command given to the entrypoint (e.g., from docker-compose).
    exec gosu appuser "$0" "$@"
fi

# --- From this point on, the script is guaranteed to be running as appuser ---

# Log function for this script
log() {
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

    log "Checking out 'main' and resetting to match 'upstream/main'..."
    git checkout main
        git reset --hard upstream/main
else
    log "No repository found in $TARGET_REPO_DIR. Cloning from fork..."
    git clone "$FORK_REPO_URL" "$TARGET_REPO_DIR"
        cd "$TARGET_REPO_DIR"

    log "Adding 'upstream' remote..."
    git remote add upstream "$ACTUAL_UPSTREAM_REPO_URL"

    log "Fetching latest changes from upstream..."
    git fetch --prune --tags upstream

    log "Checking out 'main' and resetting to match 'upstream/main'..."
    git checkout main
        git reset --hard upstream/main
fi

log "Repository is up to date."
cd /app # Return to the application's working directory

# --- Execute Main Command ---
# The entrypoint has finished its setup. The container's main command can now be executed.
# The update-translations.sh script is responsible for managing its own working directory.
log "Handing off to the main container command:" "$@"
exec "$@" 