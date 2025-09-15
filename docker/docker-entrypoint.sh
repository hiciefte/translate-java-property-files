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

# --- SSH Configuration ---
# The local dev environment uses SSH Agent Forwarding, while the server uses a mounted key.
# This logic detects the SSH agent socket and configures Git to use it if present.
if [ -S "$SSH_AUTH_SOCK" ]; then
    log "SSH Agent socket found. Configuring Git to use SSH Agent Forwarding."
    # When using the agent, we don't need to write to known_hosts, which might be in a read-only volume.
    export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
else
    log "No SSH Agent socket found. Using mounted SSH keys."
    # Fix for macOS users: Comment out UseKeychain option if it exists in ssh config,
    # as it's not supported on Linux and causes git operations to fail.
    SSH_CONFIG_FILE="/home/appuser/.ssh/config"
    if [ -f "$SSH_CONFIG_FILE" ]; then
        log "Checking for incompatible macOS SSH options in $SSH_CONFIG_FILE..."
        # Use sed to comment out the line. The -i.bak creates a backup for safety.
        sed -i.bak 's/^\s*UseKeychain\s.*$/# &/' "$SSH_CONFIG_FILE"
    fi
fi

# We expect this script to be run from the repository root.
# All subsequent git commands will be run from here.
cd /target_repo

# --- Execute Main Command ---
log "Handing off to the main container command:" "$@"
exec "$@" 