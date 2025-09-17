#!/bin/bash
#
# Entrypoint script for the Translate Java Property Files service.
# This script handles initial setup, privilege dropping, and Git repository management.
#

# --- Strict Mode ---
set -euo pipefail

# Resolve appuser's UID/GID once; allow override via env for edge images.
APPUSER_UID="${APPUSER_UID:-$(id -u appuser 2>/dev/null || echo 9999)}"
APPUSER_GID="${APPUSER_GID:-$(id -g appuser 2>/dev/null || echo 9999)}"

# --- Log Function ---
# Defined at the top to be available for all parts of the script.
log() {
    local message="$1"
    local level="${2:-INFO}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint] [$level] $message"
}

# --- Unified Helper Functions ---

# Set up SSH host keys for secure git operations.
setup_ssh() {
    log "Configuring SSH..."
    mkdir -p /home/appuser/.ssh

    if [ "${ALLOW_INSECURE_SSH:-false}" = "true" ]; then
        log "WARNING: ALLOW_INSECURE_SSH is true. Host key verification is disabled." "WARNING"
        echo -e "Host github.com\n\tStrictHostKeyChecking no\n\tUserKnownHostsFile=/dev/null" > /home/appuser/.ssh/config
    else
        if [ ! -r /etc/ssh/ssh_known_hosts ] || ! grep -q "github.com" /etc/ssh/ssh_known_hosts; then
            log "ERROR: The pinned SSH known_hosts file is missing or invalid." "ERROR"
            log "To run in an insecure mode for development, set ALLOW_INSECURE_SSH=true." "ERROR"
            exit 1
        fi
        log "SSH is configured for strict host key checking using the baked-in known_hosts file."
    fi

    # Ensure correct ownership and permissions, but only chown if running as root.
    if [ "$(id -u)" -eq 0 ]; then
        chown -R "${APPUSER_UID}:${APPUSER_GID}" /home/appuser/.ssh || log "Warning: unable to chown /home/appuser/.ssh" "WARNING"
    fi
    # These chmod operations are safe for appuser to run on its own files.
    chmod 700 /home/appuser/.ssh
    chmod 600 /home/appuser/.ssh/config 2>/dev/null || true # Might not exist in secure mode
    chmod 600 /home/appuser/.ssh/known_hosts 2>/dev/null || true # Might not exist in insecure mode
}

# Helper function to ensure log directory exists and has correct permissions.
ensure_logs_dir() {
  local mode="${LOG_DIR_MODE:-0755}"
  mkdir -p /app/logs
  # Check if ownership is incorrect.
  if find /app/logs -mindepth 0 -maxdepth 0 \( ! -uid "$APPUSER_UID" -o ! -gid "$APPUSER_GID" \) -print -quit | read -r; then
    # Only attempt to chown if running as root.
    if [ "$(id -u)" -eq 0 ]; then
      chown -R "${APPUSER_UID}:${APPUSER_GID}" /app/logs || log "Warning: unable to chown /app/logs; continuing" "WARNING"
    fi
  fi
  chmod "$mode" /app/logs || log "Warning: Could not set permissions on /app/logs. Continuing..." "WARNING"
}

# --- Main Execution Logic ---
# The script acts as a gate:
# 1. If run as root, it fixes permissions and then re-executes itself as appuser.
# 2. If run as non-root (appuser), it performs the git operations and runs the main command.

if [ "$(id -u)" -ne 0 ]; then
    # --- appuser Execution Block ---
    log "Starting entrypoint script as user: $(whoami)"

    # Ensure logs and SSH are configured correctly before proceeding.
    ensure_logs_dir
    setup_ssh

    TARGET_REPO_DIR="${TARGET_REPO_DIR:-/target_repo}"

    # --- Git Configuration ---
    log "Configuring git user..."
    GIT_USER_NAME=$(git config --global --get user.name || echo "bisq-bot")
    GIT_USER_EMAIL=$(git config --global --get user.email || echo "bisq-bot@users.noreply.github.com")
    GPG_SIGNING_KEY=$(gpg --list-secret-keys --with-colons 2>/dev/null | grep '^sec' | cut -d: -f5 | head -n1 || true)

    git config --global user.name "$GIT_USER_NAME"
    git config --global user.email "$GIT_USER_EMAIL"

    if [ -n "$GPG_SIGNING_KEY" ]; then
        git config --global user.signingkey "$GPG_SIGNING_KEY"
            git config --global commit.gpgsign true
        log "Git user configured with GPG signing key."
        else
        git config --global --unset-all user.signingkey >/dev/null 2>&1 || true
            git config --global commit.gpgsign false
        log "Git user configured without a GPG signing key; commit signing disabled."
    fi

    # --- Repository Initialization/Update ---
    if [ -d "$TARGET_REPO_DIR/.git" ]; then
        if [ ! -w "$TARGET_REPO_DIR" ]; then
          log "Error: $TARGET_REPO_DIR is not writable by $(whoami). Ensure correct ownership/permissions." "ERROR"
          exit 1
        fi
        log "Repository already exists in $TARGET_REPO_DIR. Updating..."
        cd "$TARGET_REPO_DIR"
    else
        if [ -e "$TARGET_REPO_DIR" ] && [ ! -w "$TARGET_REPO_DIR" ]; then
          log "Error: $TARGET_REPO_DIR exists but is not writable by $(whoami)." "ERROR"
          exit 1
        fi
        log "No repository found in $TARGET_REPO_DIR. Cloning from fork..."
        # Use parameter expansion with error message for required variables
        FORK_REPO_URL="git@github.com:${FORK_REPO_NAME:?FORK_REPO_NAME must be set}.git"
        git clone "$FORK_REPO_URL" "$TARGET_REPO_DIR"
            cd "$TARGET_REPO_DIR"
    fi

    # --- Git Remote and Branch Harmonization ---
    REMOTE=""
    if git remote | grep -q "^upstream$"; then
        REMOTE="upstream"
    elif git remote | grep -q "^origin$"; then
        REMOTE="origin"
    fi

    if ! git remote | grep -q "^upstream$"; then
        if [ -n "${UPSTREAM_REPO_NAME:-}" ]; then
            log "Adding 'upstream' remote from UPSTREAM_REPO_NAME..."
            git remote add upstream "https://github.com/${UPSTREAM_REPO_NAME}.git"
            REMOTE="upstream"
        elif [ -z "$REMOTE" ]; then
            log "Error: No 'upstream' or 'origin' remote found, and UPSTREAM_REPO_NAME is not set." "ERROR" >&2
            exit 1
        fi
    fi
    if [ -z "$REMOTE" ]; then
        REMOTE="origin"
    fi

    log "Using remote: ${REMOTE}"
    log "Fetching latest changes from ${REMOTE}..."
    git fetch --prune --tags "$REMOTE"

    DEFAULT_BRANCH="${TARGET_BRANCH_FOR_PR:-}"
    if [ -z "$DEFAULT_BRANCH" ]; then
      DEFAULT_BRANCH="$(git remote show "$REMOTE" 2>/dev/null | awk -F': ' '/HEAD branch/ {print $2}')"
      DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
      # If remote doesn't have that branch, try 'master'
      if ! git ls-remote --exit-code --heads "$REMOTE" "$DEFAULT_BRANCH" >/dev/null 2>&1; then
        if git ls-remote --exit-code --heads "$REMOTE" master >/dev/null 2>&1; then
          DEFAULT_BRANCH="master"
        fi
      fi
    fi
    log "Using default branch: ${DEFAULT_BRANCH}"

    log "Checking out '${DEFAULT_BRANCH}' and resetting to match '${REMOTE}/${DEFAULT_BRANCH}'..."
    if git rev-parse --verify --quiet "refs/remotes/${REMOTE}/${DEFAULT_BRANCH}" >/dev/null; then
      git checkout -B "$DEFAULT_BRANCH" "${REMOTE}/${DEFAULT_BRANCH}"
    else
      log "Error: remote branch '${REMOTE}/${DEFAULT_BRANCH}' not found." "ERROR" >&2
      exit 1
    fi

    # --- Final Steps ---
    log "Repository is up to date."

    if [ "$#" -eq 0 ]; then
      log "Error: no command provided to exec. Set CMD in Dockerfile or command in docker-compose.yml." "ERROR" >&2; exit 1
    fi
    log "Handing off to the main container command: $*"
    # Hand off to the intended command (e.g., update-translations.sh)
    exec "$@"

else
    # --- Root Execution Block ---
    log "Running as root. Ensuring directories exist and have correct permissions..."

    # Ensure the home directory for appuser exists and has correct ownership.
    mkdir -p /home/appuser
    chown "${APPUSER_UID}:${APPUSER_GID}" /home/appuser

    # Ensure log directory exists and has correct permissions.
    ensure_logs_dir

    # Fix permissions on the target repository if it's a mounted volume
    if [ -d "/target_repo" ]; then
        chown -R "${APPUSER_UID}:${APPUSER_GID}" "/target_repo"
    fi

    # Avoid git safety warnings when root later re-executes a git command as appuser
    # on a directory that root has just owned.
    git config --global --add safe.directory /target_repo || true

    # Set up SSH. This is done as root to ensure correct ownership of created files.
    setup_ssh

    # Attempt to switch to the appuser.
    # If this fails (e.g., on Docker for Mac), check the ALLOW_RUN_AS_ROOT flag.
    log "Permissions fixed. Re-executing as appuser..."

    # Set HOME and USER explicitly for gosu to ensure a clean environment for git and other tools.
    export HOME=/home/appuser
    export USER=appuser

    # Use gosu to drop privileges and re-execute this same script as the appuser.
    # The script will then enter the `if [ "$(id -u)" -ne 0 ]` block.
    if ! exec gosu appuser "$0" "$@"; then
        log "Warning: gosu failed to switch to appuser." "WARNING"
        if [ "${ALLOW_RUN_AS_ROOT:-false}" = "true" ]; then
            log "ALLOW_RUN_AS_ROOT=true; continuing as root." "WARNING"
            # Fall through to execute the command as root
        else
            log "Refusing to continue as root. Set ALLOW_RUN_AS_ROOT=true to override." "ERROR"
            exit 1
        fi
    fi
fi 